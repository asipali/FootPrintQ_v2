"""Phase G — Dedicated Correlation Engine coordinating normalization, matching, deduplication, and persistence."""

from datetime import datetime, timezone
import hashlib
import logging
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel, EvidenceModel, TargetAuthorizationModel
from app.models.scan import ScanFindingHostModel, ScanFindingPortModel, ActiveScanJobModel
from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.models.correlation import CorrelationRecordModel
from app.services.correlation.deduplicator import VulnerabilityLifecycleTracker
from app.services.correlation.evidence_verifier import EvidenceVerifier
from app.services.correlation.models import (
    AssetType,
    CorrelatedRelationship,
    EvidenceVerificationState,
    FindingLifecycleState,
    NormalizedAsset,
    RelationshipStrength,
)
from app.services.correlation.normalizer import (
    classify_and_normalize_asset,
    normalize_domain_name,
    normalize_ip,
    normalize_port_protocol,
)
from app.services.correlation.rules import (
    DNSHostResolutionRule,
    EvidenceAssetLinkRule,
    HostGeneralVulnerabilityRule,
    HostPortVulnerabilityMatchRule,
    ServiceBannerMatchRule,
)

logger = logging.getLogger("footprintiq.services.correlation.engine")


class CorrelationEngine:
    """Orchestrates multi-source forensic evidence correlation for FootprintIQ investigations."""

    def __init__(self, db: Session):
        self.db = db
        self.evidence_verifier = EvidenceVerifier(db)
        self.rule_port_vuln = HostPortVulnerabilityMatchRule()
        self.rule_service = ServiceBannerMatchRule()
        self.rule_dns = DNSHostResolutionRule()
        self.rule_general_vuln = HostGeneralVulnerabilityRule()
        self.rule_evidence = EvidenceAssetLinkRule()

    def run_correlation(self, investigation_id: str) -> Dict[str, Any]:
        """Executes full cross-stage correlation and persists relationships idempotently.
        
        Args:
            investigation_id: Scope boundary for tenant isolation.
            
        Returns:
            Dict containing correlation summary, normalized assets, relationships, and knowledge graph.
        """
        inv = self.db.get(InvestigationModel, investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        # 1. Ingest all records strictly bounded by investigation_id
        authorizations = self.db.scalars(
            select(TargetAuthorizationModel).where(TargetAuthorizationModel.investigation_id == investigation_id)
        ).all()

        entities = self.db.scalars(
            select(EntityModel).where(EntityModel.investigation_id == investigation_id)
        ).all()

        hosts = self.db.scalars(
            select(ScanFindingHostModel).where(ScanFindingHostModel.investigation_id == investigation_id)
        ).all()

        host_ids = [h.id for h in hosts]
        ports = self.db.scalars(
            select(ScanFindingPortModel).where(ScanFindingPortModel.host_id.in_(host_ids))
        ).all() if host_ids else []

        vuln_jobs = self.db.scalars(
            select(VulnerabilityScanJobModel).where(VulnerabilityScanJobModel.investigation_id == investigation_id)
        ).all()

        vulns = self.db.scalars(
            select(VulnerabilityFindingModel).where(VulnerabilityFindingModel.investigation_id == investigation_id)
        ).all()

        evidence_items = self.db.scalars(
            select(EvidenceModel).where(EvidenceModel.investigation_id == investigation_id)
        ).all()

        # 2. Track Finding Lifecycles
        lifecycle_tracker = VulnerabilityLifecycleTracker(
            investigation_id=investigation_id,
            findings=vulns,
            scan_jobs=vuln_jobs,
        )
        finding_lifecycles = lifecycle_tracker.compute_finding_lifecycles()

        # 3. Build Normalized Assets Inventory
        assets: Dict[str, NormalizedAsset] = {}

        def _get_or_create_asset(raw_identifier: str, explicit_type: Optional[str] = None) -> NormalizedAsset:
            canon_val, atype, orig_val = classify_and_normalize_asset(raw_identifier, explicit_type)
            key = canon_val or orig_val.strip().lower()
            if key not in assets:
                assets[key] = NormalizedAsset(
                    identifier=key,
                    asset_type=atype,
                    original_value=orig_val,
                    investigation_id=investigation_id,
                )
            return assets[key]

        # Ingest target authorizations as known scope assets
        for auth in authorizations:
            if auth.target:
                a = _get_or_create_asset(auth.target, auth.target_type)
                a.metadata["authorized"] = True
                a.metadata["allowed_operations"] = auth.allowed_operations

        # Ingest scan hosts
        host_id_to_norm_ip: Dict[str, str] = {}
        for h in hosts:
            raw_addr = getattr(h, "address", None) or getattr(h, "ipv4_address", None)
            if not raw_addr:
                continue
            norm_ip, _ = normalize_ip(raw_addr)
            ip_val = norm_ip or raw_addr.strip().lower()
            host_id_to_norm_ip[h.id] = ip_val

            asset = _get_or_create_asset(ip_val, "IP_ADDRESS")
            asset.ips.add(ip_val)
            if h.hostname:
                norm_h = normalize_domain_name(h.hostname) or h.hostname.strip().lower()
                asset.hostnames.add(norm_h)
            if h.evidence_id:
                asset.evidence_ids.add(h.evidence_id)

        # Ingest open ports onto host assets
        host_ports_map: Dict[str, List[ScanFindingPortModel]] = {}
        for p in ports:
            ip_val = host_id_to_norm_ip.get(p.host_id)
            if not ip_val:
                continue
            host_ports_map.setdefault(ip_val, []).append(p)
            asset = _get_or_create_asset(ip_val, "IP_ADDRESS")
            asset.open_ports.append({
                "port_id": p.id,
                "port": p.port_number,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service_name or "unknown",
                "product": p.product,
                "version": p.version,
            })

        # Ingest vulnerabilities onto assets
        for v in vulns:
            raw_host = getattr(v, "host", None) or getattr(v, "target", None) or "unknown"
            norm_ip, _ = normalize_ip(raw_host)
            ip_val = norm_ip or raw_host.strip().lower()

            asset = _get_or_create_asset(ip_val, "IP_ADDRESS")
            cves = v.cve_references if isinstance(v.cve_references, list) else []
            lstate, lmeta = finding_lifecycles.get(v.id, (FindingLifecycleState.NEW, {}))

            asset.vulnerabilities.append({
                "finding_id": v.id,
                "name": v.name,
                "severity": (v.severity or "unknown").lower(),
                "cvss_score": v.cvss_score,
                "cve_references": cves,
                "nvt_oid": v.nvt_oid,
                "qod": v.qod,
                "port": v.port,
                "protocol": v.protocol,
                "solution": v.solution,
                "evidence_id": v.evidence_id,
                "lifecycle_state": lstate.value,
                "lifecycle_meta": lmeta,
            })
            if v.evidence_id:
                asset.evidence_ids.add(v.evidence_id)

        # Ingest passive recon entities
        dns_records: List[EntityModel] = []
        for e in entities:
            val = e.canonical_value or e.original_value or ""
            if not val:
                continue
            canon_val, atype, orig_val = classify_and_normalize_asset(val, e.entity_type)
            if not canon_val:
                continue

            if atype in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
                asset = _get_or_create_asset(canon_val, atype.value)
                asset.domains.add(canon_val)
                for evid in (e.evidence_ids or []):
                    if evid:
                        asset.evidence_ids.add(evid)
            elif atype == AssetType.IP_ADDRESS:
                asset = _get_or_create_asset(canon_val, "IP_ADDRESS")
                asset.ips.add(canon_val)
                for evid in (e.evidence_ids or []):
                    if evid:
                        asset.evidence_ids.add(evid)

            if e.entity_type == "DNS_RECORD" or (e.metadata_json and "resolved_ips" in e.metadata_json):
                dns_records.append(e)

        # 4. Evaluate Deterministic Correlation Rules
        relationships: List[CorrelatedRelationship] = []
        matched_obs_ids: Set[str] = set()

        # Rule 1 & Rule 2: Correlate Nmap Ports with Greenbone Vulnerabilities
        for asset_key, asset in assets.items():
            if asset.asset_type != AssetType.IP_ADDRESS:
                continue

            host_ports = host_ports_map.get(asset_key, [])
            for vuln in asset.vulnerabilities:
                vuln_port = vuln.get("port")
                vuln_proto = vuln.get("protocol")
                vuln_id = vuln["finding_id"]

                matched_port = None
                for p in host_ports:
                    res = self.rule_port_vuln.evaluate(
                        host_ip=asset_key,
                        nmap_port=p.port_number,
                        nmap_protocol=p.protocol,
                        nmap_state=p.state,
                        vuln_port=vuln_port,
                        vuln_protocol=vuln_proto,
                    )
                    if res:
                        rel_type, score, attrs, summary = res
                        matched_port = p
                        matched_obs_ids.add(p.id)
                        matched_obs_ids.add(vuln_id)

                        # Check Rule 2: Service banner / product match
                        srv_res = self.rule_service.evaluate(
                            nmap_service=p.service_name,
                            nmap_product=p.product,
                            vuln_name=vuln["name"],
                            vuln_description=vuln.get("description"),
                        )
                        if srv_res:
                            s_rel, s_score, s_attrs, s_sum = srv_res
                            attrs = list(dict.fromkeys(attrs + s_attrs))
                            score = max(score, s_score)
                            summary += f" Also corroborated: {s_sum}"

                        # Verify evidence if attached
                        ev_refs = [vuln["evidence_id"]] if vuln.get("evidence_id") else []
                        ev_status = EvidenceVerificationState.NOT_APPLICABLE
                        if ev_refs:
                            ev_status, _ = self.evidence_verifier.verify_evidence(ev_refs[0])

                        rel = CorrelatedRelationship(
                            correlation_id=f"corr-portvuln-{uuid.uuid4().hex[:10]}",
                            investigation_id=investigation_id,
                            correlation_rule_id=self.rule_port_vuln.rule_id,
                            rule_version=self.rule_port_vuln.rule_version,
                            relationship_type=rel_type,
                            confidence_score=score,
                            asset_identifier=asset_key,
                            asset_type=AssetType.IP_ADDRESS,
                            source_modules=["active_scanner", "vuln_scanner"],
                            source_scanners=["nmap", "openvas"],
                            source_observation_ids=[p.id, vuln_id],
                            matching_attributes=attrs,
                            related_vulnerability_id=vuln_id,
                            evidence_references=ev_refs,
                            evidence_verification_status=ev_status,
                            lifecycle_status=FindingLifecycleState(vuln["lifecycle_state"]),
                            summary=summary,
                            details={
                                "port": p.port_number,
                                "protocol": p.protocol,
                                "service": p.service_name,
                                "product": p.product,
                                "vulnerability_name": vuln["name"],
                                "severity": vuln["severity"],
                                "cvss_score": vuln["cvss_score"],
                                "cves": vuln["cve_references"],
                            },
                        )
                        relationships.append(rel)
                        break

                # If vulnerability had no port match (e.g. host-level flaw)
                if not matched_port and vuln_port is None:
                    gen_res = self.rule_general_vuln.evaluate(host_ip=asset_key, vuln_port=vuln_port)
                    if gen_res:
                        rel_type, score, attrs, summary = gen_res
                        matched_obs_ids.add(vuln_id)

                        ev_refs = [vuln["evidence_id"]] if vuln.get("evidence_id") else []
                        ev_status = EvidenceVerificationState.NOT_APPLICABLE
                        if ev_refs:
                            ev_status, _ = self.evidence_verifier.verify_evidence(ev_refs[0])

                        rel = CorrelatedRelationship(
                            correlation_id=f"corr-genvuln-{uuid.uuid4().hex[:10]}",
                            investigation_id=investigation_id,
                            correlation_rule_id=self.rule_general_vuln.rule_id,
                            rule_version=self.rule_general_vuln.rule_version,
                            relationship_type=rel_type,
                            confidence_score=score,
                            asset_identifier=asset_key,
                            asset_type=AssetType.IP_ADDRESS,
                            source_modules=["vuln_scanner"],
                            source_scanners=["openvas"],
                            source_observation_ids=[vuln_id],
                            matching_attributes=attrs,
                            related_vulnerability_id=vuln_id,
                            evidence_references=ev_refs,
                            evidence_verification_status=ev_status,
                            lifecycle_status=FindingLifecycleState(vuln["lifecycle_state"]),
                            summary=summary,
                            details={"vulnerability_name": vuln["name"], "severity": vuln["severity"]},
                        )
                        relationships.append(rel)

        # Rule 3: DNS Hostname Resolution to Scanned IP
        for dns_ent in dns_records:
            resolved_ips = (dns_ent.metadata_json or {}).get("resolved_ips", [])
            domain_val = dns_ent.canonical_value or dns_ent.original_value or ""
            for asset_key, asset in assets.items():
                if asset.asset_type == AssetType.IP_ADDRESS:
                    dns_res = self.rule_dns.evaluate(
                        domain_name=domain_val,
                        resolved_ips=resolved_ips,
                        scanned_ip=asset_key,
                    )
                    if dns_res:
                        rel_type, score, attrs, summary = dns_res
                        matched_obs_ids.add(dns_ent.id)
                        asset.domains.add(domain_val)

                        rel = CorrelatedRelationship(
                            correlation_id=f"corr-dns-{uuid.uuid4().hex[:10]}",
                            investigation_id=investigation_id,
                            correlation_rule_id=self.rule_dns.rule_id,
                            rule_version=self.rule_dns.rule_version,
                            relationship_type=rel_type,
                            confidence_score=score,
                            asset_identifier=asset_key,
                            asset_type=AssetType.IP_ADDRESS,
                            source_modules=["passive_recon", "active_scanner"],
                            source_scanners=["dns_osint", "nmap"],
                            source_observation_ids=[dns_ent.id],
                            matching_attributes=attrs,
                            summary=summary,
                            details={"domain": domain_val, "resolved_ip": asset_key},
                        )
                        relationships.append(rel)

        # Rule 5: Forensic Evidence Link & SHA-256 Verification
        for ev in evidence_items:
            ev_target = getattr(ev, "target", None)
            if not ev_target:
                continue
            norm_target, _ = normalize_ip(ev_target)
            target_key = norm_target or ev_target.strip().lower()

            if target_key in assets:
                ver_st, _ = self.evidence_verifier.verify_evidence(ev.id)
                ev_res = self.rule_evidence.evaluate(
                    asset_id=target_key,
                    evidence_target=target_key,
                    is_hash_verified=(ver_st == EvidenceVerificationState.VERIFIED),
                )
                if ev_res:
                    rel_type, score, attrs, summary = ev_res
                    matched_obs_ids.add(ev.id)
                    assets[target_key].evidence_ids.add(ev.id)

                    rel = CorrelatedRelationship(
                        correlation_id=f"corr-evi-{uuid.uuid4().hex[:10]}",
                        investigation_id=investigation_id,
                        correlation_rule_id=self.rule_evidence.rule_id,
                        rule_version=self.rule_evidence.rule_version,
                        relationship_type=rel_type,
                        confidence_score=score,
                        asset_identifier=target_key,
                        asset_type=assets[target_key].asset_type,
                        source_modules=["evidence_store"],
                        source_scanners=[ev.source_type or "collector"],
                        source_observation_ids=[ev.id],
                        matching_attributes=attrs,
                        evidence_references=[ev.id],
                        evidence_verification_status=ver_st,
                        summary=summary,
                        details={
                            "evidence_id": ev.id,
                            "source_name": ev.source_name,
                            "content_hash": ev.content_hash,
                            "storage_backend": ev.storage_backend,
                            "size_bytes": ev.content_size_bytes,
                        },
                    )
                    relationships.append(rel)

        # Unmatched Observations
        unmatched_observations: List[Dict[str, Any]] = []

        for p in ports:
            if p.id not in matched_obs_ids:
                ip_val = host_id_to_norm_ip.get(p.host_id, "unknown")
                unmatched_observations.append({
                    "id": p.id,
                    "type": "PORT",
                    "host": ip_val,
                    "port": p.port_number,
                    "protocol": p.protocol,
                    "service": p.service_name,
                    "reason": "Open port detected without corroborating vulnerability or application finding.",
                })

        for v in vulns:
            if v.id not in matched_obs_ids:
                unmatched_observations.append({
                    "id": v.id,
                    "type": "VULNERABILITY",
                    "host": v.host,
                    "port": v.port,
                    "name": v.name,
                    "severity": v.severity,
                    "reason": "Vulnerability reported on port not confirmed open by active port scanner.",
                })

        # 5. Idempotent Persistence into SQL Server / SQLite
        self._persist_relationships_idempotently(investigation_id, relationships)

        # 6. Format Graph Nodes & Edges
        graph_nodes: List[Dict[str, Any]] = []
        graph_edges: List[Dict[str, Any]] = []
        seen_nodes: Set[str] = set()

        def _add_graph_node(nid: str, label: str, ntype: str, props: Optional[Dict[str, Any]] = None):
            if nid not in seen_nodes:
                seen_nodes.add(nid)
                graph_nodes.append({
                    "id": nid,
                    "label": label,
                    "type": ntype,
                    "properties": props or {},
                })

        inv_node_id = f"inv_{investigation_id}"
        _add_graph_node(inv_node_id, inv.name, "investigation", {"organization": inv.organization_name})

        for a_key, a in sorted(assets.items(), key=lambda x: x[0]):
            a_node_id = f"asset_{a_key}"
            _add_graph_node(a_node_id, a_key, a.asset_type.value.lower(), {
                "open_ports_count": len(a.open_ports),
                "vulns_count": len(a.vulnerabilities),
            })
            graph_edges.append({"source": inv_node_id, "target": a_node_id, "relationship": "targets"})

            for p in a.open_ports:
                p_node_id = f"port_{a_key}_{p['port']}_{p['protocol']}"
                _add_graph_node(p_node_id, f"{p['port']}/{p['protocol']} ({p['service']})", "port", p)
                graph_edges.append({"source": a_node_id, "target": p_node_id, "relationship": "exposes"})

            for v in a.vulnerabilities:
                v_node_id = f"vuln_{v['finding_id']}"
                _add_graph_node(v_node_id, v["name"][:50], "vulnerability", {
                    "severity": v["severity"],
                    "cvss": v["cvss_score"],
                    "lifecycle": v["lifecycle_state"],
                })
                graph_edges.append({"source": a_node_id, "target": v_node_id, "relationship": "affected_by"})

        # Summary statistics
        rel_type_counts: Dict[str, int] = {}
        for r in relationships:
            t = r.relationship_type.value
            rel_type_counts[t] = rel_type_counts.get(t, 0) + 1

        ev_status_counts: Dict[str, int] = {}
        for r in relationships:
            st = r.evidence_verification_status.value
            ev_status_counts[st] = ev_status_counts.get(st, 0) + 1

        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for v in vulns:
            sev = (v.severity or "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "investigation_id": investigation_id,
            "correlation_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_assets": len(assets),
                "total_correlations": len(relationships),
                "total_entities": len(entities),
                "total_discovered_hosts": len(hosts),
                "total_open_ports": len(ports),
                "total_vulnerabilities": len(vulns),
                "severity_breakdown": severity_counts,
                "relationship_types": rel_type_counts,
                "evidence_verification_breakdown": ev_status_counts,
                "total_unmatched": len(unmatched_observations),
                "total_evidence_verified": ev_status_counts.get(EvidenceVerificationState.VERIFIED.value, 0),
            },
            "assets": [a.to_dict() for a in sorted(assets.values(), key=lambda x: x.identifier)],
            "correlations": [
                {
                    "id": r.correlation_id,
                    "correlation_id": r.correlation_id,
                    "correlation_rule_id": r.correlation_rule_id,
                    "rule_version": r.rule_version,
                    "relationship_type": r.relationship_type.value,
                    "confidence_score": r.confidence_score,
                    "asset_identifier": r.asset_identifier,
                    "asset_type": r.asset_type.value,
                    "source_modules": r.source_modules,
                    "source_scanners": r.source_scanners,
                    "source_observation_ids": r.source_observation_ids,
                    "matching_attributes": r.matching_attributes,
                    "related_vulnerability_id": r.related_vulnerability_id,
                    "evidence_references": r.evidence_references,
                    "evidence_verification_status": r.evidence_verification_status.value,
                    "lifecycle_status": r.lifecycle_status.value,
                    "summary": r.summary,
                    "details": r.details,
                    "created_at": r.created_at.isoformat(),
                }
                for r in relationships
            ],
            "unmatched_observations": unmatched_observations,
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_edges,
            },
        }

    def _persist_relationships_idempotently(
        self,
        investigation_id: str,
        relationships: List[CorrelatedRelationship],
    ) -> None:
        """Atomically replaces active correlation records for this investigation to maintain strict idempotency."""
        # Delete existing active records for this investigation
        self.db.execute(
            delete(CorrelationRecordModel).where(CorrelationRecordModel.investigation_id == investigation_id)
        )
        self.db.flush()

        now = datetime.now(timezone.utc)
        for r in relationships:
            rec = CorrelationRecordModel(
                id=r.correlation_id,
                investigation_id=investigation_id,
                correlation_rule_id=r.correlation_rule_id,
                rule_version=r.rule_version,
                relationship_type=r.relationship_type.value,
                confidence_score=r.confidence_score,
                asset_identifier=r.asset_identifier,
                asset_type=r.asset_type.value,
                source_modules=r.source_modules,
                source_scanners=r.source_scanners,
                source_observation_ids=r.source_observation_ids,
                matching_attributes=r.matching_attributes,
                related_vulnerability_id=r.related_vulnerability_id,
                evidence_references=r.evidence_references,
                evidence_verification_status=r.evidence_verification_status.value,
                lifecycle_status=r.lifecycle_status.value,
                correlation_status=r.correlation_status,
                summary=r.summary,
                details_json=r.details,
                created_at=now,
                updated_at=now,
            )
            self.db.add(rec)

        self.db.commit()
