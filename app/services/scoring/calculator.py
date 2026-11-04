"""Finalized, versioned 5-factor exposure scoring engine for FootprintIQ investigations.

Supported Formulas:
1. v3.0-5factor (Authoritative active-weighted model):
   R = (0.20 * P) + (0.15 * D) + (0.25 * S) + (0.35 * V) + (0.05 * C)

2. v1.0-legacy (Historical passive-weighted baseline model):
   R = (0.25 * P) + (0.20 * D) + (0.25 * S) + (0.20 * V) + (0.10 * C)

Where:
  - P: Public Footprint (0 - 100) based on deduplicated discovered emails, persons, documents, and search evidence.
  - D: Domain Hygiene (0 - 100) based on deduplicated subdomains and missing DMARC/SPF policies.
  - S: Service Exposure (0 - 100) based on confirmed open network ports on reachable hosts and sensitive listeners.
  - V: Vulnerability Severity (0 - 100) based on CVSS-rated Greenbone/OpenVAS findings and QoD factors.
  - C: Correlation Confidence (0 - 100) based on deterministic cross-tool matches and SHA-256 evidence integrity.

Risk Tiers:
  - Minimal:   0 - 19
  - Low:      20 - 39
  - Moderate: 40 - 59
  - High:     60 - 79
  - Critical: 80 - 100
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.recon import CollectionJobModel, EntityModel, EvidenceModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.models.correlation import CorrelationRecordModel
from app.models.exposure_score import ExposureScoreModel
from app.services.vuln.normalizer import generate_finding_deduplication_key


SCORING_MODELS = {
    "v3.0-5factor": {
        "version": "v3.0-5factor",
        "description": "Authoritative active-weighted model emphasizing confirmed CVSS vulnerabilities (0.20P + 0.15D + 0.25S + 0.35V + 0.05C)",
        "weights": {"P": 0.20, "D": 0.15, "S": 0.25, "V": 0.35, "C": 0.05},
        "formula": "0.20*P + 0.15*D + 0.25*S + 0.35*V + 0.05*C",
    },
    "v1.0-legacy": {
        "version": "v1.0-legacy",
        "description": "Historical passive-weighted baseline model with equal OSINT emphasis (0.25P + 0.20D + 0.25S + 0.20V + 0.10C)",
        "weights": {"P": 0.25, "D": 0.20, "S": 0.25, "V": 0.20, "C": 0.10},
        "formula": "0.25*P + 0.20*D + 0.25*S + 0.20*V + 0.10*C",
    },
}

DEFAULT_SCORING_MODEL = "v3.0-5factor"


@dataclass
class ExposureScoreBreakdown:
    """In-memory breakdown of calculated exposure score with complete factor contributions."""

    P: int
    D: int
    S: int
    V: int
    C: int
    total_score: int
    tier: str
    formula_version: str
    calculation_timestamp: str
    reviewer_notes: str
    components_detail: Dict[str, Any]
    assessment_status: str
    score_id: Optional[str] = None
    renormalized_score: Optional[float] = None
    weighted_contributions: Optional[Dict[str, float]] = None
    factor_weights: Optional[Dict[str, float]] = None
    explanation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExposureScorer:
    """Calculates, normalizes, explains, and persists 5-factor Exposure Scores."""

    WEIGHT_P = 0.20
    WEIGHT_D = 0.15
    WEIGHT_S = 0.25
    WEIGHT_V = 0.35
    WEIGHT_C = 0.05

    DATABASE_PORTS = {3306, 5432, 27017, 1433, 1521, 6379, 9200}
    ADMIN_PORTS = {8080, 8443, 9090, 10000, 2082, 2083, 2086, 2087}

    @classmethod
    def calculate_for_investigation(
        cls,
        investigation_id: str,
        db: Session,
        model_version: str = DEFAULT_SCORING_MODEL,
        reviewer_notes: Optional[str] = None,
        persist: bool = True,
    ) -> ExposureScoreBreakdown:
        """Computes exposure score for an investigation using persisted records.
        
        Args:
            investigation_id: Investigation primary key
            db: Active SQLAlchemy Session
            model_version: "v3.0-5factor" (default) or "v1.0-legacy"
            reviewer_notes: Optional human analyst observation notes
            persist: Whether to store calculation in exposure_scores table
        """
        model_meta = SCORING_MODELS.get(model_version, SCORING_MODELS[DEFAULT_SCORING_MODEL])
        weights = model_meta["weights"]

        # -----------------------------------------------------------------
        # 1. Fetch persisted records
        # -----------------------------------------------------------------
        entities: List[EntityModel] = db.scalars(
            select(EntityModel).where(EntityModel.investigation_id == investigation_id)
        ).all()

        evidence_list: List[EvidenceModel] = db.scalars(
            select(EvidenceModel).where(EvidenceModel.investigation_id == investigation_id)
        ).all()

        ports: List[ScanFindingPortModel] = db.scalars(
            select(ScanFindingPortModel)
            .join(ScanFindingHostModel, ScanFindingPortModel.host_id == ScanFindingHostModel.id)
            .where(ScanFindingHostModel.investigation_id == investigation_id)
        ).all()

        hosts: List[ScanFindingHostModel] = db.scalars(
            select(ScanFindingHostModel).where(ScanFindingHostModel.investigation_id == investigation_id)
        ).all()

        vulns: List[VulnerabilityFindingModel] = db.scalars(
            select(VulnerabilityFindingModel).where(VulnerabilityFindingModel.investigation_id == investigation_id)
        ).all()

        collection_jobs = db.scalars(
            select(CollectionJobModel).where(CollectionJobModel.investigation_id == investigation_id)
        ).all()

        active_jobs = db.scalars(
            select(ActiveScanJobModel).where(ActiveScanJobModel.investigation_id == investigation_id)
        ).all()

        vuln_jobs = db.scalars(
            select(VulnerabilityScanJobModel).where(VulnerabilityScanJobModel.investigation_id == investigation_id)
        ).all()

        correlation_records: List[CorrelationRecordModel] = db.scalars(
            select(CorrelationRecordModel).where(
                CorrelationRecordModel.investigation_id == investigation_id,
            )
        ).all()

        jobs = [*collection_jobs, *active_jobs, *vuln_jobs]

        # -----------------------------------------------------------------
        # 2. Multi-Dimension Assessment Coverage Evaluation
        # -----------------------------------------------------------------
        def _evaluate_dimension(job_list: list, has_findings: bool, scanner_label: str) -> Tuple[str, Optional[str]]:
            if not job_list:
                return (
                    "NOT_EXECUTED",
                    f"{scanner_label} assessment was not executed; factor score reflects absence of scan data, not verified absence of risk.",
                )

            any_running = any(
                (j.status or "").upper()
                in {"QUEUED", "AUTHORIZING", "RUNNING", "PARSING", "CONFIGURING_TARGET", "CREATING_TASK", "RETRIEVING_REPORT"}
                for j in job_list
            )
            if any_running:
                return "IN_PROGRESS", None

            any_successful = any((j.status or "").upper() in {"COMPLETED", "PARTIAL"} for j in job_list)
            if any_successful:
                if has_findings:
                    return "COMPLETED", None
                return "NO_FINDINGS_DETECTED", None

            # All jobs finished with non-successful statuses
            for j in job_list:
                cat = getattr(j, "error_category", None) or ""
                if cat in {"TOOL_UNAVAILABLE", "NOT_CONFIGURED", "CONNECTION_ERROR", "AUTHENTICATION_FAILED", "SCANNER_UNAVAILABLE"}:
                    return (
                        "SCANNER_UNAVAILABLE",
                        f"{scanner_label} scanner was unavailable ({cat}); factor score reflects tool unavailability rather than zero risk.",
                    )

            return "FAILED", f"{scanner_label} assessment failed during execution."

        dim_passive_status, warn_p = _evaluate_dimension(
            collection_jobs,
            has_findings=(len(entities) > 0 or len(evidence_list) > 0),
            scanner_label="Passive reconnaissance",
        )
        dim_active_status, warn_a = _evaluate_dimension(
            active_jobs,
            has_findings=(len(ports) > 0),
            scanner_label="Active network (Nmap)",
        )
        dim_vuln_status, warn_v = _evaluate_dimension(
            vuln_jobs,
            has_findings=(len(vulns) > 0),
            scanner_label="Vulnerability (Greenbone)",
        )

        # DNS sub-dimension
        dns_jobs = [j for j in collection_jobs if "dns" in getattr(j, "collector_name", "").lower()]
        has_dns_evidence = any("dns" in (ev.source_type or "").lower() for ev in evidence_list)
        if dns_jobs or has_dns_evidence:
            dim_dns_status = "COMPLETED" if has_dns_evidence else "NO_FINDINGS_DETECTED"
        else:
            dim_dns_status = dim_passive_status

        # Correlation sub-dimension
        if correlation_records:
            dim_corr_status = "COMPLETED"
        elif evidence_list:
            dim_corr_status = "PARTIAL"
        else:
            dim_corr_status = "NOT_EXECUTED"

        dimension_status = {
            "passive_recon": dim_passive_status,
            "active_nmap": dim_active_status,
            "vulnerability_scan": dim_vuln_status,
            "dns": dim_dns_status,
            "evidence_correlation": dim_corr_status,
        }

        coverage_warnings = [w for w in [warn_p, warn_a, warn_v] if w]
        completed_dims = sum(1 for s in [dim_passive_status, dim_active_status, dim_vuln_status] if s in {"COMPLETED", "NO_FINDINGS_DETECTED"})
        coverage_pct = round((completed_dims / 3.0) * 100)
        is_fully_assessed = (completed_dims == 3)

        running = any(
            (job.status or "").upper()
            in {"QUEUED", "AUTHORIZING", "RUNNING", "PARSING", "CONFIGURING_TARGET", "CREATING_TASK", "RETRIEVING_REPORT"}
            for job in jobs
        )
        if running:
            assessment_status = "IN_PROGRESS"
        elif completed_dims == 3:
            assessment_status = "FULL_ASSESSMENT"
        elif completed_dims > 0:
            assessment_status = "PARTIAL"
        elif any(s == "SCANNER_UNAVAILABLE" for s in dimension_status.values()):
            assessment_status = "SCANNER_UNAVAILABLE"
        elif jobs:
            assessment_status = "FAILED"
        else:
            assessment_status = "NOT_ASSESSED"

        # -----------------------------------------------------------------
        # 3. Factor P: Public Footprint (0 - 100)
        # -----------------------------------------------------------------
        # Deduplicate entities by canonical value and entity type to avoid inflation
        seen_emails: Set[str] = set()
        seen_persons: Set[str] = set()
        seen_docs: Set[str] = set()
        for e in entities:
            etype = (e.entity_type or "").lower()
            val = (e.canonical_value or e.original_value or "").strip().lower()
            if not val:
                continue
            if etype == "email":
                seen_emails.add(val)
            elif etype == "person":
                seen_persons.add(val)
            elif etype == "document":
                seen_docs.add(val)

        search_evidence = [ev for ev in evidence_list if "search" in (ev.source_type or "").lower()]

        raw_p = (len(seen_emails) * 12) + (len(seen_persons) * 8) + (len(seen_docs) * 18) + (len(search_evidence) * 10)
        p = min(100, max(0, round(raw_p)))

        # -----------------------------------------------------------------
        # 4. Factor D: Domain Hygiene (0 - 100)
        # -----------------------------------------------------------------
        seen_subdomains: Set[str] = set()
        for e in entities:
            etype = (e.entity_type or "").lower()
            val = (e.canonical_value or e.original_value or "").strip().lower()
            if etype in ("subdomain", "domain") and val:
                seen_subdomains.add(val)

        dns_evidence = [ev for ev in evidence_list if "dns" in (ev.source_type or "").lower()]
        has_dmarc = any("dmarc" in str(ev.source_metadata).lower() for ev in dns_evidence)
        missing_dmarc = len(dns_evidence) > 0 and not has_dmarc

        raw_d = len(seen_subdomains) * 10
        if missing_dmarc:
            raw_d += 25
        d = min(100, max(0, round(raw_d)))

        # -----------------------------------------------------------------
        # 5. Factor S: Service Exposure (0 - 100)
        # -----------------------------------------------------------------
        # Confirmed open ports on responsive hosts (ignore down/unreachable hosts)
        responsive_host_ids = {
            h.id for h in hosts if (h.status or "").lower() in ("up", "host_confirmed_up", "host_assumed_up")
        }
        # Filtered ports are explicitly excluded; only state == 'open'
        open_ports = [
            p_obj
            for p_obj in ports
            if (p_obj.state or "").lower() == "open"
            and (not responsive_host_ids or p_obj.host_id in responsive_host_ids)
        ]

        raw_s = len(open_ports) * 14
        db_listener_count = 0
        admin_listener_count = 0
        for p_obj in open_ports:
            port_num = p_obj.port_number
            if port_num in cls.DATABASE_PORTS:
                raw_s += 20
                db_listener_count += 1
            elif port_num in cls.ADMIN_PORTS:
                raw_s += 15
                admin_listener_count += 1
            elif port_num == 80:
                raw_s += 5
        s = min(100, max(0, round(raw_s)))

        # -----------------------------------------------------------------
        # 6. Factor V: Vulnerability Severity (0 - 100)
        # -----------------------------------------------------------------
        raw_v = 0.0
        unique_findings: Dict[str, VulnerabilityFindingModel] = {}
        for v_obj in vulns:
            cves = sorted(v_obj.cve_references or [])
            key = generate_finding_deduplication_key(
                v_obj.host or "",
                v_obj.port,
                v_obj.protocol,
                v_obj.name or "",
                v_obj.nvt_oid,
                cves[0] if cves else None,
            )
            unique_findings.setdefault(key, v_obj)

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        max_cvss = 0.0

        for v_obj in unique_findings.values():
            sev = (v_obj.severity or "info").lower()
            qod_factor = min(100, max(0, 100 if v_obj.qod is None else v_obj.qod)) / 100.0
            if v_obj.cvss_score:
                max_cvss = max(max_cvss, float(v_obj.cvss_score))

            if sev == "critical":
                pts = 35
                critical_count += 1
            elif sev == "high":
                pts = 22
                high_count += 1
            elif sev == "medium":
                pts = 12
                medium_count += 1
            elif sev == "low":
                pts = 5
                low_count += 1
            else:
                pts = 1
            raw_v += pts * qod_factor
        v = min(100, max(0, round(raw_v)))

        # -----------------------------------------------------------------
        # 7. Factor C: Correlation Confidence (0 - 100)
        # -----------------------------------------------------------------
        distinct_sources: Set[str] = {ev.source_name for ev in evidence_list if ev.source_name}
        evidence_count = len(evidence_list)

        if correlation_records:
            # Use deterministic correlation intelligence from Step 5
            confirmed_cnt = sum(1 for r in correlation_records if r.relationship_type == "CONFIRMED_MATCH")
            strong_cnt = sum(1 for r in correlation_records if r.relationship_type == "STRONG_MATCH")
            possible_cnt = sum(1 for r in correlation_records if r.relationship_type == "POSSIBLE_MATCH")
            verified_ev_cnt = sum(1 for r in correlation_records if r.evidence_verification_status == "VERIFIED")
            raw_c = (confirmed_cnt * 25) + (strong_cnt * 15) + (possible_cnt * 5) + (verified_ev_cnt * 10)
            if not raw_c:
                raw_c = min(100, (len(distinct_sources) * 20) + min(40, evidence_count * 5))
        else:
            raw_c = min(100, (len(distinct_sources) * 20) + min(40, evidence_count * 5))
        c = min(100, max(0, round(raw_c)))

        # -----------------------------------------------------------------
        # 8. Weighted Contributions and Composite Scores
        # -----------------------------------------------------------------
        contributions = {
            "P": round(weights["P"] * p, 2),
            "D": round(weights["D"] * d, 2),
            "S": round(weights["S"] * s, 2),
            "V": round(weights["V"] * v, 2),
            "C": round(weights["C"] * c, 2),
        }
        composite = sum(contributions.values())
        total_score = min(100, max(0, round(composite)))

        # Available-factor renormalization
        assessed_weights = 0.0
        assessed_points = 0.0
        # Map dimensions to factors
        dim_map = {
            "P": dim_passive_status,
            "D": dim_dns_status,
            "S": dim_active_status,
            "V": dim_vuln_status,
            "C": dim_corr_status,
        }
        for f_key, w in weights.items():
            st = dim_map.get(f_key, "NOT_EXECUTED")
            if st in {"COMPLETED", "NO_FINDINGS_DETECTED"}:
                assessed_weights += w
                f_val = {"P": p, "D": d, "S": s, "V": v, "C": c}[f_key]
                assessed_points += w * f_val

        if assessed_weights > 0:
            renormalized_score = round(assessed_points / assessed_weights, 2)
        else:
            renormalized_score = None

        # -----------------------------------------------------------------
        # 9. Risk Tier Assignment
        # -----------------------------------------------------------------
        if assessment_status in ("NOT_ASSESSED", "FAILED") and total_score == 0:
            tier = "Minimal"
        elif total_score >= 80:
            tier = "Critical"
        elif total_score >= 60:
            tier = "High"
        elif total_score >= 40:
            tier = "Moderate"
        elif total_score >= 20:
            tier = "Low"
        else:
            tier = "Minimal"

        # -----------------------------------------------------------------
        # 10. Reviewer Notes & Explanation Generation
        # -----------------------------------------------------------------
        base_notes = reviewer_notes or (
            f"Automated 5-factor calculation based on {len(seen_emails) + len(seen_persons) + len(seen_docs)} entities, "
            f"{len(open_ports)} exposed ports, and {len(unique_findings)} unique vulnerabilities."
        )
        if coverage_warnings:
            notes = f"{base_notes} [COVERAGE NOTICE]: {'; '.join(coverage_warnings)}"
        else:
            notes = base_notes

        explanation = cls._generate_explanation(
            total_score=total_score,
            tier=tier,
            model_version=model_meta["version"],
            weights=weights,
            factors={"P": p, "D": d, "S": s, "V": v, "C": c},
            contributions=contributions,
            assessment_status=assessment_status,
            renormalized_score=renormalized_score,
            coverage_pct=coverage_pct,
            counts={
                "emails": len(seen_emails),
                "persons": len(seen_persons),
                "docs": len(seen_docs),
                "subdomains": len(seen_subdomains),
                "missing_dmarc": missing_dmarc,
                "open_ports": len(open_ports),
                "db_listeners": db_listener_count,
                "admin_listeners": admin_listener_count,
                "vulns_unique": len(unique_findings),
                "critical_vulns": critical_count,
                "high_vulns": high_count,
                "max_cvss": max_cvss,
                "correlations": len(correlation_records),
                "evidence_sources": len(distinct_sources),
            },
            coverage_warnings=coverage_warnings,
        )

        components_detail = {
            "public_entities_count": len(entities),
            "emails_count": len(seen_emails),
            "open_ports_count": len(open_ports),
            "vulnerabilities_count": len(unique_findings),
            "vulnerability_records_count": len(vulns),
            "evidence_records_count": len(evidence_list),
            "distinct_sources_count": len(distinct_sources),
            "coverage_percentage": coverage_pct,
            "is_fully_assessed": is_fully_assessed,
            "dimensions_assessed_count": completed_dims,
            "dimensions_total_count": 3,
            "dimension_status": dimension_status,
            "coverage_warnings": coverage_warnings,
            "model_version": model_meta["version"],
            "model_weights": weights,
            "weighted_contributions": contributions,
            "renormalized_score": renormalized_score,
            "critical_vulns_count": critical_count,
            "high_vulns_count": high_count,
            "max_cvss_score": max_cvss,
            "correlation_records_count": len(correlation_records),
        }

        raw_inputs = {
            "emails": len(seen_emails),
            "persons": len(seen_persons),
            "documents": len(seen_docs),
            "search_evidence": len(search_evidence),
            "subdomains": len(seen_subdomains),
            "missing_dmarc": missing_dmarc,
            "open_ports": len(open_ports),
            "database_ports": db_listener_count,
            "admin_ports": admin_listener_count,
            "unique_vulnerabilities": len(unique_findings),
            "raw_vulnerabilities": len(vulns),
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "evidence_count": len(evidence_list),
            "distinct_evidence_sources": len(distinct_sources),
            "correlation_records": len(correlation_records),
        }

        source_obs_ids = [
            *[e.id for e in entities[:20]],
            *[p_obj.id for p_obj in open_ports[:20]],
            *[v_obj.id for v_obj in list(unique_findings.values())[:20]],
            *[r.id for r in correlation_records[:20]],
        ]

        # -----------------------------------------------------------------
        # 11. Persistence into exposure_scores table
        # -----------------------------------------------------------------
        score_record_id = None
        if persist:
            score_record_id = f"exp-{uuid.uuid4().hex[:12]}"
            # Deactivate previous active calculations for this investigation
            db.query(ExposureScoreModel).filter(
                ExposureScoreModel.investigation_id == investigation_id,
                ExposureScoreModel.is_active == True,
            ).update({"is_active": False}, synchronize_session=False)

            score_record = ExposureScoreModel(
                id=score_record_id,
                investigation_id=investigation_id,
                formula_version=model_meta["version"],
                formula_weights=weights,
                raw_factor_inputs=raw_inputs,
                normalized_factor_scores={"P": p, "D": d, "S": s, "V": v, "C": c},
                weighted_contributions=contributions,
                total_score=total_score,
                renormalized_score=renormalized_score,
                risk_tier=tier,
                assessment_status=assessment_status,
                coverage_percentage=coverage_pct,
                is_fully_assessed=is_fully_assessed,
                coverage_metadata=dimension_status,
                scanner_availability={
                    "passive": dim_passive_status,
                    "nmap": dim_active_status,
                    "greenbone": dim_vuln_status,
                },
                source_observation_ids=source_obs_ids,
                reviewer_notes=notes,
                explanation=explanation,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(score_record)
            db.flush()

        return ExposureScoreBreakdown(
            P=p,
            D=d,
            S=s,
            V=v,
            C=c,
            total_score=total_score,
            tier=tier,
            formula_version=f"{model_meta['version']} ({model_meta['formula']})",
            calculation_timestamp=datetime.now(timezone.utc).isoformat(),
            reviewer_notes=notes,
            components_detail=components_detail,
            assessment_status=assessment_status,
            score_id=score_record_id,
            renormalized_score=renormalized_score,
            weighted_contributions=contributions,
            factor_weights=weights,
            explanation=explanation,
        )

    @classmethod
    def get_score_history(cls, investigation_id: str, db: Session) -> List[Dict[str, Any]]:
        """Retrieves historical exposure scoring calculations for an investigation."""
        records = db.scalars(
            select(ExposureScoreModel)
            .where(ExposureScoreModel.investigation_id == investigation_id)
            .order_by(ExposureScoreModel.created_at.desc())
        ).all()
        return [r.to_dict() for r in records]

    @classmethod
    def compare_scores(cls, score_a: Dict[str, Any], score_b: Dict[str, Any]) -> Dict[str, Any]:
        """Compares two historical score records and produces an explainable delta."""
        v_a = score_a.get("formula_version")
        v_b = score_b.get("formula_version")
        same_formula = (v_a == v_b)

        delta_total = score_a.get("total_score", 0) - score_b.get("total_score", 0)
        norm_a = score_a.get("normalized_factor_scores", {})
        norm_b = score_b.get("normalized_factor_scores", {})

        factor_deltas = {
            f: norm_a.get(f, 0) - norm_b.get(f, 0) for f in ("P", "D", "S", "V", "C")
        }

        notes = []
        if not same_formula:
            notes.append(
                f"Formula versions differ ({v_a} vs {v_b}); direct numeric comparison is indicative only, not mathematically equivalent."
            )
        if delta_total > 0:
            notes.append(f"Exposure increased by +{delta_total} points.")
        elif delta_total < 0:
            notes.append(f"Exposure decreased by {delta_total} points.")
        else:
            notes.append("Exposure remained unchanged.")

        return {
            "same_formula_version": same_formula,
            "version_a": v_a,
            "version_b": v_b,
            "delta_total_score": delta_total,
            "factor_deltas": factor_deltas,
            "comparison_notes": notes,
        }

    @staticmethod
    def _generate_explanation(
        total_score: int,
        tier: str,
        model_version: str,
        weights: Dict[str, float],
        factors: Dict[str, int],
        contributions: Dict[str, float],
        assessment_status: str,
        renormalized_score: Optional[float],
        coverage_pct: int,
        counts: Dict[str, Any],
        coverage_warnings: List[str],
    ) -> str:
        """Generates an executive, evidence-backed narrative explaining the score."""
        lines = [
            f"Overall Exposure Score: {total_score}/100 ({tier.upper()}) under model {model_version}.",
            f"Assessment Coverage: {coverage_pct}% ({assessment_status.replace('_', ' ')}).",
        ]
        if renormalized_score is not None and renormalized_score != total_score:
            lines.append(
                f"Renormalized Score (Assessed Dimensions Only): {renormalized_score}/100. "
                "Notice: Missing dimensions are not treated as clean; they are excluded from the denominator."
            )

        lines.append("\nFactor Contributions & Evidence Breakdown:")
        lines.append(
            f"  - Factor P (Public Footprint): {factors['P']}/100 (Weight: {int(weights['P']*100)}%, Contributes: +{contributions['P']} pts) "
            f"derived from {counts['emails']} emails, {counts['persons']} persons, {counts['docs']} documents."
        )
        d_extra = " [Missing DMARC Policy detected: +25 penalty]" if counts["missing_dmarc"] else ""
        lines.append(
            f"  - Factor D (Domain Hygiene): {factors['D']}/100 (Weight: {int(weights['D']*100)}%, Contributes: +{contributions['D']} pts) "
            f"derived from {counts['subdomains']} subdomains{d_extra}."
        )
        s_extra = []
        if counts["db_listeners"]:
            s_extra.append(f"{counts['db_listeners']} database listener(s)")
        if counts["admin_listeners"]:
            s_extra.append(f"{counts['admin_listeners']} admin listener(s)")
        s_note = f" including {', '.join(s_extra)}" if s_extra else ""
        lines.append(
            f"  - Factor S (Service Exposure): {factors['S']}/100 (Weight: {int(weights['S']*100)}%, Contributes: +{contributions['S']} pts) "
            f"derived from {counts['open_ports']} open port(s){s_note}."
        )
        lines.append(
            f"  - Factor V (Vulnerability Severity): {factors['V']}/100 (Weight: {int(weights['V']*100)}%, Contributes: +{contributions['V']} pts) "
            f"derived from {counts['vulns_unique']} unique vulnerability finding(s) "
            f"({counts['critical_vulns']} Critical, {counts['high_vulns']} High, Max CVSS: {counts['max_cvss']})."
        )
        lines.append(
            f"  - Factor C (Correlation & Evidence): {factors['C']}/100 (Weight: {int(weights['C']*100)}%, Contributes: +{contributions['C']} pts) "
            f"derived from {counts['correlations']} deterministic correlation relationships across {counts['evidence_sources']} source(s)."
        )

        if coverage_warnings:
            lines.append("\nCoverage Notices & Limitations:")
            for w in coverage_warnings:
                lines.append(f"  * {w}")

        return "\n".join(lines)
