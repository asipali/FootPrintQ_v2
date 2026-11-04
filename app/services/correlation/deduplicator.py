"""Phase E — Vulnerability Finding Deduplication and Lifecycle Engine."""

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.models.vulnerability import VulnerabilityFindingModel, VulnerabilityScanJobModel
from app.services.correlation.models import FindingLifecycleState
from app.services.correlation.normalizer import normalize_ip, normalize_port_protocol

logger = logging.getLogger("footprintiq.services.correlation.deduplicator")


def compute_vulnerability_dedup_key(
    investigation_id: str,
    host: str,
    port: Optional[int],
    protocol: Optional[str],
    nvt_oid: Optional[str],
    name: str,
    primary_cve: Optional[str] = None,
) -> str:
    """Computes a stable, deterministic deduplication key for a vulnerability finding.
    
    Composite identity attributes:
    - investigation_id
    - normalized host IP/hostname
    - port & protocol (e.g. 443/tcp or general/any)
    - nvt_oid (or clean name if OID unavailable)
    - primary CVE
    
    Prevents false merges between different services or different vulnerabilities sharing a CVE.
    """
    inv_clean = investigation_id.strip()
    norm_ip, _ = normalize_ip(host)
    host_clean = (norm_ip or host).strip().lower()
    port_num, proto_str = normalize_port_protocol(port, protocol)
    port_part = f"{port_num}/{proto_str}" if port_num else "general/any"
    oid_part = nvt_oid.strip() if nvt_oid else name.strip().lower()
    cve_part = primary_cve.strip().upper() if primary_cve else "NO_CVE"

    raw_key = f"{inv_clean}::{host_clean}::{port_part}::{oid_part}::{cve_part}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class VulnerabilityLifecycleTracker:
    """Tracks finding observations across scan history and determines lifecycle transitions."""

    def __init__(
        self,
        investigation_id: str,
        findings: List[VulnerabilityFindingModel],
        scan_jobs: List[VulnerabilityScanJobModel],
    ):
        self.investigation_id = investigation_id
        self.findings = findings
        self.scan_jobs = sorted(scan_jobs, key=lambda j: j.started_at or j.created_at if hasattr(j, "created_at") else 0)
        self.completed_jobs = [j for j in self.scan_jobs if j.status == "COMPLETED"]
        self.failed_or_incomplete_jobs = [j for j in self.scan_jobs if j.status != "COMPLETED"]

    def compute_finding_lifecycles(self) -> Dict[str, Tuple[FindingLifecycleState, Dict[str, Any]]]:
        """Evaluates each finding and assigns its lifecycle state.
        
        Returns:
            map of finding_id -> (FindingLifecycleState, metadata_dict)
        """
        # Group findings by deduplication key
        grouped: Dict[str, List[VulnerabilityFindingModel]] = {}
        for f in self.findings:
            cves = f.cve_references if isinstance(f.cve_references, list) else []
            primary_cve = cves[0] if cves else None
            k = compute_vulnerability_dedup_key(
                investigation_id=self.investigation_id,
                host=f.host,
                port=f.port,
                protocol=f.protocol,
                nvt_oid=f.nvt_oid,
                name=f.name,
                primary_cve=primary_cve,
            )
            grouped.setdefault(k, []).append(f)

        results: Dict[str, Tuple[FindingLifecycleState, Dict[str, Any]]] = {}

        for dedup_key, finding_list in grouped.items():
            # Sort chronologically by first_seen or ID
            sorted_fl = sorted(finding_list, key=lambda f: f.first_seen if f.first_seen else 0)
            total_observations = len(sorted_fl)

            # Target of these findings
            sample = sorted_fl[0]
            target_host = sample.host

            # Check successful scans against this target that occurred after this finding
            subsequent_successful_jobs = [
                j for j in self.completed_jobs
                if j.target == target_host and sample.first_seen and j.completed_at and j.completed_at > sample.first_seen
            ]
            has_failed_subsequent = any(
                j for j in self.failed_or_incomplete_jobs
                if j.target == target_host and sample.first_seen and getattr(j, "started_at", None) and j.started_at > sample.first_seen
            )

            for i, f in enumerate(sorted_fl):
                meta = {
                    "dedup_key": dedup_key,
                    "observation_count": total_observations,
                    "first_seen": sorted_fl[0].first_seen.isoformat() if sorted_fl[0].first_seen else None,
                    "last_seen": sorted_fl[-1].last_seen.isoformat() if sorted_fl[-1].last_seen else None,
                    "historical_job_ids": [x.job_id for x in sorted_fl if x.job_id],
                }

                if total_observations == 1:
                    # Single observation
                    if has_failed_subsequent:
                        state = FindingLifecycleState.UNCONFIRMED
                        meta["lifecycle_reason"] = "Subsequent scan attempt failed, timed out, or target was unreachable."
                    else:
                        state = FindingLifecycleState.NEW
                        meta["lifecycle_reason"] = "First-time observation in investigation scope."
                else:
                    # Multiple observations
                    # Check if severity or CVSS changed
                    first = sorted_fl[0]
                    if f.severity != first.severity or f.cvss_score != first.cvss_score:
                        state = FindingLifecycleState.CHANGED
                        meta["lifecycle_reason"] = f"Severity/CVSS changed (was {first.severity}/{first.cvss_score}, now {f.severity}/{f.cvss_score})."
                    else:
                        state = FindingLifecycleState.REOBSERVED
                        meta["lifecycle_reason"] = f"Re-observed across {total_observations} scan campaigns."

                results[f.id] = (state, meta)

        return results

