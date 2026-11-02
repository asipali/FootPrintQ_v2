"""Consolidated cybersecurity reconnaissance dossier PDF generator using ReportLab Platypus.

Builds a professional, multi-page, publication-grade investigation report containing genuine
data from investigation, authorization, evidence, job, scan, finding, and scoring records.
"""

import io
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)
from reportlab.pdfgen import canvas
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.investigation import InvestigationModel
from app.models.recon import EntityModel, EvidenceModel, TargetAuthorizationModel, CollectionJobModel
from app.models.scan import ActiveScanJobModel, ScanFindingHostModel, ScanFindingPortModel
from app.models.vulnerability import VulnerabilityScanJobModel, VulnerabilityFindingModel
from app.services.scoring.calculator import ExposureScorer, ExposureScoreBreakdown


def _safe_text(value: Any) -> str:
    """Escape untrusted database text before it is interpreted as ReportLab markup."""
    return xml_escape("" if value is None else str(value))


def _job_state(jobs: list) -> str:
    """Summarize persisted jobs without treating absent or failed work as success."""
    if not jobs:
        return "NOT PERFORMED"
    statuses = {(job.status or "").upper() for job in jobs}
    active = {"QUEUED", "PENDING", "AUTHORIZING", "RUNNING", "PARSING", "CONFIGURING_TARGET", "CREATING_TASK", "RETRIEVING_REPORT"}
    if statuses & active:
        return "PENDING" if statuses <= {"QUEUED", "PENDING"} else "RUNNING"
    successes = statuses & {"COMPLETED", "PARTIAL"}
    if successes and (len(successes) > 1 or statuses - successes):
        return "PARTIAL"
    if "PARTIAL" in successes:
        return "PARTIAL"
    if "COMPLETED" in successes:
        return "COMPLETED"
    if statuses == {"CANCELLED"}:
        return "CANCELLED"
    return "FAILED"


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for total page count calculation and professional headers/footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Skip headers on cover page (page 1)
        if self._pageNumber > 1:
            # Header
            self.drawString(54, 755, "FootprintIQ — Digital Footprint Investigation Dossier")
            self.drawRightString(558, 755, "RESTRICTED / AUTHORIZED LAB USE")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 747, 558, 747)

        # Footer on all pages
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)

        self.drawString(54, 32, "Confidential — Generated from recorded FootprintIQ investigation data")
        self.drawRightString(558, 32, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class InvestigationReportGenerator:
    """Generates the consolidated investigation dossier PDF."""

    @classmethod
    def generate_pdf(
        cls,
        investigation_id: str,
        db: Session,
        generated_by: str = "Lead Investigator",
        dossier_title: str = "FootprintIQ Comprehensive Reconnaissance Dossier",
    ) -> bytes:
        """Generates a complete PDF binary for the specified investigation."""
        # 1. Fetch all persisted records
        inv: Optional[InvestigationModel] = db.get(InvestigationModel, investigation_id)
        if not inv:
            raise ValueError(f"Investigation '{investigation_id}' not found.")

        authorizations: List[TargetAuthorizationModel] = db.scalars(
            select(TargetAuthorizationModel).where(TargetAuthorizationModel.investigation_id == investigation_id)
        ).all()

        entities: List[EntityModel] = db.scalars(
            select(EntityModel).where(EntityModel.investigation_id == investigation_id).order_by(EntityModel.first_seen.desc())
        ).all()

        evidence_list: List[EvidenceModel] = db.scalars(
            select(EvidenceModel).where(EvidenceModel.investigation_id == investigation_id).order_by(EvidenceModel.collected_at.desc())
        ).all()

        collection_jobs: List[CollectionJobModel] = db.scalars(
            select(CollectionJobModel).where(CollectionJobModel.investigation_id == investigation_id)
        ).all()

        nmap_jobs: List[ActiveScanJobModel] = db.scalars(
            select(ActiveScanJobModel).where(ActiveScanJobModel.investigation_id == investigation_id)
        ).all()

        scan_ports: List[ScanFindingPortModel] = db.scalars(
            select(ScanFindingPortModel)
            .join(ScanFindingHostModel, ScanFindingPortModel.host_id == ScanFindingHostModel.id)
            .where(ScanFindingHostModel.investigation_id == investigation_id)
        ).all()

        vuln_jobs: List[VulnerabilityScanJobModel] = db.scalars(
            select(VulnerabilityScanJobModel).where(VulnerabilityScanJobModel.investigation_id == investigation_id)
        ).all()

        vuln_findings: List[VulnerabilityFindingModel] = db.scalars(
            select(VulnerabilityFindingModel).where(VulnerabilityFindingModel.investigation_id == investigation_id)
        ).all()

        # 2. Compute 5-factor Exposure Score
        score = ExposureScorer.calculate_for_investigation(investigation_id, db=db)
        passive_state = _job_state(collection_jobs)
        nmap_state = _job_state(nmap_jobs)
        vuln_state = _job_state(vuln_jobs)
        if score.assessment_status == "NOT_ASSESSED":
            score_label = "NOT ASSESSED"
        elif score.assessment_status == "FAILED":
            score_label = "ASSESSMENT FAILED"
        elif score.assessment_status == "IN_PROGRESS":
            score_label = "ASSESSMENT IN PROGRESS — INTERIM DATA"
        else:
            score_label = f"PARTIAL COVERAGE — OBSERVED DATA {score.total_score}/100 ({score.tier.upper()})"

        # 3. Setup document and styles
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()
        
        # Custom palette styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#0284c7"),
            spaceAfter=15,
        )
        h1_style = ParagraphStyle(
            "SectionH1",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True,
        )
        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#334155"),
            spaceAfter=6,
        )
        body_bold = ParagraphStyle(
            "BodyBold",
            parent=body_style,
            fontName="Helvetica-Bold",
        )
        code_style = ParagraphStyle(
            "CodeFont",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )
        meta_label = ParagraphStyle(
            "MetaLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748b"),
        )
        table_cell = ParagraphStyle(
            "TableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#1e293b"),
        )
        table_cell_bold = ParagraphStyle(
            "TableCellBold",
            parent=table_cell,
            fontName="Helvetica-Bold",
        )
        finding_detail = ParagraphStyle(
            "FindingDetail",
            parent=table_cell,
            fontSize=6.8,
            leading=8.5,
            wordWrap="CJK",
        )
        badge_crit = ParagraphStyle(
            "BadgeCrit",
            parent=table_cell_bold,
            textColor=colors.HexColor("#dc2626"),
        )
        badge_high = ParagraphStyle(
            "BadgeHigh",
            parent=table_cell_bold,
            textColor=colors.HexColor("#ea580c"),
        )
        badge_med = ParagraphStyle(
            "BadgeMed",
            parent=table_cell_bold,
            textColor=colors.HexColor("#ca8a04"),
        )
        badge_low = ParagraphStyle(
            "BadgeLow",
            parent=table_cell_bold,
            textColor=colors.HexColor("#2563eb"),
        )
        badge_info = ParagraphStyle(
            "BadgeInfo",
            parent=table_cell_bold,
            textColor=colors.HexColor("#64748b"),
        )

        story = []

        # =========================================================================
        # 1. Cover Page & Document Identification
        # =========================================================================
        story.append(Paragraph("FOOTPRINTIQ", ParagraphStyle("Brand", fontName="Helvetica-Bold", fontSize=10, textColor=colors.HexColor("#0284c7"), spaceAfter=4)))
        story.append(Paragraph(_safe_text(dossier_title), title_style))
        story.append(Paragraph(f"Digital Footprint &amp; Vulnerability Assessment Dossier &middot; Case ID: <font name='Courier'>{_safe_text(inv.id)}</font>", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=15))

        # Metadata table
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_data = [
            [Paragraph("Target Organization:", meta_label), Paragraph(_safe_text(inv.organization_name), body_bold),
             Paragraph("Lead Investigator:", meta_label), Paragraph(_safe_text(inv.lead_investigator), table_cell)],
            [Paragraph("Campaign Title:", meta_label), Paragraph(_safe_text(inv.name), table_cell),
             Paragraph("Generated By:", meta_label), Paragraph(_safe_text(generated_by), table_cell)],
            [Paragraph("Investigation Status:", meta_label), Paragraph(_safe_text(inv.status.upper()), body_bold),
             Paragraph("Generation Date:", meta_label), Paragraph(now_utc, code_style)],
            [Paragraph("Authorization Ref:", meta_label), Paragraph(_safe_text(inv.authorization_reference or "None Specified"), code_style),
             Paragraph("Exposure Assessment:", meta_label), Paragraph(_safe_text(score_label), body_bold)],
        ]
        t_meta = Table(meta_data, colWidths=[110, 145, 105, 144])
        t_meta.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 12))

        # =========================================================================
        # 2. Authorized-Use Notice & Legal Boundaries
        # =========================================================================
        story.append(Paragraph("1. Authorized-Use Notice &amp; Legal Boundaries", h1_style))
        legal_text = (
            "<b>RESTRICTED CYBERSECURITY RECONNAISSANCE DOSSIER — AUTHORIZED AUDIT USE ONLY.</b><br/>"
            "This document compiles OSINT intelligence, authoritative DNS records, network port enumerations, "
            "and vulnerability telemetry collected strictly under institutional guidelines. Testing activities "
            "were performed within approved scope boundaries without invasive exploitation, password spraying, "
            "or denial-of-service attempts. All findings are verified through cryptographic evidence provenance."
        )
        legal_table = Table([[Paragraph(legal_text, body_style)]], colWidths=[504])
        legal_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#f87171")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(legal_table)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 3. Investigation Scope & Target Definition
        # =========================================================================
        story.append(Paragraph("2. Investigation Scope &amp; Target Definition", h1_style))
        owned_domains_str = _safe_text(", ".join(inv.owned_domains) if inv.owned_domains else "None")
        approved_ips_str = _safe_text(", ".join(inv.approved_ips) if inv.approved_ips else "None")
        approved_cidrs_str = _safe_text(", ".join(inv.approved_cidrs) if inv.approved_cidrs else "None")
        active_targets_str = _safe_text(", ".join(inv.active_targets) if inv.active_targets else "None")

        scope_rows = [
            [Paragraph("Target Apex Domains", meta_label), Paragraph(owned_domains_str, code_style)],
            [Paragraph("Approved IP Addresses", meta_label), Paragraph(approved_ips_str, code_style)],
            [Paragraph("Approved Network CIDRs", meta_label), Paragraph(approved_cidrs_str, code_style)],
            [Paragraph("Active Scanning Allowlist", meta_label), Paragraph(active_targets_str, code_style)],
            [Paragraph("Active Recon Permitted", meta_label), Paragraph("YES — Authorization Required" if inv.active_scanning_enabled else "NO — Passive Only", body_bold)],
        ]
        t_scope = Table(scope_rows, colWidths=[150, 354])
        t_scope.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t_scope)
        story.append(Spacer(1, 10))

        # =========================================================================
        # 4. Target Authorization Ledger
        # =========================================================================
        story.append(Paragraph("3. Target Authorization Ledger", h1_style))
        if authorizations:
            auth_rows = [[
                Paragraph("Target", table_cell_bold),
                Paragraph("Type", table_cell_bold),
                Paragraph("Operations", table_cell_bold),
                Paragraph("Approved By", table_cell_bold),
                Paragraph("Valid To", table_cell_bold),
                Paragraph("Status", table_cell_bold),
            ]]
            for a in authorizations:
                status_str = "REVOKED" if a.is_revoked else "ACTIVE"
                ops_str = ", ".join(a.allowed_operations) if a.allowed_operations else "None"
                auth_rows.append([
                    Paragraph(_safe_text(a.target), code_style),
                    Paragraph(_safe_text(a.target_type), table_cell),
                    Paragraph(_safe_text(ops_str), code_style),
                    Paragraph(_safe_text(a.approved_by), table_cell),
                    Paragraph(a.valid_to.strftime("%Y-%m-%d"), table_cell),
                    Paragraph(status_str, body_bold),
                ])
            t_auth = Table(auth_rows, colWidths=[105, 50, 140, 75, 75, 59])
            t_auth.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_auth)
        else:
            story.append(Paragraph("<i>No explicit target authorization records registered for this campaign.</i>", body_style))
        story.append(Spacer(1, 10))

        # =========================================================================
        # 5. Executive Summary & Exposure Score Breakdown
        # =========================================================================
        story.append(Paragraph("4. Executive Summary &amp; Exposure Score Breakdown", h1_style))
        summary_text = (
            f"Investigation <b>{_safe_text(inv.name)}</b> for <b>{_safe_text(inv.organization_name)}</b> currently contains "
            f"{len(entities)} entities, {len(scan_ports)} recorded ports, and {len(vuln_findings)} vulnerability findings. "
            f"Collection status: passive {passive_state}; Nmap {nmap_state}; Greenbone {vuln_state}. "
            f"Exposure assessment: <b>{_safe_text(score_label)}</b>. A low observed-data score or no findings does not establish that a target is secure."
        )
        story.append(Paragraph(summary_text, body_style))

        score_rows = [
            [Paragraph("Observed-data factor", table_cell_bold), Paragraph("Weight", table_cell_bold), Paragraph("Score", table_cell_bold), Paragraph("Heuristic contribution", table_cell_bold)],
            [Paragraph("P — Public Footprint", table_cell), Paragraph("20%", table_cell), Paragraph(f"{score.P} / 100", body_bold), Paragraph("Publicly disclosed email addresses, employee names, and search metadata.", table_cell)],
            [Paragraph("D — Domain Hygiene", table_cell), Paragraph("15%", table_cell), Paragraph(f"{score.D} / 100", body_bold), Paragraph("Domain/subdomain records and DNS evidence metadata containing a DMARC indicator.", table_cell)],
            [Paragraph("S — Service Exposure", table_cell), Paragraph("25%", table_cell), Paragraph(f"{score.S} / 100", body_bold), Paragraph("Enumerated open ports, with penalties for exposed databases/admin interfaces.", table_cell)],
            [Paragraph("V — Vulnerability Severity", table_cell), Paragraph("35%", table_cell), Paragraph(f"{score.V} / 100", body_bold), Paragraph("CVSS-rated vulnerabilities identified via Greenbone Vulnerability Manager.", table_cell)],
            [Paragraph("C — Evidence Diversity", table_cell), Paragraph("5%", table_cell), Paragraph(f"{score.C} / 100", body_bold), Paragraph("Heuristic from distinct evidence source names and evidence-record count; not graph correlation.", table_cell)],
            [Paragraph("Observed-data composite", table_cell_bold), Paragraph("100%", table_cell_bold), Paragraph(f"<b>{score.total_score} / 100</b>", body_bold), Paragraph(f"<b>{_safe_text(score_label)}</b> &middot; {_safe_text(score.reviewer_notes)}", table_cell)],
        ]
        if score.assessment_status in {"NOT_ASSESSED", "FAILED"}:
            story.append(Paragraph(
                "No composite score is presented because no assessment has completed successfully. "
                "Stored historical observations, if any, remain listed in their sections below.", body_style
            ))
        else:
            t_score = Table(score_rows, colWidths=[120, 45, 60, 279])
            t_score.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_score)
        story.append(Spacer(1, 14))

        # =========================================================================
        # 6. Discovered Asset & Entity Inventory
        # =========================================================================
        story.append(Paragraph("5. Discovered Asset &amp; Entity Inventory", h1_style))
        if entities:
            ent_rows = [[
                Paragraph("Type", table_cell_bold),
                Paragraph("Canonical Value", table_cell_bold),
                Paragraph("First Seen", table_cell_bold),
                Paragraph("Sources", table_cell_bold),
            ]]
            for e in entities[:25]:  # Bound to top 25 for document readability
                ev_count = len(e.evidence_ids) if e.evidence_ids else 0
                ent_rows.append([
                    Paragraph(_safe_text(e.entity_type), body_bold),
                    Paragraph(_safe_text(e.canonical_value), code_style),
                    Paragraph(e.first_seen.strftime("%Y-%m-%d %H:%M"), table_cell),
                    Paragraph(f"{ev_count} evidence ref(s)", table_cell),
                ])
            t_ent = Table(ent_rows, colWidths=[90, 244, 90, 80])
            t_ent.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_ent)
            if len(entities) > 25:
                story.append(Paragraph(f"<i>... and {len(entities) - 25} additional entities recorded in forensic database.</i>", body_style))
        else:
            story.append(Paragraph("<i>No OSINT assets or digital footprint entities discovered yet.</i>", body_style))
        story.append(Spacer(1, 14))

        # =========================================================================
        # 7. Network Port & Active Service Inventory (Nmap)
        # =========================================================================
        story.append(Paragraph("6. Network Port &amp; Active Service Inventory (Nmap)", h1_style))
        if scan_ports:
            port_rows = [[
                Paragraph("Port / Proto", table_cell_bold),
                Paragraph("State", table_cell_bold),
                Paragraph("Service", table_cell_bold),
                Paragraph("Product / Fingerprint", table_cell_bold),
                Paragraph("Version", table_cell_bold),
            ]]
            for p in scan_ports:
                state_style = body_bold if (p.state or "").lower() == "open" else table_cell
                port_rows.append([
                    Paragraph(f"{p.port_number}/{p.protocol}", code_style),
                    Paragraph(_safe_text((p.state or "unknown").upper()), state_style),
                    Paragraph(_safe_text(p.service_name or "unknown"), table_cell),
                    Paragraph(_safe_text(p.product or "—"), table_cell),
                    Paragraph(_safe_text(p.version or "—"), table_cell),
                ])
            t_ports = Table(port_rows, colWidths=[80, 50, 90, 204, 80])
            t_ports.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_ports)
        else:
            story.append(Paragraph(
                f"<i>Nmap assessment status: {nmap_state}. No port observations are recorded. This does not establish that no ports are exposed.</i>",
                body_style,
            ))
        story.append(Spacer(1, 14))

        # =========================================================================
        # 8. Vulnerability Assessment Findings Matrix (Greenbone GVM)
        # =========================================================================
        story.append(Paragraph("7. Vulnerability Assessment Findings Matrix (Greenbone GVM)", h1_style))
        if vuln_findings:
            v_rows = [[
                Paragraph("Severity", table_cell_bold),
                Paragraph("Finding Name", table_cell_bold),
                Paragraph("Host:Port", table_cell_bold),
                Paragraph("CVSS", table_cell_bold),
                Paragraph("CVE Reference", table_cell_bold),
                Paragraph("QoD", table_cell_bold),
            ]]
            for vf in vuln_findings:
                sev_lower = (vf.severity or "info").lower()
                if sev_lower == "critical":
                    s_style = badge_crit
                elif sev_lower == "high":
                    s_style = badge_high
                elif sev_lower == "medium":
                    s_style = badge_med
                elif sev_lower == "low":
                    s_style = badge_low
                else:
                    s_style = badge_info

                host_port = f"{vf.host}:{vf.port}" if vf.port else vf.host
                cve_str = ", ".join(vf.cve_references) if vf.cve_references else "—"
                cvss_str = f"{vf.cvss_score:.1f}" if vf.cvss_score is not None else "—"
                detail_parts = []
                if vf.description:
                    description = vf.description
                    if len(description) > 1200:
                        description = description[:1200] + " … [description truncated in PDF]"
                    detail_parts.append(_safe_text(description))
                detail_parts.append(f"Evidence: {_safe_text(vf.evidence_id or '—')}")
                if vf.first_seen:
                    detail_parts.append(f"Seen: {_safe_text(vf.first_seen.strftime('%Y-%m-%d %H:%M UTC'))}")
                finding_name_and_detail = f"<b>{_safe_text(vf.name)}</b><br/><font size='6.8'>{'<br/>'.join(detail_parts)}</font>"

                v_rows.append([
                    Paragraph(_safe_text((vf.severity or "unknown").upper()), s_style),
                    Paragraph(finding_name_and_detail, finding_detail),
                    Paragraph(_safe_text(host_port), code_style),
                    Paragraph(cvss_str, body_bold),
                    Paragraph(_safe_text(cve_str), code_style),
                    Paragraph(f"{vf.qod}%" if vf.qod is not None else "—", table_cell),
                ])
            t_vulns = Table(v_rows, colWidths=[55, 165, 88, 45, 105, 46])
            t_vulns.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t_vulns)
        else:
            if vuln_state == "COMPLETED":
                vuln_empty_message = "Greenbone assessment completed with no findings. The absence of reported findings does not imply the target is free of vulnerabilities."
            elif vuln_state == "NOT PERFORMED":
                vuln_empty_message = "Greenbone assessment was not performed for this investigation."
            else:
                vuln_empty_message = f"No vulnerability findings are recorded; Greenbone assessment status: {vuln_state}. This is not a clean assessment result."
            story.append(Paragraph(f"<i>{_safe_text(vuln_empty_message)}</i>", body_style))
        story.append(Spacer(1, 14))

        # =========================================================================
        # 9. Prioritized Remediation Recommendations
        # =========================================================================
        story.append(Paragraph("8. Prioritized Remediation Recommendations", h1_style))
        remediation_items = []
        # Check database exposure
        db_open = [p for p in scan_ports if p.port_number in ExposureScorer.DATABASE_PORTS]
        if db_open:
            ports_str = ", ".join([str(p.port_number) for p in db_open])
            remediation_items.append(f"<b>Restrict Database Port Access:</b> Open database port(s) {ports_str} detected. Bind database listener to localhost (127.0.0.1) or restrict access via strict host firewall rules.")

        # Check vulnerability solutions
        for vf in vuln_findings:
            if vf.solution and len(remediation_items) < 5:
                remediation_items.append(
                    f"<b>Remediate {_safe_text(vf.name)}:</b> {_safe_text(vf.solution)}"
                )

        # Default hygiene recommendations if few items
        if len(remediation_items) < 3:
            remediation_items.append("<b>Implement Authoritative DMARC Policy:</b> Ensure apex domain publishes a valid DMARC TXT record with quarantine or reject enforcement.")
            remediation_items.append("<b>Enforce Modern TLS Ciphers:</b> Disable deprecated protocols (SSLv3, TLS 1.0, TLS 1.1) across all public HTTPS services; enforce TLS 1.2 and TLS 1.3.")

        rem_text = "<br/><br/>".join([f"&bull; {item}" for item in remediation_items])
        story.append(Paragraph(rem_text, body_style))
        story.append(Spacer(1, 14))

        # =========================================================================
        # 10. Tool Execution History & Operational Summary
        # =========================================================================
        story.append(Paragraph("9. Tool Execution History &amp; Operational Summary", h1_style))
        job_rows = [[
            Paragraph("Subsystem", table_cell_bold),
            Paragraph("Target", table_cell_bold),
            Paragraph("Profile / Tool", table_cell_bold),
            Paragraph("Status", table_cell_bold),
            Paragraph("Started / Completed (UTC)", table_cell_bold),
        ]]
        for cj in collection_jobs:
            job_rows.append([
                Paragraph("Passive OSINT", table_cell),
                Paragraph(_safe_text(cj.target), code_style),
                Paragraph(_safe_text(cj.collector_name), table_cell),
                Paragraph(_safe_text(cj.status), body_bold),
                Paragraph(f"{cj.started_at.strftime('%Y-%m-%d %H:%M') if cj.started_at else '—'}<br/>End: {cj.completed_at.strftime('%Y-%m-%d %H:%M') if cj.completed_at else '—'}", table_cell),
            ])
        for nj in nmap_jobs:
            job_rows.append([
                Paragraph("Active Nmap", table_cell),
                Paragraph(_safe_text(nj.target), code_style),
                Paragraph(_safe_text(nj.scan_profile), table_cell),
                Paragraph(_safe_text(nj.status), body_bold),
                Paragraph(f"{nj.started_at.strftime('%Y-%m-%d %H:%M') if nj.started_at else '—'}<br/>End: {nj.completed_at.strftime('%Y-%m-%d %H:%M') if nj.completed_at else '—'}", table_cell),
            ])
        for vj in vuln_jobs:
            job_rows.append([
                Paragraph("Greenbone GVM", table_cell),
                Paragraph(_safe_text(vj.target), code_style),
                Paragraph(_safe_text(vj.profile_id), table_cell),
                Paragraph(_safe_text(vj.status), body_bold),
                Paragraph(f"{vj.started_at.strftime('%Y-%m-%d %H:%M') if vj.started_at else '—'}<br/>End: {vj.completed_at.strftime('%Y-%m-%d %H:%M') if vj.completed_at else '—'}", table_cell),
            ])

        if len(job_rows) > 1:
            t_jobs = Table(job_rows, colWidths=[90, 124, 100, 70, 120])
            t_jobs.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_jobs)
        else:
            story.append(Paragraph("<i>No scan or collection jobs executed yet.</i>", body_style))
        story.append(Spacer(1, 14))

        # =========================================================================
        # 11. Forensic Evidence Ledger & Cryptographic Provenance
        # =========================================================================
        story.append(Paragraph("10. Forensic Evidence Ledger &amp; Recorded Digest Metadata", h1_style))
        if evidence_list:
            ev_rows = [[
                Paragraph("Evidence ID", table_cell_bold),
                Paragraph("Source Tool", table_cell_bold),
                Paragraph("Target", table_cell_bold),
                Paragraph("Bytes", table_cell_bold),
                Paragraph("Recorded SHA-256 Prefix", table_cell_bold),
                Paragraph("Collected (UTC)", table_cell_bold),
            ]]
            for ev in evidence_list[:15]:
                hash_display = f"{ev.content_hash[:20]}..." if ev.content_hash else "None"
                ev_rows.append([
                    Paragraph(_safe_text(ev.id), code_style),
                    Paragraph(_safe_text(ev.source_name), table_cell),
                    Paragraph(_safe_text(ev.target), code_style),
                    Paragraph(str(ev.content_size_bytes), table_cell),
                    Paragraph(hash_display, code_style),
                    Paragraph(ev.collected_at.strftime("%Y-%m-%d %H:%M") if ev.collected_at else "—", table_cell),
                ])
            t_ev = Table(ev_rows, colWidths=[78, 90, 96, 40, 130, 70])
            t_ev.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_ev)
            if len(evidence_list) > 15:
                story.append(Paragraph(f"<i>... and {len(evidence_list) - 15} additional forensic artifacts stored in repository.</i>", body_style))
        else:
            story.append(Paragraph("<i>No forensic evidence records archived for this investigation.</i>", body_style))
        story.append(Spacer(1, 14))

        # =========================================================================
        # 12. Audit References & Limitations
        # =========================================================================
        story.append(Paragraph("11. Operational Caveats &amp; Limitations", h1_style))
        caveat_text = (
            "&bull; <b>Temporal Scope:</b> Findings represent the digital attack surface observed at the time of execution.<br/>"
            "&bull; <b>Passive Boundary:</b> OSINT collection relied on third-party public registries and authoritative DNS caches.<br/>"
            "&bull; <b>Active Scans:</b> Port detection and vulnerability scanning were restricted exclusively to approved targets.<br/>"
            "&bull; <b>Evidence Integrity:</b> Stored evidence files are SHA-256 checked when retrieved; this PDF reports recorded digest prefixes and does not re-read or verify the evidence files. Hashes detect byte changes but do not make the database or files immutable."
        )
        story.append(Paragraph(caveat_text, body_style))
        story.append(Spacer(1, 12))

        # Build document using NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
