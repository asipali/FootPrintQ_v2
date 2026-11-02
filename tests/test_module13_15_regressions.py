"""Focused job/report regressions for actual state labels and safe PDF text."""

from types import SimpleNamespace

from app.services.reporting.pdf_generator import _job_state, _safe_text
from app.services.vuln.orchestrator import _reported_progress


def test_report_job_state_does_not_turn_missing_or_failed_jobs_into_success():
    assert _job_state([]) == "NOT PERFORMED"
    assert _job_state([SimpleNamespace(status="QUEUED")]) == "PENDING"
    assert _job_state([SimpleNamespace(status="RUNNING")]) == "RUNNING"
    assert _job_state([SimpleNamespace(status="COMPLETED")]) == "COMPLETED"
    assert _job_state([SimpleNamespace(status="FAILED")]) == "FAILED"
    assert _job_state([SimpleNamespace(status="COMPLETED"), SimpleNamespace(status="FAILED")]) == "PARTIAL"


def test_report_dynamic_text_is_escaped_before_reportlab_markup():
    assert _safe_text("Acme & <R&D>") == "Acme &amp; &lt;R&amp;D&gt;"
    assert _safe_text(None) == ""


def test_gvm_progress_uses_only_reported_bounded_percentage():
    assert _reported_progress(42) == 42
    assert _reported_progress("40.8") == 40
    assert _reported_progress(-10) == 0
    assert _reported_progress(130) == 100
    assert _reported_progress("unknown") is None
    assert _reported_progress(None) is None
