"""Real end-to-end integration test for the JAR security scan pipeline.

Exercises the REAL decompiler (CFR shelling out to the vendored
`tools/cfr-0.152.jar`), REAL static analysis, and the REAL Anthropic API for
all 7 LLM calls (6 category reviews + verification) — no mocking on this
path. Long-running (multiple minutes, 7 real Claude calls plus a real CFR
decompile of ~90+ classes) — that is expected and correct per
`spec/roadmap.md` ("correctness over speed").
"""

import json
import sys
from pathlib import Path

import pytest

# Ensure the repo root is importable as `tests.fixtures.build_fixture_jar`
# regardless of pytest's per-test-file sys.path insertion behaviour.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.fixtures.build_fixture_jar import (  # noqa: E402
    PLAIN_POJO_SAMPLE_CLASS_NAME,
    SECURITY_RELEVANT_CLASS_NAMES,
    build_fixture_jar,
)

_REQUIRED_REPORT_HEADERS = [
    "# Executive Summary",
    "# Risk Score",
    "# Severity Dashboard",
    "# OWASP Top 10 Findings",
    "# STRIDE Findings",
    "# Dependency Vulnerabilities",
    "# Sensitive Data Exposure",
    "# Authentication Issues",
    "# Authorization Issues",
    "# Cryptography Issues",
    "# Injection Issues",
    "# Configuration Issues",
    "# Logging Issues",
    "# Secure Coding Recommendations",
    "# Developer Remediation Plan",
    "# Appendix",
]

# The 20 required Finding fields, per spec/agent.md's Required Report
# Structure note. `affected_methods` is allowed to be a legitimately empty
# list for categories with no method-level granularity (e.g. a
# config-file-only finding, or a dependency-list-only finding) — every other
# field must be truthy for a genuine (non-marker) finding.
_REQUIRED_FIELDS_MUST_BE_TRUTHY = [
    "title",
    "severity",
    "cvss_score",
    "owasp_category",
    "stride_category",
    "cwe_id",
    "affected_classes",
    "description",
    "business_impact",
    "technical_impact",
    "attack_scenario",
    "evidence",
    "code_snippet",
    "why_vulnerable",
    "how_exploitable",
    "recommended_fix",
    "secure_code_example",
    "references",
    "confidence",
]


@pytest.fixture(scope="session")
def fixture_jar_path(tmp_path_factory) -> str:
    output_dir = tmp_path_factory.mktemp("fixture-jar")
    jar_path = build_fixture_jar(output_dir / "scanner-fixture.jar")
    return str(jar_path)


@pytest.mark.usefixtures("_require_llm_key")
def test_full_scan_pipeline_end_to_end(_isolated_db, fixture_jar_path, monkeypatch, tmp_path):
    from db.models import ScanRow
    from db.session import create_db_session
    from graph.runner import run_scan

    # Isolate scan working directories to a tmp dir for this test run.
    monkeypatch.setenv("AGENT_SCAN_WORK_DIR", str(tmp_path / "decompiled"))
    import config.settings as settings_module
    settings_module._settings = None

    scan_id = "integration-test-scan-1"
    with create_db_session() as session:
        session.add(
            ScanRow(
                id=scan_id,
                original_filename="scanner-fixture.jar",
                jar_path=fixture_jar_path,
                status="processing",
                current_phase="queued",
            )
        )

    run_scan(scan_id, fixture_jar_path)

    with create_db_session() as session:
        row = session.get(ScanRow, scan_id)
        assert row is not None
        session.expunge(row)

    # --- status ---------------------------------------------------------
    assert row.status == "completed", f"scan failed: {row.error_message}"
    assert row.current_phase == "completed"

    # --- report structure -------------------------------------------------
    assert row.report_markdown is not None
    for header in _REQUIRED_REPORT_HEADERS:
        assert header in row.report_markdown, f"missing required report header: {header}"

    # --- triage cap actually engaged ------------------------------------
    assert row.class_count is not None and row.class_count > 60, (
        f"fixture must have more classes than AGENT_TRIAGE_MAX_CLASSES=60 to prove the cap "
        f"engages; got class_count={row.class_count}"
    )
    assert row.triaged_class_count is not None and row.triaged_class_count <= 60

    # --- every verified, non-marker finding has all 20 required fields non-empty ---
    findings = json.loads(row.findings_json)
    assert isinstance(findings, list) and len(findings) > 0

    real_findings = [f for f in findings if f.get("verified") and not f.get("no_evidence_marker")]
    assert len(real_findings) >= 1, "expected at least one real verified finding on a deliberately vulnerable fixture"

    for f in real_findings:
        for field in _REQUIRED_FIELDS_MUST_BE_TRUTHY:
            assert f.get(field), f"finding {f.get('title')!r} has empty/null required field {field!r}: {f.get(field)!r}"
        # affected_methods may legitimately be [] for config/dependency-only
        # findings, but must always be present as a list.
        assert isinstance(f.get("affected_methods"), list)

    # --- at least one category renders "No evidence found." ---------------
    assert "No evidence found." in row.report_markdown

    # --- known security-relevant fixture classes appear in the Appendix ---
    for class_name in SECURITY_RELEVANT_CLASS_NAMES:
        assert class_name in row.report_markdown, f"expected {class_name} to appear in the report (Appendix deep-reviewed listing)"

    # --- a known plain-POJO class must NOT appear (excluded by triage) ---
    assert PLAIN_POJO_SAMPLE_CLASS_NAME not in row.report_markdown

    # --- cost accounting -----------------------------------------------
    assert row.total_input_tokens is not None and row.total_input_tokens > 0
    assert row.total_output_tokens is not None and row.total_output_tokens > 0
    assert row.estimated_cost_usd is not None and row.estimated_cost_usd > 0
    assert row.risk_score is not None and 0 <= row.risk_score <= 100
