"""Unit tests for the 15 scan-pipeline nodes.

Deterministic non-LLM nodes (decompile/analysis) are tested with
monkeypatched fakes of `decompile.unpack`/`decompile.cfr`/`analysis.*` so
these tests stay fast and don't need the real CFR/fixture-JAR machinery
(covered by `tests/integration/test_scan_pipeline.py`). LLM-touching nodes
get one real Anthropic call each (gated on `_require_llm_key`) plus
monkeypatched-LLM tests for behaviour that doesn't need a real call.
"""

import json

import pytest

from db.models import ScanRow
from db.session import create_db_session


def _insert_scan_row(scan_id: str) -> None:
    with create_db_session() as session:
        session.add(
            ScanRow(
                id=scan_id,
                original_filename="fixture.jar",
                jar_path="/tmp/fixture.jar",
                status="processing",
                current_phase="queued",
            )
        )


def _get_scan_row(scan_id: str) -> ScanRow:
    with create_db_session() as session:
        row = session.get(ScanRow, scan_id)
        session.expunge(row)
        return row


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------


def test_decompile_happy_path(monkeypatch, _isolated_db, tmp_path):
    import graph.nodes as nodes

    scan_id = "scan-decompile-1"
    _insert_scan_row(scan_id)

    def fake_unpack_jar(jar_path, extract_dir):
        return {
            "extract_dir": str(tmp_path / "extract"),
            "is_spring_boot": True,
            "has_spring_security": True,
            "spring_evidence": ["fake evidence"],
            "classes_root": str(tmp_path / "extract" / "classes"),
            "nested_jars": [str(tmp_path / "lib1.jar")],
            "manifest": {},
            "config_file_paths": {},
        }

    def fake_decompile_classes(classes_root_or_jar, output_dir, **kwargs):
        if "lib1" in classes_root_or_jar:
            return {"output_dir": output_dir, "class_count": 3, "errors": []}
        return {"output_dir": output_dir, "class_count": 10, "errors": []}

    monkeypatch.setattr(nodes, "unpack_jar", fake_unpack_jar)
    monkeypatch.setattr(nodes, "decompile_classes", fake_decompile_classes)

    state = {"scan_id": scan_id, "jar_path": "/tmp/fixture.jar", "error": None}
    result = nodes.decompile(state)

    assert result.get("error") is None
    assert result["class_count"] == 13
    assert result["is_spring_boot"] is True
    assert result["has_spring_security"] is True
    assert len(result["decompiled_lib_dirs"]) == 1

    row = _get_scan_row(scan_id)
    assert row.class_count == 13
    assert row.is_spring_boot is True
    assert row.current_phase == "decompiling"


def test_decompile_zero_classes_everywhere_is_fatal(monkeypatch, _isolated_db, tmp_path):
    import graph.nodes as nodes

    scan_id = "scan-decompile-2"
    _insert_scan_row(scan_id)

    def fake_unpack_jar(jar_path, extract_dir):
        return {
            "extract_dir": str(tmp_path / "extract"),
            "is_spring_boot": False,
            "has_spring_security": False,
            "spring_evidence": [],
            "classes_root": str(tmp_path / "extract" / "classes"),
            "nested_jars": [],
            "manifest": {},
            "config_file_paths": {},
        }

    def fake_decompile_classes(classes_root_or_jar, output_dir, **kwargs):
        return {"output_dir": output_dir, "class_count": 0, "errors": ["nothing to decompile"]}

    monkeypatch.setattr(nodes, "unpack_jar", fake_unpack_jar)
    monkeypatch.setattr(nodes, "decompile_classes", fake_decompile_classes)

    state = {"scan_id": scan_id, "jar_path": "/tmp/fixture.jar", "error": None}
    result = nodes.decompile(state)

    assert result.get("error") is not None
    assert "zero classes" in result["error"]


def test_decompile_invalid_jar_sets_error(monkeypatch, _isolated_db):
    import graph.nodes as nodes

    scan_id = "scan-decompile-3"
    _insert_scan_row(scan_id)

    def fake_unpack_jar(jar_path, extract_dir):
        raise ValueError("File is not a valid JAR/ZIP archive: /tmp/not-a-jar.txt")

    monkeypatch.setattr(nodes, "unpack_jar", fake_unpack_jar)

    state = {"scan_id": scan_id, "jar_path": "/tmp/not-a-jar.txt", "error": None}
    result = nodes.decompile(state)

    assert result.get("error") is not None
    assert "not a valid JAR" in result["error"]


# ---------------------------------------------------------------------------
# scan_dependencies / scan_secrets / extract_config / triage
# ---------------------------------------------------------------------------


def test_scan_dependencies_happy_path(monkeypatch, _isolated_db, tmp_path):
    import graph.nodes as nodes

    scan_id = "scan-deps-1"
    _insert_scan_row(scan_id)

    fake_deps = [{"artifact_id": "jackson-databind", "group_id": None, "version": "2.9.8", "source": "nested_jar_filename"}]
    monkeypatch.setattr(nodes, "extract_dependencies", lambda unpack_result: fake_deps)

    state = {"scan_id": scan_id, "extract_dir": str(tmp_path), "decompiled_app_dir": str(tmp_path), "error": None}
    result = nodes.scan_dependencies(state)

    assert result.get("error") is None
    assert result["dependencies"] == fake_deps
    row = _get_scan_row(scan_id)
    assert json.loads(row.dependencies_json) == fake_deps


def test_scan_dependencies_no_nested_jars_or_manifest_edge_case(monkeypatch, _isolated_db, tmp_path):
    """Edge case: an extract_dir with no BOOT-INF/lib and no MANIFEST.MF —
    should not crash, just yield whatever extract_dependencies returns."""
    import graph.nodes as nodes

    scan_id = "scan-deps-2"
    _insert_scan_row(scan_id)
    monkeypatch.setattr(nodes, "extract_dependencies", lambda unpack_result: [])

    state = {"scan_id": scan_id, "extract_dir": str(tmp_path / "does-not-exist"), "error": None}
    result = nodes.scan_dependencies(state)

    assert result.get("error") is None
    assert result["dependencies"] == []


def test_scan_secrets_happy_path(monkeypatch, _isolated_db, tmp_path):
    import graph.nodes as nodes

    scan_id = "scan-secrets-1"
    _insert_scan_row(scan_id)

    fake_secrets = [
        {"pattern_name": "AWS Access Key ID", "file_path": "X.java", "line_number": 1, "matched_text_redacted": "AKIA…MNOP", "confidence": "High"}
    ]
    monkeypatch.setattr(nodes, "_run_secret_scan", lambda dirs, config_paths: fake_secrets)

    state = {"scan_id": scan_id, "decompiled_app_dir": str(tmp_path), "decompiled_lib_dirs": [], "config_file_paths": {}, "error": None}
    result = nodes.scan_secrets(state)

    assert result.get("error") is None
    assert result["secret_findings"] == fake_secrets
    row = _get_scan_row(scan_id)
    assert row.secret_findings_count == 1


def test_scan_secrets_none_found_edge_case(monkeypatch, _isolated_db, tmp_path):
    import graph.nodes as nodes

    scan_id = "scan-secrets-2"
    _insert_scan_row(scan_id)
    monkeypatch.setattr(nodes, "_run_secret_scan", lambda dirs, config_paths: [])

    state = {"scan_id": scan_id, "decompiled_app_dir": str(tmp_path), "decompiled_lib_dirs": [], "config_file_paths": {}, "error": None}
    result = nodes.scan_secrets(state)

    assert result["secret_findings"] == []
    row = _get_scan_row(scan_id)
    assert row.secret_findings_count == 0


def test_extract_config_happy_path(monkeypatch, _isolated_db):
    import graph.nodes as nodes

    monkeypatch.setattr(nodes, "extract_config_files", lambda unpack_result: {"application.yml": "server:\n  port: 8080"})

    state = {"scan_id": "scan-config-1", "config_file_paths": {"application.yml": "/tmp/application.yml"}, "error": None}
    result = nodes.extract_config(state)

    assert result.get("error") is None
    assert result["config_files"]["application.yml"].startswith("server:")


def test_triage_happy_path(monkeypatch, _isolated_db, tmp_path):
    import graph.nodes as nodes

    scan_id = "scan-triage-1"
    _insert_scan_row(scan_id)

    fake_chunks = [
        {"file_path": "X.java", "class_name": "X", "source_text": "code", "relevance_score": 3, "category_hints": ["injection"], "truncated": False}
    ]
    monkeypatch.setattr(nodes, "triage_classes", lambda app_dir, lib_dirs, **kwargs: fake_chunks)

    state = {"scan_id": scan_id, "decompiled_app_dir": str(tmp_path), "decompiled_lib_dirs": [], "error": None}
    result = nodes.triage(state)

    assert result.get("error") is None
    assert result["triaged_chunks"] == fake_chunks
    row = _get_scan_row(scan_id)
    assert row.triaged_class_count == 1


def test_triage_empty_result_edge_case(monkeypatch, _isolated_db, tmp_path):
    import graph.nodes as nodes

    scan_id = "scan-triage-2"
    _insert_scan_row(scan_id)
    monkeypatch.setattr(nodes, "triage_classes", lambda app_dir, lib_dirs, **kwargs: [])

    state = {"scan_id": scan_id, "decompiled_app_dir": str(tmp_path), "decompiled_lib_dirs": [], "error": None}
    result = nodes.triage(state)

    assert result["triaged_chunks"] == []
    row = _get_scan_row(scan_id)
    assert row.triaged_class_count == 0


# ---------------------------------------------------------------------------
# review_authn_authz — Spring Security conditional prompt logic (no LLM needed)
# ---------------------------------------------------------------------------


class _FakeLLMClient:
    """Captures the user message passed to `call_model` without making a
    real network call — used for testing prompt-construction logic that
    doesn't need a real LLM response."""

    captured_user_message: str | None = None

    def call_model(self, prompt, *, system=None):
        _FakeLLMClient.captured_user_message = prompt
        return {"text": "[]", "input_tokens": 5, "output_tokens": 5, "model": "claude-sonnet-4-6"}


def test_review_authn_authz_includes_spring_security_true_note(monkeypatch, _isolated_db):
    import graph.nodes as nodes

    monkeypatch.setattr(nodes, "LLMClient", _FakeLLMClient)
    state = {
        "scan_id": "scan-authz-1",
        "has_spring_security": True,
        "triaged_chunks": [],
        "error": None,
    }
    result = nodes.review_authn_authz(state)

    assert result.get("error") is None
    assert "has_spring_security: true" in _FakeLLMClient.captured_user_message
    assert "IS present" in _FakeLLMClient.captured_user_message


def test_review_authn_authz_includes_spring_security_false_note(monkeypatch, _isolated_db):
    import graph.nodes as nodes

    monkeypatch.setattr(nodes, "LLMClient", _FakeLLMClient)
    state = {
        "scan_id": "scan-authz-2",
        "has_spring_security": False,
        "triaged_chunks": [],
        "error": None,
    }
    result = nodes.review_authn_authz(state)

    assert result.get("error") is None
    assert "has_spring_security: false" in _FakeLLMClient.captured_user_message
    assert "is NOT present" in _FakeLLMClient.captured_user_message


def test_review_node_llm_error_sets_state_error(monkeypatch, _isolated_db):
    import graph.nodes as nodes

    class _RaisingLLMClient:
        def call_model(self, prompt, *, system=None):
            raise RuntimeError("simulated Anthropic API failure")

    monkeypatch.setattr(nodes, "LLMClient", _RaisingLLMClient)
    state = {"scan_id": "scan-injection-err", "triaged_chunks": [], "error": None}
    result = nodes.review_injection(state)

    assert result.get("error") == "simulated Anthropic API failure"


def test_review_node_parse_failure_sets_state_error(monkeypatch, _isolated_db):
    import graph.nodes as nodes

    class _BadJSONLLMClient:
        def call_model(self, prompt, *, system=None):
            return {"text": "not json", "input_tokens": 1, "output_tokens": 1, "model": "claude-sonnet-4-6"}

    monkeypatch.setattr(nodes, "LLMClient", _BadJSONLLMClient)
    state = {"scan_id": "scan-injection-badjson", "triaged_chunks": [], "error": None}
    result = nodes.review_injection(state)

    assert result.get("error") is not None
    assert "not valid JSON" in result["error"]


# ---------------------------------------------------------------------------
# review_injection — one REAL Anthropic call (gated on key presence)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_require_llm_key")
def test_review_injection_real_llm_call_happy_path(_isolated_db):
    import graph.nodes as nodes

    vulnerable_chunk = {
        "file_path": "UserController.java",
        "class_name": "UserController",
        "source_text": (
            "public boolean findUserByName(java.sql.Connection connection, String name) throws java.sql.SQLException {\n"
            "    java.sql.Statement stmt = connection.createStatement();\n"
            "    return stmt.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\");\n"
            "}\n"
        ),
        "relevance_score": 3,
        "category_hints": ["injection"],
        "truncated": False,
    }
    state = {
        "scan_id": "scan-real-injection-1",
        "triaged_chunks": [vulnerable_chunk],
        "error": None,
    }
    result = nodes.review_injection(state)

    assert result.get("error") is None
    assert len(result["raw_findings"]) >= 1
    assert len(result["token_usage"]) == 1
    usage = result["token_usage"][0]
    assert usage["node"] == "review_injection"
    assert usage["input_tokens"] > 0
    assert usage["output_tokens"] > 0

    # At least one finding should genuinely reference the SQL injection.
    real_findings = [f for f in result["raw_findings"] if not f["no_evidence_marker"]]
    assert len(real_findings) >= 1
    assert any("Injection" in (f["owasp_category"] or "") for f in real_findings)


# ---------------------------------------------------------------------------
# assemble_report — deterministic, no LLM call
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS = [
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


def _finding(**overrides) -> dict:
    base = {
        "title": "Test Finding",
        "severity": "High",
        "cvss_score": 7.5,
        "owasp_category": "A03:2021 - Injection",
        "stride_category": "Tampering",
        "cwe_id": "CWE-89",
        "affected_classes": ["com.example.Foo"],
        "affected_methods": ["bar()"],
        "description": "d",
        "business_impact": "b",
        "technical_impact": "t",
        "attack_scenario": "a",
        "evidence": "evidence text",
        "code_snippet": "code",
        "why_vulnerable": "why",
        "how_exploitable": "how",
        "recommended_fix": "fix",
        "secure_code_example": "example",
        "references": ["https://owasp.org/"],
        "confidence": "High",
        "category_source": "review_injection",
        "no_evidence_marker": False,
        "verified": True,
        "verification_note": None,
    }
    base.update(overrides)
    return base


def test_assemble_report_contains_all_required_headers(_isolated_db):
    import graph.nodes as nodes

    state = {
        "scan_id": "scan-assemble-1",
        "verified_findings": [_finding()],
        "dependencies": [{"artifact_id": "jackson-databind", "group_id": None, "version": "2.9.8", "source": "nested_jar_filename"}],
        "secret_findings": [],
        "class_count": 90,
        "triaged_chunks": [{"file_path": "X", "class_name": "X", "source_text": "", "relevance_score": 1, "category_hints": [], "truncated": False}],
        "decompile_errors": [],
        "is_spring_boot": True,
        "has_spring_security": True,
        "spring_evidence": ["evidence"],
        "token_usage": [{"node": "review_injection", "model": "claude-sonnet-4-6", "input_tokens": 100, "output_tokens": 50}],
        "error": None,
    }
    result = nodes.assemble_report(state)

    assert result.get("error") is None
    for header in _REQUIRED_HEADERS:
        assert header in result["report_markdown"], f"missing header: {header}"


def test_assemble_report_risk_score_formula():
    import graph.nodes as nodes

    findings = [
        _finding(severity="Critical"),
        _finding(severity="High"),
        _finding(severity="Medium"),
        _finding(severity="Low"),
    ]
    state = {
        "scan_id": "scan-assemble-2",
        "verified_findings": findings,
        "dependencies": [],
        "secret_findings": [],
        "class_count": 10,
        "triaged_chunks": [],
        "decompile_errors": [],
        "is_spring_boot": False,
        "has_spring_security": False,
        "spring_evidence": [],
        "token_usage": [],
        "error": None,
    }
    result = nodes.assemble_report(state)
    assert result["risk_score"] == 10 + 6 + 3 + 1


def test_assemble_report_no_findings_edge_case_renders_no_evidence_found():
    import graph.nodes as nodes

    state = {
        "scan_id": "scan-assemble-3",
        "verified_findings": [],
        "dependencies": [],
        "secret_findings": [],
        "class_count": 5,
        "triaged_chunks": [],
        "decompile_errors": [],
        "is_spring_boot": False,
        "has_spring_security": False,
        "spring_evidence": [],
        "token_usage": [],
        "error": None,
    }
    result = nodes.assemble_report(state)
    assert result["risk_score"] == 0
    assert "No evidence found." in result["report_markdown"]


def test_assemble_report_excludes_dropped_findings_from_risk_score():
    import graph.nodes as nodes

    findings = [_finding(severity="Critical", verified=False, verification_note="dropped: not supported by evidence")]
    state = {
        "scan_id": "scan-assemble-4",
        "verified_findings": findings,
        "dependencies": [],
        "secret_findings": [],
        "class_count": 5,
        "triaged_chunks": [],
        "decompile_errors": [],
        "is_spring_boot": False,
        "has_spring_security": False,
        "spring_evidence": [],
        "token_usage": [],
        "error": None,
    }
    result = nodes.assemble_report(state)
    assert result["risk_score"] == 0


# ---------------------------------------------------------------------------
# handle_error / finalize
# ---------------------------------------------------------------------------


def test_handle_error_writes_failed_status(_isolated_db):
    import graph.nodes as nodes

    scan_id = "scan-handle-error-1"
    _insert_scan_row(scan_id)

    state = {"scan_id": scan_id, "error": "something broke"}
    result = nodes.handle_error(state)

    assert result["status"] == "failed"
    row = _get_scan_row(scan_id)
    assert row.status == "failed"
    assert row.error_message == "something broke"
    assert row.current_phase == "failed"


def test_finalize_writes_completed_status_and_report(_isolated_db):
    import graph.nodes as nodes

    scan_id = "scan-finalize-1"
    _insert_scan_row(scan_id)

    state = {
        "scan_id": scan_id,
        "verified_findings": [_finding()],
        "report_markdown": "# Executive Summary\n\ntest",
        "risk_score": 42,
        "total_input_tokens": 100,
        "total_output_tokens": 50,
        "estimated_cost_usd": 0.01,
    }
    result = nodes.finalize(state)

    assert result["status"] == "completed"
    row = _get_scan_row(scan_id)
    assert row.status == "completed"
    assert row.current_phase == "completed"
    assert row.risk_score == 42
    assert row.report_markdown.startswith("# Executive Summary")
    assert json.loads(row.findings_json)[0]["title"] == "Test Finding"
