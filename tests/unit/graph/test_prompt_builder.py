import json

import pytest

from graph.prompt_builder import (
    build_chunks_message,
    build_config_message,
    build_dependencies_message,
    build_secret_findings_message,
    filter_chunks_for_category,
    parse_findings_json,
    parse_verification_decisions,
)

_VALID_FINDING = {
    "title": "SQL Injection in OrderRepository",
    "severity": "Critical",
    "cvss_score": 9.1,
    "owasp_category": "A03:2021 - Injection",
    "stride_category": "Tampering",
    "cwe_id": "CWE-89",
    "affected_classes": ["com.example.OrderRepository"],
    "affected_methods": ["findByStatus(String)"],
    "description": "desc",
    "business_impact": "impact",
    "technical_impact": "impact",
    "attack_scenario": "scenario",
    "evidence": "stmt.execute(\"...\" + status + \"...\")",
    "code_snippet": "stmt.execute(...)",
    "why_vulnerable": "why",
    "how_exploitable": "how",
    "recommended_fix": "fix",
    "secure_code_example": "example",
    "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
    "confidence": "High",
}


def _chunk(class_name: str, category_hints: list[str], source_text: str = "code", relevance_score: int = 1) -> dict:
    return {
        "file_path": f"/tmp/{class_name}.java",
        "class_name": class_name,
        "source_text": source_text,
        "relevance_score": relevance_score,
        "category_hints": category_hints,
        "truncated": False,
    }


# --- filter_chunks_for_category -------------------------------------------------


def test_filter_chunks_for_category_happy_path():
    chunks = [_chunk("A", ["injection"]), _chunk("B", ["authn_authz"]), _chunk("C", ["injection", "crypto_secrets"])]
    result = filter_chunks_for_category(chunks, "injection")
    assert [c["class_name"] for c in result] == ["A", "C"]


def test_filter_chunks_for_category_empty_input():
    assert filter_chunks_for_category([], "injection") == []


# --- build_chunks_message --------------------------------------------------------


def test_build_chunks_message_happy_path():
    chunks = [_chunk("A", ["injection"], source_text="int x = 1;")]
    msg = build_chunks_message(chunks, per_category_max_chars=10_000)
    assert "A.java" in msg
    assert "int x = 1;" in msg


def test_build_chunks_message_empty_returns_placeholder_not_crash():
    msg = build_chunks_message([], per_category_max_chars=10_000)
    assert "No triaged code chunks" in msg


def test_build_chunks_message_respects_char_budget():
    chunks = [_chunk(f"C{i}", ["injection"], source_text="x" * 100) for i in range(50)]
    msg = build_chunks_message(chunks, per_category_max_chars=500)
    assert len(msg) < 2000  # bounded, not all 50 chunks included


# --- build_dependencies_message / build_config_message / build_secret_findings_message ------


def test_build_dependencies_message_happy_path():
    deps = [{"artifact_id": "jackson-databind", "group_id": None, "version": "2.9.8", "source": "nested_jar_filename"}]
    msg = build_dependencies_message(deps)
    assert "jackson-databind" in msg


def test_build_dependencies_message_empty():
    assert "No dependencies" in build_dependencies_message([])


def test_build_config_message_empty():
    assert "No config files" in build_config_message({}, 10_000)


def test_build_secret_findings_message_empty():
    assert "No candidate secrets" in build_secret_findings_message([])


# --- parse_findings_json ----------------------------------------------------------


def test_parse_findings_json_happy_path():
    text = json.dumps([_VALID_FINDING])
    findings = parse_findings_json(text, category_source="review_injection")
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == _VALID_FINDING["title"]
    assert f["category_source"] == "review_injection"
    assert f["no_evidence_marker"] is False
    assert f["verified"] is False


def test_parse_findings_json_strips_markdown_code_fence():
    text = "```json\n" + json.dumps([_VALID_FINDING]) + "\n```"
    findings = parse_findings_json(text, category_source="review_injection")
    assert len(findings) == 1


def test_parse_findings_json_no_evidence_marker_entry():
    marker = {
        **{k: None for k in _VALID_FINDING},
        "title": "No evidence found.",
        "severity": "Informational",
        "cvss_score": None,
        "owasp_category": None,
        "stride_category": None,
        "cwe_id": None,
        "affected_classes": [],
        "affected_methods": [],
        "description": "",
        "business_impact": "",
        "technical_impact": "",
        "attack_scenario": "",
        "evidence": "",
        "code_snippet": "",
        "why_vulnerable": "",
        "how_exploitable": "",
        "recommended_fix": "",
        "secure_code_example": "",
        "references": [],
        "confidence": "High",
    }
    findings = parse_findings_json(json.dumps([marker]), category_source="review_injection")
    assert len(findings) == 1
    assert findings[0]["no_evidence_marker"] is True


def test_parse_findings_json_empty_array_becomes_marker_entry():
    findings = parse_findings_json("[]", category_source="review_injection")
    assert len(findings) == 1
    assert findings[0]["no_evidence_marker"] is True
    assert findings[0]["title"] == "No evidence found."


def test_parse_findings_json_invalid_json_raises_clear_error():
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_findings_json("not json at all {{{", category_source="review_injection")


def test_parse_findings_json_not_a_list_raises():
    with pytest.raises(ValueError, match="expected a JSON array"):
        parse_findings_json(json.dumps({"title": "oops"}), category_source="review_injection")


def test_parse_findings_json_missing_field_raises_clear_error():
    incomplete = dict(_VALID_FINDING)
    del incomplete["cvss_score"]
    with pytest.raises(ValueError, match="missing required field"):
        parse_findings_json(json.dumps([incomplete]), category_source="review_injection")


# --- parse_verification_decisions --------------------------------------------------


def test_parse_verification_decisions_happy_path():
    decisions = [{"index": 0, "decision": "keep", "severity": "High", "confidence": "High", "verification_note": "ok"}]
    parsed = parse_verification_decisions(json.dumps(decisions))
    assert parsed == decisions


def test_parse_verification_decisions_invalid_decision_value_raises():
    decisions = [{"index": 0, "decision": "maybe", "severity": "High", "confidence": "High", "verification_note": "?"}]
    with pytest.raises(ValueError, match="invalid decision value"):
        parse_verification_decisions(json.dumps(decisions))


def test_parse_verification_decisions_missing_field_raises():
    decisions = [{"index": 0, "decision": "keep", "severity": "High"}]
    with pytest.raises(ValueError, match="missing required field"):
        parse_verification_decisions(json.dumps(decisions))
