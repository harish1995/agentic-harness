"""Helpers to serialize triaged/analysis data into bounded per-category user
messages, and a strict JSON-array parser for LLM `Finding[]` responses.

See `spec/agent.md` -> Triage Heuristic step 5 (per-category character cap)
and -> Nodes / Steps (review_* Behaviour) for the exact rules implemented
here.
"""

import json
import re

from graph.state import Finding, TriagedChunk

# The 20 content fields an LLM review response must supply per finding
# (the 4 remaining `Finding` fields — category_source, no_evidence_marker,
# verified, verification_note — are set programmatically by the node/verify
# pass, never requested from the model).
REQUIRED_FINDING_FIELDS: tuple[str, ...] = (
    "title",
    "severity",
    "cvss_score",
    "owasp_category",
    "stride_category",
    "cwe_id",
    "affected_classes",
    "affected_methods",
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
)

_LIST_FIELDS = {"affected_classes", "affected_methods", "references"}

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def filter_chunks_for_category(
    triaged_chunks: list[TriagedChunk], category: str
) -> list[TriagedChunk]:
    """Chunks whose `category_hints` includes `category`, in the same
    relevance-sorted order `triage_classes` already produced them in."""
    return [chunk for chunk in triaged_chunks if category in chunk["category_hints"]]


def build_chunks_message(chunks: list[TriagedChunk], per_category_max_chars: int) -> str:
    """Serialize chunks with file-path headers, taking chunks in order until
    the running total would exceed `per_category_max_chars` (the hard bound
    from `spec/agent.md` -> Triage Heuristic step 5)."""
    if not chunks:
        return "(No triaged code chunks matched this category.)"

    parts: list[str] = []
    running_total = 0
    for chunk in chunks:
        header = f"=== File: {chunk['file_path']} (class {chunk['class_name']}) ===\n"
        block = f"{header}{chunk['source_text']}\n\n"
        if running_total + len(block) > per_category_max_chars and parts:
            break
        parts.append(block)
        running_total += len(block)
    return "".join(parts) if parts else "(No triaged code chunks fit within the character budget.)"


def build_dependencies_message(dependencies: list[dict]) -> str:
    if not dependencies:
        return "(No dependencies were extracted from this JAR.)"
    return json.dumps(dependencies, indent=2)


def build_config_message(config_files: dict[str, str], per_category_max_chars: int) -> str:
    if not config_files:
        return "(No config files were found in this JAR.)"

    parts: list[str] = []
    running_total = 0
    for path, text in config_files.items():
        block = f"=== Config file: {path} ===\n{text}\n\n"
        if running_total + len(block) > per_category_max_chars and parts:
            break
        parts.append(block)
        running_total += len(block)
    return "".join(parts) if parts else "(No config files fit within the character budget.)"


def build_secret_findings_message(secret_findings: list[dict]) -> str:
    if not secret_findings:
        return "(No candidate secrets were detected by the regex secret scanner.)"
    return json.dumps(secret_findings, indent=2)


def _no_evidence_marker_finding(category_source: str) -> Finding:
    return Finding(
        title="No evidence found.",
        severity="Informational",
        cvss_score=None,
        owasp_category=None,
        stride_category=None,
        cwe_id=None,
        affected_classes=[],
        affected_methods=[],
        description="",
        business_impact="",
        technical_impact="",
        attack_scenario="",
        evidence="",
        code_snippet="",
        why_vulnerable="",
        how_exploitable="",
        recommended_fix="",
        secure_code_example="",
        references=[],
        confidence="High",
        category_source=category_source,
        no_evidence_marker=True,
        verified=True,
        verification_note=None,
    )


def parse_findings_json(text: str, *, category_source: str) -> list[Finding]:
    """Strictly parse an LLM response expected to be a raw JSON array of
    `Finding`-shaped objects (no prose wrapper). Tolerates a markdown code
    fence around the array (models sometimes add one despite instructions)
    but otherwise enforces the schema exactly.

    Raises `ValueError` with a clear, actionable message on any parse/schema
    failure — treated by the caller as a node-level error per
    `spec/agent.md` -> Prompt strategy.
    """
    cleaned = _CODE_FENCE_RE.sub("", text).strip()

    try:
        parsed, _end_idx = json.JSONDecoder().raw_decode(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{category_source}: LLM response was not valid JSON: {exc}. "
            f"Raw response (truncated): {text[:500]!r}"
        ) from exc

    if not isinstance(parsed, list):
        raise ValueError(
            f"{category_source}: expected a JSON array of findings, got {type(parsed).__name__}."
        )

    findings: list[Finding] = []
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise ValueError(f"{category_source}: finding[{idx}] is not a JSON object.")

        missing = [f for f in REQUIRED_FINDING_FIELDS if f not in item]
        if missing:
            raise ValueError(
                f"{category_source}: finding[{idx}] is missing required field(s): {missing}."
            )

        no_evidence_marker = bool(item.get("no_evidence_marker", False)) or (
            item.get("title") == "No evidence found."
        )

        finding: Finding = Finding(
            title=str(item["title"]),
            severity=item["severity"],
            cvss_score=item["cvss_score"],
            owasp_category=item["owasp_category"],
            stride_category=item["stride_category"],
            cwe_id=item["cwe_id"],
            affected_classes=list(item["affected_classes"]) if item["affected_classes"] else [],
            affected_methods=list(item["affected_methods"]) if item["affected_methods"] else [],
            description=str(item["description"]),
            business_impact=str(item["business_impact"]),
            technical_impact=str(item["technical_impact"]),
            attack_scenario=str(item["attack_scenario"]),
            evidence=str(item["evidence"]),
            code_snippet=str(item["code_snippet"]),
            why_vulnerable=str(item["why_vulnerable"]),
            how_exploitable=str(item["how_exploitable"]),
            recommended_fix=str(item["recommended_fix"]),
            secure_code_example=str(item["secure_code_example"]),
            references=list(item["references"]) if item["references"] else [],
            confidence=item["confidence"],
            category_source=category_source,
            no_evidence_marker=no_evidence_marker,
            verified=False,
            verification_note=None,
        )
        findings.append(finding)

    if not findings:
        # A genuinely empty array is treated the same as an explicit
        # "No evidence found." marker — the model must always say so
        # explicitly per the mandatory rules, but a defensively-empty
        # array should never silently vanish from the report either.
        findings.append(_no_evidence_marker_finding(category_source))

    return findings


_VERIFICATION_DECISION_FIELDS: tuple[str, ...] = (
    "index",
    "decision",
    "severity",
    "confidence",
    "verification_note",
)
_VALID_DECISIONS = {"keep", "downgrade", "drop"}


def parse_verification_decisions(text: str) -> list[dict]:
    """Strictly parse `verify_findings`'s LLM response — a JSON array of
    `{index, decision, severity, confidence, verification_note}` objects.
    Raises `ValueError` with a clear message on any parse/schema failure.
    """
    cleaned = _CODE_FENCE_RE.sub("", text).strip()

    try:
        parsed, _end_idx = json.JSONDecoder().raw_decode(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"verify_findings: LLM response was not valid JSON: {exc}. "
            f"Raw response (truncated): {text[:500]!r}"
        ) from exc

    if not isinstance(parsed, list):
        raise ValueError(
            f"verify_findings: expected a JSON array of decisions, got {type(parsed).__name__}."
        )

    decisions: list[dict] = []
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise ValueError(f"verify_findings: decision[{idx}] is not a JSON object.")
        missing = [f for f in _VERIFICATION_DECISION_FIELDS if f not in item]
        if missing:
            raise ValueError(
                f"verify_findings: decision[{idx}] is missing required field(s): {missing}."
            )
        if item["decision"] not in _VALID_DECISIONS:
            raise ValueError(
                f"verify_findings: decision[{idx}] has invalid decision value "
                f"{item['decision']!r} (must be one of {sorted(_VALID_DECISIONS)})."
            )
        decisions.append(item)

    return decisions
