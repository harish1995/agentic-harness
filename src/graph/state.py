"""LangGraph pipeline state for the JAR security scanner.

Pinned exactly per `spec/agent.md` -> Agent State. Do not rename fields —
`api-and-db` (db.models.ScanRow) and the frontend slices consume the shapes
below (via `Finding`/`DependencyInfo` JSON serialization) verbatim.
"""

from typing import Literal, TypedDict

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Confidence = Literal["High", "Medium", "Low"]


class DependencyInfo(TypedDict):
    artifact_id: str
    group_id: str | None
    version: str | None
    source: Literal["manifest", "nested_jar_filename", "pom_properties"]


class SecretFinding(TypedDict):
    pattern_name: str
    file_path: str
    line_number: int
    matched_text_redacted: str
    confidence: Confidence


class TriagedChunk(TypedDict):
    file_path: str
    class_name: str
    source_text: str
    relevance_score: int
    category_hints: list[str]
    truncated: bool


class Finding(TypedDict):
    title: str
    severity: Severity
    cvss_score: float | None
    owasp_category: str | None
    stride_category: str | None
    cwe_id: str | None
    affected_classes: list[str]
    affected_methods: list[str]
    description: str
    business_impact: str
    technical_impact: str
    attack_scenario: str
    evidence: str
    code_snippet: str
    why_vulnerable: str
    how_exploitable: str
    recommended_fix: str
    secure_code_example: str
    references: list[str]
    confidence: Confidence
    category_source: str
    no_evidence_marker: bool
    verified: bool
    verification_note: str | None


class TokenUsageEntry(TypedDict):
    node: str
    model: str
    input_tokens: int
    output_tokens: int


class ScanState(TypedDict, total=False):
    # Identity
    scan_id: str
    jar_path: str
    original_filename: str

    # decompile
    extract_dir: str
    decompiled_app_dir: str
    decompiled_lib_dirs: list[str]
    is_spring_boot: bool
    has_spring_security: bool
    spring_evidence: list[str]
    class_count: int
    decompile_errors: list[str]
    config_file_paths: dict[str, str]

    # static analysis
    dependencies: list[DependencyInfo]
    secret_findings: list[SecretFinding]
    config_files: dict[str, str]

    # triage
    triaged_chunks: list[TriagedChunk]

    # LLM review accumulation
    raw_findings: list[Finding]
    token_usage: list[TokenUsageEntry]

    # verification
    verified_findings: list[Finding]

    # report
    risk_score: int
    total_input_tokens: int
    total_output_tokens: int
    estimated_cost_usd: float
    report_markdown: str

    # control
    error: str | None
    status: str
