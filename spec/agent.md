# Agent

---

## Agent Architecture Pattern

| Pattern | Use when |
|---------|----------|
| **Single-agent loop** | One LLM drives a deterministic tool-call loop. No branches, no handoffs. |
| **Graph (LangGraph)** | Multi-step pipeline with conditional edges, checkpointing, or parallel nodes. |
| **Multi-agent** | Specialised sub-agents with distinct roles; orchestrator routes between them. |
| **Supervisor** | One supervisor LLM dispatches to worker agents based on task type. |
| **Human-in-the-loop** | Execution pauses at defined checkpoints for user review or approval. |

**Chosen: Graph (LangGraph).** The task decomposes into a fixed, ordered pipeline (decompile → static analysis → triage → category-partitioned review → verify → assemble) with real conditional error-routing at every step and one reflection pass — not a tool-calling loop (no step re-decides what to do next based on an LLM's live choice) and not multiple autonomous peer agents (no role needs independent judgment about *what* to do, only *how well* the evidence supports each finding). Composed sub-patterns from `harness/patterns/agentic-ai.md`:

- **Prompt Chaining (#1)** — the deterministic decompile → static-analysis → triage → report-assembly spine.
- **Reflection (#4)** — the `verify_findings` node is an LLM-as-judge critic pass over every raw finding before it can appear in the final report.
- **Resource-Aware Optimization (#16)** — the triage/chunk-budget mechanism (below) and the token/cost accounting are first-class, not an afterthought.
- **Guardrails (#18)** — every review/verification prompt enforces "evidence or don't report it" and "state 'No evidence found.' rather than omit."
- **Observability (#19)** — LangSmith tracing + structured request/response logging, wired in Phase 1.

This is deliberately *not* a ReAct tool-use loop: there is no step where the LLM chooses which tool to call next. The "tools" (decompiler, analyzers) run deterministically, in a fixed order, before any LLM call — only their *outputs* are read by the LLM.

---

## LLM Provider & Model

| Agent / Node | Provider | Model ID | Rationale |
|-------------|----------|----------|-----------|
| `review_injection` | Anthropic | `claude-sonnet-4-6` | Security-finding quality directly affects developer trust; no latency-driven downgrade. |
| `review_authn_authz` | Anthropic | `claude-sonnet-4-6` | Same. |
| `review_crypto_secrets` | Anthropic | `claude-sonnet-4-6` | Same. |
| `review_deserialization_upload` | Anthropic | `claude-sonnet-4-6` | Same. |
| `review_config_logging` | Anthropic | `claude-sonnet-4-6` | Same. |
| `review_dependencies` | Anthropic | `claude-sonnet-4-6` | Reasoning about known-CVE-shaped risk from a dependency list benefits from the stronger model; this is the category most prone to confident-sounding hallucination if under-powered. |
| `verify_findings` | Anthropic | `claude-sonnet-4-6` | The judge must be at least as capable as the generator to catch unsupported claims. |

Single model throughout by design (see `spec/architecture.md` → Stack). Model ID is env-configurable (`AGENT_LLM_MODEL`, existing skeleton mechanism) so it can be bumped without a code change.

**Fallback behaviour (Phase 1):** none beyond the existing skeleton's fail-fast — a call that raises sets `state["error"]` and the graph routes to `handle_error`, the scan is marked `failed` with the error message surfaced to the UI. Retry/backoff/degraded-mode is added in Phase 3 (`spec/roadmap.md`) — Phase 1 correctness comes first.

**Prompt strategy:** every review/verification node uses a **system prompt** (the category's fixed rules — evidence discipline, required fields, output JSON schema) plus a **user message** built from the triaged code/config chunks assigned to that category. Output is requested as a **JSON array of findings** (the model is instructed to return only a JSON array matching the `Finding` shape below, no prose wrapper) — parsed with a strict schema check; a parse failure is treated as a node-level error (Phase 1: fails the scan with a clear message; Phase 3: retried once, then degrades that category).

---

## Tools & Tool Calling

These are not LLM-invoked function calls (this graph has no ReAct tool-use step) — they are deterministic pipeline steps the graph calls directly, listed here because `harness/patterns/agentic-ai.md` treats them as the Tool Use (#5) surface this pipeline depends on.

| Tool name | Description | Inputs | Output | Side-effects |
|-----------|-------------|--------|--------|--------------|
| `unpack_jar` | Unpack a JAR, detect Spring Boot fat-JAR structure, locate nested lib jars and config files | `jar_path`, `extract_dir` | `UnpackResult` | Writes extracted files under `extract_dir` |
| `decompile_classes` | Shell out to CFR to decompile a classes-root directory or a single jar | `classes_root_or_jar`, `output_dir`, `cfr_jar_path`, `java_bin`, `timeout_s` | `DecompileResult` | Writes `.java`-like source under `output_dir`; runs a local subprocess |
| `detect_spring` | Heuristically decide if the JAR is Spring Boot / has Spring Security | `UnpackResult` | `SpringDetection` | None (pure function) |
| `extract_dependencies` | Parse `MANIFEST.MF`, nested-jar filenames, and `pom.properties` for dependency name/version | `UnpackResult` | `list[DependencyInfo]` | None (pure function) |
| `scan_secrets` | Regex-scan decompiled source + config text for hardcoded secrets | `decompiled_dirs`, `config_file_paths` | `list[SecretFinding]` | None (pure function; reads files) |
| `extract_config_files` | Read known config file paths as text | `UnpackResult` | `dict[str, str]` | None (reads files) |
| `triage_classes` | Score and select the bounded set of security-relevant classes/chunks per category | `decompiled_app_dir`, `decompiled_lib_dirs`, budgets | `list[TriagedChunk]` | None (pure function) |
| `LLMClient.call_model` | Call Anthropic, return text + token usage | `prompt`, `system` | `LLMResult` | Network call to Anthropic |

**Tool selection strategy:** fixed — every tool runs exactly once (or, for `decompile_classes`, once per component: app classes + each nested lib jar), in the fixed graph order below. No LLM chooses whether/which tool to call.

**Tool failure handling:** Phase 1 — any tool exception sets `state["error"]` and routes to `handle_error` (fatal, whole-scan abort), **except** `decompile_classes` and `scan_secrets`, which collect **per-item** errors into a list (`decompile_errors`) and continue with whatever succeeded, since a single unreadable nested jar or unreadable file should not abort an otherwise-scannable JAR. Phase 3 adds subprocess timeouts and per-category LLM degraded-mode (see `spec/roadmap.md`).

---

## Agent State

```python
# src/graph/state.py

from typing import TypedDict, Literal

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Confidence = Literal["High", "Medium", "Low"]

class DependencyInfo(TypedDict):
    artifact_id: str
    group_id: str | None
    version: str | None
    source: Literal["manifest", "nested_jar_filename", "pom_properties"]

class SecretFinding(TypedDict):
    pattern_name: str            # e.g. "AWS Access Key" — see Secret Pattern Table below
    file_path: str
    line_number: int
    matched_text_redacted: str   # never the raw secret in full — see Secret Redaction Rule below
    confidence: Confidence

class TriagedChunk(TypedDict):
    file_path: str
    class_name: str
    source_text: str             # possibly truncated (see Triage Heuristic), with a "[TRUNCATED]" marker appended
    relevance_score: int
    category_hints: list[str]    # subset of CATEGORY_KEYWORDS keys this chunk matched
    truncated: bool

class Finding(TypedDict):
    title: str
    severity: Severity
    cvss_score: float | None
    owasp_category: str | None   # e.g. "A03:2021 - Injection"
    stride_category: str | None  # one of Spoofing/Tampering/Repudiation/InformationDisclosure/DenialOfService/ElevationOfPrivilege
    cwe_id: str | None           # e.g. "CWE-89"
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
    category_source: str         # which review node produced it, e.g. "review_injection"
    no_evidence_marker: bool     # True for the synthetic "No evidence found." placeholder entries
    verified: bool                # set by verify_findings
    verification_note: str | None

class TokenUsageEntry(TypedDict):
    node: str
    model: str
    input_tokens: int
    output_tokens: int

class ScanState(TypedDict, total=False):
    # Identity
    scan_id: str                          # set at initialisation
    jar_path: str                         # set at initialisation
    original_filename: str                # set at initialisation

    # decompile
    extract_dir: str
    decompiled_app_dir: str
    decompiled_lib_dirs: list[str]
    is_spring_boot: bool
    has_spring_security: bool
    spring_evidence: list[str]
    class_count: int
    decompile_errors: list[str]
    config_file_paths: dict[str, str]     # relative path -> absolute path

    # static analysis
    dependencies: list[DependencyInfo]
    secret_findings: list[SecretFinding]
    config_files: dict[str, str]          # relative path -> text content

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
    status: str                           # "processing" | "completed" | "failed"
```

---

## Internal Module Contracts

Pinned exactly so the `decompiler`, `static-analysis`, and `graph-and-llm-pipeline` slices (`spec/roadmap.md`) can build concurrently without waiting on each other.

```python
# src/decompile/unpack.py
class UnpackResult(TypedDict):
    extract_dir: str
    is_spring_boot: bool
    has_spring_security: bool
    spring_evidence: list[str]
    classes_root: str                 # dir of raw .class files for the "app" component
    nested_jars: list[str]            # absolute paths to BOOT-INF/lib/*.jar; [] for plain jars
    manifest: dict[str, str]
    config_file_paths: dict[str, str] # relative path -> absolute path

def unpack_jar(jar_path: str, extract_dir: str) -> UnpackResult: ...


# src/decompile/cfr.py
class DecompileResult(TypedDict):
    output_dir: str
    class_count: int
    errors: list[str]

def decompile_classes(
    classes_root_or_jar: str,
    output_dir: str,
    *,
    cfr_jar_path: str,
    java_bin: str = "java",
    timeout_s: int = 120,
) -> DecompileResult: ...


# src/analysis/spring_detect.py
class SpringDetection(TypedDict):
    is_spring_boot: bool
    has_spring_security: bool
    evidence: list[str]

def detect_spring(unpack_result: "UnpackResult") -> SpringDetection: ...
# Heuristic (ALL evaluated; is_spring_boot = True if ANY match):
#   1. extract_dir contains both "BOOT-INF/classes" and "BOOT-INF/lib"
#   2. extract_dir contains "org/springframework/boot/loader/JarLauncher.class"
#   3. manifest["Main-Class"] == "org.springframework.boot.loader.JarLauncher" (or .WarLauncher)
#   4. any nested_jars filename matches r"^spring-boot(-\w+)*-\d"
#   5. "application.yml" | "application.yaml" | "application.properties" present in config_file_paths
# has_spring_security = True if any nested_jars filename matches r"^spring-security-\w+-\d"
#   (gates Spring-Security-specific checks inside review_authn_authz — see that node's Behaviour)


# src/analysis/dependencies.py
class DependencyInfo(TypedDict):
    artifact_id: str
    group_id: str | None
    version: str | None
    source: str

def extract_dependencies(unpack_result: "UnpackResult") -> list[DependencyInfo]: ...
# Sources, deduplicated by (artifact_id, version):
#   - MANIFEST.MF: Implementation-Title / Implementation-Version (source="manifest")
#   - nested jar filenames: regex r"^(?P<artifact>[A-Za-z0-9._-]+?)-(?P<version>\d[\w.\-]*)\.jar$"
#     (source="nested_jar_filename"; group_id=None — not derivable from filename alone)
#   - any nested META-INF/maven/*/*/pom.properties found inside a nested jar (source="pom_properties";
#     parsed groupId/artifactId/version key=value)


# src/analysis/secrets.py
class SecretFinding(TypedDict):
    pattern_name: str
    file_path: str
    line_number: int
    matched_text_redacted: str
    confidence: str

def scan_secrets(decompiled_dirs: list[str], config_file_paths: dict[str, str]) -> list[SecretFinding]: ...
# Pattern table (fixed, all applied; case-insensitive except AWS key ID):
#   AWS Access Key ID        AKIA[0-9A-Z]{16}                                                       High
#   AWS Secret Access Key    (?i)aws.{0,20}?(secret|access)?_?key.{0,20}?['"][0-9a-zA-Z/+]{40}['"]   High
#   Generic API Key          (?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]      Medium
#   Private Key Block        -----BEGIN ((RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY-----                 High
#   JDBC Creds in URL        jdbc:[a-z]+://[^"'\s]*:[^"'\s]*@[^"'\s]+                                 High
#   Generic DB Creds in URL  (?i)(mongodb(\+srv)?|postgres(ql)?|mysql)://[^:\s]+:[^@\s]+@[^\s'"]+     High
#   JWT / Generic Secret Key (?i)(jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['"][^'"]{8,}['"]           Medium
#   Hardcoded Password       (?i)password\s*[:=]\s*['"][^'"]{4,}['"]                                  Low
#     (Low confidence, and flagged not dropped, since this pattern also matches intentional
#      placeholders like "${DB_PASSWORD}" or the literal "changeme" — the LLM crypto/secrets
#      review node re-triages Low-confidence hits using surrounding code context.)
#   Slack Token              xox[baprs]-[0-9A-Za-z-]{10,48}                                          High
#   Stripe Live Key          sk_live_[0-9a-zA-Z]{24,}                                                 High
#   GitHub Token             ghp_[0-9A-Za-z]{36}                                                      High
# Redaction rule: matched_text_redacted keeps the first 4 and last 4 characters of the matched
# secret value, replacing the middle with "…" (e.g. "AKIA…3F9K") — the raw full secret is never
# persisted to the DB or sent to the LLM; only the redacted form and its file/line location are.


# src/analysis/config_files.py
def extract_config_files(unpack_result: "UnpackResult") -> dict[str, str]: ...
# Reads every path in unpack_result["config_file_paths"] as UTF-8 text (best-effort; a decode
# failure records the path with value "<binary or unreadable>" rather than raising).
# config_file_paths is populated by unpack_jar() by scanning the extracted tree (recursively,
# excluding nested BOOT-INF/lib/*.jar contents which are not unzipped further for this purpose)
# for filenames matching: application.yml, application.yaml, application.properties,
# application-*.yml, application-*.properties, logback.xml, logback-spring.xml, pom.xml,
# build.gradle, build.gradle.kts, Dockerfile, and any *.yaml/*.yml under a "k8s/" or "kubernetes/" path.


# src/analysis/triage.py
def triage_classes(
    decompiled_app_dir: str,
    decompiled_lib_dirs: list[str],
    *,
    max_classes: int = 60,          # AGENT_TRIAGE_MAX_CLASSES
    max_total_chars: int = 150_000, # AGENT_TRIAGE_MAX_CHARS
    per_category_max_chars: int = 30_000,  # AGENT_TRIAGE_PER_CATEGORY_MAX_CHARS
) -> list[TriagedChunk]: ...
```

### Triage Heuristic (concrete — the cost-control mechanism)

1. Walk every decompiled `.java`-like file under `decompiled_app_dir` and every dir in `decompiled_lib_dirs`.
2. For each file, compute a `relevance_score` = count of distinct matches (path-based + content-based, below), and a `category_hints` list of which categories it's relevant to.
   - **Path/filename match** (case-insensitive substring): `Controller`, `Security`, `Auth`, `Filter`, `Config`, `Crypto`, `Encrypt`, `Password`, `Token`, `Jwt`, `Session`, `Repository`, `Dao`, `Service`, `Upload`, `Serial`, `Deserial`, `Xml`, `Ldap`.
   - **Package path contains**: `security`, `auth`, `config`, `crypto`, `filter`, `web`, `controller`, `rest`.
   - **Content keyword match** (grep, not LLM) against `CATEGORY_KEYWORDS`:

     | category_hint | keywords (any match adds the hint + 1 to relevance_score) |
     |---|---|
     | `injection` | `PreparedStatement`, `Statement.execute`, `createStatement`, `@Query`, `EntityManager`, `Runtime.exec`, `ProcessBuilder`, `DocumentBuilder`, `SAXParser`, `XPath` |
     | `authn_authz` | `@PreAuthorize`, `@Secured`, `HttpSecurity`, `WebSecurityConfigurerAdapter`, `SecurityFilterChain`, `PasswordEncoder`, `BCrypt`, `Jwts.`, `jwt`, `UserDetailsService` |
     | `crypto_secrets` | `MessageDigest`, `Cipher.getInstance`, `KeyGenerator`, `SecureRandom`, `new Random`, `@Value(`, `System.getenv` |
     | `deserialization_upload` | `ObjectInputStream`, `readObject`, `XMLDecoder`, `MultipartFile`, `FileOutputStream`, `Files.write` |
     | `config_logging` | `Logger`, `@ConfigurationProperties`, `.properties`, `.yml` |
   - A file with `relevance_score == 0` is excluded from triage entirely (not fed to the LLM at all), but still counted in `class_count` and listed in the Appendix as structurally scanned but not deep-reviewed.
3. Sort remaining files by `relevance_score` descending, then by file size ascending (prefer including more distinct relevant classes over exhaustively including a few huge ones).
4. Take files in that order until **either** `max_classes` files are taken **or** the running sum of (possibly per-file-truncated) character counts would exceed `max_total_chars` — whichever bound is hit first. Any file whose own source exceeds 4,000 characters is truncated to its first 4,000 characters plus a literal `"\n[TRUNCATED]"` marker (and `truncated=True`), before being counted toward `max_total_chars`.
5. Each `review_*` node (below) receives only the subset of `triaged_chunks` whose `category_hints` includes its category, further capped per call at `per_category_max_chars` total characters (take chunks in the same relevance-sorted order until the per-category cap is hit) — this is the hard bound that keeps any single LLM call bounded regardless of how large `triaged_chunks` is overall.
6. `review_dependencies` does not consume `triaged_chunks` at all — it is given only `state["dependencies"]` (names/versions, no source code).

This heuristic and its constants (`AGENT_TRIAGE_MAX_CLASSES=60`, `AGENT_TRIAGE_MAX_CHARS=150000`, `AGENT_TRIAGE_PER_CATEGORY_MAX_CHARS=30000`) are the concrete cost-control mechanism required by `spec/roadmap.md`; the Phase 1 integration gate specifically uses a fixture JAR with more classes than `max_classes` to prove this bound is real (`harness/patterns/test-driven.md` — data-processing gates must exceed the sampling threshold).

---

## Nodes / Steps

### `decompile`

**Reads from state:** `jar_path`, `scan_id`
**Writes to state:** `extract_dir`, `decompiled_app_dir`, `decompiled_lib_dirs`, `is_spring_boot`, `has_spring_security`, `spring_evidence`, `class_count`, `decompile_errors`, `config_file_paths`, `error`
**LLM call:** no
**External calls:**

| System | Operation | On Failure |
|--------|-----------|------------|
| Local filesystem | `unpack_jar` | Fatal — invalid/corrupt/empty file → `error` set, routes to `handle_error` |
| CFR subprocess (`java -jar cfr-<version>.jar`) | `decompile_classes`, once for app classes + once per nested lib jar | Per-component: caught, appended to `decompile_errors`, that component's classes are simply absent from `decompiled_*` (partial, non-fatal) — unless **zero** classes decompile successfully anywhere, which is fatal |

**Behaviour:** writes `current_phase="decompiling"` to the DB immediately on entry (see Progress Reporting below), unpacks the JAR, runs `detect_spring`, decompiles the app-classes component and every nested lib jar (a plain, non-Boot JAR has no nested jars — it's decompiled directly as the single "app" component), and collects every per-component decompile error without aborting the whole scan unless nothing decompiled at all.

### `scan_dependencies`

**Reads from state:** the `UnpackResult`-shaped fields written by `decompile`
**Writes to state:** `dependencies`
**LLM call:** no
**External calls:** none (pure function over the unpacked tree)
**Behaviour:** writes `current_phase="scanning_dependencies"`, calls `extract_dependencies`.

### `scan_secrets`

**Reads from state:** `decompiled_app_dir`, `decompiled_lib_dirs`, `config_file_paths`
**Writes to state:** `secret_findings`
**LLM call:** no
**External calls:** none
**Behaviour:** writes `current_phase="scanning_secrets"`, applies the fixed regex pattern table to every decompiled file and every config file's text.

### `extract_config`

**Reads from state:** `config_file_paths`
**Writes to state:** `config_files`
**LLM call:** no
**External calls:** none
**Behaviour:** writes `current_phase="extracting_config"`, reads each config path as text.

### `triage`

**Reads from state:** `decompiled_app_dir`, `decompiled_lib_dirs`
**Writes to state:** `triaged_chunks`
**LLM call:** no
**External calls:** none
**Behaviour:** writes `current_phase="triaging"`, applies the Triage Heuristic above.

### `review_injection` / `review_authn_authz` / `review_crypto_secrets` / `review_deserialization_upload` / `review_config_logging` / `review_dependencies`

**Reads from state:** `triaged_chunks` (filtered to that node's category — except `review_dependencies`, which reads `dependencies`), `is_spring_boot`, `has_spring_security`, `secret_findings` (only `review_crypto_secrets`), `config_files` (only `review_config_logging`)
**Writes to state:** appends to `raw_findings`, appends to `token_usage`
**LLM call:** yes — one call per node (see LLM Provider & Model table). System prompt = that category's fixed rules file under `src/prompts/` (`review_injection.md`, `review_authn_authz.md`, `review_crypto_secrets.md`, `review_deserialization_upload.md`, `review_config_logging.md`, `review_dependencies.md`); user message = the filtered/capped chunks (or dependency list) serialized with file-path headers. Every prompt hard-codes: never invent a finding; every finding must cite `evidence` verbatim from the supplied text; if genuinely nothing is found for this category, return exactly one `Finding`-shaped entry with `no_evidence_marker=True`, `title="No evidence found."`, `severity="Informational"`, `confidence="High"`; state confidence explicitly and lower it rather than omit uncertainty. Output requested as a raw JSON array of `Finding` objects (no prose wrapper) — parsed strictly; a parse failure is a node-level error (Phase 1: fatal to the scan).
**External calls:**

| System | Operation | On Failure |
|--------|-----------|------------|
| Anthropic API | `LLMClient.call_model(prompt, system=...)` | Fatal in Phase 1 (`error` set, routes to `handle_error`); retried + degraded in Phase 3 |

**Behaviour:** each node writes `current_phase="reviewing_<category>"` (e.g. `reviewing_injection`) on entry, builds its category-scoped prompt from triaged data, calls Claude, parses the JSON array into `Finding` objects tagged with `category_source=<this node's name>`, appends them (and the call's token usage) to state, and passes through unchanged otherwise. `review_authn_authz` additionally skips Spring-Security-specific sub-checks (filter chain config, `@PreAuthorize` coverage, CSRF config) — rather than emitting "No evidence found." for them — when `has_spring_security` is `False`, per the Spring-detection gating requirement; it still runs the generic authN/authZ/JWT checks regardless of framework.

**Ordering:** these six nodes run **sequentially** (not parallel fan-out) — a deliberate simplicity choice: it keeps `current_phase` progress deterministic and single-valued for the polling UI, and avoids LangGraph's parallel-branch state-merge/reducer complexity for a Phase-1 scope where "a scan takes a few minutes" is explicitly acceptable. Parallelizing them is a valid future latency optimization, not a Phase 1 requirement.

### `verify_findings`

**Reads from state:** `raw_findings`
**Writes to state:** `verified_findings`, appends to `token_usage`
**LLM call:** yes — one call (may internally batch across multiple Anthropic calls if `raw_findings` is large enough to exceed a single context-safe batch, using the same `per_category_max_chars`-style budget applied to the serialized findings-plus-evidence payload; batches are merged before writing `verified_findings`). System prompt = `src/prompts/verify_findings.md`: for each non-`no_evidence_marker` finding, re-examine `evidence` and `code_snippet` and decide **keep** (mark `verified=True`), **downgrade** (lower `severity`/`confidence`, `verified=True`, `verification_note` explains why), or **drop** (`verified=False`, excluded from the report, `verification_note` explains why) — a finding must never appear in the final report without this pass having explicitly kept or downgraded it. `no_evidence_marker` entries pass through unchanged (`verified=True`).
**External calls:** Anthropic API, same failure handling as the review nodes.
**Behaviour:** writes `current_phase="verifying"` on entry; this is the Reflection (#4) step — it is the sole gate between "the model claimed a vulnerability" and "the report states a vulnerability."

### `assemble_report`

**Reads from state:** `verified_findings`, `dependencies`, `secret_findings`, `class_count`, `triaged_chunks`, `decompile_errors`, `is_spring_boot`, `has_spring_security`, `spring_evidence`, `token_usage`
**Writes to state:** `risk_score`, `total_input_tokens`, `total_output_tokens`, `estimated_cost_usd`, `report_markdown`
**LLM call:** no — deterministic assembly only, for testability (`harness/patterns/test-driven.md`: assert the computed value, not a proxy).
**External calls:** none
**Behaviour:** writes `current_phase="assembling_report"`; computes:
- `risk_score = min(100, 10*count(Critical) + 6*count(High) + 3*count(Medium) + 1*count(Low))` over `verified_findings` where `verified=True and not no_evidence_marker` (Informational contributes 0); rendered with a band label: 80-100 Critical Risk, 60-79 High Risk, 35-59 Medium Risk, 15-34 Low Risk, 0-14 Minimal Risk.
- token/cost totals by summing `token_usage` and applying the pricing table (`src/llm/pricing.py`, see Cost Accounting below).
- buckets `verified_findings` into every required report section by `owasp_category`, `stride_category`, and `category_source` (Dependency Vulnerabilities ← `category_source="review_dependencies"`; Sensitive Data Exposure ← secret-scan findings + `review_crypto_secrets` findings tagged as data-exposure; Authentication Issues / Authorization Issues ← `review_authn_authz` findings split by whether the finding's `owasp_category`/title concerns identity verification vs. permission enforcement; Cryptography Issues ← `review_crypto_secrets`; Injection Issues ← `review_injection`; Configuration Issues / Logging Issues ← `review_config_logging` split by topic).
- renders the exact required Markdown structure (below), including the Severity Summary / OWASP Summary / STRIDE Summary / Dependency Summary tables and the Priority 1-4 Developer Fix Roadmap (Priority 1 = Critical, 2 = High, 3 = Medium, 4 = Low/Informational, ordered within each priority by `risk_score` contribution).
- Appendix explicitly states: total classes scanned (`class_count`) vs. classes deep-reviewed (`len(triaged_chunks)`), any `decompile_errors`, the Spring-detection evidence, and the fixed disclaimer that dependency-vulnerability findings are Claude's evidence-based reasoning over the extracted dependency list, **not** a live CVE database query.

#### Required Report Structure (verbatim section order)

```
# Executive Summary
# Risk Score
# Severity Dashboard
# OWASP Top 10 Findings
# STRIDE Findings
# Dependency Vulnerabilities
# Sensitive Data Exposure
# Authentication Issues
# Authorization Issues
# Cryptography Issues
# Injection Issues
# Configuration Issues
# Logging Issues
# Secure Coding Recommendations
# Developer Remediation Plan
# Appendix
```

Every individual finding, wherever it appears, is rendered with all 20 fields: Title, Severity, CVSS Score, OWASP Category, STRIDE Category, CWE ID, Affected Classes, Affected Methods, Description, Business Impact, Technical Impact, Attack Scenario, Evidence, Code Snippet, Why it is vulnerable, How attacker can exploit, Recommended Fix, Secure Code Example, References, Confidence Level.

### `handle_error`

**Reads from state:** `error`, `scan_id`
**Writes to state:** `status="failed"`
**Behaviour:** writes the DB row's `status="failed"`, `error_message=state["error"]`, `current_phase="failed"`; logs the error with `scan_id` context; terminates the graph.

### `finalize`

**Reads from state:** everything assembled by `assemble_report`
**Writes to state:** `status="completed"`
**Behaviour:** writes the DB row's `status="completed"`, `current_phase="completed"`, and persists `report_markdown`, `risk_score`, `findings_json` (serialized `verified_findings`), token/cost totals.

---

## Graph / Flow Topology

```
START
  │
  ▼
decompile ──(error)──► handle_error ──► END
  │
  ▼
scan_dependencies ──(error)──► handle_error
  │
  ▼
scan_secrets ──(error)──► handle_error
  │
  ▼
extract_config ──(error)──► handle_error
  │
  ▼
triage ──(error)──► handle_error
  │
  ▼
review_injection ──(error)──► handle_error
  │
  ▼
review_authn_authz ──(error)──► handle_error
  │
  ▼
review_crypto_secrets ──(error)──► handle_error
  │
  ▼
review_deserialization_upload ──(error)──► handle_error
  │
  ▼
review_config_logging ──(error)──► handle_error
  │
  ▼
review_dependencies ──(error)──► handle_error
  │
  ▼
verify_findings ──(error)──► handle_error
  │
  ▼
assemble_report ──(error)──► handle_error
  │
  ▼
finalize ──► END

handle_error ──► END
```

**Conditional edges:** every node above transitions via the same predicate — `lambda s: "handle_error" if s.get("error") else "<next node>"` — implemented as one reusable `after(next_node_name)` edge-function factory in `src/graph/edges.py`, not fourteen bespoke functions.

| Source node | Condition | Target |
|-------------|-----------|--------|
| every node except `handle_error`/`finalize` | `state.get("error")` is not `None` | `handle_error` |
| every node except `handle_error`/`finalize` | otherwise | the next node in pipeline order (above) |

---

## Memory & Context

| Scope | Mechanism | What is stored |
|-------|-----------|----------------|
| **Within a run** | LangGraph state (`ScanState`) | All pipeline data for one scan — decompile output paths, findings, token usage, the assembled report. |
| **Across runs** | SQLite `scans` table | One row per completed/failed scan: metadata, final report, findings JSON, cost totals. No cross-scan state is read back into a new scan's pipeline in Phase 1. |
| **Conversation** | None in Phase 1 (one-shot: upload → report, no chat surface exists yet). Phase 2 adds a `chat_messages` table and a small follow-up-chat graph that reads the full prior-turn history for that scan's session on every new turn (Memory Management, `harness/patterns/agentic-ai.md` #8) — see `spec/roadmap.md` Phase 2. |

**Context window management:** the Triage Heuristic + per-category character caps (above) are the context-management mechanism — no summarization or RAG is needed because the input volume is bounded at the source by triage, not by truncating an already-oversized prompt.

---

## Human-in-the-Loop Checkpoints

None. This is a fully automated, one-shot pipeline (upload → report) with no approval gate — appropriate for a read-only, non-destructive security-review tool with no side effects on the scanned system.

---

## Error Handling & Recovery

**Node-level:** every node catches its own tool/LLM exceptions (decompile/analysis nodes catch per-item where the item-level failure is genuinely non-fatal, per the Tools table above); any exception that escapes item-level handling sets `state["error"] = str(exc)` and the node returns normally (never re-raises past the graph) so the conditional edge can route to `handle_error`.

**Graph-level (`handle_error` node):**
- Reads: `state["error"]`, `state["scan_id"]`
- Updates DB: `status="failed"`, `error_message`, `current_phase="failed"`
- Logs the error with `scan_id` context via `structlog`
- Terminates the graph

**Resume / retry strategy (Phase 1):** none — a failed scan must be re-uploaded from scratch. No checkpoint resume in Phase 1 (the pipeline is not long-running enough relative to a full re-scan's cost to justify resume complexity at this scope).

**Partial failure:** decompile and secret-scan failures are itemized and non-fatal (see Tools table); every other node's failure is fatal to the scan in Phase 1. Phase 3 (`spec/roadmap.md`) adds degraded-mode continuation for a single failed review category instead of whole-scan failure.

---

## Observability

| Signal | What | Where |
|--------|------|-------|
| **Trace** | One trace per scan, one span per node | LangSmith (`LANGCHAIN_TRACING_V2=true`, `LANGCHAIN_API_KEY` from `.env`) — wired in Phase 1, not deferred |
| **LLM calls** | Prompt tokens, completion tokens, latency, model, category | LangSmith + structured `structlog` JSON line per call (`event="llm_call", node=..., input_tokens=..., output_tokens=..., latency_ms=..., model=...`) |
| **Tool calls** | Decompile/analysis step name, duration, item-level success/error counts | Structured log (`event="tool_call", tool=..., scan_id=..., duration_ms=..., errors=[...]`) |
| **Scan outcome** | Status, total duration, phase reached, error if any | SQLite `scans` row + structured log line on `finalize`/`handle_error` |

## Progress Reporting (how the API exposes live phase state)

Because each node runs synchronously inside a single Python call to `agentic_ai.invoke(...)` (itself run inside a background thread spawned by `POST /scans`), fine-grained progress cannot come from LangGraph's return value alone — a caller polling the API would see nothing until the whole graph finishes. Every node therefore performs a **side-effect DB write at the start of its work** (`current_phase`, and for the six review nodes, `current_detail` = the category name) via a `create_db_session()` call, **before** doing its actual work — not just returning it as part of the final state. The `GET /scans/{id}/status` endpoint (`spec/api.md`) simply reads the current DB row; it never talks to the running graph directly. This is a deliberate, documented deviation from "nodes are pure functions" for the sole purpose of live progress visibility, and is scoped to exactly one `UPDATE` statement per node (plus one for `handle_error`/`finalize`).

`current_phase` values (in pipeline order): `queued` (written synchronously by `POST /scans` before the background thread starts; the pipeline's own first write immediately replaces it with `decompiling`), `decompiling`, `scanning_dependencies`, `scanning_secrets`, `extracting_config`, `triaging`, `reviewing_injection`, `reviewing_authn_authz`, `reviewing_crypto_secrets`, `reviewing_deserialization_upload`, `reviewing_config_logging`, `reviewing_dependencies`, `verifying`, `assembling_report`, `completed`, `failed`. The UI groups these into the 8 user-facing macro-phases (Decompiling / Dependency Scan / Secret Scan / Config Extraction / Triage / LLM Security Review / Verification / Report Generation) via a fixed lookup table documented in `spec/ui.md`.

---

## Cost Accounting

`src/llm/pricing.py` holds a hardcoded, versioned, **approximate** pricing table (`AGENT_PRICING_TABLE_VERSION`, default `"2026-07"`):

```python
PRICING_USD_PER_MTOK = {
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-opus-4-8": {"input": 15.00, "output": 75.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
}
```
> **Assumed:** these per-million-token USD figures are a reasonable-current approximation at spec-writing time, not fetched live — verify against Anthropic's published pricing page before relying on them for real budgeting, and bump `AGENT_PRICING_TABLE_VERSION` (and this table) when they change. The report's cost footer must state "(estimated, approximate pricing)" for exactly this reason.

`estimated_cost_usd = sum over every TokenUsageEntry of (input_tokens/1_000_000 * price["input"] + output_tokens/1_000_000 * price["output"])`, computed in `assemble_report`. Every LLM call site (`LLMClient.call_model`) must return `(text, input_tokens, output_tokens, model)` — extending the existing skeleton's `AnthropicProvider.call_model`, which currently discards usage — so the pipeline can accumulate it. `GeminiProvider.call_model` is updated to the same return-shape for interface consistency (returning `input_tokens=0, output_tokens=0` since this project never selects Gemini); not exercised by this project's tests.

```python
# src/llm/client.py — extended contract (pinned)
class LLMResult(TypedDict):
    text: str
    input_tokens: int
    output_tokens: int
    model: str

class LLMClient:
    def call_model(self, prompt: str, *, system: str | None = None) -> LLMResult: ...
```

---

## Concurrency Model

- **Run isolation:** one scan at a time — `POST /scans` checks for any `scans` row with `status="processing"` and returns `409 Conflict` if found, rather than queueing or interleaving. This matches the "single-user, ad hoc" usage model and avoids needing a job queue.
- **Parallel nodes within a run:** none in Phase 1 — the six review nodes run sequentially by design (see `review_*` Behaviour → Ordering above), for deterministic single-valued progress reporting and to avoid LangGraph state-merge complexity at this scope.
- **Checkpointing:** none (`MemorySaver`/`SqliteSaver` not used) — no human-in-the-loop pause exists, and Phase 1 has no resume requirement (see Error Handling → Resume/retry strategy).

---

## Graph Assembly (`src/graph/agent.py`)

```python
from langgraph.graph import StateGraph, END

from graph.state import ScanState
from graph.nodes import (
    decompile, scan_dependencies, scan_secrets, extract_config, triage,
    review_injection, review_authn_authz, review_crypto_secrets,
    review_deserialization_upload, review_config_logging, review_dependencies,
    verify_findings, assemble_report, handle_error, finalize,
)
from graph.edges import after

_PIPELINE = [
    ("decompile", decompile),
    ("scan_dependencies", scan_dependencies),
    ("scan_secrets", scan_secrets),
    ("extract_config", extract_config),
    ("triage", triage),
    ("review_injection", review_injection),
    ("review_authn_authz", review_authn_authz),
    ("review_crypto_secrets", review_crypto_secrets),
    ("review_deserialization_upload", review_deserialization_upload),
    ("review_config_logging", review_config_logging),
    ("review_dependencies", review_dependencies),
    ("verify_findings", verify_findings),
    ("assemble_report", assemble_report),
]

def _build_graph() -> StateGraph:
    g = StateGraph(ScanState)
    for name, fn in _PIPELINE:
        g.add_node(name, fn)
    g.add_node("handle_error", handle_error)
    g.add_node("finalize", finalize)

    g.set_entry_point(_PIPELINE[0][0])
    for (name, _), (next_name, _) in zip(_PIPELINE, _PIPELINE[1:]):
        g.add_conditional_edges(name, after(next_name), {next_name: next_name, "handle_error": "handle_error"})
    g.add_conditional_edges(
        _PIPELINE[-1][0], after("finalize"), {"finalize": "finalize", "handle_error": "handle_error"}
    )
    g.add_edge("finalize", END)
    g.add_edge("handle_error", END)
    return g.compile()

agentic_ai = _build_graph()
```

```python
# src/graph/edges.py
from graph.state import ScanState

def after(next_node: str):
    def _edge(state: ScanState) -> str:
        return "handle_error" if state.get("error") else next_node
    return _edge
```
