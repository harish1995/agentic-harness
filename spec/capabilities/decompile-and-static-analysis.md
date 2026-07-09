# Capability: Local Decompilation & Static Analysis

## What It Does

Unpacks and locally decompiles the uploaded JAR (handling plain JARs, Spring Boot fat JARs with nested `BOOT-INF/lib/*.jar`, and vendor bytecode-only JARs), then runs deterministic static analysis — dependency extraction, secret-pattern scanning, config-file surfacing, and security-relevant-class triage — entirely on the local machine, before any LLM call is made.

## Inputs

| Input | Type | Source | Required |
|-------|------|--------|----------|
| `jar_path` | local file path | The stored upload from the JAR Upload & Validation capability | yes |

## Outputs

| Output | Type | Destination |
|--------|------|-------------|
| Decompiled source tree | files | Local disk only (path pinned in `spec/data.md`) |
| `is_spring_boot`, `has_spring_security`, `class_count`, `decompile_errors` | scalar/list | `ScanState` (`spec/agent.md`), persisted to the `Scan` row |
| `dependencies: list[DependencyInfo]` | list | `ScanState`, persisted as `dependencies_json` |
| `secret_findings: list[SecretFinding]` | list | `ScanState` (feeds the `review_crypto_secrets` LLM node; count persisted as `secret_findings_count`) |
| `config_files: dict[str, str]` | dict | `ScanState` (feeds the `review_config_logging` LLM node) |
| `triaged_chunks: list[TriagedChunk]` | list | `ScanState`, persisted count as `triaged_class_count` |

## External Calls

| System | Operation | On Failure |
|--------|-----------|------------|
| Local decompiler (the specific tool is pinned in `spec/architecture.md`) | Decompile app classes / each nested lib jar | Per-component: collected in `decompile_errors`, non-fatal, that component's classes are absent from further analysis; zero successful components is fatal (scan marked `failed`) |
| Local filesystem | Unpack JAR, read config files, walk decompiled tree | Fatal for a genuinely corrupt/unreadable archive; per-file read errors during config extraction are recorded as `"<binary or unreadable>"`, non-fatal |

No LLM/network calls in this capability — the entire decompile + static-analysis + triage stage is local and deterministic (`spec/architecture.md` → Data Residency).

## Business Rules

- Spring Boot detection is heuristic and multi-signal (`spec/agent.md` → `detect_spring`); when a JAR is not Spring, `has_spring_security` is `False` and Spring-Security-specific checks are **skipped**, not filled with "No evidence found." (the distinction matters: skipped means "not applicable," not "checked, found nothing").
- Dependency extraction never requires a live network lookup — it parses `MANIFEST.MF`, nested-jar filenames, and embedded `pom.properties` only.
- The secret-scanning pattern table (`spec/agent.md` → `scan_secrets`) is fixed and applied uniformly; every match is redacted (first 4 / last 4 characters) before being stored anywhere — the raw secret value is never persisted or logged.
- Triage is a hard bound, not a suggestion: at most `AGENT_TRIAGE_MAX_CLASSES` (60) classes and `AGENT_TRIAGE_MAX_CHARS` (150,000 characters) total ever become eligible for any LLM call, selected by the concrete relevance-scoring heuristic in `spec/agent.md`, never a naive "first N classes."
- A decompile error on one class or one nested jar never aborts the scan — it is recorded and the scan proceeds with everything that did decompile.

## Success Criteria

- [ ] A real Spring Boot fat JAR (BOOT-INF/classes + BOOT-INF/lib nested jars) unpacks and decompiles both the app classes and every nested lib jar.
- [ ] A plain (non-Boot) JAR and a vendor bytecode-only JAR both decompile via the same pipeline without special-casing failure.
- [ ] `is_spring_boot=False` on a non-Spring JAR results in the Spring-Security-specific sub-checks being skipped in the review stage, not rendered as "No evidence found."
- [ ] On a fixture JAR with more classes than `AGENT_TRIAGE_MAX_CLASSES`, `len(triaged_chunks) <= AGENT_TRIAGE_MAX_CLASSES` while `class_count` reflects the true total, and known security-relevant fixture classes are included while known plain-POJO fixture classes are excluded (the data-processing gate test, `spec/roadmap.md` Phase 1 gate item 4).
- [ ] A secret embedded in a fixture config file or decompiled class is detected, and the persisted `matched_text_redacted` never contains the full raw secret value.
- [ ] A corrupted nested lib jar produces a non-fatal entry in `decompile_errors` and the scan still completes using the app classes and other nested jars.
