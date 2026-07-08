# Capability: Exhaustive LLM Security Review & Verification

## What It Does

Drives Claude through six category-partitioned security review passes (injection; authN/authZ/Spring-Security/JWT; crypto/secrets; deserialization/file-upload; config/logging; dependency vulnerabilities) over the triaged, bounded local evidence, then runs a second LLM-as-judge verification pass that checks every proposed finding against its cited evidence before it is allowed into the final report.

## Inputs

| Input | Type | Source | Required |
|-------|------|--------|----------|
| `triaged_chunks` (category-filtered) | list | Local Decompilation & Static Analysis capability | yes (except the dependency-review pass) |
| `dependencies` | list | Local Decompilation & Static Analysis capability | yes (dependency-review pass only) |
| `secret_findings`, `config_files` | list/dict | Local Decompilation & Static Analysis capability | yes (crypto/secrets and config/logging passes) |
| `is_spring_boot`, `has_spring_security` | bool | Local Decompilation & Static Analysis capability | yes (gates Spring-Security sub-checks) |
| Category-specific system prompts | `.md` files | `src/prompts/review_*.md`, `src/prompts/verify_findings.md` (`spec/agent.md`) | yes |

## Outputs

| Output | Type | Destination |
|--------|------|-------------|
| `raw_findings: list[Finding]` | list | `ScanState`, intermediate (consumed by verification) |
| `verified_findings: list[Finding]` | list | `ScanState`, persisted as `findings_json` on the `Scan` row |
| `token_usage: list[TokenUsageEntry]` | list | `ScanState`, feeds cost accounting (Scan Progress & Report Delivery capability) |

## External Calls

| System | Operation | On Failure |
|--------|-----------|------------|
| LLM provider (Anthropic — model pinned in `spec/agent.md`) | One call per review category (6) + one verification call | Phase 1: fatal — sets `error`, scan marked `failed` with the API error surfaced. Phase 3 (`spec/roadmap.md`): retried with backoff; a persistently failing category degrades to a "Review failed" marker rather than failing the whole scan. |

## Business Rules

- **Never invent a finding.** Every finding must cite `evidence` drawn verbatim from the supplied triaged text or dependency list — this is enforced in both the review prompts and, independently, re-checked by the verification pass.
- **Explicit "No evidence found."** — a category with nothing detected returns a synthetic `Finding` with `no_evidence_marker=True`, `title="No evidence found."`; a category section is never silently empty or omitted from the report.
- **Confidence is always stated**, and low confidence is stated explicitly rather than the finding being upgraded to sound more certain than the evidence supports.
- **The verification pass is mandatory and gating** — a raw finding only reaches `verified_findings` if the verification pass explicitly kept it (unchanged) or downgraded it (lower severity/confidence, with a note); a finding it decides to drop never appears in the report, and the reason is recorded (`verification_note`) even though it isn't shown to the user, for auditability during development.
- **Spring-Security gating**: `review_authn_authz` skips Spring-Security-specific sub-checks entirely when `has_spring_security=False`, rather than emitting "No evidence found." for a framework that isn't present.
- **Cost is bounded by construction**, not by luck: each review call only ever receives its category's triaged/capped subset (`spec/agent.md` → Triage Heuristic step 5), never the full triaged set and never the full decompiled tree.

## Success Criteria

- [ ] All 6 category-review nodes plus the verification node run and each successful category-review call's output is JSON-parsed into `Finding` objects without a schema violation.
- [ ] Every category defined in the required report structure has at least one entry in the final report — either real findings or an explicit "No evidence found." — never a missing section.
- [ ] A finding present in `raw_findings` whose evidence does not actually support it (tested with a deliberately weak/contradictory fixture) is downgraded or dropped by the verification pass, and never appears unchanged in `verified_findings`.
- [ ] On a non-Spring-Security fixture JAR, no Spring-Security-specific finding or "No evidence found." placeholder for a Spring-Security sub-check appears in the authN/authZ section.
- [ ] `token_usage` contains one entry per successful LLM call (7 entries in the fully-successful case) with non-zero `input_tokens`/`output_tokens`.
