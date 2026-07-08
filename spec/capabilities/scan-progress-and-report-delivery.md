# Capability: Scan Progress & Report Delivery

## What It Does

Exposes live phase-by-phase scan progress to the UI while the pipeline runs, and, once complete, assembles and delivers one structured, dashboarded Markdown security report with a downloadable file and a token/cost summary.

## Inputs

| Input | Type | Source | Required |
|-------|------|--------|----------|
| `verified_findings`, `dependencies`, `secret_findings`, `class_count`, `triaged_chunks`, `decompile_errors`, `is_spring_boot`, `has_spring_security`, `spring_evidence` | various | Local Decompilation & Static Analysis + Exhaustive LLM Security Review capabilities | yes (report assembly) |
| `token_usage` | list | Exhaustive LLM Security Review capability | yes (cost accounting) |
| `current_phase`, `current_detail`, `status` | scalar | Written by every pipeline node as a side effect (`spec/agent.md` → Progress Reporting) | yes (progress polling) |

## Outputs

| Output | Type | Destination |
|--------|------|-------------|
| `{status, current_phase, ...}` | JSON | `GET /scans/{id}/status` response, polled every 2s by the UI (`spec/api.md`) |
| `risk_score`, `report_markdown`, `findings_json`, `total_input_tokens`, `total_output_tokens`, `estimated_cost_usd` | scalar/text | `Scan` row (`spec/data.md`), returned by `GET /scans/{id}` |
| Downloadable `.md` file | file | `GET /scans/{id}/download` (`spec/api.md`) |
| Rendered report UI | HTML/React | Report screen (`spec/ui.md`) — dashboards, syntax-highlighted evidence, cost footer, download button |

## External Calls

| System | Operation | On Failure |
|--------|-----------|------------|
| Database | Write progress on every node transition; write final report/findings/cost on completion | A write failure here is a genuine internal error (500) — the scan's actual work already succeeded, so this is logged loudly, not silently swallowed |

No LLM/network calls in this capability — report assembly and progress reporting are deterministic (`spec/agent.md` → `assemble_report` Behaviour).

## Business Rules

- **Risk score is deterministic and testable**: `min(100, 10*Critical + 6*High + 3*Medium + 1*Low)` over verified, non-`no_evidence_marker` findings — never LLM-generated, so it is reproducible and assertable in a test.
- **The exact required report section order is non-negotiable** (`spec/agent.md` → Required Report Structure) — Executive Summary through Appendix, in that order, every time.
- **The dependency-CVE-reasoning limitation is always disclosed** — both in the Dependency Summary table caption and restated in the Appendix — since it is model reasoning, not a live CVE database query (`spec/architecture.md`).
- **Progress is never faked** — `current_phase` reflects the actual node executing right now (written as a side effect at that node's start), never a simulated/interpolated progress bar (`harness/patterns/ui-ux.md` → Honesty).
- **Cost is always labelled approximate** — the pricing table is a hardcoded, versioned estimate (`spec/agent.md` → Cost Accounting), and the UI states "(approximate)" next to the cost figure, never presenting it as an exact bill.
- **The download always matches what's rendered** — `report_markdown` is generated once by `assemble_report` and never regenerated or re-rendered differently between the API response and the download endpoint; both serve the exact same persisted string.

## Success Criteria

- [ ] Polling `GET /scans/{id}/status` during a real scan shows `current_phase` advancing through the pipeline order in `spec/agent.md`, never stuck or skipping backwards.
- [ ] A completed scan's `GET /scans/{id}` response contains `report_markdown` with all 16 required top-level section headers present, in the required order.
- [ ] `risk_score` matches the deterministic formula recomputed independently from the same `findings_json` in a test (not just "some number is present").
- [ ] `GET /scans/{id}/download` returns a `text/markdown` body byte-identical to the `report_markdown` field from `GET /scans/{id}`.
- [ ] `total_input_tokens`/`total_output_tokens`/`estimated_cost_usd` are non-zero after a real scan and `estimated_cost_usd` matches `sum(tokens * pricing table)` recomputed independently in a test.
- [ ] The Report screen renders the Severity/OWASP/STRIDE/Dependency tables as real UI components (assertable by an automated E2E check), not raw markdown text.
