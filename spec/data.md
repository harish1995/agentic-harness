# Data Model

---

## Storage Technology

SQLite (`AGENT_DATABASE_URL=sqlite:///./data/agent.db`) via SQLAlchemy 2.0, migrated with Alembic — this is this project's **chosen production database** (single-user, local, ad hoc tool), not a substitute for anything larger; see `spec/architecture.md` → Stack. `alembic upgrade head` is still mandatory before first run, per `harness/patterns/project-layout.md`, even though the driver is SQLite.

---

## Entities

### Entity: Scan (`ScanRow`, table `scans`)

One row per uploaded JAR / scan attempt. Replaces the skeleton's `RunRow` entirely (this project's single capability is JAR scanning, not generic text transforms — `runs` table is dropped, not kept alongside).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | Text (UUID, PK) | yes | Scan identifier, used as `scan_id` everywhere |
| original_filename | Text | yes | The uploaded file's original name, used for the download filename and history display |
| jar_path | Text | yes | Local path to the stored upload (`data/uploads/<id>.jar`) — never transmitted anywhere; local-only |
| uploaded_at | Timestamp (tz-aware) | yes | Set at row creation |
| status | Text | yes | `"processing"` \| `"completed"` \| `"failed"` |
| current_phase | Text | yes | One of the 15 phase values in `spec/agent.md` → Progress Reporting; `"queued"` immediately at row creation before the background thread's first node writes `"decompiling"` |
| current_detail | Text, nullable | no | Free-text detail for the active phase (e.g. which review category, or which nested jar is decompiling) |
| is_spring_boot | Boolean, nullable | no | Set once `decompile` completes |
| has_spring_security | Boolean, nullable | no | Set once `decompile` completes |
| class_count | Integer, nullable | no | Total classes structurally found, set once `decompile` completes |
| triaged_class_count | Integer, nullable | no | `len(triaged_chunks)`, set once `triage` completes |
| decompile_errors_json | Text (JSON array), nullable | no | Per-item decompile errors, if any |
| dependencies_json | Text (JSON array of `DependencyInfo`), nullable | no | Set once `scan_dependencies` completes |
| secret_findings_count | Integer, nullable | no | `len(secret_findings)`, set once `scan_secrets` completes (the raw secret matches themselves are not persisted independently of the findings that reference them, to avoid a second copy of redacted-secret text sitting in a row nobody renders — they flow into `findings_json` via `review_crypto_secrets`) |
| risk_score | Integer, nullable | no | 0-100, set once `assemble_report` completes |
| report_markdown | Text, nullable | no | The full assembled report, set once `assemble_report` completes |
| findings_json | Text (JSON array of `Finding`), nullable | no | `verified_findings`, set once `assemble_report` completes — the structured source the UI dashboards render from (the markdown is for the download, not for driving the UI) |
| total_input_tokens | Integer, nullable | no | Set once `assemble_report` completes |
| total_output_tokens | Integer, nullable | no | Set once `assemble_report` completes |
| estimated_cost_usd | Float, nullable | no | Set once `assemble_report` completes; approximate, see `spec/agent.md` → Cost Accounting |
| error_message | Text, nullable | no | Set only if `status == "failed"` |
| created_at | Timestamp (tz-aware) | yes | Row creation |
| updated_at | Timestamp (tz-aware) | yes | Updated on every progress write (`onupdate`) |

### Relationships

None in Phase 1 — `scans` is a single, self-contained table; there is no separate `findings` table (findings live denormalized inside `findings_json` on the owning scan, since Phase 1 never queries an individual finding independently of its scan). Phase 2 introduces `FindingStatusRow` (accepted-risk/false-positive per finding, keyed by `scan_id` + a finding index/slug within `findings_json`) and `ChatMessageRow` (keyed by `scan_id`, ordered by `created_at`, holding `role` + `content` for the follow-up chat's turn history) — both are additive tables introduced when Phase 2 is built, not part of the Phase 1 schema.

---

## Data Lifecycle

- **Created:** a `scans` row is created synchronously in `POST /scans` (`status="processing"`, `current_phase="queued"`) before the background pipeline thread starts.
- **Updated:** every pipeline node updates `current_phase` (and `current_detail` where applicable) as a side effect at the start of its work (`spec/agent.md` → Progress Reporting); `decompile`, `scan_dependencies`, `triage`, and `assemble_report` additionally populate their respective result columns as they complete.
- **Terminal:** `finalize` sets `status="completed"` and writes the full report/findings/cost columns in one update; `handle_error` sets `status="failed"` and `error_message`.
- **Deleted / archived:** nothing is deleted or archived in Phase 1 — every scan attempt (including failed ones) remains in `scans` indefinitely; there is no retention policy or TTL. `data/uploads/<id>.jar` and `data/decompiled/<id>/` are similarly retained on local disk after the scan completes (not auto-cleaned in Phase 1) so a failed scan can be diagnosed; this is called out as a known future improvement (disk-space cleanup), not a Phase 1 requirement.

---

## Sensitive Data

- **The report itself is the sensitive artifact.** `report_markdown` and `findings_json` contain code snippets, config values, and (redacted) secret excerpts extracted from the **user's own** JAR — this is the user's own source/IP, not third-party PII, but it is still confidential and is kept entirely local in SQLite; it is never transmitted anywhere except back to the same user's browser over `localhost`.
- **Secrets are never persisted in full.** `scan_secrets` (`spec/agent.md`) redacts every matched secret to first-4/last-4 characters before it ever reaches state, the DB, or an LLM prompt — the raw full secret value is discarded at detection time and never written anywhere, including logs.
- **The JAR and decompiled tree never leave the machine** (`spec/architecture.md` → Data Residency) — only the bounded, triaged snippets each LLM call needs are sent to the Anthropic API; `jar_path` and the `data/decompiled/` working tree are local filesystem paths only, never included in any API response.
- **No PII handling concerns beyond the above** — this tool processes Java bytecode/source and config files, not personal data about people, except incidentally if the scanned application's own code/config happens to contain it (e.g. a hardcoded test email address) — such incidental content is treated exactly like any other extracted evidence: kept local, never sent further than the Anthropic API's bounded snippet, and never logged in full for secret-pattern matches.
