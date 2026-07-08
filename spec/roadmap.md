# Roadmap

---

## What This Agent Does

A local-first, AI-powered security scanner for Java/Spring Boot JAR files. A solo AppSec-minded developer drags a `.jar` onto a web UI; the agent decompiles it entirely on the local machine, runs deterministic static analysis (dependency extraction, secret scanning, config-file surfacing), then drives an exhaustive, evidence-based Claude security review across every mandated category (OWASP Top 10 2021, STRIDE, CWE, CVSS v3.1, Spring Security, authN/authZ, injection classes, deserialization, file upload, crypto, secrets, config, logging, dependency CVEs) with a verification pass before assembling one structured Markdown report. The user watches phase-by-phase progress, then reads the report in a dashboarded UI, downloads it as `.md`, and sees token/cost spent.

## Who Uses It

A single AppSec-minded developer, ad hoc, scanning **their own** Spring Boot / Java JARs for a defensive code-review pass before shipping or as a periodic self-audit. Not a multi-tenant service, not a tool for scanning third-party or adversarial targets.

## Core Problem Being Solved

Manually auditing a Spring Boot fat JAR for security issues (dependency CVEs, hardcoded secrets, injection points, misconfigured auth, weak crypto) requires decompiling it, reading through hundreds of classes, and cross-referencing OWASP/CWE/CVSS by hand — slow, easy to miss things, and rarely done consistently. This agent automates the decompile → triage → exhaustive review → verify → report pipeline into one upload-and-wait action, while keeping the JAR and its source **entirely local** (only bounded, relevant snippets reach the LLM).

## Success Criteria

- [ ] Uploading a real Spring Boot fat JAR (tens of MB, 1000+ classes) completes a scan end-to-end (decompile → static analysis → LLM review → verify → report) without crashing, in a few minutes.
- [ ] The rendered report contains every required top-level section (Executive Summary through Appendix) and every individual finding carries all 20 required fields (Title through Confidence Level).
- [ ] Categories with zero detected issues explicitly render "No evidence found." — never silently omitted, never invented.
- [ ] Only a bounded, triaged subset of decompiled code/config ever leaves the process boundary to the Anthropic API; the full JAR and all decompiled output stay on the local machine at all times.
- [ ] The UI shows live phase-by-phase progress during the scan and, after completion, total tokens used and estimated cost.
- [ ] An invalid/corrupted/non-JAR upload produces a clear error, never a blank or broken report.

## What This Agent Does NOT Do (Out of Scope)

- No chat/follow-up Q&A on a report in Phase 1 (deferred to Phase 2, with turn-level memory — see below).
- No batch upload or multi-JAR comparison in Phase 1 (deferred to Phase 2).
- No JSON/SARIF export in Phase 1 (deferred to Phase 2).
- No accepted-risk / false-positive tracking across scans in Phase 1 (deferred to Phase 2).
- No scan-history browsing UI in Phase 1 (the DB write is real; the browsing UI is a labelled stub — deferred to Phase 2).
- No live CVE database (NVD/OSV) lookup — dependency vulnerability findings are Claude's evidence-based reasoning over the extracted dependency list, always evidence-and-confidence labelled, never a live network CVE query. This is a permanent, documented limitation (see `spec/architecture.md`), not a phase-2 item.
- No authentication/access control (single-user, local, ad hoc tool).
- No offensive/exploitation tooling of any kind — this is a defensive, read-only static/AI review of a JAR the user owns.
- No editing or patching of the scanned code — the agent only reports and recommends.

## Key Constraints

- **Data residency:** the JAR file and every decompiled artifact stay on the local machine/server. Only bounded, triage-selected code/config snippets are sent to the Anthropic API per LLM call. This is a hard architectural constraint, not a preference — see `spec/architecture.md`.
- **Cost bound:** the agent never feeds the full decompiled output of a 1000+-class JAR to the LLM. A concrete triage heuristic and per-call character budget (see `spec/agent.md`) bound total LLM spend per scan.
- **Correctness over speed:** a scan of a real fat JAR taking a few minutes is acceptable and expected; Phase 1 optimizes for evidence-backed correctness, not latency.
- **Evidence discipline:** every finding must cite evidence (code snippet / config line); a category with nothing detected renders an explicit "No evidence found." line — never omitted, never fabricated.
- **Single scan at a time:** this is a solo, ad hoc tool — one scan runs at a time; a second upload while one is in-flight is rejected with a clear error rather than queued or silently interleaved.
- **Java runtime prerequisite:** the local decompiler (CFR) requires a JDK/JRE on the host — a new, documented prerequisite beyond the base Python/Node stack.

---

## Phases of Development

> **Phasing rationale (read before the per-phase detail):** Phase 1 delivers the complete primary journey — upload → decompile → static analysis → exhaustive LLM review → verification → rendered report — because this project's "smallest testable win" *is* the full pipeline; a partial security review is not a coherent product to hand a user to test. The agentic stack (LangGraph pipeline + reflection/verification node + resource-aware triage + guardrailed prompting + observability) is therefore wired for real in Phase 1, per `harness/patterns/phases.md`'s "agentic stack is wired from day one" rule — there is no smaller agentic skeleton to defer to a later "upgrade" phase. Phase 2 is the single requirements phase (5 capabilities, comfortably over the 3-capability floor) that turns every remaining Phase-1 stub into a real feature — it therefore also satisfies the "Complete Agentic System" milestone from `harness/patterns/phases.md`, including the one genuinely new agentic pattern this project needs (Memory Management, for follow-up chat turn history). Phase 3 is the "Agentic Stack Upgrade + Resilience" phase, placed *after* Phase 2 rather than before it: its job is to harden every external call (Anthropic API, CFR subprocess) with retries/timeouts/degraded-mode handling, and Phase 2 adds new external calls (chat) that also need that hardening — so hardening after both requirements phases covers 100% of the system's external calls instead of only Phase 1's. This ordering is an explicit, documented deviation from the generic N+1-before-N+2 ladder in `harness/patterns/phases.md`, justified by that file's own flexibility clause ("what varies: names/count of requirements phases").

### Phase 1 — Upload, Scan, and Get Your Security Report

- **Goal:** upload a real Spring Boot fat JAR through the web UI, watch live phase-by-phase progress, and receive one complete, evidence-backed, dashboarded Markdown security report — the full primary journey, real end-to-end, first-time-right.

- **Independent slices (parallel build units):** every slice below builds against the pinned contracts in `spec/agent.md` (Internal Module Contracts) and `spec/api.md` (API contract) — no slice blocks on another slice's code being written first.
  - `decompiler` (backend) — unpacking (plain JAR / Spring Boot fat JAR with `BOOT-INF/classes` + `BOOT-INF/lib/*.jar`) and CFR invocation. Deps: none (builds to the pinned `unpack_jar`/`decompile_classes` signatures in `spec/agent.md`).
  - `static-analysis` (backend) — Spring detection, dependency extraction, secret scanning, config-file surfacing, triage/chunking. Deps: none (builds to the pinned `spec/agent.md` signatures; tests use fixture decompiled-directory trees, not a live decompile).
  - `graph-and-llm-pipeline` (backend) — LangGraph state/nodes/edges/assembly/runner, the extended `LLMClient` (token-usage-returning), the pricing/cost module, all category-review + verification prompts. Deps: none to *start* (calls the pinned decompiler/static-analysis signatures); integration verified once all three backend slices land.
  - `api-and-db` (backend) — `ScanRow` model + Alembic migration, `/scans` endpoints, request/response domain models. Deps: none to *start* (calls the pinned `run_scan()` signature and `ScanRow` schema from `spec/agent.md` / `spec/data.md`).
  - `upload-progress-ui` (frontend) — upload screen (drag-and-drop), progress screen (phase stepper + polling). Deps: none (builds to the pinned API contract in `spec/api.md`).
  - `report-dashboard-ui` (frontend) — report screen: dashboards, syntax-highlighted findings, download button, cost footer, labelled stubs for history/export/chat/risk-tracking/comparison, plus the Playwright E2E smoke test. Deps: none (builds to the pinned API contract and `Finding` JSON shape in `spec/api.md`).

- **Key surfaces / files:**
  - `decompiler`: `src/decompile/unpack.py`, `src/decompile/cfr.py`, `tests/unit/decompile/`
  - `static-analysis`: `src/analysis/spring_detect.py`, `src/analysis/dependencies.py`, `src/analysis/secrets.py`, `src/analysis/config_files.py`, `src/analysis/triage.py`, `tests/unit/analysis/`
  - `graph-and-llm-pipeline`: `src/graph/state.py`, `src/graph/nodes.py`, `src/graph/edges.py`, `src/graph/agent.py`, `src/graph/runner.py`, `src/llm/client.py`, `src/llm/providers/anthropic.py`, `src/llm/pricing.py`, `src/prompts/*.md`, `tests/unit/graph/`, `tests/integration/test_scan_pipeline.py`, `tests/fixtures/build_fixture_jar.py`
  - `api-and-db`: `src/db/models.py` (replace `RunRow` with `ScanRow`), `src/domain/scan.py` (replace `src/domain/run.py`), `src/api/scans.py` (replace `src/api/runs.py`), `src/api/__init__.py` (router registration), `alembic/versions/0002_scans.py`, `tests/unit/api/test_scans.py`
  - `upload-progress-ui`: `frontend/src/app/page.tsx`, `frontend/src/components/UploadForm.tsx`, `frontend/src/components/ProgressPanel.tsx`, `frontend/src/lib/api.ts`
  - `report-dashboard-ui`: `frontend/src/components/ReportView.tsx`, `frontend/src/components/SeverityDashboard.tsx`, `frontend/src/components/CategorySummary.tsx`, `frontend/src/components/DependencyTable.tsx`, `frontend/src/components/CodeSnippet.tsx`, `frontend/src/components/FindingCard.tsx`, `tests/e2e/scan-journey.spec.ts`

- **Gate commands (run in order, from repo root, real Anthropic key from `.env`, real local JDK + CFR jar, production DB driver = SQLite):**
  1. `uv sync`
  2. `uv run alembic upgrade head` then `uv run alembic current` (must show a revision hash, not blank)
  3. `uv run pytest tests/unit -v` (no external calls; deterministic)
  4. `uv run pytest tests/integration/test_scan_pipeline.py -v` — runs the real CFR decompiler (via `java -jar tools/cfr-0.152.jar`) against a fixture JAR built by `tests/fixtures/build_fixture_jar.py` (compiled at session scope via `javac`+`jar`, ~90 classes — deliberately more than `AGENT_TRIAGE_MAX_CLASSES=60` so the gate proves triage actually bounds what reaches the LLM, not just that it runs on a tiny fixture that never exercises the cap) and the real Anthropic API; asserts `status == "completed"`, `report_markdown` contains every required top-level section header, every verified finding has all 20 required fields non-empty, at least one category renders "No evidence found.", `len(triaged_chunks) <= 60` while `class_count > 60`, and the fixture's known security-relevant class names appear in the report's affected-classes/Appendix listing while a known plain-POJO class name does not.
  5. `uv run python -m src` (starts the server on `:8001`) — leave running
  6. `cd frontend && pnpm build` (verify the static export builds and the built CSS bundle contains real Tailwind utility selectors, not just `@tailwind` unexpanded)
  7. `npx playwright test tests/e2e/ --reporter=line` against `http://localhost:8001/app/` — uploads the same fixture JAR, watches the phase stepper advance through all 8 macro-phases, and asserts the completed report renders real dashboard tables (not raw markdown) and a working download link.
  8. **Observability confirmed, not assumed:** during step 4's real run, confirm at least one `event="llm_call"` structured JSON log line appears on stdout (or via `grep event=llm_call`) for each of the 7 real LLM calls, and — if `LANGCHAIN_API_KEY`/`LANGCHAIN_TRACING_V2=true` are set in `.env` — confirm the run appears as a trace with one span per node in the LangSmith dashboard. Observability is wired in Phase 1, never deferred (`spec/agent.md` → Observability).

- **How the user tests it (handoff seed):**
  0. **New prerequisite:** confirm `java -version` reports Java 17+ on `PATH` (or set `AGENT_JAVA_BIN`), and that `tools/cfr-0.152.jar` exists (README documents the exact download step) — required to run the local decompiler.
  1. `cp .env.example .env` and fill `AGENT_ANTHROPIC_API_KEY` (already confirmed present).
  2. `uv sync && uv run alembic upgrade head`
  3. `cd frontend && pnpm build && cd ..`
  4. `uv run python -m src`
  5. Open `http://localhost:8001/app/`. Drag a real Spring Boot fat JAR (or any `.jar`) onto the upload zone and click **Start Scan**.
  6. **Real, on this path:** the phase stepper (Decompiling → Dependency Scan → Secret Scan → Config Extraction → Triage → LLM Security Review [with a per-category sub-label] → Verification → Report Generation) advances live via polling; when it finishes, a full report renders with real severity/OWASP/STRIDE/dependency dashboard tables, syntax-highlighted code evidence, a working **Download .md** button, and a token/cost footer. The scan record is really written to SQLite (`data/agent.db`).
  7. **Labelled stubs (visibly greyed, "Coming soon" tooltip, never mistaken for a bug):** a top-nav "Scan History" link, and on the report screen: "Export JSON/SARIF", "Ask a follow-up", "Mark as accepted risk", "Compare with another scan."
  8. Try an invalid file (e.g. a `.txt` renamed to `.jar`) — expect a clear, immediate error, never a blank/broken report.

---

### Phase 2 — Scan History, Export, Accepted-Risk Tracking & Follow-Up Chat

- **Goal:** every Phase-1 stub becomes real — the user can browse past scans, export a report as JSON/SARIF, mark findings as accepted-risk/false-positive, compare two scans, and ask follow-up questions about a completed report with the agent remembering the conversation so far.

- **Capabilities delivered (≥3, five total):**
  1. **Scan-history browsing** — list past scans (filename, date, risk score, status), reopen any past report exactly as rendered originally.
  2. **JSON/SARIF export** — export the same verified-findings data already in `findings_json` as a downloadable SARIF 2.1.0 file (for IDE/CI tool ingestion) alongside the existing Markdown/JSON exports.
  3. **Accepted-risk / false-positive tracking** — mark an individual finding on a scan as "Accepted Risk" or "False Positive" with a note; persisted per finding, reflected in the dashboard counts and excluded from the risk score on re-view.
  4. **Multi-JAR / version comparison** — pick two completed scans and see a diff view: findings introduced, findings resolved, findings unchanged, risk-score delta.
  5. **Follow-up Q&A chat on a completed report** — a chat panel on the report screen; the user asks questions about the findings and the agent answers grounded in that scan's verified findings and decompiled evidence already gathered (no re-decompilation). **Includes conversation history (turn memory) within a scan's chat session** — every answer is generated with the full prior turn history for that session, not just the latest question; this is Memory Management (`harness/patterns/agentic-ai.md` #8), added new in this phase (Phase 1's pipeline has no conversational surface).

- **Independent slices (parallel build units):**
  - `history-and-comparison-api` (backend) — `GET /scans` list endpoint, `GET /scans/compare?a=&b=` diff endpoint. Deps: none.
  - `export-sarif-api` (backend) — `GET /scans/{id}/export/sarif`, `GET /scans/{id}/export/json`. Deps: none.
  - `risk-tracking-api` (backend) — `finding_status` column/table + `PATCH /scans/{id}/findings/{finding_id}` endpoint. Deps: none.
  - `followup-chat-graph-and-api` (backend) — new small LangGraph chat node/graph reusing the scan's stored findings + evidence as context, `chat_messages` table, `POST /scans/{id}/chat` endpoint carrying full turn history. Deps: none.
  - `history-and-comparison-ui` (frontend) — history list screen, comparison view. Deps: pinned list/compare API contract (declared, non-blocking).
  - `export-risk-chat-ui` (frontend) — wires the four remaining Phase-1 stub buttons (export, accepted-risk toggle, chat panel) into real calls. Deps: pinned export/risk/chat API contracts (declared, non-blocking).

- **Key surfaces / files:** `src/api/scans.py` (new routes), `src/db/models.py` (add `FindingStatusRow`, `ChatMessageRow`), `alembic/versions/0003_history_risk_chat.py`, `src/graph/chat_nodes.py`, `src/prompts/chat_answer.md`, `frontend/src/app/history/page.tsx`, `frontend/src/components/ComparisonView.tsx`, `frontend/src/components/ChatPanel.tsx`, `frontend/src/components/FindingStatusToggle.tsx`, `tests/unit/api/test_history.py`, `tests/integration/test_chat.py` (real key; asserts a second chat turn sees the first turn's context — the multi-interaction test `harness/patterns/test-driven.md` requires for any stateful capability), `tests/e2e/chat-and-history.spec.ts`.

- **Gate command:** `uv run alembic upgrade head && uv run pytest tests/unit tests/integration -v && (cd frontend && pnpm build) && uv run python -m src` (leave running) `&& npx playwright test tests/e2e/ --reporter=line` — all against the real Anthropic key from `.env` and the production SQLite DB; `tests/integration/test_chat.py` specifically drives two chat turns in the same scan session and asserts the second answer reflects the first turn's content (not just a non-empty response).

- **How the user tests it (handoff seed):** run a second scan (or reuse Phase 1's), open **Scan History**, confirm the earlier scan reopens with its original report; on a report, click **Export JSON/SARIF** and confirm a real file downloads; mark one finding **Accepted Risk** and confirm the dashboard count updates; select two scans under **Compare** and confirm a diff view renders; open **Ask a follow-up**, ask a question about a specific finding, then ask a second question referring back to the first ("what about that one's fix?") and confirm the agent's second answer correctly uses the first turn's context.

---

### Phase 3 — Agentic Resilience & Hardening

- **Goal:** the full system (Phase 1's scan pipeline + Phase 2's chat/export/history calls) degrades gracefully instead of crashing on any external-call failure — Anthropic API errors/rate-limits, CFR subprocess hangs/crashes — and every documented failure mode is exercised by a real test. No new user-facing capability; this phase hardens what already exists. (This is the `harness/patterns/phases.md` "Agentic Stack Upgrade + Resilience" phase, placed after the requirements phase per the rationale note above.)

- **Independent slices (parallel build units):**
  - `llm-call-resilience` (backend) — retry-with-backoff (max 3 attempts, exponential, on `anthropic.APIStatusError` 429/5xx and `anthropic.APITimeoutError`) wrapped around every `LLMClient.call_model` call site; on exhausted retries for a single category-review node, that node marks its category's findings as `["Review failed — see error: <reason>"]` (a synthetic Finding-shaped entry with `severity="Informational"`, `confidence="Low"`, `no_evidence_marker=True`, note explaining the failure) instead of aborting the whole scan. Deps: none.
  - `cfr-subprocess-resilience` (backend) — hard timeout (`AGENT_CFR_TIMEOUT_S`, default 180s per invocation) on every `subprocess.run` call to CFR; on timeout or non-zero exit, the affected component (a single nested lib jar, or the app classes) is recorded in `decompile_errors` and skipped rather than crashing the `decompile` node — the scan continues with whatever did decompile. Deps: none.
  - `observability-thresholds` (backend) — LangSmith run-level latency/error alerting config (documented threshold: any node p95 > 60s or any run with >1 failed-and-recovered category logs a WARNING-level structured event) layered onto the Phase-1 tracing setup. Deps: none.

- **Key surfaces / files:** `src/llm/client.py` (retry wrapper), `src/graph/nodes.py` (per-category degraded-mode handling), `src/decompile/cfr.py` (timeout + partial-failure handling), `src/observability/events.py` (threshold logging), `tests/unit/llm/test_retry.py`, `tests/integration/test_resilience.py` (real key; forces a timeout/error path and asserts the scan still completes with a degraded category rather than failing).

- **Gate command:** `uv run pytest tests/unit tests/integration -v` (real Anthropic key from `.env`) — must include `tests/integration/test_resilience.py::test_scan_survives_one_category_review_failure` and `tests/integration/test_resilience.py::test_scan_survives_cfr_timeout_on_one_nested_jar`, both green, both proving degraded-not-crashed behavior against real dependencies (a monkeypatched transient failure injected once, not every call).

- **How the user tests it (handoff seed):** no new UI. The maintainer confirms: (1) `uv run pytest tests/integration/test_resilience.py -v` passes, showing a scan that survives a simulated Anthropic 500 on one review category and still produces a complete report with that category marked "Review failed — see error" rather than the whole scan failing; (2) same for a simulated CFR timeout on one nested dependency jar.
