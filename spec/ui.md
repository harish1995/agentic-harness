# UI

---

## UI Type

Web dashboard (Next.js static export, served by FastAPI at `/app` per `harness/patterns/tech-stack.md`). Three logical views on one page flow (upload → progress → report), driven by client-side state transitioning on the polled `status` field — not three separate routes, so the user never loses context mid-scan on a refresh-prone flow. (History/comparison get their own route in Phase 2.)

---

## Views / Screens

### Screen: Upload

**Purpose:** the user selects/drags a JAR and starts a scan.

**Key elements:**
- Drag-and-drop zone (large, primary) with a "Choose file" fallback button — accepts `.jar` only client-side (`accept=".jar"`), with a clear label ("Drop your JAR here, or click to browse").
- Selected-file preview (filename + size) before submit.
- **Start Scan** primary button — disabled until a file is selected, disabled again immediately on click (prevents double-submit) with its label changing to "Starting…".
- Top-nav **Scan History** link — **labelled stub in Phase 1**: visibly greyed out with a "Coming soon" tooltip on hover/focus; not a dead unstyled link, a deliberately-styled disabled state so it never reads as a bug.

**Actions available:** select file, start scan.

**States:**
- *Empty (default):* drop-zone with instructional copy, no file selected, button disabled.
- *Loading:* immediately after clicking Start Scan, transitions to the Progress screen (no separate loading state on this screen itself beyond the brief button-disable while `POST /scans` is in flight).
- *Error:* if `POST /scans` returns 400/413/409, an inline error banner appears above the drop-zone naming the exact reason (`"Uploaded file is not a valid JAR (not a readable ZIP archive)."` / `"File exceeds the 150 MB limit."` / `"A scan is already in progress. Wait for it to finish before starting another."`) with a "Try again" affordance that just re-enables the form — never a raw stack trace, never a silent no-op.

### Screen: Progress

**Purpose:** live phase-by-phase visibility while the pipeline runs (`GET /scans/{id}/status`, polled every 2 seconds).

**Key elements:**
- A **macro-phase stepper** (8 steps, each shown as a labelled node in a horizontal/vertical progress track): **Decompiling → Dependency Scan → Secret Scan → Config Extraction → Triage → LLM Security Review → Verification → Report Generation**. Each backend `current_phase` value maps to exactly one macro-step via this fixed table:

  | `current_phase` | Macro-step | Sub-label shown |
  |---|---|---|
  | `queued`, `decompiling` | Decompiling | — |
  | `scanning_dependencies` | Dependency Scan | — |
  | `scanning_secrets` | Secret Scan | — |
  | `extracting_config` | Config Extraction | — |
  | `triaging` | Triage | "Selecting security-relevant code" |
  | `reviewing_injection` | LLM Security Review | "Injection" |
  | `reviewing_authn_authz` | LLM Security Review | "Authentication & Authorization" |
  | `reviewing_crypto_secrets` | LLM Security Review | "Cryptography & Secrets" |
  | `reviewing_deserialization_upload` | LLM Security Review | "Deserialization & File Upload" |
  | `reviewing_config_logging` | LLM Security Review | "Configuration & Logging" |
  | `reviewing_dependencies` | LLM Security Review | "Dependency Vulnerabilities" |
  | `verifying` | Verification | — |
  | `assembling_report` | Report Generation | — |
  | `completed` | (transitions to Report screen) | — |
  | `failed` | (renders the Error state below, no macro-step highlighted as active) | — |

  Completed macro-steps show a checkmark; the active one shows a spinner + its sub-label if any; future steps are dimmed — never a frozen screen with no indication of what's happening now.
- Elapsed time counter (client-side, since `uploaded_at`).
- Once `class_count`/`is_spring_boot` are available (after the Decompiling step), a small "Scanning `<class_count>` classes · Spring Boot detected" info line.

**Actions available:** none (no cancel in Phase 1 — explicitly noted as absent, not broken, via a disabled "Cancel" button with a tooltip "Not available yet").

**States:**
- *Loading (the normal state for this whole screen):* the stepper itself, always showing real, current progress — never a fake/looping progress bar unrelated to actual phase (`harness/patterns/ui-ux.md` → Honesty: never fake progress).
- *Error:* if `status == "failed"`, the stepper freezes on the phase it failed at (shown with an error icon, not a checkmark), and a clear error banner shows `error_message` plus an "Upload a different file" button that returns to the Upload screen.

### Screen: Report

**Purpose:** read the completed security report with real dashboards, not raw markdown; download it; see cost.

**Key elements:**
- **Executive Summary** — rendered via `react-markdown` + `remark-gfm` (never a raw string node, per `harness/patterns/ui-ux.md`).
- **Risk Score** — a large number + band label (e.g. "72 — High Risk") with a colored badge matching the band.
- **Severity Dashboard** — a real table/bar chart (not raw markdown) of Critical/High/Medium/Low/Informational counts, each with its own color.
- **OWASP Top 10 Summary** and **STRIDE Summary** — real tables of category → finding count, clicking a row scrolls/filters to that category's findings.
- **Dependency Summary** — real table: Library | Version | Suspected CVE(s) | Severity | Confidence, with a visible caption: "Based on model reasoning over extracted dependency versions — not a live CVE database lookup" (surfacing the documented limitation from `spec/architecture.md`, never hidden).
- **Per-category finding sections** (Sensitive Data Exposure, Authentication Issues, Authorization Issues, Cryptography Issues, Injection Issues, Configuration Issues, Logging Issues) — each renders either its real `FindingCard`s or, if its only entry is `no_evidence_marker: true`, a plain, clearly-styled **"No evidence found."** line (never omitted, never rendered as if it were an error).
- **`FindingCard`** — every one of the 20 required fields visible (collapsible sections for the longer free-text fields to keep the card scannable): Title + Severity badge + CVSS + OWASP/STRIDE/CWE tags header row; Affected Classes/Methods as a code-styled list; Description/Business Impact/Technical Impact/Attack Scenario as prose; Evidence + Code Snippet + Secure Code Example as syntax-highlighted code blocks (`react-syntax-highlighter`, language `java`); Why Vulnerable/How Exploitable/Recommended Fix as prose; References as links; Confidence badge.
- **Secure Coding Recommendations** and **Developer Remediation Plan** (Priority 1-4) sections, rendered as real ordered lists/tables, not raw markdown.
- **Appendix** — scan stats (classes scanned vs. deep-reviewed, decompile errors if any, Spring-detection evidence, the dependency-CVE-reasoning disclaimer restated).
- **Cost footer bar** (sticky, bottom of report): `"~48,210 input / 11,340 output tokens · est. $0.31 (approximate)"`.
- **Download .md** button — real, downloads `GET /scans/{id}/download`.
- **Labelled stub buttons** (Phase 1, all visibly disabled/greyed with a "Coming soon" tooltip, grouped near Download so they read as a deliberate roadmap strip, not a missing feature): **Export JSON/SARIF**, **Ask a follow-up**, **Mark as accepted risk** (shown per-`FindingCard`, also disabled), **Compare with another scan**.

**Actions available:** scroll/navigate between sections, download report, (Phase 2) export/chat/accept-risk/compare.

**States:**
- *Ideal/populated:* as above.
- *Empty:* not applicable to this screen — it only renders once a scan is `completed`, and `assemble_report` always produces at least the "No evidence found." entries for empty categories, so there is no genuinely empty report state to design.
- *Loading:* not applicable — this screen only mounts once `status == "completed"`; the Progress screen owns all in-flight states.
- *Error:* not applicable to this screen — a failed scan never reaches it (handled entirely on the Progress screen).

---

## Error States (cross-cutting)

- **Network error** (server unreachable during any fetch/poll): a persistent, non-blocking banner — `"Can't reach the server — retrying…"` — with automatic retry on the next poll tick; never a full-page crash.
- **Every error message names the cause and the next step** (`harness/patterns/ui-ux.md` → Copy) — no bare "Error 500", no raw stack traces surfaced to the user anywhere in this UI.
- **Loading states always show context**, never a bare spinner with no label (per the Progress screen's stepper + sub-labels above).

---

## Frontend Component Contract (pins the `upload-progress-ui` / `report-dashboard-ui` slice boundary)

`frontend/src/app/page.tsx` (owned by `upload-progress-ui`) renders exactly one of three states based on client-side scan status and imports two components it does not implement:

- `<ProgressPanel status={ScanStatusResponse} />` (owned by `upload-progress-ui` itself) — `ScanStatusResponse` is the `data` object shape from `GET /scans/{id}/status` in `spec/api.md`, verbatim.
- `<ReportView scan={ScanDetailResponse} />` (owned by `report-dashboard-ui`) — `ScanDetailResponse` is the `data` object shape from `GET /scans/{id}` (completed case) in `spec/api.md`, verbatim — including the full `findings: Finding[]` array as defined there.

Both components are pure presentational React components (props in, JSX out — they do not fetch data themselves); `page.tsx` owns all polling/fetching and passes the already-fetched JSON straight through as props. This is the only contract the two frontend slices share, and it is fully pinned by the `spec/api.md` response shapes already fixed above — neither slice needs the other's code to build against it.

## Tech Stack

Next.js 15 + React 19 + Tailwind v4 (existing skeleton), static-exported (`output: 'export'`, `basePath: '/app'`) and served by FastAPI at `http://localhost:8001/app/` — single-origin run/test path per `harness/patterns/tech-stack.md`. `react-markdown` + `remark-gfm` for markdown-bearing free text; `react-syntax-highlighter` for code evidence and secure-code-example blocks (language `java`). `@playwright/test` for the required `tests/e2e/` smoke suite (`harness/patterns/tech-stack.md`), covering: upload a fixture JAR → stepper advances through all 8 macro-phases → completed report renders real dashboard tables and a working download link.
