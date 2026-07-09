# API

---

## API Style

REST (FastAPI), JSON envelope `{"data": ..., "error": null}` on success / `HTTPException(detail={"code", "message"})` on failure — the existing skeleton's convention (`src/api/_common.py`: `ok()`, `api_error()`). One exception: `GET /scans/{id}/download` returns a raw `text/markdown` file body, not the JSON envelope.

This contract is pinned here precisely so the `upload-progress-ui` / `report-dashboard-ui` frontend slices and the `api-and-db` backend slice can build concurrently (`spec/roadmap.md`) without waiting on each other's code.

---

## Endpoints

### `POST /scans`

**Purpose:** upload a JAR and start a scan. Returns immediately (the pipeline runs in a background thread) — the client polls `/scans/{id}/status` for progress.

**Request:** `multipart/form-data`, single field `file` (the `.jar`).

**Response (200):**
```json
{
  "data": {
    "scan_id": "3fae6c1e-...-uuid",
    "status": "processing",
    "current_phase": "queued"
  },
  "error": null
}
```
`current_phase` is `"queued"` at this instant — the background pipeline thread has been spawned but its first node (`decompile`) may not yet have written `"decompiling"`. The very next `GET /scans/{id}/status` poll typically already shows `"decompiling"`.

**Error cases:**
| Status | Condition |
|--------|-----------|
| 400 | Missing `file` field, empty file, or the file is not a readable ZIP/JAR (`zipfile.is_zipfile()` fails) — message names the reason, e.g. `"Uploaded file is not a valid JAR (not a readable ZIP archive)."` |
| 413 | File exceeds `AGENT_MAX_UPLOAD_MB` (default 150 MB) |
| 409 | Another scan currently has `status="processing"` — message: `"A scan is already in progress. Wait for it to finish before starting another."` |
| 500 | Unexpected failure saving the upload or creating the DB row |

---

### `GET /scans/{scan_id}/status`

**Purpose:** the polling endpoint the progress screen calls every 2 seconds while `status == "processing"`.

**Response (200):**
```json
{
  "data": {
    "scan_id": "3fae6c1e-...-uuid",
    "status": "processing",
    "current_phase": "reviewing_crypto_secrets",
    "is_spring_boot": true,
    "class_count": 1284,
    "error": null
  },
  "error": null
}
```
`current_phase` is one of the 15 values listed in `spec/agent.md` → Progress Reporting (`decompiling` … `assembling_report`, then terminal `completed` / `failed`). `is_spring_boot` and `class_count` are `null` until the `decompile` node has written them. `error` is `null` unless `status == "failed"`, in which case it holds the human-readable failure message.

**Why polling, not SSE:** chosen over Server-Sent Events for this project because (a) the pipeline already writes progress to SQLite as a side effect of each node (`spec/agent.md` → Progress Reporting) — polling that row needs no new infrastructure, whereas SSE would require a second coordination mechanism (an in-process pub/sub or queue) to bridge the background thread running the graph to a streaming HTTP response; (b) this is a single-user, ad hoc, local tool — a 2-second poll has no meaningful cost or scaling concern; (c) it keeps the FastAPI app fully synchronous, matching the existing skeleton's synchronous SQLAlchemy session model, with no added async/await surface. A 2-second poll interval is fast enough that "watch it process" reads as live progress to a human.

**Error cases:**
| Status | Condition |
|--------|-----------|
| 404 | No scan with that `scan_id` |

---

### `GET /scans/{scan_id}`

**Purpose:** fetch the full scan record, including the assembled report once `status == "completed"`.

**Response (200, while processing):**
```json
{
  "data": {
    "scan_id": "3fae6c1e-...-uuid",
    "original_filename": "my-service-1.4.2.jar",
    "uploaded_at": "2026-07-09T14:02:11Z",
    "status": "processing",
    "current_phase": "reviewing_authn_authz",
    "is_spring_boot": true,
    "class_count": 1284,
    "triaged_class_count": null,
    "risk_score": null,
    "report_markdown": null,
    "findings": null,
    "dependencies": null,
    "total_input_tokens": null,
    "total_output_tokens": null,
    "estimated_cost_usd": null,
    "error": null
  },
  "error": null
}
```

**Response (200, completed):**
```json
{
  "data": {
    "scan_id": "3fae6c1e-...-uuid",
    "original_filename": "my-service-1.4.2.jar",
    "uploaded_at": "2026-07-09T14:02:11Z",
    "status": "completed",
    "current_phase": "completed",
    "is_spring_boot": true,
    "class_count": 1284,
    "triaged_class_count": 58,
    "risk_score": 72,
    "report_markdown": "# Executive Summary\n\n...",
    "findings": [
      {
        "title": "SQL Injection via string-concatenated query in OrderRepository.findByCustomer",
        "severity": "Critical",
        "cvss_score": 9.1,
        "owasp_category": "A03:2021 - Injection",
        "stride_category": "Tampering",
        "cwe_id": "CWE-89",
        "affected_classes": ["com.example.repo.OrderRepository"],
        "affected_methods": ["findByCustomer(String)"],
        "description": "...",
        "business_impact": "...",
        "technical_impact": "...",
        "attack_scenario": "...",
        "evidence": "...",
        "code_snippet": "...",
        "why_vulnerable": "...",
        "how_exploitable": "...",
        "recommended_fix": "...",
        "secure_code_example": "...",
        "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
        "confidence": "High",
        "category_source": "review_injection",
        "no_evidence_marker": false
      }
    ],
    "dependencies": [
      {"artifact_id": "jackson-databind", "group_id": null, "version": "2.9.8", "source": "nested_jar_filename"}
    ],
    "total_input_tokens": 48210,
    "total_output_tokens": 11340,
    "estimated_cost_usd": 0.31,
    "error": null
  },
  "error": null
}
```
`findings` is the full `verified_findings` list (`spec/agent.md` → `Finding`), including any `no_evidence_marker: true` entries for categories with nothing detected — the UI is responsible for rendering those as "No evidence found." rather than a finding card. `triaged_class_count` is `len(triaged_chunks)` — always shown alongside `class_count` so the Appendix's "N of M classes deep-reviewed" statement is reproducible from the API response, not just the rendered markdown.

**Error cases:**
| Status | Condition |
|--------|-----------|
| 404 | No scan with that `scan_id` |

---

### `GET /scans/{scan_id}/download`

**Purpose:** download the completed report as a `.md` file.

**Response (200):** `Content-Type: text/markdown`, `Content-Disposition: attachment; filename="<original_filename>-security-report.md"`, body = `report_markdown` verbatim.

**Error cases:**
| Status | Condition |
|--------|-----------|
| 404 | No scan with that `scan_id` |
| 409 | Scan exists but `status != "completed"` — message: `"Report is not ready yet — scan is still <current_phase>."` (or, if failed, the failure message) |

---

## Future Endpoints (Phase 2 — not part of the Phase 1 contract)

Named here only so the Phase 1 route table has no collisions; shapes are defined when Phase 2 is spec'd in detail per `spec/roadmap.md`: `GET /scans` (history list), `GET /scans/compare` (diff), `GET /scans/{id}/export/sarif`, `GET /scans/{id}/export/json`, `PATCH /scans/{id}/findings/{finding_id}` (accepted-risk/false-positive), `POST /scans/{id}/chat` (follow-up Q&A, carries turn history).

---

## Authentication

None. Single-user, local, ad hoc tool (`spec/roadmap.md` → Key Constraints) — the server is expected to run on `localhost` under the user's own control, with no multi-tenant or network-exposed deployment in scope.
