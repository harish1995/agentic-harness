# Capability: JAR Upload & Validation

## What It Does

Accepts a JAR upload through the web UI, validates it is a readable, size-bounded ZIP/JAR archive before any processing begins, and creates the scan record that the rest of the pipeline runs against.

## Inputs

| Input | Type | Source | Required |
|-------|------|--------|----------|
| `file` | multipart file (`.jar`) | Browser upload, `POST /scans` | yes |

## Outputs

| Output | Type | Destination |
|--------|------|-------------|
| `Scan` row (`status="processing"`, `current_phase="queued"`) | DB row | The `scans` table (`spec/data.md`) |
| Stored upload | file | `data/uploads/<scan_id>.jar` (local disk only) |
| `{scan_id, status, current_phase}` | JSON | HTTP response to the browser (`spec/api.md` → `POST /scans`) |

## External Calls

| System | Operation | On Failure |
|--------|-----------|------------|
| Local filesystem | Save uploaded bytes, `zipfile.is_zipfile()` check | 400 if not a valid ZIP/JAR; 500 if the local write itself fails |
| Database | Insert `Scan` row | 500, upload is not accepted |

## Business Rules

- A file that is not a readable ZIP archive (`zipfile.is_zipfile()` returns `False`) is rejected with a 400 before any decompilation is attempted — never silently proceeds to produce a blank/broken report.
- A file over `AGENT_MAX_UPLOAD_MB` (default 150 MB) is rejected with 413 before being written to disk.
- Only one scan may have `status="processing"` at a time; a second upload while one is in-flight is rejected with 409 (`spec/roadmap.md` → single-user, ad hoc constraint).
- The uploaded file is never transmitted anywhere beyond local disk — this capability performs zero network calls (`spec/architecture.md` → Data Residency).

## Success Criteria

- [ ] A valid Spring Boot fat JAR is accepted, stored locally, and returns a `scan_id` with `status="processing"`.
- [ ] A `.txt` file renamed to `.jar` is rejected with a 400 naming the exact reason, and no `Scan` row with `status="processing"` is left behind for it.
- [ ] A file larger than `AGENT_MAX_UPLOAD_MB` is rejected with 413.
- [ ] Uploading a second file while a scan is `processing` returns 409 and does not create a second `processing` row.
