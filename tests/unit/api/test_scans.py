"""/scans API contract tests — no LLM key required, graph.runner.run_scan is faked."""
import io
import json
import sys
import time
import types
import zipfile

import pytest


def _make_jar_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("com/example/Hello.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34")
    return buf.getvalue()


def _install_fake_run_scan(monkeypatch, fn) -> None:
    """Install a fake `graph.runner` module exposing `run_scan=fn` directly into
    sys.modules, so `src/api/scans.py`'s `from graph.runner import run_scan` picks it
    up without ever importing the real `graph.agent`/`graph.state` chain — that chain
    belongs to the concurrently-built graph-and-llm-pipeline slice and is not part of
    this slice's test contract (per the api-and-db handoff notes)."""
    fake_module = types.ModuleType("graph.runner")
    fake_module.run_scan = fn
    monkeypatch.setitem(sys.modules, "graph.runner", fake_module)


def _noop_run_scan(scan_id: str, jar_path: str) -> None:
    """Lightweight fake for graph.runner.run_scan — proves plumbing only."""


def _completing_run_scan(scan_id: str, jar_path: str) -> None:
    """Fake that writes a 'completed' scan directly to the DB, like the real pipeline would."""
    from db.models import ScanRow
    from db.session import create_db_session

    with create_db_session() as session:
        row = session.get(ScanRow, scan_id)
        row.status = "completed"
        row.current_phase = "completed"
        row.is_spring_boot = True
        row.class_count = 42
        row.triaged_class_count = 10
        row.risk_score = 55
        row.report_markdown = "# Executive Summary\n\nAll good."
        row.findings_json = json.dumps(
            [{"title": "No evidence found.", "no_evidence_marker": True}]
        )
        row.dependencies_json = json.dumps(
            [
                {
                    "artifact_id": "jackson-databind",
                    "group_id": None,
                    "version": "2.9.8",
                    "source": "nested_jar_filename",
                }
            ]
        )
        row.total_input_tokens = 100
        row.total_output_tokens = 50
        row.estimated_cost_usd = 0.01


def _failing_run_scan(scan_id: str, jar_path: str) -> None:
    from db.models import ScanRow
    from db.session import create_db_session

    with create_db_session() as session:
        row = session.get(ScanRow, scan_id)
        row.status = "failed"
        row.current_phase = "failed"
        row.error_message = "CFR decompile produced zero classes."


def test_health(api_client):
    r = api_client.get("/health")
    assert r.status_code == 200
    assert r.json()["data"]["status"] == "ok"


# ---------------------------------------------------------------------------
# POST /scans
# ---------------------------------------------------------------------------


def test_create_scan_success(api_client, monkeypatch):
    _install_fake_run_scan(monkeypatch, _noop_run_scan)

    r = api_client.post(
        "/scans", files={"file": ("service.jar", _make_jar_bytes(), "application/java-archive")}
    )

    assert r.status_code == 200
    body = r.json()
    assert body["error"] is None
    data = body["data"]
    assert set(data.keys()) == {"scan_id", "status", "current_phase"}
    assert data["status"] == "processing"
    assert data["current_phase"] == "queued"
    assert data["scan_id"]


def test_create_scan_persists_processing_row(api_client, monkeypatch, _isolated_db):
    from sqlalchemy.orm import Session

    from db.models import ScanRow

    _install_fake_run_scan(monkeypatch, _noop_run_scan)

    r = api_client.post(
        "/scans", files={"file": ("service.jar", _make_jar_bytes(), "application/java-archive")}
    )
    scan_id = r.json()["data"]["scan_id"]

    with Session(_isolated_db) as s:
        row = s.get(ScanRow, scan_id)
        assert row is not None
        assert row.status == "processing"
        assert row.current_phase == "queued"
        assert row.original_filename == "service.jar"
        assert row.jar_path.endswith(f"{scan_id}.jar")


def test_create_scan_rejects_empty_file(api_client):
    r = api_client.post(
        "/scans", files={"file": ("empty.jar", b"", "application/java-archive")}
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "INVALID_FILE"
    assert "empty" in r.json()["detail"]["message"].lower()


def test_create_scan_rejects_non_jar(api_client):
    r = api_client.post(
        "/scans", files={"file": ("notes.txt", b"this is not a jar file at all", "text/plain")}
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "INVALID_FILE"


def test_create_scan_rejects_oversized_file(api_client, monkeypatch):
    # `get_settings()` is a process-wide singleton already populated by the
    # `api_client` fixture's app-startup lifespan (before this test body runs), so
    # merely setting the env var here would be read too late. Mutate the cached
    # settings object directly (reset by the autouse `_reset_settings_singleton`
    # fixture after every test) instead.
    from config.settings import get_settings

    get_settings().max_upload_mb = 0

    r = api_client.post(
        "/scans", files={"file": ("service.jar", _make_jar_bytes(), "application/java-archive")}
    )
    assert r.status_code == 413


def test_create_scan_rejects_when_already_processing(api_client, _isolated_db):
    from sqlalchemy.orm import Session

    from db.models import ScanRow

    with Session(_isolated_db) as s:
        s.add(ScanRow(original_filename="in-flight.jar", jar_path="data/uploads/x.jar"))
        s.commit()

    r = api_client.post(
        "/scans", files={"file": ("service.jar", _make_jar_bytes(), "application/java-archive")}
    )
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "SCAN_IN_PROGRESS"


def test_create_scan_missing_file_field(api_client):
    r = api_client.post("/scans")
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/status
# ---------------------------------------------------------------------------


def test_status_not_found(api_client):
    r = api_client.get("/scans/does-not-exist/status")
    assert r.status_code == 404


def test_status_shape_while_processing(api_client, _isolated_db):
    from sqlalchemy.orm import Session

    from db.models import ScanRow

    with Session(_isolated_db) as s:
        row = ScanRow(original_filename="app.jar", jar_path="data/uploads/a.jar")
        s.add(row)
        s.commit()
        scan_id = row.id

    r = api_client.get(f"/scans/{scan_id}/status")
    assert r.status_code == 200
    data = r.json()["data"]
    assert set(data.keys()) == {
        "scan_id",
        "status",
        "current_phase",
        "is_spring_boot",
        "class_count",
        "error",
    }
    assert data["scan_id"] == scan_id
    assert data["status"] == "processing"
    assert data["current_phase"] == "queued"
    assert data["is_spring_boot"] is None
    assert data["class_count"] is None
    assert data["error"] is None


def test_status_shape_on_failure(api_client, monkeypatch, _isolated_db):
    _install_fake_run_scan(monkeypatch, _failing_run_scan)

    r = api_client.post(
        "/scans", files={"file": ("service.jar", _make_jar_bytes(), "application/java-archive")}
    )
    scan_id = r.json()["data"]["scan_id"]

    status_data = None
    for _ in range(50):
        status_data = api_client.get(f"/scans/{scan_id}/status").json()["data"]
        if status_data["status"] == "failed":
            break
        time.sleep(0.05)

    assert status_data["status"] == "failed"
    assert status_data["error"] == "CFR decompile produced zero classes."


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}
# ---------------------------------------------------------------------------


def test_get_scan_not_found(api_client):
    r = api_client.get("/scans/does-not-exist")
    assert r.status_code == 404


def test_get_scan_shape_while_processing(api_client, _isolated_db):
    from sqlalchemy.orm import Session

    from db.models import ScanRow

    with Session(_isolated_db) as s:
        row = ScanRow(original_filename="my-service-1.4.2.jar", jar_path="data/uploads/a.jar")
        s.add(row)
        s.commit()
        scan_id = row.id

    r = api_client.get(f"/scans/{scan_id}")
    assert r.status_code == 200
    data = r.json()["data"]
    expected_keys = {
        "scan_id",
        "original_filename",
        "uploaded_at",
        "status",
        "current_phase",
        "is_spring_boot",
        "class_count",
        "triaged_class_count",
        "risk_score",
        "report_markdown",
        "findings",
        "dependencies",
        "total_input_tokens",
        "total_output_tokens",
        "estimated_cost_usd",
        "error",
    }
    assert set(data.keys()) == expected_keys
    assert data["original_filename"] == "my-service-1.4.2.jar"
    assert data["status"] == "processing"
    assert data["triaged_class_count"] is None
    assert data["report_markdown"] is None
    assert data["findings"] is None
    assert data["dependencies"] is None


def test_get_scan_shape_when_completed(api_client, monkeypatch):
    _install_fake_run_scan(monkeypatch, _completing_run_scan)

    r = api_client.post(
        "/scans", files={"file": ("service.jar", _make_jar_bytes(), "application/java-archive")}
    )
    scan_id = r.json()["data"]["scan_id"]

    data = None
    for _ in range(50):
        data = api_client.get(f"/scans/{scan_id}").json()["data"]
        if data["status"] == "completed":
            break
        time.sleep(0.05)

    assert data["status"] == "completed"
    assert data["current_phase"] == "completed"
    assert data["risk_score"] == 55
    assert data["triaged_class_count"] == 10
    assert data["report_markdown"].startswith("# Executive Summary")
    assert data["findings"] == [{"title": "No evidence found.", "no_evidence_marker": True}]
    assert data["dependencies"] == [
        {
            "artifact_id": "jackson-databind",
            "group_id": None,
            "version": "2.9.8",
            "source": "nested_jar_filename",
        }
    ]
    assert data["total_input_tokens"] == 100
    assert data["total_output_tokens"] == 50
    assert data["estimated_cost_usd"] == 0.01
    assert data["error"] is None


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/download
# ---------------------------------------------------------------------------


def test_download_not_found(api_client):
    r = api_client.get("/scans/does-not-exist/download")
    assert r.status_code == 404


def test_download_conflicts_before_completion(api_client, _isolated_db):
    from sqlalchemy.orm import Session

    from db.models import ScanRow

    with Session(_isolated_db) as s:
        row = ScanRow(original_filename="app.jar", jar_path="data/uploads/a.jar")
        row.current_phase = "reviewing_injection"
        s.add(row)
        s.commit()
        scan_id = row.id

    r = api_client.get(f"/scans/{scan_id}/download")
    assert r.status_code == 409
    assert "reviewing_injection" in r.json()["detail"]["message"]


def test_download_conflicts_with_failure_message(api_client, _isolated_db):
    from sqlalchemy.orm import Session

    from db.models import ScanRow

    with Session(_isolated_db) as s:
        row = ScanRow(original_filename="app.jar", jar_path="data/uploads/a.jar")
        row.status = "failed"
        row.current_phase = "failed"
        row.error_message = "CFR decompile produced zero classes."
        s.add(row)
        s.commit()
        scan_id = row.id

    r = api_client.get(f"/scans/{scan_id}/download")
    assert r.status_code == 409
    assert r.json()["detail"]["message"] == "CFR decompile produced zero classes."


def test_download_success(api_client, _isolated_db):
    from sqlalchemy.orm import Session

    from db.models import ScanRow

    with Session(_isolated_db) as s:
        row = ScanRow(original_filename="my-service-1.4.2.jar", jar_path="data/uploads/a.jar")
        row.status = "completed"
        row.current_phase = "completed"
        row.report_markdown = "# Executive Summary\n\nAll good."
        s.add(row)
        s.commit()
        scan_id = row.id

    r = api_client.get(f"/scans/{scan_id}/download")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert (
        r.headers["content-disposition"]
        == 'attachment; filename="my-service-1.4.2.jar-security-report.md"'
    )
    assert r.text == "# Executive Summary\n\nAll good."
