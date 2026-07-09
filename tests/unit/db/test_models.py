"""ScanRow DB-layer tests — no LLM key required."""
import json

from sqlalchemy.orm import Session

from db.models import ScanRow


def test_scan_row_roundtrip(_isolated_db):
    with Session(_isolated_db) as s:
        scan = ScanRow(
            original_filename="my-service.jar",
            jar_path="data/uploads/abc.jar",
        )
        s.add(scan)
        s.commit()
        scan_id = scan.id

    with Session(_isolated_db) as s:
        fetched = s.get(ScanRow, scan_id)
        assert fetched is not None
        assert fetched.original_filename == "my-service.jar"
        assert fetched.jar_path == "data/uploads/abc.jar"
        # defaults
        assert fetched.status == "processing"
        assert fetched.current_phase == "queued"
        assert fetched.uploaded_at is not None
        assert fetched.created_at is not None
        assert fetched.updated_at is not None
        # nullable fields default to None
        assert fetched.current_detail is None
        assert fetched.is_spring_boot is None
        assert fetched.has_spring_security is None
        assert fetched.class_count is None
        assert fetched.triaged_class_count is None
        assert fetched.decompile_errors_json is None
        assert fetched.dependencies_json is None
        assert fetched.secret_findings_count is None
        assert fetched.risk_score is None
        assert fetched.report_markdown is None
        assert fetched.findings_json is None
        assert fetched.total_input_tokens is None
        assert fetched.total_output_tokens is None
        assert fetched.estimated_cost_usd is None
        assert fetched.error_message is None


def test_scan_row_progress_and_completion_update(_isolated_db):
    with Session(_isolated_db) as s:
        scan = ScanRow(original_filename="app.jar", jar_path="data/uploads/x.jar")
        s.add(scan)
        s.commit()
        scan_id = scan.id

    # Simulate a pipeline node writing progress.
    with Session(_isolated_db) as s:
        scan = s.get(ScanRow, scan_id)
        scan.current_phase = "decompiling"
        scan.is_spring_boot = True
        scan.has_spring_security = False
        scan.class_count = 1284
        s.commit()

    with Session(_isolated_db) as s:
        scan = s.get(ScanRow, scan_id)
        assert scan.current_phase == "decompiling"
        assert scan.is_spring_boot is True
        assert scan.class_count == 1284

    # Simulate finalize().
    findings = [{"title": "SQL Injection", "severity": "Critical"}]
    with Session(_isolated_db) as s:
        scan = s.get(ScanRow, scan_id)
        scan.status = "completed"
        scan.current_phase = "completed"
        scan.risk_score = 72
        scan.report_markdown = "# Executive Summary\n..."
        scan.findings_json = json.dumps(findings)
        scan.total_input_tokens = 48210
        scan.total_output_tokens = 11340
        scan.estimated_cost_usd = 0.31
        s.commit()

    with Session(_isolated_db) as s:
        scan = s.get(ScanRow, scan_id)
        assert scan.status == "completed"
        assert scan.risk_score == 72
        assert json.loads(scan.findings_json) == findings
        assert scan.estimated_cost_usd == 0.31


def test_scan_row_failure_path(_isolated_db):
    with Session(_isolated_db) as s:
        scan = ScanRow(original_filename="broken.jar", jar_path="data/uploads/y.jar")
        s.add(scan)
        s.commit()
        scan_id = scan.id

    with Session(_isolated_db) as s:
        scan = s.get(ScanRow, scan_id)
        scan.status = "failed"
        scan.current_phase = "failed"
        scan.error_message = "CFR decompile produced zero classes."
        s.commit()

    with Session(_isolated_db) as s:
        scan = s.get(ScanRow, scan_id)
        assert scan.status == "failed"
        assert scan.error_message == "CFR decompile produced zero classes."


def test_multiple_scans_independent(_isolated_db):
    ids = []
    with Session(_isolated_db) as s:
        for i in range(3):
            s.add(ScanRow(original_filename=f"app-{i}.jar", jar_path=f"data/uploads/{i}.jar"))
        s.commit()
        ids = [r.id for r in s.query(ScanRow).all()]

    assert len(ids) == 3
    assert len(set(ids)) == 3  # all unique UUIDs


def test_updated_at_changes_on_update(_isolated_db):
    with Session(_isolated_db) as s:
        scan = ScanRow(original_filename="app.jar", jar_path="data/uploads/z.jar")
        s.add(scan)
        s.commit()
        scan_id = scan.id
        first_updated_at = scan.updated_at

    with Session(_isolated_db) as s:
        scan = s.get(ScanRow, scan_id)
        scan.current_phase = "triaging"
        s.commit()
        second_updated_at = scan.updated_at

    assert second_updated_at >= first_updated_at
