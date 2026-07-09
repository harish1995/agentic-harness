import io
import threading
import zipfile
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Response, UploadFile
from sqlalchemy.orm import Session

from api._common import api_error, ok
from config.settings import get_settings
from db.models import ScanRow
from db.session import get_session
from domain.scan import ScanCreateData, ScanDetailData, ScanStatusData
from observability.events import get_logger

router = APIRouter()

_logger = get_logger("api.scans")


def _row_to_status(row: ScanRow) -> ScanStatusData:
    return ScanStatusData(
        scan_id=row.id,
        status=row.status,
        current_phase=row.current_phase,
        is_spring_boot=row.is_spring_boot,
        class_count=row.class_count,
        error=row.error_message if row.status == "failed" else None,
    )


def _row_to_detail(row: ScanRow) -> ScanDetailData:
    import json

    findings = json.loads(row.findings_json) if row.findings_json else None
    dependencies = json.loads(row.dependencies_json) if row.dependencies_json else None
    return ScanDetailData(
        scan_id=row.id,
        original_filename=row.original_filename,
        uploaded_at=row.uploaded_at,
        status=row.status,
        current_phase=row.current_phase,
        is_spring_boot=row.is_spring_boot,
        class_count=row.class_count,
        triaged_class_count=row.triaged_class_count,
        risk_score=row.risk_score,
        report_markdown=row.report_markdown,
        findings=findings,
        dependencies=dependencies,
        total_input_tokens=row.total_input_tokens,
        total_output_tokens=row.total_output_tokens,
        estimated_cost_usd=row.estimated_cost_usd,
        error=row.error_message if row.status == "failed" else None,
    )


@router.post("/scans")
def create_scan(file: UploadFile = File(...), session: Session = Depends(get_session)) -> dict:
    settings = get_settings()

    raw = file.file.read()
    if not raw:
        raise api_error("INVALID_FILE", "Uploaded file is empty.", 400)

    if not zipfile.is_zipfile(io.BytesIO(raw)):
        raise api_error(
            "INVALID_FILE",
            "Uploaded file is not a valid JAR (not a readable ZIP archive).",
            400,
        )

    max_bytes = settings.max_upload_mb * 1024 * 1024
    if len(raw) > max_bytes:
        raise api_error(
            "FILE_TOO_LARGE",
            f"File exceeds the maximum upload size of {settings.max_upload_mb} MB.",
            413,
        )

    existing = session.query(ScanRow).filter(ScanRow.status == "processing").first()
    if existing is not None:
        raise api_error(
            "SCAN_IN_PROGRESS",
            "A scan is already in progress. Wait for it to finish before starting another.",
            409,
        )

    scan_id = str(uuid4())
    try:
        upload_dir = Path(settings.scan_upload_dir)
        upload_dir.mkdir(parents=True, exist_ok=True)
        jar_path = upload_dir / f"{scan_id}.jar"
        jar_path.write_bytes(raw)

        row = ScanRow(
            id=scan_id,
            original_filename=file.filename or "upload.jar",
            jar_path=str(jar_path),
            status="processing",
            current_phase="queued",
        )
        session.add(row)
        session.commit()
    except Exception as exc:  # noqa: BLE001 — genuinely unexpected failure
        session.rollback()
        _logger.error("scan_create_failed", scan_id=scan_id, error=str(exc))
        raise api_error("INTERNAL_ERROR", "Unexpected failure creating the scan.", 500) from exc

    from graph.runner import run_scan  # deferred import — see api-and-db handoff notes

    thread = threading.Thread(target=run_scan, args=(scan_id, str(jar_path)), daemon=True)
    thread.start()

    _logger.info("scan_created", scan_id=scan_id, filename=row.original_filename)

    return ok(
        ScanCreateData(scan_id=scan_id, status="processing", current_phase="queued").model_dump()
    )


@router.get("/scans/{scan_id}/status")
def get_scan_status(scan_id: str, session: Session = Depends(get_session)) -> dict:
    row = session.get(ScanRow, scan_id)
    if row is None:
        raise api_error("NOT_FOUND", f"Scan {scan_id} not found", 404)
    return ok(_row_to_status(row).model_dump())


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> dict:
    row = session.get(ScanRow, scan_id)
    if row is None:
        raise api_error("NOT_FOUND", f"Scan {scan_id} not found", 404)
    return ok(_row_to_detail(row).model_dump())


@router.get("/scans/{scan_id}/download")
def download_scan_report(scan_id: str, session: Session = Depends(get_session)) -> Response:
    row = session.get(ScanRow, scan_id)
    if row is None:
        raise api_error("NOT_FOUND", f"Scan {scan_id} not found", 404)

    if row.status != "completed":
        if row.status == "failed":
            message = row.error_message or "Scan failed."
        else:
            message = f"Report is not ready yet — scan is still {row.current_phase}."
        raise api_error("NOT_READY", message, 409)

    return Response(
        content=row.report_markdown or "",
        media_type="text/markdown",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{row.original_filename}-security-report.md"'
            )
        },
    )
