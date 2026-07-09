"""Request/response domain models for the /scans API surface (spec/api.md)."""
from datetime import datetime

from pydantic import BaseModel


class ScanCreateData(BaseModel):
    """Response body of POST /scans."""

    scan_id: str
    status: str
    current_phase: str


class ScanStatusData(BaseModel):
    """Response body of GET /scans/{scan_id}/status."""

    scan_id: str
    status: str
    current_phase: str
    is_spring_boot: bool | None = None
    class_count: int | None = None
    error: str | None = None


class ScanDetailData(BaseModel):
    """Response body of GET /scans/{scan_id}."""

    scan_id: str
    original_filename: str
    uploaded_at: datetime
    status: str
    current_phase: str
    is_spring_boot: bool | None = None
    class_count: int | None = None
    triaged_class_count: int | None = None
    risk_score: int | None = None
    report_markdown: str | None = None
    findings: list[dict] | None = None
    dependencies: list[dict] | None = None
    total_input_tokens: int | None = None
    total_output_tokens: int | None = None
    estimated_cost_usd: float | None = None
    error: str | None = None
