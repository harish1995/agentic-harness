from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Float, Integer, Text, TIMESTAMP
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _uuid() -> str:
    return str(uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    """One row per uploaded JAR / scan attempt. See spec/data.md → Entity: Scan."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=_uuid)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    jar_path: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=_now
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, default="processing")
    current_phase: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    current_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_spring_boot: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_spring_security: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    class_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    triaged_class_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    decompile_errors_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    dependencies_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_findings_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    report_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    estimated_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, default=_now, onupdate=_now
    )
