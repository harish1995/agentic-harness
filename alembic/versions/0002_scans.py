"""scans

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # `runs` (the skeleton's generic transform_text capability) was never used in
    # production — this project's single capability is JAR scanning, not generic
    # text transforms — so it is dropped, not kept alongside `scans`.
    op.drop_table("runs")

    op.create_table(
        "scans",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("original_filename", sa.Text(), nullable=False),
        sa.Column("jar_path", sa.Text(), nullable=False),
        sa.Column("uploaded_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("current_phase", sa.Text(), nullable=False),
        sa.Column("current_detail", sa.Text(), nullable=True),
        sa.Column("is_spring_boot", sa.Boolean(), nullable=True),
        sa.Column("has_spring_security", sa.Boolean(), nullable=True),
        sa.Column("class_count", sa.Integer(), nullable=True),
        sa.Column("triaged_class_count", sa.Integer(), nullable=True),
        sa.Column("decompile_errors_json", sa.Text(), nullable=True),
        sa.Column("dependencies_json", sa.Text(), nullable=True),
        sa.Column("secret_findings_count", sa.Integer(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("report_markdown", sa.Text(), nullable=True),
        sa.Column("findings_json", sa.Text(), nullable=True),
        sa.Column("total_input_tokens", sa.Integer(), nullable=True),
        sa.Column("total_output_tokens", sa.Integer(), nullable=True),
        sa.Column("estimated_cost_usd", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("scans")

    op.create_table(
        "runs",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("input_text", sa.Text(), nullable=True),
        sa.Column("output_text", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
