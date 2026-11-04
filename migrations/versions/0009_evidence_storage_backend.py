"""Add storage_backend column to evidence table for object storage abstraction.

Revision ID: 0009_evidence_storage_backend
Revises: 0008_durable_jobs
Create Date: 2026-11-02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_evidence_storage_backend"
down_revision: Union[str, None] = "0008_durable_jobs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add storage_backend column with default 'filesystem'
    op.add_column(
        "evidence",
        sa.Column(
            "storage_backend",
            sa.String(length=32),
            server_default="filesystem",
            nullable=False,
        ),
    )
    # Ensure any existing rows explicitly have 'filesystem'
    op.execute("UPDATE evidence SET storage_backend = 'filesystem' WHERE storage_backend IS NULL")


def downgrade() -> None:
    op.drop_column("evidence", "storage_backend")

