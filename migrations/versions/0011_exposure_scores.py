"""Add exposure_scores table for finalized exposure scoring engine.

Revision ID: 0011_exposure_scores
Revises: 0010_correlation_records
Create Date: 2026-11-04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0011_exposure_scores"
down_revision: Union[str, None] = "0010_correlation_records"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "exposure_scores",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("investigation_id", sa.String(length=64), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("formula_version", sa.String(length=32), nullable=False),
        sa.Column("formula_weights", sa.JSON(), nullable=False),
        sa.Column("raw_factor_inputs", sa.JSON(), nullable=False),
        sa.Column("normalized_factor_scores", sa.JSON(), nullable=False),
        sa.Column("weighted_contributions", sa.JSON(), nullable=False),
        sa.Column("total_score", sa.Integer(), nullable=False),
        sa.Column("renormalized_score", sa.Float(), nullable=True),
        sa.Column("risk_tier", sa.String(length=32), nullable=False),
        sa.Column("assessment_status", sa.String(length=32), nullable=False),
        sa.Column("coverage_percentage", sa.Integer(), nullable=False),
        sa.Column("is_fully_assessed", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("coverage_metadata", sa.JSON(), nullable=False),
        sa.Column("scanner_availability", sa.JSON(), nullable=False),
        sa.Column("source_observation_ids", sa.JSON(), nullable=False),
        sa.Column("reviewer_notes", sa.Text(), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_exp_score_inv_id", "exposure_scores", ["investigation_id"])
    op.create_index("ix_exp_score_formula", "exposure_scores", ["formula_version"])
    op.create_index("ix_exp_score_is_active", "exposure_scores", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_exp_score_is_active", table_name="exposure_scores")
    op.drop_index("ix_exp_score_formula", table_name="exposure_scores")
    op.drop_index("ix_exp_score_inv_id", table_name="exposure_scores")
    op.drop_table("exposure_scores")

