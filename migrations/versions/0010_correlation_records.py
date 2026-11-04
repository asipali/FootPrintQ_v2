"""Add correlation_records table for findings and evidence correlation engine.

Revision ID: 0010_correlation_records
Revises: 0009_evidence_storage_backend
Create Date: 2026-11-04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_correlation_records"
down_revision: Union[str, None] = "0009_evidence_storage_backend"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "correlation_records",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("investigation_id", sa.String(length=64), sa.ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("correlation_rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("relationship_type", sa.String(length=32), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("asset_identifier", sa.String(length=255), nullable=False),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("source_modules", sa.JSON(), nullable=False),
        sa.Column("source_scanners", sa.JSON(), nullable=False),
        sa.Column("source_observation_ids", sa.JSON(), nullable=False),
        sa.Column("matching_attributes", sa.JSON(), nullable=False),
        sa.Column("related_vulnerability_id", sa.String(length=64), nullable=True),
        sa.Column("evidence_references", sa.JSON(), nullable=False),
        sa.Column("evidence_verification_status", sa.String(length=32), nullable=False, server_default="NOT_APPLICABLE"),
        sa.Column("lifecycle_status", sa.String(length=32), nullable=False, server_default="NEW"),
        sa.Column("correlation_status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("summary", sa.String(length=1024), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index("ix_corr_inv_id", "correlation_records", ["investigation_id"])
    op.create_index("ix_corr_rule_id", "correlation_records", ["correlation_rule_id"])
    op.create_index("ix_corr_rel_type", "correlation_records", ["relationship_type"])
    op.create_index("ix_corr_asset_id", "correlation_records", ["asset_identifier"])
    op.create_index("ix_corr_asset_type", "correlation_records", ["asset_type"])
    op.create_index("ix_corr_vuln_id", "correlation_records", ["related_vulnerability_id"])
    op.create_index("ix_corr_inv_asset", "correlation_records", ["investigation_id", "asset_identifier"])
    op.create_index("ix_corr_inv_rule", "correlation_records", ["investigation_id", "correlation_rule_id"])
    op.create_index("ix_corr_inv_rel", "correlation_records", ["investigation_id", "relationship_type"])


def downgrade() -> None:
    op.drop_index("ix_corr_inv_rel", table_name="correlation_records")
    op.drop_index("ix_corr_inv_rule", table_name="correlation_records")
    op.drop_index("ix_corr_inv_asset", table_name="correlation_records")
    op.drop_index("ix_corr_vuln_id", table_name="correlation_records")
    op.drop_index("ix_corr_asset_type", table_name="correlation_records")
    op.drop_index("ix_corr_asset_id", table_name="correlation_records")
    op.drop_index("ix_corr_rel_type", table_name="correlation_records")
    op.drop_index("ix_corr_rule_id", table_name="correlation_records")
    op.drop_index("ix_corr_inv_id", table_name="correlation_records")
    op.drop_table("correlation_records")

