"""Record investigation owners without rewriting legacy records.

Revision ID: 0007_investigation_ownership
Revises: 0006_account_approval
Create Date: 2026-11-02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0007_investigation_ownership"
down_revision: Union[str, None] = "0006_account_approval"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(sa.Column("owner_user_id", sa.String(length=64), nullable=True))
        batch_op.create_foreign_key(
            "fk_investigations_owner_user_id_users",
            "users",
            ["owner_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index("ix_investigations_owner_user_id", ["owner_user_id"], unique=False)

    # Preserve ownership for legacy rows only when the lead investigator uniquely
    # matches an account username or full name. Ambiguous/unmatched rows stay
    # unassigned and are visible to administrators for deliberate reassignment.
    op.execute(
        """
        UPDATE investigations
        SET owner_user_id = (
            SELECT u.id
            FROM users AS u
            WHERE lower(trim(u.username)) = lower(trim(investigations.lead_investigator))
               OR (u.full_name IS NOT NULL AND lower(trim(u.full_name)) = lower(trim(investigations.lead_investigator)))
        )
        WHERE (
            SELECT count(*)
            FROM users AS u
            WHERE lower(trim(u.username)) = lower(trim(investigations.lead_investigator))
               OR (u.full_name IS NOT NULL AND lower(trim(u.full_name)) = lower(trim(investigations.lead_investigator)))
        ) = 1
        """
    )


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_index("ix_investigations_owner_user_id")
        batch_op.drop_constraint("fk_investigations_owner_user_id_users", type_="foreignkey")
        batch_op.drop_column("owner_user_id")
