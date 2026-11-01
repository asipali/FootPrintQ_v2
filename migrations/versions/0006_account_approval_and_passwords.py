"""Add investigator approval metadata and password lifecycle fields.

Revision ID: 0006_account_approval
Revises: 0005_vuln
Create Date: 2026-11-02
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0006_account_approval"
down_revision: Union[str, None] = "0005_vuln"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.String(length=128), nullable=True))
    op.add_column(
        "users",
        sa.Column("account_status", sa.String(length=16), nullable=False, server_default="active"),
    )
    op.add_column("users", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    if op.get_bind().dialect.name == "sqlite":
        op.execute(
            "ALTER TABLE users ADD COLUMN approved_by_id VARCHAR(64) "
            "REFERENCES users (id) ON DELETE SET NULL"
        )
    else:
        op.add_column(
            "users",
            sa.Column(
                "approved_by_id",
                sa.String(length=64),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    op.add_column("users", sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True))
    if op.get_bind().dialect.name == "sqlite":
        op.execute(
            "ALTER TABLE users ADD COLUMN rejected_by_id VARCHAR(64) "
            "REFERENCES users (id) ON DELETE SET NULL"
        )
    else:
        op.add_column(
            "users",
            sa.Column(
                "rejected_by_id",
                sa.String(length=64),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
        )
    op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_account_status", "users", ["account_status"])


def downgrade() -> None:
    op.drop_index("ix_users_account_status", table_name="users")
    op.drop_column("users", "password_changed_at")
    op.drop_column("users", "rejected_by_id")
    op.drop_column("users", "rejected_at")
    op.drop_column("users", "approved_by_id")
    op.drop_column("users", "approved_at")
    op.drop_column("users", "account_status")
    op.drop_column("users", "full_name")
