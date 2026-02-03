"""Add status index for exit hubs to accelerate filtered reads.

Revision ID: 202403011200
Revises: 202402291330
Create Date: 2024-03-01 12:00:00.000000
"""
from __future__ import annotations

from alembic import op


revision = "202403011200"
down_revision = "202402291330"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_tensorprox_exit_hubs_status",
        "tensorprox_exit_hubs",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index("ix_tensorprox_exit_hubs_status", table_name="tensorprox_exit_hubs")
