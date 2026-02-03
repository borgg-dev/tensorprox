"""Remove global unique constraint on origin_id to allow per-client numbering.

Revision ID: 202403011230
Revises: 202403011200
Create Date: 2024-03-01 12:30:00.000000
"""
from __future__ import annotations

from alembic import op


revision = "202403011230"
down_revision = "202403011200"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_tensorprox_origins_origin_id", table_name="tensorprox_origins")


def downgrade() -> None:
    op.create_index(
        "ix_tensorprox_origins_origin_id",
        "tensorprox_origins",
        ["origin_id"],
        unique=True,
    )
