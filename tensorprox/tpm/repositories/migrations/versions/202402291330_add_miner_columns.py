"""Add miner metadata columns to origins and exit hubs.

Revision ID: 202402291330
Revises: 202402291300
Create Date: 2024-02-29 13:30:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "202402291330"
down_revision = "202402291300"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tensorprox_exit_hubs",
        sa.Column("miner_id", sa.Text(), nullable=True),
    )
    op.add_column(
        "tensorprox_exit_hubs",
        sa.Column("miner_ip", sa.Text(), nullable=True),
    )

    op.add_column(
        "tensorprox_origins",
        sa.Column("miner_id", sa.Text(), nullable=True),
    )
    op.add_column(
        "tensorprox_origins",
        sa.Column("miner_ip", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tensorprox_origins", "miner_ip")
    op.drop_column("tensorprox_origins", "miner_id")
    op.drop_column("tensorprox_exit_hubs", "miner_ip")
    op.drop_column("tensorprox_exit_hubs", "miner_id")
