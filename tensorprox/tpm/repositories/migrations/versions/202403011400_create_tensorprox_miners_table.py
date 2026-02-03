"""Create tensorprox_miners table.

Revision ID: 202403011400
Revises: 202403011230
Create Date: 2024-03-01 14:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "202403011400"
down_revision = "202403011230"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tensorprox_miners",
        sa.Column("miner_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("current_ip", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default="active",
        ),
        sa.Column("secret_hash", sa.Text(), nullable=False),
        sa.Column("secret_plaintext", sa.Text(), nullable=False),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_tensorprox_miners_status",
        "tensorprox_miners",
        ["status"],
    )
    op.create_index(
        "ix_tensorprox_miners_last_seen",
        "tensorprox_miners",
        ["last_seen"],
    )


def downgrade() -> None:
    op.drop_index("ix_tensorprox_miners_last_seen", table_name="tensorprox_miners")
    op.drop_index("ix_tensorprox_miners_status", table_name="tensorprox_miners")
    op.drop_table("tensorprox_miners")
