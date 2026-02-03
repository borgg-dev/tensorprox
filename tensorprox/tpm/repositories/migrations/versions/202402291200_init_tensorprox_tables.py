"""Initial TensorProx management tables.

Revision ID: 202402291200
Revises:
Create Date: 2024-02-29 12:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "202402291200"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tensorprox_clients",
        sa.Column("client_id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=True),
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
    )

    op.create_table(
        "tensorprox_exit_hubs",
        sa.Column(
            "exit_hub_id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column(
            "client_id",
            sa.Text(),
            sa.ForeignKey("tensorprox_clients.client_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("origin_id", sa.Text(), nullable=False),
        sa.Column("origin_ip", sa.Text(), nullable=False),
        sa.Column("instance_id", sa.Text(), nullable=True),
        sa.Column("exit_hub_ip", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("wg_interface", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
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
    )

    op.create_index(
        "ix_tensorprox_exit_hubs_client_id",
        "tensorprox_exit_hubs",
        ["client_id"],
    )
    op.create_index(
        "ix_tensorprox_exit_hubs_origin_id",
        "tensorprox_exit_hubs",
        ["origin_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_tensorprox_exit_hubs_origin_id", table_name="tensorprox_exit_hubs")
    op.drop_index("ix_tensorprox_exit_hubs_client_id", table_name="tensorprox_exit_hubs")
    op.drop_table("tensorprox_exit_hubs")
    op.drop_table("tensorprox_clients")
