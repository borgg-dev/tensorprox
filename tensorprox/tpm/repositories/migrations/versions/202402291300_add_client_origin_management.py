"""Add client/origin management tables and sequences.

Revision ID: 202402291300
Revises: 202402291200
Create Date: 2024-02-29 13:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "202402291300"
down_revision = "202402291200"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SEQUENCE IF NOT EXISTS tensorprox_client_id_seq START 1;")

    op.add_column(
        "tensorprox_clients",
        sa.Column(
            "auto_generated",
            sa.Boolean(),
            server_default=sa.text("FALSE"),
            nullable=False,
        ),
    )
    op.add_column(
        "tensorprox_clients",
        sa.Column(
            "next_origin_number",
            sa.Integer(),
            server_default="1",
            nullable=False,
        ),
    )

    op.create_table(
        "tensorprox_origins",
        sa.Column(
            "client_id",
            sa.Text(),
            sa.ForeignKey("tensorprox_clients.client_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("origin_id", sa.Text(), nullable=False),
        sa.Column("origin_num", sa.Integer(), nullable=True),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default="provisioning",
        ),
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
        sa.PrimaryKeyConstraint("client_id", "origin_id", name="pk_tensorprox_origins"),
    )
    op.create_index(
        "ix_tensorprox_origins_origin_id",
        "tensorprox_origins",
        ["origin_id"],
        unique=True,
    )
    op.create_index(
        "ix_tensorprox_origins_status",
        "tensorprox_origins",
        ["status"],
    )
    op.create_index(
        "ix_tensorprox_origins_origin_num",
        "tensorprox_origins",
        ["client_id", "origin_num"],
    )


def downgrade() -> None:
    op.drop_index("ix_tensorprox_origins_origin_num", table_name="tensorprox_origins")
    op.drop_index("ix_tensorprox_origins_status", table_name="tensorprox_origins")
    op.drop_index("ix_tensorprox_origins_origin_id", table_name="tensorprox_origins")
    op.drop_table("tensorprox_origins")

    op.drop_column("tensorprox_clients", "next_origin_number")
    op.drop_column("tensorprox_clients", "auto_generated")

    op.execute("DROP SEQUENCE IF EXISTS tensorprox_client_id_seq;")
