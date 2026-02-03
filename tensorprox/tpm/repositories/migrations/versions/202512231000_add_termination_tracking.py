"""Add termination tracking columns for reliable webapp notification.

This migration adds columns to ensure TPM can always notify webapp of
termination status, even when exit_hub records are deleted:

tensorprox_origins:
- last_exit_hub_id: UUID of the most recent exit_hub for this origin
- deletion_error: Internal error tracking (not exposed to webapp)

tensorprox_exit_hubs:
- purge_after: Timestamp when this record can be deleted by sweeper

Revision ID: 202512231000
Revises: 202512221500
Create Date: 2025-12-23 10:00:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "202512231000"
down_revision = "202512221500"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add last_exit_hub_id to origins - preserves exit_hub association
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD COLUMN IF NOT EXISTS last_exit_hub_id UUID
    """)

    # Add deletion_error for internal error tracking
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD COLUMN IF NOT EXISTS deletion_error TEXT
    """)

    # Add purge_after for deferred exit_hub cleanup
    op.execute("""
        ALTER TABLE tensorprox_exit_hubs
        ADD COLUMN IF NOT EXISTS purge_after TIMESTAMPTZ
    """)

    # Index for sweeper efficiency
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_exit_hubs_purge_after
        ON tensorprox_exit_hubs (purge_after)
        WHERE purge_after IS NOT NULL
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_exit_hubs_purge_after")
    op.execute("ALTER TABLE tensorprox_exit_hubs DROP COLUMN IF EXISTS purge_after")
    op.execute("ALTER TABLE tensorprox_origins DROP COLUMN IF EXISTS deletion_error")
    op.execute("ALTER TABLE tensorprox_origins DROP COLUMN IF EXISTS last_exit_hub_id")
