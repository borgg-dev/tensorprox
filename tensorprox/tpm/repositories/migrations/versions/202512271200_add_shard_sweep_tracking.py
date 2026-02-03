"""Add shard sweep tracking columns.

Adds sweep_after and origin_count columns to tensorprox_miner_shards
for the Shard Sweeper service that cleans up empty shards after grace period.

Revision ID: 202512271200
Revises: 202512261200
Create Date: 2025-12-27 12:00:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "202512271200"
down_revision = "202512261200"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE tensorprox_miner_shards
        ADD COLUMN IF NOT EXISTS sweep_after TIMESTAMPTZ;
    """)
    op.execute("""
        ALTER TABLE tensorprox_miner_shards
        ADD COLUMN IF NOT EXISTS origin_count INTEGER NOT NULL DEFAULT 0;
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_miner_shards_sweep
        ON tensorprox_miner_shards(sweep_after)
        WHERE sweep_after IS NOT NULL;
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_miner_shards_sweep")
    op.execute("ALTER TABLE tensorprox_miner_shards DROP COLUMN IF EXISTS origin_count")
    op.execute("ALTER TABLE tensorprox_miner_shards DROP COLUMN IF EXISTS sweep_after")
