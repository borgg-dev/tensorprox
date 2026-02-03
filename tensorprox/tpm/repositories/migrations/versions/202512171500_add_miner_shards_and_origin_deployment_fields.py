"""Add miner shards table and origin deployment fields.

This migration implements Phase 1 of the TPM database restructure:
- Creates tensorprox_miner_shards table to establish region ownership
- Adds shard_id and tensorprox_ip columns to tensorprox_origins
- Additive only - no column drops, no FK constraints yet

Revision ID: 202512171500
Revises: 202403011400
Create Date: 2025-12-17 15:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "202512171500"
down_revision = "202403011400"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create tensorprox_miner_shards table if it doesn't exist
    op.execute("""
        CREATE TABLE IF NOT EXISTS tensorprox_miner_shards (
            miner_id UUID NOT NULL,
            shard_id TEXT NOT NULL,
            region TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            last_synced_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT pk_tensorprox_miner_shards PRIMARY KEY (miner_id, shard_id)
        )
    """)

    # Create indexes on tensorprox_miner_shards (IF NOT EXISTS)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_miner_shards_region
        ON tensorprox_miner_shards(region)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_miner_shards_status
        ON tensorprox_miner_shards(status)
    """)

    # Add new columns to tensorprox_origins (IF NOT EXISTS)
    # These are nullable for now - data will be migrated in Phase 2
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD COLUMN IF NOT EXISTS shard_id TEXT
    """)
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD COLUMN IF NOT EXISTS tensorprox_ip TEXT
    """)

    # Create indexes on tensorprox_origins new columns (IF NOT EXISTS)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_origins_miner_shard
        ON tensorprox_origins(miner_id, shard_id)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_origins_tensorprox_ip
        ON tensorprox_origins(tensorprox_ip)
    """)


def downgrade() -> None:
    # Drop indexes on tensorprox_origins (IF EXISTS for idempotency)
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_origins_tensorprox_ip")
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_origins_miner_shard")

    # Drop columns from tensorprox_origins (IF EXISTS for idempotency)
    op.execute("ALTER TABLE tensorprox_origins DROP COLUMN IF EXISTS tensorprox_ip")
    op.execute("ALTER TABLE tensorprox_origins DROP COLUMN IF EXISTS shard_id")

    # Drop indexes on tensorprox_miner_shards
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_miner_shards_status")
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_miner_shards_region")

    # Drop tensorprox_miner_shards table
    op.execute("DROP TABLE IF EXISTS tensorprox_miner_shards")
