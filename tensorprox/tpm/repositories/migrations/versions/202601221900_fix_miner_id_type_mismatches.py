"""Fix miner_id type mismatches (TEXT to UUID).

Converts miner_id columns from TEXT to UUID in:
1. tensorprox_origins
2. tensorprox_exit_hubs

This enables proper foreign key constraints to tensorprox_miners.miner_id
and tensorprox_miner_shards(miner_id, shard_id).

Revision ID: 202601221900
Revises: 202601221800
Create Date: 2026-01-22 19:00:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "202601221900"
down_revision = "202601221800"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Convert tensorprox_origins.miner_id from TEXT to UUID
    op.execute("""
        ALTER TABLE tensorprox_origins
        ALTER COLUMN miner_id TYPE UUID
        USING miner_id::uuid;
    """)

    # Convert tensorprox_exit_hubs.miner_id from TEXT to UUID
    op.execute("""
        ALTER TABLE tensorprox_exit_hubs
        ALTER COLUMN miner_id TYPE UUID
        USING miner_id::uuid;
    """)

    # Add foreign key constraint: origins.miner_id -> miners.miner_id
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD CONSTRAINT fk_origin_miner
            FOREIGN KEY (miner_id)
            REFERENCES tensorprox_miners(miner_id)
            ON DELETE SET NULL;
    """)

    # Add foreign key constraint: exit_hubs.miner_id -> miners.miner_id
    op.execute("""
        ALTER TABLE tensorprox_exit_hubs
        ADD CONSTRAINT fk_exit_hub_miner
            FOREIGN KEY (miner_id)
            REFERENCES tensorprox_miners(miner_id)
            ON DELETE SET NULL;
    """)

    # Add composite foreign key: origins(miner_id, shard_id) -> miner_shards(miner_id, shard_id)
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD CONSTRAINT fk_origin_shard
            FOREIGN KEY (miner_id, shard_id)
            REFERENCES tensorprox_miner_shards(miner_id, shard_id)
            ON DELETE SET NULL;
    """)


def downgrade() -> None:
    # Remove foreign key constraints
    op.execute("ALTER TABLE tensorprox_origins DROP CONSTRAINT IF EXISTS fk_origin_shard")
    op.execute("ALTER TABLE tensorprox_exit_hubs DROP CONSTRAINT IF EXISTS fk_exit_hub_miner")
    op.execute("ALTER TABLE tensorprox_origins DROP CONSTRAINT IF EXISTS fk_origin_miner")

    # Convert back to TEXT (with explicit cast)
    op.execute("""
        ALTER TABLE tensorprox_exit_hubs
        ALTER COLUMN miner_id TYPE TEXT
        USING miner_id::text;
    """)

    op.execute("""
        ALTER TABLE tensorprox_origins
        ALTER COLUMN miner_id TYPE TEXT
        USING miner_id::text;
    """)
