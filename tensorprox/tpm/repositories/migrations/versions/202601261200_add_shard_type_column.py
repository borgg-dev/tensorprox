"""Add shard_type column to tensorprox_miner_shards.

Revision ID: 202601261200
Revises: 202601221900
Create Date: 2026-01-26 12:00:00

Two-tier shard architecture:
- 'audit': Created by miner on startup, used for validator scoring only (exactly 1 per miner)
- 'production': Created by TPM on-demand, used for customer origins

Existing shards default to 'audit' since they were created on miner startup.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '202601261200'
down_revision = '202601221900'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add shard_type column with default 'audit'
    op.execute("""
        ALTER TABLE tensorprox_miner_shards
        ADD COLUMN IF NOT EXISTS shard_type VARCHAR(20) DEFAULT 'audit';
    """)

    # Create index for efficient filtering by shard_type
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_miner_shards_shard_type
        ON tensorprox_miner_shards(shard_type);
    """)

    # Create composite index for miner + type queries
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_miner_shards_miner_type
        ON tensorprox_miner_shards(miner_id, shard_type);
    """)

    # Mark all existing shards as 'audit' (they were created on miner startup)
    op.execute("""
        UPDATE tensorprox_miner_shards
        SET shard_type = 'audit'
        WHERE shard_type IS NULL;
    """)


def downgrade() -> None:
    op.execute("""
        DROP INDEX IF EXISTS idx_miner_shards_miner_type;
    """)
    op.execute("""
        DROP INDEX IF EXISTS idx_miner_shards_shard_type;
    """)
    op.execute("""
        ALTER TABLE tensorprox_miner_shards
        DROP COLUMN IF EXISTS shard_type;
    """)
