"""Add miner operation queue table for FIFO processing.

Revision ID: 202512221500
Revises: 202512221200
Create Date: 2025-12-22

Purpose:
    Implements per-miner FIFO queue to prevent concurrent long-running operations
    from overwhelming miners. Each miner processes one operation at a time.

Operations queued:
    - deploy_shard: Creates scrubber infrastructure (~5-7 min)
    - register_origin: Registers origin with miner (~30-60s)
    - delete_origin: Removes origin from miner (~30-60s)
"""
from alembic import op


revision = "202512221500"
down_revision = "202512221200"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create miner operation queue table with FIFO indexes."""
    op.execute("""
        CREATE TABLE IF NOT EXISTS tensorprox_miner_operations (
            operation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            miner_id UUID NOT NULL,
            operation_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            priority INTEGER NOT NULL DEFAULT 100,
            payload JSONB NOT NULL DEFAULT '{}',
            result JSONB,
            error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            started_at TIMESTAMPTZ,
            completed_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            exit_hub_id UUID,
            origin_id TEXT,
            shard_id TEXT,

            CONSTRAINT check_operation_type CHECK (
                operation_type IN ('deploy_shard', 'register_origin', 'delete_origin')
            ),
            CONSTRAINT check_status CHECK (
                status IN ('queued', 'processing', 'succeeded', 'failed', 'cancelled')
            )
        );
    """)

    # FIFO index: find next queued operation per miner ordered by creation time
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_miner_operations_queue
        ON tensorprox_miner_operations (miner_id, created_at)
        WHERE status = 'queued';
    """)

    # Find currently processing operation per miner (should be at most one)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_miner_operations_processing
        ON tensorprox_miner_operations (miner_id)
        WHERE status = 'processing';
    """)

    # Cleanup index for old completed operations
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_miner_operations_completed
        ON tensorprox_miner_operations (completed_at)
        WHERE status IN ('succeeded', 'failed', 'cancelled');
    """)

    # Trace operations by exit_hub_id (for cancel flow)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_miner_operations_exit_hub
        ON tensorprox_miner_operations (exit_hub_id)
        WHERE exit_hub_id IS NOT NULL;
    """)

    # Trace operations by origin_id
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_miner_operations_origin
        ON tensorprox_miner_operations (origin_id)
        WHERE origin_id IS NOT NULL;
    """)


def downgrade() -> None:
    """Drop miner operation queue table."""
    op.execute("DROP TABLE IF EXISTS tensorprox_miner_operations CASCADE;")
