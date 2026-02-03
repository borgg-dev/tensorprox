"""Add system errors table for capturing orphan errors.

Revision ID: 202512261200
Revises: 202512231000
Create Date: 2025-12-26

Purpose:
    Captures system-level errors that don't belong to specific exit hubs or other
    entities. These are "orphan" errors that occur before entity assignment or
    at the system infrastructure level.

Error sources captured:
    - target_selection: Miner unreachable during target selection
    - capacity_check: Shard capacity check failures
    - api_validation: Request-level validation errors
    - geolocation: IP geolocation failures
    - queue: Validation queue overflow
    - metrics: Metrics forwarder errors
"""
from alembic import op


revision = "202512261200"
down_revision = "202512231000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create system errors table with indexes."""
    op.execute("""
        CREATE TABLE IF NOT EXISTS tensorprox_system_errors (
            id              SERIAL PRIMARY KEY,
            error_source    TEXT NOT NULL,
            error_code      TEXT NOT NULL,
            error_message   TEXT NOT NULL,
            context         JSONB,
            exit_hub_id     UUID,
            origin_id       TEXT,
            miner_id        UUID,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    # Index for querying by error source (target_selection, capacity_check, etc.)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_system_errors_source
        ON tensorprox_system_errors (error_source);
    """)

    # Index for time-based queries and cleanup
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_system_errors_created
        ON tensorprox_system_errors (created_at);
    """)

    # Partial index for miner-related errors (only indexes non-NULL miner_id)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_system_errors_miner
        ON tensorprox_system_errors (miner_id)
        WHERE miner_id IS NOT NULL;
    """)


def downgrade() -> None:
    """Drop system errors table and indexes."""
    op.execute("DROP TABLE IF EXISTS tensorprox_system_errors CASCADE;")
