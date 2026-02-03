"""Defer FK constraints due to type mismatch (Phase 4).

This migration implements Phase 4 of the TPM database restructure:
- Documents type mismatch between origins.miner_id (TEXT) and miner_shards.miner_id (UUID)
- Adds partial indexes for improved query performance with NULL handling
- Defers FK constraint until column types are aligned in future migration

TYPE MISMATCH DETAILS:
---------------------
tensorprox_origins.miner_id:        TEXT (from migration 202402291330)
tensorprox_miner_shards.miner_id:   UUID (from migration 202512171500)
tensorprox_miners.miner_id:         UUID (from migration 202403011400)

DESIRED FK CONSTRAINT (blocked by type mismatch):
-------------------------------------------------
ALTER TABLE tensorprox_origins
    ADD CONSTRAINT fk_origin_shard
        FOREIGN KEY (miner_id, shard_id)
        REFERENCES tensorprox_miner_shards(miner_id, shard_id)
        ON DELETE SET NULL;

CURRENT WORKAROUND:
-------------------
Application code uses explicit casting in JOINs:
    ON o.miner_id::uuid = ms.miner_id AND o.shard_id = ms.shard_id

FUTURE MIGRATION:
-----------------
A future migration will:
1. Migrate data: Convert existing TEXT miner_id values to UUID format
2. Alter column: ALTER TABLE tensorprox_origins ALTER COLUMN miner_id TYPE UUID USING miner_id::uuid
3. Add FK: Add the fk_origin_shard constraint as shown above

DECISION RATIONALE:
-------------------
- Changing column types on live tables is risky and requires careful data validation
- Current ::uuid casting in JOINs already works correctly
- Indexes on (miner_id, shard_id) provide query performance benefits
- FK constraint provides data integrity but can be added later when types align

Revision ID: 202512171600
Revises: 202512171500
Create Date: 2025-12-17 16:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "202512171600"
down_revision = "202512171500"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add partial indexes to improve query performance for non-NULL values
    # These are useful for JOINs when shard_id/tensorprox_ip are populated

    # Partial index for origins with assigned shards (excludes NULL shard_id)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_origins_assigned_shard
        ON tensorprox_origins(miner_id, shard_id)
        WHERE shard_id IS NOT NULL
    """)

    # Partial index for origins with tensorprox_ip assigned (active deployments)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_tensorprox_origins_active_deployment
        ON tensorprox_origins(tensorprox_ip)
        WHERE tensorprox_ip IS NOT NULL AND status = 'active'
    """)

    # Add a check constraint to ensure miner_id is valid UUID format when not NULL
    # This helps prevent bad data before we convert to UUID type
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD CONSTRAINT check_miner_id_uuid_format
        CHECK (miner_id IS NULL OR miner_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    """)

    # NOTE: We intentionally do NOT add check_shard_miner_consistency constraint.
    # The deployment workflow sets miner_id BEFORE shard_id:
    #   1. prepare_deploy -> set_miner_assignment() sets miner_id
    #   2. target selection -> sets shard_id on request
    #   3. registration -> set_deployment_result() sets shard_id + tensorprox_ip
    # A constraint requiring both to be set/unset together would break this flow.


def downgrade() -> None:
    # Drop check constraints
    op.execute("ALTER TABLE tensorprox_origins DROP CONSTRAINT IF EXISTS check_shard_miner_consistency")
    op.execute("ALTER TABLE tensorprox_origins DROP CONSTRAINT IF EXISTS check_miner_id_uuid_format")

    # Drop partial indexes
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_origins_active_deployment")
    op.execute("DROP INDEX IF EXISTS ix_tensorprox_origins_assigned_shard")
