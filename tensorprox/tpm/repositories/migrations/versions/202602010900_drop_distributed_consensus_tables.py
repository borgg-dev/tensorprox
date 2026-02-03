"""Drop distributed consensus tables - removing inter-TPM gossip/consensus.

Each TPM now operates independently with exclusive ownership of its origins.
No inter-TPM communication or failover needed.

Drops tables:
- distributed_assignments
- tpm_sync_state
- tpm_conflict_history

Revision ID: 202602010900
Revises: 202601261200
Create Date: 2026-02-01 09:00:00
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '202602010900'
down_revision = '202601261200'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop indexes first
    op.execute("DROP INDEX IF EXISTS idx_tpm_conflict_history_timestamp")
    op.execute("DROP INDEX IF EXISTS idx_tpm_conflict_history_origin")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_validator")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_state")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_miner")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_origin")

    # Drop tables
    op.execute("DROP TABLE IF EXISTS tpm_conflict_history")
    op.execute("DROP TABLE IF EXISTS tpm_sync_state")
    op.execute("DROP TABLE IF EXISTS distributed_assignments")


def downgrade() -> None:
    # Recreate distributed_assignments table
    op.execute("""
        CREATE TABLE IF NOT EXISTS distributed_assignments (
            id SERIAL PRIMARY KEY,
            origin_id VARCHAR(64) NOT NULL,
            miner_uid INTEGER NOT NULL,
            validator_uid INTEGER NOT NULL,
            assignment_nonce VARCHAR(64) NOT NULL UNIQUE,
            timestamp TIMESTAMPTZ NOT NULL,
            state VARCHAR(32) DEFAULT 'active',
            confirming_validators INTEGER[],
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    """)

    # Recreate indexes for distributed_assignments
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_distributed_assignments_origin
        ON distributed_assignments(origin_id);
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_distributed_assignments_miner
        ON distributed_assignments(miner_uid);
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_distributed_assignments_state
        ON distributed_assignments(state);
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_distributed_assignments_validator
        ON distributed_assignments(validator_uid);
    """)

    # Recreate tpm_sync_state table
    op.execute("""
        CREATE TABLE IF NOT EXISTS tpm_sync_state (
            validator_uid INTEGER PRIMARY KEY,
            last_seen_version BIGINT DEFAULT 0,
            last_sync_timestamp TIMESTAMPTZ,
            sync_status VARCHAR(32) DEFAULT 'unknown'
        );
    """)

    # Recreate tpm_conflict_history table
    op.execute("""
        CREATE TABLE IF NOT EXISTS tpm_conflict_history (
            id SERIAL PRIMARY KEY,
            origin_id VARCHAR(64) NOT NULL,
            conflict_type VARCHAR(32) NOT NULL,
            assignment_a JSONB NOT NULL,
            assignment_b JSONB NOT NULL,
            resolution_winner VARCHAR(32) NOT NULL,
            resolution_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            details JSONB
        );
    """)

    # Recreate indexes for conflict history
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_tpm_conflict_history_origin
        ON tpm_conflict_history(origin_id);
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_tpm_conflict_history_timestamp
        ON tpm_conflict_history(resolution_timestamp);
    """)
