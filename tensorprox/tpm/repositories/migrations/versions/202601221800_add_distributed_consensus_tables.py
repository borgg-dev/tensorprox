"""Add distributed consensus tables for TPM-Lite decentralization.

Adds three tables required for decentralized TPM operation:
1. distributed_assignments - Tracks origin-to-miner assignments across validators
2. tpm_sync_state - Tracks sync status between validators
3. tpm_conflict_history - Logs assignment conflicts for debugging

Revision ID: 202601221800
Revises: 202512271200
Create Date: 2026-01-22 18:00:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "202601221800"
down_revision = "202512271200"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create distributed_assignments table
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

    # Create indexes for distributed_assignments
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

    # Create tpm_sync_state table
    op.execute("""
        CREATE TABLE IF NOT EXISTS tpm_sync_state (
            validator_uid INTEGER PRIMARY KEY,
            last_seen_version BIGINT DEFAULT 0,
            last_sync_timestamp TIMESTAMPTZ,
            sync_status VARCHAR(32) DEFAULT 'unknown'
        );
    """)

    # Create tpm_conflict_history table
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

    # Create index for conflict history lookups
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_tpm_conflict_history_origin
        ON tpm_conflict_history(origin_id);
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_tpm_conflict_history_timestamp
        ON tpm_conflict_history(resolution_timestamp);
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_tpm_conflict_history_timestamp")
    op.execute("DROP INDEX IF EXISTS idx_tpm_conflict_history_origin")
    op.execute("DROP TABLE IF EXISTS tpm_conflict_history")
    op.execute("DROP TABLE IF EXISTS tpm_sync_state")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_validator")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_state")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_miner")
    op.execute("DROP INDEX IF EXISTS idx_distributed_assignments_origin")
    op.execute("DROP TABLE IF EXISTS distributed_assignments")
