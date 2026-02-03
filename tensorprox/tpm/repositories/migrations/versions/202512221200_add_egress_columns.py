"""Add egress columns to tensorprox_origins.

This migration adds columns to support egress routing functionality:
- egress_enabled: Whether this origin uses TensorProx for outbound traffic
- egress_questionnaire: Stores onboarding questionnaire responses as JSONB
- egress_activated_at: Timestamp when egress was activated

Revision ID: 202512221200
Revises: 202512171600
Create Date: 2025-12-22 12:00:00.000000
"""
from __future__ import annotations

from alembic import op

revision = "202512221200"
down_revision = "202512171600"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD COLUMN IF NOT EXISTS egress_enabled BOOLEAN DEFAULT FALSE
    """)
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD COLUMN IF NOT EXISTS egress_questionnaire JSONB
    """)
    op.execute("""
        ALTER TABLE tensorprox_origins
        ADD COLUMN IF NOT EXISTS egress_activated_at TIMESTAMPTZ
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE tensorprox_origins DROP COLUMN IF EXISTS egress_activated_at")
    op.execute("ALTER TABLE tensorprox_origins DROP COLUMN IF EXISTS egress_questionnaire")
    op.execute("ALTER TABLE tensorprox_origins DROP COLUMN IF EXISTS egress_enabled")
