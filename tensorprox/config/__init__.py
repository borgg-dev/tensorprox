"""
TensorProx Configuration Module.

Provides centralized configuration for all TensorProx components.
"""

from tensorprox.config.audit_config import (
    # Enums
    ThroughputLevel,
    DropReason,
    ExpectedAction,
    AttackCategory,

    # Config class
    AuditSystemConfig,
    AUDIT_CONFIG,
    get_audit_config,

    # Key constants
    EMA_ALPHA,
    VARIANCE_THRESHOLD,
    ELIGIBILITY_THRESHOLD,
    VOLUME_WEIGHT,
    AUDIT_WEIGHT,
    THROUGHPUT_PACKETS,
)

__all__ = [
    "ThroughputLevel",
    "DropReason",
    "ExpectedAction",
    "AttackCategory",
    "AuditSystemConfig",
    "AUDIT_CONFIG",
    "get_audit_config",
    "EMA_ALPHA",
    "VARIANCE_THRESHOLD",
    "ELIGIBILITY_THRESHOLD",
    "VOLUME_WEIGHT",
    "AUDIT_WEIGHT",
    "THROUGHPUT_PACKETS",
]
