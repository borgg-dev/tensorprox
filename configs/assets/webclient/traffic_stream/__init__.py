"""
Traffic stream client for continuous edge platform validation.

This module provides configuration management and traffic generation
for testing origin servers through scrubbers.
"""

from .config import (
    TCPPortConfig,
    UDPPortConfig,
    DefaultsConfig,
    OriginConfig,
    PatternConfig,
    TimeOfDayConfig,
    StreamConfig,
    load_config,
)
from .metrics import MetricsDB

__all__ = [
    "TCPPortConfig",
    "UDPPortConfig",
    "DefaultsConfig",
    "OriginConfig",
    "PatternConfig",
    "TimeOfDayConfig",
    "StreamConfig",
    "load_config",
    "MetricsDB",
]
