"""
Logging utilities for TensorProx subnet.

Provides structured logging with loguru.
"""

import os
import sys
from typing import Optional, Dict, Any
from datetime import datetime

from loguru import logger


def setup_logging(
    level: str = "INFO",
    log_dir: str = "/tmp/tensorprox",
    name: str = "tensorprox",
    rotation: str = "100 MB",
    retention: str = "7 days",
) -> None:
    """
    Setup logging with loguru.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        log_dir: Directory for log files.
        name: Base name for log files.
        rotation: When to rotate log files.
        retention: How long to keep old logs.
    """
    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Remove default logger
    logger.remove()

    # Add stderr handler with custom format
    logger.add(
        sys.stderr,
        level=level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
               "<level>{message}</level>",
    )

    # Add file handler
    log_path = os.path.join(log_dir, f"{name}.log")
    logger.add(
        log_path,
        level="DEBUG",  # Always debug level for file
        rotation=rotation,
        retention=retention,
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | "
               "{name}:{function}:{line} | {message}",
    )

    logger.info(f"Logging initialized: level={level}, file={log_path}")


def get_logger(name: str = "tensorprox"):
    """
    Get a logger instance.

    Args:
        name: Logger name (for context).

    Returns:
        Logger instance.
    """
    return logger.bind(name=name)


class LogEvent:
    """Structured log event for monitoring."""

    def __init__(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        uid: Optional[int] = None,
        step: Optional[int] = None,
    ):
        """
        Create a log event.

        Args:
            event_type: Type of event (e.g., "reward", "weight").
            data: Event data.
            uid: Associated UID.
            step: Step/iteration number.
        """
        self.event_type = event_type
        self.data = data or {}
        self.uid = uid
        self.step = step
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "uid": self.uid,
            "step": self.step,
            **self.data,
        }

    def log(self, level: str = "INFO") -> None:
        """Log the event."""
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"Event [{self.event_type}]: {self.data}")
