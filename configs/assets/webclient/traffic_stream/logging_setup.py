"""JSON structured logging for traffic stream client."""

import logging
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        """Convert log record to JSON string.

        Args:
            record: Log record to format

        Returns:
            JSON formatted log line
        """
        log_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
        }

        # Add all extra fields from the record
        if hasattr(record, "origin_ip"):
            log_data["origin_ip"] = record.origin_ip
        if hasattr(record, "service"):
            log_data["service"] = record.service
        if hasattr(record, "port"):
            log_data["port"] = record.port
        if hasattr(record, "success"):
            log_data["success"] = record.success
        if hasattr(record, "latency_ms"):
            log_data["latency_ms"] = record.latency_ms
        if hasattr(record, "error"):
            log_data["error"] = record.error
        if hasattr(record, "pattern"):
            log_data["pattern"] = record.pattern

        # Include message if present
        if record.msg:
            log_data["message"] = record.getMessage()

        return json.dumps(log_data)


def setup_logging(
    log_dir: str = "/var/log/traffic_stream",
    log_level: int = logging.INFO
) -> logging.Logger:
    """Set up logging with JSON file output and console output.

    Creates:
    - /var/log/traffic_stream/requests.jsonl (rotating, 5MB, 10 backups)
    - Console handler for INFO+ messages

    Args:
        log_dir: Directory for log files
        log_level: Minimum log level

    Returns:
        Configured logger instance

    Raises:
        OSError: If log directory cannot be created
    """
    # Create log directory if it doesn't exist
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # Create logger
    logger = logging.getLogger("traffic_stream")
    logger.setLevel(log_level)
    logger.propagate = False

    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()

    # Create rotating file handler with JSON formatting
    log_file = log_path / "requests.jsonl"
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=10,
        encoding="utf-8"
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    # Create console handler with simple formatting
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger


def log_request(
    logger: logging.Logger,
    origin_ip: str,
    service: str,
    port: int,
    success: bool,
    latency_ms: float,
    error: Optional[str] = None,
    pattern: Optional[str] = None
):
    """Log a request result as structured JSON.

    Args:
        logger: Logger instance to use
        origin_ip: Origin server IP address
        service: Service name (e.g., "tcp_http")
        port: Service port number
        success: Whether request succeeded
        latency_ms: Request latency in milliseconds
        error: Error message if request failed
        pattern: Traffic pattern name (e.g., "BURST")
    """
    # Build log message
    message = f"{service}:{port} -> {origin_ip}"
    if success:
        message += f" OK ({latency_ms:.1f}ms)"
    else:
        message += f" FAILED ({error})"

    # Create log record with extra fields
    extra = {
        "origin_ip": origin_ip,
        "service": service,
        "port": port,
        "success": success,
        "latency_ms": round(latency_ms, 2),
    }

    if error is not None:
        extra["error"] = error

    if pattern is not None:
        extra["pattern"] = pattern

    # Log at appropriate level
    if success:
        logger.info(message, extra=extra)
    else:
        logger.error(message, extra=extra)
