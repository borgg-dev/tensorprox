"""Centralized logging configuration for TensorProx services.

Provides:
- Structured logging with context tracking
- Rate limiting for repetitive errors
- Flask integration
- File rotation
- Operation context management

Usage:
    # In service startup (miner.py, tensorprox_management.py, etc.)
    from shared.utils.logging import setup_logging
    setup_logging(service_name="miner", log_level="INFO")

    # In any module
    from shared.utils.logging import get_logger, OperationContext
    logger = get_logger(__name__)

    with OperationContext(operation="deploy", edge_name="edge-a"):
        logger.info("Starting deployment")  # Includes context automatically
"""
import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from contextvars import ContextVar
from typing import Optional, Dict, Any
import hashlib
import time
from functools import wraps


# Thread-safe context storage for operation tracking
_operation_context: ContextVar[Dict[str, Any]] = ContextVar('operation_context', default={})


class ContextFilter(logging.Filter):
    """Add operation context to log records.

    Context includes:
    - operation: Current operation (deploy, cleanup, bootstrap, etc.)
    - edge_name: Scrubber name (edge-a, edge-b)
    - instance_id: AWS/Linode instance ID
    - origin_id: Origin identifier

    Format: [edge-a/i-0690c4c9]
    """

    def filter(self, record):
        ctx = _operation_context.get()

        # Store individual context fields
        record.operation = ctx.get('operation', '')
        record.instance_id = ctx.get('instance_id', '')
        record.edge_name = ctx.get('edge_name', '')
        record.origin_id = ctx.get('origin_id', '')

        # Build context string for log output
        context_parts = []

        if record.edge_name:
            context_parts.append(record.edge_name)
        elif record.origin_id:
            context_parts.append(record.origin_id)

        if record.instance_id:
            # Truncate instance ID for readability (i-0690c4c9b0f1ee4dd -> i-0690c4c9)
            short_id = record.instance_id[:12] if record.instance_id.startswith('i-') else record.instance_id[:8]
            context_parts.append(short_id)

        # Format: " [edge-a/i-0690c4c9]" or "" if no context
        record.context_str = f" [{'/'.join(context_parts)}]" if context_parts else ""

        return True


class RateLimitFilter(logging.Filter):
    """Rate limit repeated error messages to prevent log spam.

    Strategy:
    - First 3 occurrences: Log normally
    - Subsequent: Suppress for 60 seconds
    - Every 100th: Log with suppression count

    Example:
        First 3:  "SYN cookie control failed: ..."
        100th:    "[Suppressed 97x] SYN cookie control failed: ..."
        200th:    "[Suppressed 197x] SYN cookie control failed: ..."
    """

    def __init__(self, window_seconds: int = 60, max_duplicates: int = 3):
        super().__init__()
        self.window_seconds = window_seconds
        self.max_duplicates = max_duplicates
        # signature -> (count, first_seen, last_logged)
        self.error_cache: Dict[str, tuple[int, float, float]] = {}

    def filter(self, record):
        # Only rate limit WARNING and ERROR levels
        if record.levelno < logging.WARNING:
            return True

        # Create signature from message (ignore line numbers, timestamps)
        signature = hashlib.md5(record.getMessage().encode()).hexdigest()
        now = time.time()

        if signature in self.error_cache:
            count, first_seen, last_logged = self.error_cache[signature]

            # Reset window if enough time has passed
            if now - first_seen > self.window_seconds:
                self.error_cache[signature] = (1, now, now)
                return True

            # Increment count
            count += 1
            self.error_cache[signature] = (count, first_seen, last_logged)

            # Allow first N duplicates
            if count <= self.max_duplicates:
                return True

            # Log every 100th occurrence with suppression notice
            if count % 100 == 0:
                suppressed = count - self.max_duplicates
                record.msg = f"[Suppressed {suppressed}x in {int(now - first_seen)}s] {record.msg}"
                self.error_cache[signature] = (count, first_seen, now)
                return True

            # Suppress
            return False
        else:
            # First occurrence
            self.error_cache[signature] = (1, now, now)
            return True


def setup_logging(
    service_name: str = "tensorprox",
    log_level: str = "INFO",
    log_dir: Optional[Path] = None,
    console: bool = True,
    file_logging: bool = True,
    rate_limit: bool = True
):
    """Setup logging configuration for TensorProx services.

    Call this ONCE at service startup (miner.py, tensorprox_management.py, etc.)

    Args:
        service_name: Service identifier (miner, tensorprox, traffic_manager)
        log_level: Minimum console log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files (default: /tmp/tensorprox/)
        console: Enable console logging
        file_logging: Enable file logging
        rate_limit: Enable rate limiting for repetitive errors

    Example:
        setup_logging(service_name="miner", log_level="INFO")
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture everything, filter at handler level

    # Clear existing handlers to avoid duplicates
    root_logger.handlers = []

    # Create formatters
    detailed_formatter = logging.Formatter(
        fmt='[%(asctime)s] %(levelname)-7s %(name)s%(context_str)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Create filters
    context_filter = ContextFilter()

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, log_level.upper()))
        console_handler.setFormatter(detailed_formatter)
        console_handler.addFilter(context_filter)

        if rate_limit:
            console_handler.addFilter(RateLimitFilter(window_seconds=60, max_duplicates=3))

        root_logger.addHandler(console_handler)

    # File handler with rotation
    if file_logging:
        if log_dir is None:
            log_dir = Path.home() / ".tensorprox" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        log_file = log_dir / f"{service_name}.log"
        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=50 * 1024 * 1024,  # 50 MB per file
            backupCount=5,  # Keep 5 rotated files (250 MB total)
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)  # File gets everything
        file_handler.setFormatter(detailed_formatter)
        file_handler.addFilter(context_filter)
        # No rate limiting on file logs - we want complete history

        root_logger.addHandler(file_handler)

        logging.info(f"Logging initialized: console={console} file={log_file}")

    # Suppress noisy third-party libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('paramiko').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

    # Flask/Werkzeug: Show request logs but not debug spam
    logging.getLogger('werkzeug').setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the given module.

    Use __name__ to get automatic module path naming:

    Example:
        # In miner/api/admin.py
        logger = get_logger(__name__)  # Creates logger named "miner.api.admin"
        logger.info("Deploying scrubbers")

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance with configured handlers and filters
    """
    return logging.getLogger(name)


class OperationContext:
    """Context manager for tracking operations with automatic log context.

    Adds operation metadata to all log messages within the context.
    Thread-safe via contextvars.

    Example:
        with OperationContext(operation="deploy", edge_name="edge-a"):
            logger.info("Starting deployment")
            # Output: [2025-11-08 07:24:20] INFO admin.deploy [edge-a]: Starting deployment

            result = node.deploy(...)

            with OperationContext(instance_id=result.instance_id):
                logger.info("Instance created")
                # Output: [2025-11-08 07:24:35] INFO admin.deploy [edge-a/i-0690c4c9]: Instance created

    Contexts nest and merge:
        with OperationContext(edge_name="edge-a"):
            with OperationContext(instance_id="i-123"):
                # Both edge_name and instance_id are in context
    """

    def __init__(self, **kwargs):
        """Initialize context with key-value pairs.

        Common keys:
        - operation: Operation name (deploy, cleanup, bootstrap, configure)
        - edge_name: Scrubber name (edge-a, edge-b)
        - instance_id: Instance ID (i-0690c4c9b0f1ee4dd)
        - origin_id: Origin identifier (O1, O2)
        - module: Bootstrap module number (10, 20, 30, etc.)
        """
        self.context = kwargs
        self.token = None

    def __enter__(self):
        # Merge with existing context
        current = _operation_context.get().copy()
        current.update(self.context)
        self.token = _operation_context.set(current)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore previous context
        if self.token:
            _operation_context.reset(self.token)


def log_operation(operation: str):
    """Decorator to automatically add operation context to a function.

    Example:
        @log_operation("deploy")
        def deploy_scrubbers():
            logger.info("Starting")  # All logs include operation="deploy"

    Args:
        operation: Operation name to add to context
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with OperationContext(operation=operation):
                return func(*args, **kwargs)
        return wrapper
    return decorator


# Convenience function for getting current context (useful for debugging)
def get_current_context() -> Dict[str, Any]:
    """Get current operation context as dictionary.

    Returns:
        Dictionary with current context values (operation, edge_name, instance_id, etc.)
    """
    return _operation_context.get().copy()


# =============================================================================
# Rate-Limited Logging Utility
# =============================================================================

# Global state for rate-limited log messages
# key -> (last_log_time, last_value)
_rate_limit_state: Dict[str, tuple[float, Any]] = {}


def log_rate_limited(
    key: str,
    log_func: callable,
    message: str,
    interval_seconds: int = 60,
    value: Any = None
) -> bool:
    """
    Log a message with rate limiting - max once per interval OR when value changes.

    Use this for repetitive log messages that would otherwise spam the logs,
    such as "No scrubbers deployed" or "Loaded 0 nodes".

    Args:
        key: Unique identifier for this log message (e.g., "no_scrubbers", "loaded_nodes")
        log_func: Logger method to call (e.g., logger.debug, logger.info)
        message: The message to log
        interval_seconds: Minimum seconds between logs (default: 60)
        value: Optional value to track - logs immediately if value changes

    Returns:
        True if the message was logged, False if suppressed

    Examples:
        # Simple rate limiting - logs at most once per 60 seconds
        log_rate_limited(
            "health_no_scrubbers",
            logger.debug,
            "No scrubbers deployed - skipping health check"
        )

        # With value tracking - logs when count changes OR every 60 seconds
        log_rate_limited(
            "db_loaded_nodes",
            logger.info,
            f"Loaded {node_count} edge nodes: {node_list}",
            value=node_count
        )
    """
    now = time.time()

    if key in _rate_limit_state:
        last_time, last_value = _rate_limit_state[key]

        # Log if value changed (when value tracking is used)
        if value is not None and value != last_value:
            log_func(message)
            _rate_limit_state[key] = (now, value)
            return True

        # Log if interval has passed
        if now - last_time >= interval_seconds:
            log_func(message)
            _rate_limit_state[key] = (now, value)
            return True

        # Suppress
        return False
    else:
        # First occurrence - always log
        log_func(message)
        _rate_limit_state[key] = (now, value)
        return True


def clear_rate_limit_state(key: str = None) -> None:
    """
    Clear rate limit state for testing or when state should be reset.

    Args:
        key: Specific key to clear, or None to clear all
    """
    global _rate_limit_state
    if key is None:
        _rate_limit_state = {}
    elif key in _rate_limit_state:
        del _rate_limit_state[key]
