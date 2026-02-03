"""System error repository for TensorProx Management."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional
from uuid import UUID

from shared.utils.logging import get_logger

from .base import BaseRepository

logger = get_logger(__name__)


class SystemErrorRepository(BaseRepository):
    """Persistence for system-level errors (tensorprox_system_errors table).

    Captures orphan errors that occur before entity assignment or at the
    system infrastructure level: target selection, capacity checks, API
    validation, geolocation, queue overflow, metrics forwarding, etc.
    """

    def log_error(
        self,
        *,
        error_source: str,
        error_code: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
        exit_hub_id: Optional[UUID] = None,
        origin_id: Optional[str] = None,
        miner_id: Optional[UUID] = None,
    ) -> int:
        """Insert a system error record.

        Args:
            error_source: Category of the error origin. Expected values:
                - 'target_selection': Miner unreachable during target selection
                - 'capacity_check': Shard capacity check failures
                - 'api_validation': Request-level validation errors
                - 'geolocation': IP geolocation failures
                - 'queue': Validation queue overflow
                - 'metrics': Metrics forwarder errors
            error_code: Short identifier for the error type (e.g., 'miner_unreachable',
                'no_capacity', 'invalid_ip', 'queue_full').
            error_message: Human-readable description of the error.
            context: Optional JSONB context with additional details (request params,
                stack traces, timing info, etc.).
            exit_hub_id: Optional associated exit hub (if known at time of error).
            origin_id: Optional associated origin (if known at time of error).
            miner_id: Optional associated miner (if known at time of error).

        Returns:
            The auto-generated id of the inserted row.
        """
        with self.connection() as db:
            row = db.execute_returning_one(
                """
                INSERT INTO tensorprox_system_errors (
                    error_source, error_code, error_message,
                    context, exit_hub_id, origin_id, miner_id
                )
                VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s)
                RETURNING id;
                """,
                (
                    error_source,
                    error_code,
                    error_message,
                    json.dumps(context) if context else None,
                    str(exit_hub_id) if exit_hub_id else None,
                    origin_id,
                    str(miner_id) if miner_id else None,
                ),
            )

        if not row:
            logger.warning(
                "Failed to log system error: source=%s code=%s",
                error_source,
                error_code,
            )
            return 0

        error_id = row["id"]
        logger.debug(
            "Logged system error id=%d source=%s code=%s",
            error_id,
            error_source,
            error_code,
        )
        return error_id
