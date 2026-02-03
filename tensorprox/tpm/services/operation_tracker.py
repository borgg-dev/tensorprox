"""Unified operation progress tracker.

Single source of truth for ALL TPM operation notifications.
Consolidates labels, step enumeration, and deduplication.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from threading import Lock
from typing import Any, Dict, Optional, TYPE_CHECKING

from shared.utils.logging import get_logger

if TYPE_CHECKING:
    from tensorprox.tpm.services.notifier import ExitHubNotifier

logger = get_logger(__name__)


# ============================================================================
# STEP DEFINITIONS (for enumeration like "Step 2/6: Provisioning")
# ============================================================================

class ExitHubDeployStep(IntEnum):
    """Exit hub deployment steps shown to users."""
    QUEUED = 1
    SELECTING = 2
    PROVISIONING = 3
    CONFIGURING = 4
    FINALIZING = 5
    ACTIVE = 6


class ExitHubTeardownStep(IntEnum):
    """Exit hub teardown steps shown to users."""
    TEARDOWN = 1
    CLEANUP = 2
    TERMINATED = 3


class PortUpdateStep(IntEnum):
    """Port update steps shown to users."""
    RECEIVED = 1
    APPLYING = 2
    COMPLETE = 3


# ============================================================================
# STATUS → STEP MAPPINGS
# ============================================================================

# Map internal statuses to deployment steps
DEPLOY_STATUS_MAP: Dict[str, ExitHubDeployStep] = {
    "requested": ExitHubDeployStep.QUEUED,
    "queued": ExitHubDeployStep.QUEUED,
    "selecting_target": ExitHubDeployStep.SELECTING,
    "queued_for_miner": ExitHubDeployStep.SELECTING,
    "deploying_scrubbers": ExitHubDeployStep.PROVISIONING,
    "waiting_for_shard": ExitHubDeployStep.PROVISIONING,
    "scrubbers_ready": ExitHubDeployStep.PROVISIONING,
    "deploying": ExitHubDeployStep.PROVISIONING,
    "miner_processing": ExitHubDeployStep.PROVISIONING,
    "registering": ExitHubDeployStep.CONFIGURING,
    "registering_origin": ExitHubDeployStep.CONFIGURING,
    "stabilizing": ExitHubDeployStep.FINALIZING,
    "active": ExitHubDeployStep.ACTIVE,
    "failed": ExitHubDeployStep.ACTIVE,  # Deploy failures show as final step
}

# Map internal statuses to teardown steps
TEARDOWN_STATUS_MAP: Dict[str, ExitHubTeardownStep] = {
    "teardown_requested": ExitHubTeardownStep.TEARDOWN,
    "draining": ExitHubTeardownStep.TEARDOWN,
    "cancelling": ExitHubTeardownStep.TEARDOWN,
    "cloud_destroy": ExitHubTeardownStep.CLEANUP,
    "miner_cleanup": ExitHubTeardownStep.CLEANUP,
    "terminating": ExitHubTeardownStep.TERMINATED,
    "terminated": ExitHubTeardownStep.TERMINATED,
    "cancelled": ExitHubTeardownStep.TERMINATED,
    "failed": ExitHubTeardownStep.TERMINATED,  # Teardown failures show as final step
}

# Map internal statuses to port update steps
PORT_UPDATE_STATUS_MAP: Dict[str, PortUpdateStep] = {
    "received": PortUpdateStep.RECEIVED,
    "processing": PortUpdateStep.APPLYING,
    "applied": PortUpdateStep.COMPLETE,
    "failed": PortUpdateStep.COMPLETE,
}


# ============================================================================
# STEP LABELS (human-readable)
# ============================================================================

DEPLOY_LABELS: Dict[ExitHubDeployStep, str] = {
    ExitHubDeployStep.QUEUED: "Queued",
    ExitHubDeployStep.SELECTING: "Selecting region",
    ExitHubDeployStep.PROVISIONING: "Provisioning",
    ExitHubDeployStep.CONFIGURING: "Configuring",
    ExitHubDeployStep.FINALIZING: "Finalizing",
    ExitHubDeployStep.ACTIVE: "Active",
}

TEARDOWN_LABELS: Dict[ExitHubTeardownStep, str] = {
    ExitHubTeardownStep.TEARDOWN: "Initiating teardown",
    ExitHubTeardownStep.CLEANUP: "Cleaning up",
    ExitHubTeardownStep.TERMINATED: "Terminated",
}

PORT_UPDATE_LABELS: Dict[PortUpdateStep, str] = {
    PortUpdateStep.RECEIVED: "Updating ports",
    PortUpdateStep.APPLYING: "Applying changes",
    PortUpdateStep.COMPLETE: "Complete",
}

# Terminal statuses that should always emit (even if step unchanged)
TERMINAL_STATUSES = {"active", "terminated", "cancelled", "failed"}

# Error statuses
ERROR_STATUSES = {"failed"}


# ============================================================================
# OPERATION STATE TRACKING
# ============================================================================

@dataclass
class OperationState:
    """Tracks current state for an operation."""
    step: int
    total_steps: int
    queue_position: int = 0
    is_teardown: bool = False
    is_port_update: bool = False


class OperationTracker:
    """Unified progress tracker for ALL TPM operations.

    Single entry point for notifications. Handles:
    - Deduplication (only emit on actual step change)
    - Step enumeration ("Step 2/6: Selecting region")
    - Queue position in label when position > 1
    - Terminal states always emit (force=True equivalent)
    """

    def __init__(self, notifier: Optional[ExitHubNotifier] = None):
        self._notifier = notifier
        self._state: Dict[str, OperationState] = {}
        self._lock = Lock()

    def set_notifier(self, notifier: ExitHubNotifier) -> None:
        """Set the notifier (called during app init)."""
        self._notifier = notifier

    def track(
        self,
        *,
        exit_hub_id: str,
        status: str,
        client_id: Optional[str] = None,
        origin_id: Optional[str] = None,
        miner_id: Optional[str] = None,
        miner_ip: Optional[str] = None,
        queue_position: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> bool:
        """Track operation progress and emit notification if changed.

        This is the ONLY method that should be called to emit notifications.
        All other code paths should go through this.

        Args:
            exit_hub_id: Exit hub UUID (operation identifier)
            status: Internal status string
            client_id: Client ID for notification routing
            origin_id: Origin ID for notification routing
            miner_id: Miner UUID
            miner_ip: Miner IP address
            queue_position: Position in queue (0 = not queued/processing)
            metadata: Additional metadata to include
            error: Error message if status indicates failure

        Returns:
            True if notification was emitted, False if deduplicated
        """
        # Handle ambiguous statuses (like 'failed') that exist in multiple maps
        # by checking current operation state first
        with self._lock:
            current = self._state.get(exit_hub_id)

        # Determine operation type and map to step
        # For 'failed' status, use current operation state if available
        if status == "failed" and current is not None:
            # Use the operation type from current state
            is_teardown = current.is_teardown
            is_port_update = current.is_port_update
        else:
            # Normal lookup - teardown takes precedence for unambiguous statuses
            is_teardown = status in TEARDOWN_STATUS_MAP and status not in DEPLOY_STATUS_MAP
            is_port_update = status in PORT_UPDATE_STATUS_MAP
            # For 'failed' with no current state, check if it's a teardown-specific status context
            if status == "failed" and current is None:
                # Default to deployment failure (step 6/6) since we have no context
                is_teardown = False
                is_port_update = False

        if is_teardown:
            step_enum = TEARDOWN_STATUS_MAP.get(status)
            total_steps = len(ExitHubTeardownStep)
            labels = TEARDOWN_LABELS
        elif is_port_update:
            step_enum = PORT_UPDATE_STATUS_MAP.get(status)
            total_steps = len(PortUpdateStep)
            labels = PORT_UPDATE_LABELS
        else:
            step_enum = DEPLOY_STATUS_MAP.get(status)
            total_steps = len(ExitHubDeployStep)
            labels = DEPLOY_LABELS

        # Unknown status - log but don't emit
        if step_enum is None:
            logger.debug("Unknown status '%s', skipping notification", status)
            return False

        step = int(step_enum)
        is_terminal = status in TERMINAL_STATUSES

        with self._lock:
            current = self._state.get(exit_hub_id)

            # Check if operation type changed (deployment → teardown or vice versa)
            # This happens when an active deployment gets terminated - we need to
            # emit the teardown events even though step numbers "go backwards"
            operation_type_changed = (
                current is not None
                and current.is_teardown != is_teardown
            )

            # Determine if we should emit
            # IMPORTANT: Use `step > current.step` (not `step != current.step`)
            # to prevent emitting OLDER steps after we've progressed.
            # e.g., if we're at Step 3 (provisioning), don't emit Step 2 (selecting)
            # when miner_operation_queue re-emits queued_for_miner during registration.
            should_emit = (
                is_terminal  # Always emit terminal states
                or current is None  # First notification
                or operation_type_changed  # Switching between deploy/teardown
                or step > current.step  # Step advanced forward (not backward)
                or (step == 1 and queue_position > 1
                    and current.queue_position != queue_position)  # Queue position changed
            )

            if not should_emit:
                logger.debug(
                    "Dedup: exit_hub=%s status=%s step=%d current=%d (not advancing)",
                    exit_hub_id[:8], status, step, current.step if current else 0
                )
                return False

            # Update state
            self._state[exit_hub_id] = OperationState(
                step=step,
                total_steps=total_steps,
                queue_position=queue_position,
                is_teardown=is_teardown,
                is_port_update=is_port_update,
            )

        # Build label
        base_label = labels.get(step_enum, status)
        if step == 1 and queue_position > 1:
            label = f"Queued (position {queue_position})"
        elif is_terminal:
            label = base_label
        else:
            label = f"Step {step}/{total_steps}: {base_label}"

        # Emit
        self._emit(
            exit_hub_id=exit_hub_id,
            status=status,
            label=label,
            step=step,
            total_steps=total_steps,
            queue_position=queue_position,
            client_id=client_id,
            origin_id=origin_id,
            miner_id=miner_id,
            miner_ip=miner_ip,
            metadata=metadata,
            error=error,
        )
        return True

    def clear(self, exit_hub_id: str) -> None:
        """Clear state for an operation (after terminal state)."""
        with self._lock:
            self._state.pop(exit_hub_id, None)

    def _emit(
        self,
        *,
        exit_hub_id: str,
        status: str,
        label: str,
        step: int,
        total_steps: int,
        queue_position: int,
        client_id: Optional[str],
        origin_id: Optional[str],
        miner_id: Optional[str],
        miner_ip: Optional[str],
        metadata: Optional[Dict[str, Any]],
        error: Optional[str],
    ) -> None:
        """Emit notification to notifier."""
        if not self._notifier:
            logger.debug("No notifier configured, skipping emission")
            return

        # Build progress metadata
        progress_data = {
            "label": label,
            "step": step,
            "total_steps": total_steps,
            "status": status,
        }

        # Merge with provided metadata
        full_metadata = {**(metadata or {}), "progress": progress_data}
        if queue_position > 0:
            full_metadata["queue_position"] = queue_position

        logger.info(
            "Progress: exit_hub=%s step=%d/%d label='%s' status=%s",
            exit_hub_id[:8], step, total_steps, label, status
        )

        self._notifier.exit_hub_state_changed(
            exit_hub_id=exit_hub_id,
            status=status,
            client_id=client_id,
            origin_id=origin_id,
            miner_id=miner_id,
            miner_ip=miner_ip,
            metadata=full_metadata,
            error=error,
        )


# ============================================================================
# SINGLETON + BACKWARD COMPATIBILITY
# ============================================================================

_tracker: Optional[OperationTracker] = None


def get_operation_tracker() -> OperationTracker:
    """Get or create the singleton tracker."""
    global _tracker
    if _tracker is None:
        _tracker = OperationTracker()
    return _tracker


# Backward compatibility for progress.py consumers
def progress_hint(
    status: str, mapping: Dict[str, Dict[str, object]]
) -> Optional[Dict[str, object]]:
    """Deprecated: Use OperationTracker.track() instead.

    Kept for backward compatibility with api/streams.py SSE initial state.
    """
    status_lower = (status or "").lower()
    info = mapping.get(status_lower)
    if not info:
        return None
    return {
        "label": info.get("label"),
        "expected_duration_seconds": info.get("expected_duration_seconds"),
        "status": status_lower,
    }


# Backward compatibility: export old dict for api/streams.py
# Labels now include step numbers for consistency with live updates
PROGRESS_EXIT_HUB: Dict[str, Dict[str, object]] = {
    # Deployment steps (6 total)
    "requested": {"label": "Step 1/6: Queued", "expected_duration_seconds": 5},
    "queued": {"label": "Step 1/6: Queued", "expected_duration_seconds": 10},
    "selecting_target": {"label": "Step 2/6: Selecting region", "expected_duration_seconds": 20},
    "queued_for_miner": {"label": "Step 2/6: Selecting region", "expected_duration_seconds": 60},
    "miner_processing": {"label": "Step 3/6: Provisioning", "expected_duration_seconds": 300},
    "deploying_scrubbers": {"label": "Step 3/6: Provisioning", "expected_duration_seconds": 300},
    "waiting_for_shard": {"label": "Step 3/6: Provisioning", "expected_duration_seconds": 90},
    "scrubbers_ready": {"label": "Step 3/6: Provisioning", "expected_duration_seconds": 5},
    "deploying": {"label": "Step 3/6: Provisioning", "expected_duration_seconds": 120},
    "registering_origin": {"label": "Step 4/6: Configuring", "expected_duration_seconds": 45},
    "registering": {"label": "Step 4/6: Configuring", "expected_duration_seconds": 90},
    "stabilizing": {"label": "Step 5/6: Finalizing", "expected_duration_seconds": 60},
    "active": {"label": "Active", "expected_duration_seconds": 0},
    # Teardown steps (3 total)
    "teardown_requested": {"label": "Step 1/3: Initiating teardown", "expected_duration_seconds": 10},
    "draining": {"label": "Step 1/3: Initiating teardown", "expected_duration_seconds": 30},
    "cancelling": {"label": "Step 1/3: Initiating teardown", "expected_duration_seconds": 60},
    "cloud_destroy": {"label": "Step 2/3: Cleaning up", "expected_duration_seconds": 90},
    "miner_cleanup": {"label": "Step 2/3: Cleaning up", "expected_duration_seconds": 60},
    "terminating": {"label": "Step 3/3: Terminated", "expected_duration_seconds": 90},
    "terminated": {"label": "Step 3/3: Terminated", "expected_duration_seconds": 0},
    "cancelled": {"label": "Cancelled", "expected_duration_seconds": 0},
    "failed": {"label": "Failed", "expected_duration_seconds": 0},
}

PROGRESS_PORT_UPDATE: Dict[str, Dict[str, object]] = {
    "received": {"label": "Updating ports", "expected_duration_seconds": 5},
    "processing": {"label": "Applying changes", "expected_duration_seconds": 5},
    "applied": {"label": "Ports updated", "expected_duration_seconds": 0},
    "failed": {"label": "Port update failed", "expected_duration_seconds": 0},
}
