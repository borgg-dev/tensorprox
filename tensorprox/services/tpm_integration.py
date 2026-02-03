"""
TPM-Lite Integration for Validator.

Provides integration between TensorProxValidator and embedded TPM-Lite:
- TPM Flask app startup in background thread
- Startup tasks (migrations, recovery)

Each TPM operates independently - no inter-TPM communication.
Once an origin is assigned to a TPM, that TPM exclusively owns it.

Usage:
    # In validator setup:
    from tensorprox.services.tpm_integration import TPMIntegration

    tpm = TPMIntegration(validator=self)
    await tpm.start()

    # In shutdown:
    await tpm.stop()
"""

import threading
from typing import Any, Optional, Dict

from loguru import logger


class TPMIntegration:
    """
    Integrates TPM-Lite into the validator.

    Manages:
    - Flask app lifecycle (runs in background thread)
    - Startup tasks (migrations, recovery)

    Each TPM operates independently with exclusive ownership of its origins.
    """

    # Default port for TPM-Lite
    DEFAULT_PORT = 5001

    def __init__(
        self,
        validator: Any,
        port: int = DEFAULT_PORT,
    ):
        """
        Initialize TPM integration.

        Args:
            validator: TensorProxValidator instance
            port: Port for TPM-Lite Flask app
        """
        self.validator = validator
        self.port = port

        # Service instances
        self._flask_thread: Optional[threading.Thread] = None

        # State
        self._running = False
        self._app: Optional[Any] = None

        logger.info(f"TPMIntegration initialized: port={port}")

    async def start(self):
        """
        Start TPM-Lite integration.

        1. Run startup tasks (migrations, recovery)
        2. Start Flask app in background thread
        3. Start background services
        """
        if self._running:
            logger.warning("TPM integration already running")
            return

        logger.info("Starting TPM-Lite integration...")

        try:
            # Import TPM modules
            from tensorprox.tpm.app import (
                create_app,
                run_startup_tasks,
                start_background_services,
            )

            # Run startup tasks (migrations, recovery)
            logger.info("Running TPM startup tasks...")
            run_startup_tasks()

            # Create Flask app
            logger.info("Creating TPM-Lite Flask app...")
            self._app = create_app(
                validator_uid=self.validator.uid,
                validator_hotkey=self.validator.wallet.hotkey.ss58_address,
            )

            # Start Flask in background thread
            self._flask_thread = threading.Thread(
                target=self._run_flask,
                name="tpm-lite-flask",
                daemon=True,
            )
            self._flask_thread.start()
            logger.info(f"TPM-Lite Flask app started on port {self.port}")

            # Start background services
            start_background_services()

            self._running = True
            logger.info("TPM-Lite integration started successfully")

        except ImportError as e:
            logger.warning(f"TPM modules not available: {e}")
            logger.warning("TPM-Lite integration disabled")
        except Exception as e:
            logger.error(f"Failed to start TPM-Lite: {e}")
            raise

    async def stop(self):
        """Stop TPM-Lite integration."""
        if not self._running:
            return

        logger.info("Stopping TPM-Lite integration...")

        # Flask thread will stop when validator exits (daemon thread)

        self._running = False
        logger.info("TPM-Lite integration stopped")

    def _run_flask(self):
        """Run Flask app in background thread."""
        try:
            from werkzeug.serving import make_server

            # Create and run server
            server = make_server(
                "0.0.0.0",
                self.port,
                self._app,
                threaded=True,
            )
            server.serve_forever()

        except Exception as e:
            logger.error(f"Flask server error: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get TPM integration status."""
        return {
            "running": self._running,
            "port": self.port,
            "flask_alive": self._flask_thread is not None and self._flask_thread.is_alive(),
        }

    @property
    def is_running(self) -> bool:
        """Check if TPM integration is running."""
        return self._running


# Global integration instance
_tpm_integration: Optional[TPMIntegration] = None


def get_tpm_integration() -> Optional[TPMIntegration]:
    """Get the global TPM integration instance."""
    return _tpm_integration


def init_tpm_integration(
    validator: Any,
    port: int = TPMIntegration.DEFAULT_PORT,
) -> TPMIntegration:
    """Initialize the global TPM integration."""
    global _tpm_integration

    _tpm_integration = TPMIntegration(
        validator=validator,
        port=port,
    )

    return _tpm_integration
