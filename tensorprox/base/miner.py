"""
Base miner neuron for TensorProx subnet.

Extends BaseNeuron with miner-specific functionality:
- Axon serving for receiving validator queries
- Blacklisting/priority mechanisms
- Scrubber infrastructure management
- Challenge handling
"""

import time
import threading
from typing import Optional, Tuple, List, Dict, Any
from abc import abstractmethod

import bittensor as bt
from pydantic import BaseModel, Field
from loguru import logger

from tensorprox.base.neuron import BaseNeuron
from tensorprox.base.protocol import (
    PingSynapse,
    ChallengeSynapse,
    HealthReportSynapse,
    ScrubberConfig,
    AuditChallengeSynapse,
    SetupTunnelSynapse,
)
from tensorprox.settings import Settings, get_settings


class BaseMinerNeuron(BaseModel, BaseNeuron):
    """
    Base class for TensorProx miner neurons.

    Miners run scrubber infrastructure and respond to
    validator challenges. This class handles the Bittensor
    networking layer while subclasses implement the actual
    scrubbing logic.
    """

    model_config = {"arbitrary_types_allowed": True, "extra": "allow"}

    # Axon for receiving requests
    axon: Optional["bt.Axon"] = Field(default=None)

    # Scrubber configuration
    scrubber_config: ScrubberConfig = Field(
        default_factory=ScrubberConfig
    )

    # State
    is_running: bool = Field(default=False)
    last_challenge_time: float = Field(default=0.0)

    # Thread management
    _run_thread: Optional[threading.Thread] = None
    _stop_event: Optional[threading.Event] = None

    def __init__(self, settings: Optional[Settings] = None, **kwargs):
        """Initialize the miner neuron."""
        # Initialize Pydantic model
        BaseModel.__init__(self, **kwargs)
        # Initialize base neuron
        BaseNeuron.__init__(self, settings)

        # Initialize stop event for thread control
        self._stop_event = threading.Event()

    def setup_axon(self) -> "bt.Axon":
        """
        Set up the axon for serving requests.

        Attaches handlers for ping and challenge synapses
        with appropriate blacklisting and priority.
        """
        # Use port from settings (TP_AXON_PORT env var) if specified
        # This is required when running multiple miners on the same machine
        if self.settings.axon_port:
            self.axon = bt.Axon(wallet=self.wallet, port=self.settings.axon_port)
        else:
            self.axon = bt.Axon(wallet=self.wallet)

        # Attach ping handler
        self.axon.attach(
            forward_fn=self.forward,
            blacklist_fn=self.blacklist_ping,
            priority_fn=self.priority,
        )

        # Attach challenge handler
        self.axon.attach(
            forward_fn=self.handle_challenge,
            blacklist_fn=self.blacklist_challenge,
            priority_fn=self.priority_challenge,
        )

        # Attach audit challenge handler (for real traffic tests)
        self.axon.attach(
            forward_fn=self.handle_audit_challenge,
            blacklist_fn=self.blacklist_audit_challenge,
            priority_fn=self.priority_audit_challenge,
        )

        # Attach tunnel setup handler (validator requests miner to set up WG tunnel)
        self.axon.attach(
            forward_fn=self.handle_setup_tunnel,
            blacklist_fn=self.blacklist_setup_tunnel,
            priority_fn=self.priority_setup_tunnel,
        )

        logger.info(f"Axon set up on port {self.axon.port}")
        return self.axon

    async def blacklist_ping(
        self,
        synapse: PingSynapse
    ) -> Tuple[bool, str]:
        """
        Determine if a ping request should be blacklisted.

        Args:
            synapse: The incoming ping synapse.

        Returns:
            Tuple of (should_blacklist, reason).
        """
        return await self._check_blacklist(synapse)

    async def blacklist_challenge(
        self,
        synapse: ChallengeSynapse
    ) -> Tuple[bool, str]:
        """
        Determine if a challenge request should be blacklisted.

        Args:
            synapse: The incoming challenge synapse.

        Returns:
            Tuple of (should_blacklist, reason).
        """
        return await self._check_blacklist(synapse)

    async def _check_blacklist(
        self,
        synapse: bt.Synapse
    ) -> Tuple[bool, str]:
        """
        Common blacklist logic for all synapse types.

        Only allows requests from registered validators.
        """
        # Get caller's hotkey
        caller_hotkey = synapse.dendrite.hotkey
        if not caller_hotkey:
            return True, "No hotkey provided"

        # Check if caller is in metagraph
        try:
            caller_uid = self.metagraph.hotkeys.index(caller_hotkey)
        except ValueError:
            return True, "Caller not registered"

        # Check if caller has validator permit from chain
        if not self.metagraph.validator_permit[caller_uid]:
            return True, "No validator permit"

        return False, "Allowed"

    def priority(self, synapse: PingSynapse) -> float:
        """
        Determine request priority based on caller's stake.

        Higher stake = higher priority for request processing.
        """
        caller_hotkey = synapse.dendrite.hotkey
        if not caller_hotkey:
            return 0.0

        try:
            caller_uid = self.metagraph.hotkeys.index(caller_hotkey)
            return float(self.metagraph.S[caller_uid])
        except ValueError:
            return 0.0

    def priority_challenge(self, synapse: ChallengeSynapse) -> float:
        """Priority function for challenge synapses."""
        caller_hotkey = synapse.dendrite.hotkey
        if not caller_hotkey:
            return 0.0

        try:
            caller_uid = self.metagraph.hotkeys.index(caller_hotkey)
            return float(self.metagraph.S[caller_uid])
        except ValueError:
            return 0.0

    async def blacklist_audit_challenge(
        self,
        synapse: AuditChallengeSynapse
    ) -> Tuple[bool, str]:
        """Blacklist check for audit challenge synapses."""
        return await self._check_blacklist(synapse)

    def priority_audit_challenge(self, synapse: AuditChallengeSynapse) -> float:
        """Priority function for audit challenge synapses."""
        caller_hotkey = synapse.dendrite.hotkey
        if not caller_hotkey:
            return 0.0

        try:
            caller_uid = self.metagraph.hotkeys.index(caller_hotkey)
            return float(self.metagraph.S[caller_uid])
        except ValueError:
            return 0.0

    async def blacklist_setup_tunnel(
        self,
        synapse: SetupTunnelSynapse
    ) -> Tuple[bool, str]:
        """Blacklist check for tunnel setup synapses."""
        return await self._check_blacklist(synapse)

    def priority_setup_tunnel(self, synapse: SetupTunnelSynapse) -> float:
        """Priority function for tunnel setup synapses."""
        caller_hotkey = synapse.dendrite.hotkey
        if not caller_hotkey:
            return 0.0

        try:
            caller_uid = self.metagraph.hotkeys.index(caller_hotkey)
            return float(self.metagraph.S[caller_uid])
        except ValueError:
            return 0.0

    @abstractmethod
    def handle_setup_tunnel(self, synapse: SetupTunnelSynapse) -> SetupTunnelSynapse:
        """
        Handle tunnel setup request from validator.

        Miner sets up WireGuard tunnel on its own scrubber and returns
        the scrubber's WireGuard configuration.

        Args:
            synapse: The setup tunnel synapse with validator's WG config.

        Returns:
            Updated synapse with scrubber's WG config.
        """
        ...

    def forward(self, synapse: PingSynapse) -> PingSynapse:
        """
        Handle ping synapse - report availability and config.

        Args:
            synapse: The ping synapse to respond to.

        Returns:
            Updated synapse with availability information.
        """
        logger.debug("Received ping request")

        # Extract bootstrap token from validator for TPM registration
        if synapse.bootstrap_token:
            self._handle_bootstrap_token(synapse.bootstrap_token)

        # CRITICAL: Update active_nodes dynamically before responding
        # This ensures validators get current scrubber IPs, not stale cached values
        self._update_active_nodes()

        # Fill in our configuration
        synapse.max_scrubbers = self.scrubber_config.max_scrubbers
        synapse.scrubber_config = self.scrubber_config
        synapse.is_available = self.is_available()
        synapse.last_health_update = time.time()

        return synapse

    def _update_active_nodes(self) -> None:
        """
        Update scrubber_config.active_nodes to reflect current healthy scrubber state.

        This is called before each PingSynapse response to ensure validators
        receive accurate, up-to-date scrubber IPs instead of stale cached values.
        """
        # Default implementation - subclasses should override with actual logic
        pass

    def _handle_bootstrap_token(self, token: str) -> None:
        """
        Handle bootstrap token received from validator.

        Passes the token to miner_identity for TPM registration.
        """
        try:
            from miner_control_plane.services.miner_identity import miner_identity
            if not miner_identity.is_registered:
                logger.info("Received bootstrap token from validator, attempting TPM registration")
                miner_identity.set_bootstrap_token(token)
        except ImportError:
            # Control plane not available
            pass
        except Exception as e:
            logger.warning(f"Failed to process bootstrap token: {e}")

    @abstractmethod
    def handle_challenge(
        self,
        synapse: ChallengeSynapse
    ) -> ChallengeSynapse:
        """
        Handle a challenge from a validator.

        Must be implemented by subclasses with actual
        scrubber operations.

        Args:
            synapse: The challenge synapse with task details.

        Returns:
            Updated synapse with results.
        """
        pass

    @abstractmethod
    def handle_audit_challenge(
        self,
        synapse: AuditChallengeSynapse
    ) -> AuditChallengeSynapse:
        """
        Handle real traffic audit challenge from validator.

        This is for the challenge-response audit system where:
        1. Validator sends 'start' phase - miner snapshots XDP stats
        2. Validator sends real packets to scrubber
        3. Validator sends 'collect' phase - miner returns XDP stats delta

        The miner MUST return actual XDP stats, not fake values.

        Args:
            synapse: The audit challenge synapse with phase and challenge_id.

        Returns:
            Updated synapse with XDP stats (for 'collect' phase).
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if miner is available for challenges.

        Must be implemented by subclasses to check
        scrubber readiness.
        """
        pass

    @abstractmethod
    def setup_scrubbers(self) -> bool:
        """
        Set up scrubber infrastructure.

        Must be implemented by subclasses to deploy
        and configure scrubbers.
        """
        pass

    @abstractmethod
    def teardown_scrubbers(self, destroy_instances: bool = False) -> bool:
        """
        Tear down scrubber infrastructure.

        Must be implemented by subclasses to clean up
        scrubber resources.

        Args:
            destroy_instances: If True, terminate cloud instances.
                             If False (default), just save state for recovery.
        """
        pass

    def run(self) -> None:
        """
        Main run loop for the miner.

        Sets up axon and runs the main loop in the
        current thread.
        """
        logger.info("Starting miner neuron...")

        # Check registration
        if not self.check_registered():
            raise RuntimeError("Miner not registered on subnet")

        # Setup axon
        self.setup_axon()

        # Start serving
        self.axon.start()
        logger.info(f"Axon serving on port {self.axon.port}")

        # Register axon on-chain so validators can find us
        # Retry with exponential backoff to handle ServingRateLimitExceeded (error 12)
        max_retries = 5
        base_delay = 10  # seconds
        for attempt in range(max_retries):
            try:
                self.subtensor.serve_axon(
                    netuid=self.settings.netuid,
                    axon=self.axon,
                )
                logger.info("Axon registered on-chain")
                break
            except Exception as e:
                if "Custom error: 12" in str(e) or "ServingRateLimitExceeded" in str(e):
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"Axon serve rate limited, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                else:
                    raise
        else:
            logger.error("Failed to register axon after max retries - continuing without on-chain registration")

        # Setup scrubbers
        if not self.setup_scrubbers():
            logger.error("Failed to setup scrubbers")
            return

        self.is_running = True

        try:
            # Main loop
            while self.is_running:
                try:
                    # Sync with network periodically
                    if self.should_sync_metagraph():
                        self.sync()

                    # Log status
                    self.log_status()

                    # Increment step
                    self.step += 1

                    # Sleep before next iteration
                    time.sleep(60)  # Check every minute

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    time.sleep(10)

        finally:
            self.shutdown()

    def run_in_background_thread(self) -> threading.Thread:
        """
        Run the miner in a background thread.

        Returns:
            The background thread.
        """
        self._run_thread = threading.Thread(
            target=self.run,
            daemon=True
        )
        self._run_thread.start()
        return self._run_thread

    def stop_run_thread(self) -> None:
        """Stop the background thread."""
        self.is_running = False
        if self._stop_event:
            self._stop_event.set()
        if self._run_thread and self._run_thread.is_alive():
            self._run_thread.join(timeout=30)

    def shutdown(self) -> None:
        """Shutdown the miner cleanly."""
        logger.info("Shutting down miner...")
        self.is_running = False

        # Stop axon
        if self.axon:
            self.axon.stop()

        # Teardown scrubbers
        self.teardown_scrubbers()

        logger.info("Miner shutdown complete")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
        return False
