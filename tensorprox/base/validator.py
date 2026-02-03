"""
Base validator neuron for TensorProx subnet.

Extends BaseNeuron with validator-specific functionality:
- Miner querying and availability checking
- Validation round orchestration
- Scoring and weight setting
- Challenge generation
"""

import asyncio
import time
import random
import secrets
from typing import Optional, List, Dict, Any
from abc import abstractmethod

import bittensor as bt
import numpy as np
from pydantic import BaseModel, Field
from loguru import logger

from tensorprox.base.neuron import BaseNeuron
from tensorprox.base.protocol import (
    PingSynapse,
    ChallengeSynapse,
    ScrubberConfig,
)
from tensorprox.base.dendrite import DendriteResponseEvent
from tensorprox.settings import Settings, get_settings
from tensorprox import (
    AVAILABILITY_CHECK_TIMEOUT,
    SCRUBBER_SETUP_TIMEOUT,
    CHALLENGE_DURATION,
    LOCKDOWN_TIMEOUT,
    ROUND_TIMEOUT,
)


class BaseValidatorNeuron(BaseModel, BaseNeuron):
    """
    Base class for TensorProx validator neurons.

    Validators orchestrate validation rounds, query miners,
    score their performance, and set weights on-chain.
    """

    model_config = {"arbitrary_types_allowed": True}

    # Settings from BaseNeuron (must be declared for Pydantic)
    settings: Optional[Settings] = Field(default=None)
    step: int = Field(default=0)
    last_sync_block: int = Field(default=0)

    # Bittensor primitives (lazy loaded)
    _wallet: Optional["bt.Wallet"] = None
    _subtensor: Optional["bt.Subtensor"] = None
    _metagraph: Optional["bt.Metagraph"] = None
    _uid: Optional[int] = None

    # Dendrite for outbound queries
    dendrite: Optional["bt.Dendrite"] = Field(default=None)

    # Weight state
    scores: Optional[np.ndarray] = Field(default=None)
    weights: Optional[np.ndarray] = Field(default=None)
    past_weights: List[np.ndarray] = Field(default_factory=list)
    _last_weight_set_block: int = 0  # Local tracking for weight set timing

    # Round state
    current_round: int = Field(default=0)
    round_start_time: float = Field(default=0.0)
    is_running: bool = Field(default=False)

    # Tracked miners
    active_miner_uids: List[int] = Field(default_factory=list)

    # Bootstrap token for miner TPM registration (renewed per cycle)
    _bootstrap_token: str = ""

    def __init__(self, settings: Optional[Settings] = None, **kwargs):
        """Initialize the validator neuron."""
        # Get settings if not provided
        if settings is None:
            settings = get_settings()
        # Pass settings to Pydantic model init
        BaseModel.__init__(self, settings=settings, **kwargs)
        # Initialize BaseNeuron (settings already set by Pydantic)
        BaseNeuron.__init__(self, settings)

    def setup(self) -> None:
        """Set up the validator."""
        logger.info("Setting up validator...")

        # Check registration
        if not self.check_registered():
            raise RuntimeError("Validator not registered on subnet")

        # Setup dendrite
        self.dendrite = self.settings.dendrite

        # Initialize weights array
        n_uids = len(self.metagraph.S)
        self.scores = np.zeros(n_uids, dtype=np.float32)
        self.weights = np.zeros(n_uids, dtype=np.float32)

        logger.info(f"Validator setup complete. UID: {self.uid}")

        # Generate initial bootstrap token and register with TPM
        self._renew_bootstrap_token()

    def _renew_bootstrap_token(self) -> bool:
        """
        Generate a fresh bootstrap token and register it with TPM.

        Called at validator startup and before each miner discovery cycle.
        Miners receive this token in PingSynapse and use it to register with TPM.

        Returns:
            True if token was registered successfully, False otherwise.
        """
        # Generate a fresh token
        self._bootstrap_token = secrets.token_urlsafe(32)

        # Register with TPM
        try:
            import requests
            from shared.config import get_settings as get_shared_settings
            shared_settings = get_shared_settings()

            tpm_host = shared_settings.tensorprox_host
            tpm_port = shared_settings.tensorprox_port
            if tpm_host.startswith(("http://", "https://")):
                tpm_url = f"{tpm_host.rstrip('/')}/api/v1/validators/bootstrap-token"
            else:
                tpm_url = f"http://{tpm_host}:{tpm_port}/api/v1/validators/bootstrap-token"

            response = requests.post(
                tpm_url,
                json={
                    "token": self._bootstrap_token,
                    "validator_uid": self.uid,
                    "validator_hotkey": self.wallet.hotkey.ss58_address,
                },
                timeout=10,
            )

            if response.status_code == 200:
                data = response.json()
                logger.info(
                    f"Bootstrap token registered with TPM (expires_in={data.get('expires_in', '?')}s)"
                )
                return True
            else:
                logger.warning(
                    f"Failed to register bootstrap token with TPM: {response.status_code} {response.text[:200]}"
                )
                return False

        except Exception as e:
            logger.warning(f"Failed to register bootstrap token with TPM: {e}")
            return False

    @property
    def bootstrap_token(self) -> str:
        """Get current bootstrap token for miner registration."""
        return self._bootstrap_token

    def forward(self, synapse: PingSynapse) -> PingSynapse:
        """
        Validators don't respond to pings.

        This is required by BaseNeuron but not used for validators.
        """
        return synapse

    def handle_challenge(self, synapse: ChallengeSynapse) -> ChallengeSynapse:
        """
        Validators don't handle challenges.

        This is required by BaseNeuron but not used for validators.
        """
        return synapse

    def should_set_weights(self) -> bool:
        """
        Check if weights should be set based on blocks elapsed.

        Uses both metagraph's last_update and local tracking to determine
        when this validator last set weights.

        Uses weight_setter_step (default 120 blocks) as the interval, which
        must be >= the chain's weights_rate_limit (typically 100 blocks).
        """
        # Don't set weights on initialization
        if self.step == 0:
            return False

        # Check if neuron has validator permit
        if not self.settings.metagraph.validator_permit[self.uid]:
            return False

        # Get blocks since last weight update (use max of metagraph and local tracking)
        metagraph_last_update = self.settings.metagraph.last_update[self.uid]
        last_update_block = max(metagraph_last_update, self._last_weight_set_block)
        blocks_since_update = self.block - last_update_block

        # Use weight_setter_step for weight setting interval (should be >= chain rate limit)
        return blocks_since_update > self.settings.weight_setter_step

    def mark_weights_set(self) -> None:
        """Mark that weights were set at current block (local tracking)."""
        self._last_weight_set_block = self.block

    async def query_miners_availability(
        self,
        uids: List[int],
        timeout: float = AVAILABILITY_CHECK_TIMEOUT
    ) -> Dict[int, PingSynapse]:
        """
        Query miners for their availability and configuration.

        Args:
            uids: List of miner UIDs to query.
            timeout: Query timeout in seconds.

        Returns:
            Dict mapping UID to their ping response.
        """
        logger.info(f"Querying {len(uids)} neurons for availability...")

        # Get axon endpoints
        axons = [self.metagraph.axons[uid] for uid in uids]

        # Create ping synapse with bootstrap token for TPM registration
        synapse = PingSynapse(bootstrap_token=self._bootstrap_token)

        # Query all miners
        responses = await self.dendrite.forward(
            axons=axons,
            synapse=synapse,
            timeout=timeout
        )

        # Map responses to UIDs
        # Only include miners that:
        # 1. Responded successfully
        # 2. Report is_available=True
        # 3. Have valid scrubber_config with active_nodes (scrubber IPs)
        result = {}
        for uid, response in zip(uids, responses):
            # Handle different response types from bittensor
            if response is None:
                continue

            # Check if miner responded but is not available
            if not (hasattr(response, 'is_available') and response.is_available):
                if hasattr(response, 'dendrite') and response.dendrite:
                    logger.trace(f"Miner {uid} responded but is_available=False")
                continue

            # Miner says is_available=True - now validate scrubber configuration
            # Must have scrubber_config with at least one active node (scrubber IP)
            scrubber_config = getattr(response, 'scrubber_config', None)
            if scrubber_config is None:
                logger.debug(f"Miner {uid} is_available=True but scrubber_config is None - excluding")
                continue

            active_nodes = getattr(scrubber_config, 'active_nodes', None)
            if not active_nodes or len(active_nodes) == 0:
                logger.debug(f"Miner {uid} is_available=True but no active_nodes in scrubber_config - excluding")
                continue

            # Valid response: is_available=True AND has scrubber IP(s)
            result[uid] = response
            logger.trace(f"Miner {uid} available with scrubber IPs: {active_nodes}")

        logger.info(f"Got {len(result)} available miners (with valid scrubber config)")
        return result

    async def send_challenge(
        self,
        uid: int,
        task: str,
        state: str = "",
        **kwargs
    ) -> ChallengeSynapse:
        """
        Send a challenge task to a specific miner.

        Args:
            uid: Miner UID.
            task: Task name (setup, challenge, lockdown).
            state: Task configuration JSON.
            **kwargs: Additional synapse parameters.

        Returns:
            The response synapse.
        """
        axon = self.metagraph.axons[uid]

        synapse = ChallengeSynapse(
            task=task,
            state=state,
            **kwargs
        )

        responses = await self.dendrite.forward(
            axons=[axon],
            synapse=synapse,
            timeout=self.settings.neuron_forward_max_time
        )

        return responses[0] if responses else synapse

    async def run_validation_round(self) -> DendriteResponseEvent:
        """
        Execute a complete validation round.

        The round consists of:
        1. Availability check
        2. Scrubber setup
        3. Challenge execution
        4. Lockdown/cleanup

        Returns:
            DendriteResponseEvent with all responses.
        """
        self.current_round += 1
        self.round_start_time = time.time()

        response_event = DendriteResponseEvent(
            round_id=f"round-{self.current_round}-{int(time.time())}",
            block_number=self.block,
            validator_uid=self.uid,
            round_start_time=self.round_start_time
        )

        logger.info(f"Starting validation round {self.current_round}")

        try:
            # Phase 1: Availability check
            miner_uids = self.get_miner_subset()
            available = await self.query_miners_availability(miner_uids)

            for uid, ping in available.items():
                response_event.add_ping_response(
                    uid=uid,
                    response=ping.model_dump(),
                    success=True
                )

            if not available:
                logger.warning("No miners available")
                return response_event

            self.active_miner_uids = list(available.keys())

            # Phase 2: Setup
            setup_results = await self.run_setup_phase(self.active_miner_uids)
            for uid, result in setup_results.items():
                response_event.add_setup_response(
                    uid=uid,
                    response=result,
                    success=result.get("success", False)
                )

            # Phase 3: Challenge
            challenge_results = await self.run_challenge_phase(
                self.active_miner_uids
            )
            for uid, result in challenge_results.items():
                metrics = result.get("metrics", {})
                response_event.add_challenge_response(
                    uid=uid,
                    response=result,
                    metrics=metrics,
                    success=result.get("success", False)
                )

            # Phase 4: Lockdown
            lockdown_results = await self.run_lockdown_phase(
                self.active_miner_uids
            )
            for uid, result in lockdown_results.items():
                response_event.add_lockdown_response(
                    uid=uid,
                    response=result,
                    success=result.get("success", False)
                )

        except Exception as e:
            logger.error(f"Error in validation round: {e}")

        finally:
            response_event.round_end_time = time.time()

        logger.info(
            f"Round {self.current_round} complete. "
            f"Duration: {response_event.round_end_time - self.round_start_time:.1f}s"
        )

        return response_event

    @abstractmethod
    async def run_setup_phase(
        self,
        uids: List[int]
    ) -> Dict[int, Dict[str, Any]]:
        """
        Run the setup phase for all miners.

        Must be implemented by subclasses to handle
        scrubber setup verification.
        """
        pass

    @abstractmethod
    async def run_challenge_phase(
        self,
        uids: List[int]
    ) -> Dict[int, Dict[str, Any]]:
        """
        Run the challenge phase.

        Must be implemented by subclasses to generate
        traffic and measure performance.
        """
        pass

    @abstractmethod
    async def run_lockdown_phase(
        self,
        uids: List[int]
    ) -> Dict[int, Dict[str, Any]]:
        """
        Run the lockdown/cleanup phase.

        Must be implemented by subclasses to handle
        post-challenge cleanup.
        """
        pass

    def get_miner_subset(self) -> List[int]:
        """
        Get the subset of miners this validator should query.

        Uses time-synchronized seeding to ensure all validators
        query disjoint miner subsets.
        """
        all_miner_uids = self.get_miner_uids()
        if not all_miner_uids:
            return []

        # Get all validators
        validator_uids = self.get_validator_uids()
        num_validators = len(validator_uids)

        if num_validators == 0:
            return all_miner_uids

        # Time-based seed for synchronized shuffling
        # Changes every epoch to rotate miner assignments
        seed = self.block // self.settings.neuron_epoch_length

        # Shuffle miners deterministically
        rng = random.Random(seed)
        shuffled = all_miner_uids.copy()
        rng.shuffle(shuffled)

        # Get this validator's index
        try:
            my_index = validator_uids.index(self.uid)
        except ValueError:
            return []

        # Split miners among validators
        miners_per_validator = len(shuffled) // num_validators
        start_idx = my_index * miners_per_validator

        # Last validator gets remaining miners
        if my_index == num_validators - 1:
            return shuffled[start_idx:]
        else:
            return shuffled[start_idx:start_idx + miners_per_validator]

    def update_scores(
        self,
        uids: List[int],
        rewards: List[float]
    ) -> None:
        """
        Update miner scores based on round results.

        Args:
            uids: List of miner UIDs.
            rewards: Corresponding reward values.
        """
        for uid, reward in zip(uids, rewards):
            if 0 <= uid < len(self.scores):
                # Exponential moving average
                alpha = 0.1
                self.scores[uid] = (
                    alpha * reward + (1 - alpha) * self.scores[uid]
                )

        logger.debug(f"Updated scores for {len(uids)} miners")

    def set_weights(self) -> bool:
        """
        Set weights on-chain.

        Normalizes scores and submits to Bittensor.
        """
        logger.info("Setting weights on chain...")

        # Convert scores to weights
        weights = self.scores.copy()

        # Handle NaN values
        weights = np.nan_to_num(weights, nan=0.0)

        # Average with past weights for stability
        self.past_weights.append(weights)
        if len(self.past_weights) > self.settings.past_weights_count:
            self.past_weights.pop(0)

        if self.past_weights:
            weights = np.mean(self.past_weights, axis=0)

        # Normalize
        total = weights.sum()
        if total > 0:
            weights = weights / total

        # Process through Bittensor's weight utils
        try:
            processed_uids, processed_weights = bt.utils.weight_utils.process_weights_for_netuid(
                uids=np.arange(len(weights)),
                weights=weights,
                netuid=self.settings.netuid,
                subtensor=self.subtensor,
                metagraph=self.metagraph,
            )

            # Convert for chain submission
            uint_uids, uint_weights = bt.utils.weight_utils.convert_weights_and_uids_for_emit(
                uids=processed_uids,
                weights=processed_weights,
            )

            # Submit to chain
            result = self.subtensor.set_weights(
                wallet=self.wallet,
                netuid=self.settings.netuid,
                uids=uint_uids,
                weights=uint_weights,
                wait_for_finalization=True,
                wait_for_inclusion=True,
            )

            # ExtrinsicResponse supports tuple-like access: result[0] = success, result[1] = message
            if result[0]:
                logger.info("Successfully set weights on chain")
                self.weights = weights
                return True
            else:
                logger.error(f"Failed to set weights on chain: {result}")
                return False

        except Exception as e:
            logger.error(f"Error setting weights: {e}")
            return False

    def run(self) -> None:
        """Main run loop for the validator."""
        logger.info("Starting validator neuron...")

        self.setup()
        self.is_running = True

        try:
            while self.is_running:
                try:
                    # Sync with network
                    if self.should_sync_metagraph():
                        self.sync()

                    # Run validation round
                    loop = asyncio.get_event_loop()
                    response_event = loop.run_until_complete(
                        self.run_validation_round()
                    )

                    # Process results and update scores
                    self.process_round_results(response_event)

                    # Set weights if needed
                    if self.should_set_weights():
                        self.set_weights()

                    # Log status
                    self.log_status()

                    # Increment step
                    self.step += 1

                    # Wait before next round
                    self.wait_for_next_round()

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error in validation loop: {e}")
                    time.sleep(60)

        finally:
            self.shutdown()

    def process_round_results(
        self,
        response_event: DendriteResponseEvent
    ) -> None:
        """
        Process results from a validation round.

        Override in subclasses to implement specific
        scoring logic.
        """
        logger.debug(f"Processing round results: {response_event.summary()}")

    def wait_for_next_round(self) -> None:
        """Wait for the appropriate time before the next round."""
        elapsed = time.time() - self.round_start_time
        remaining = ROUND_TIMEOUT - elapsed

        if remaining > 0:
            logger.info(f"Waiting {remaining:.0f}s until next round...")
            time.sleep(remaining)

    def shutdown(self) -> None:
        """Shutdown the validator cleanly."""
        logger.info("Shutting down validator...")
        self.is_running = False

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
        return False
