"""
Traffic pattern engine for controlling request timing.

Implements a state machine with BURST, STEADY, and IDLE states
that controls when traffic is sent based on configured patterns
and time-of-day multipliers.
"""

import asyncio
import random
from datetime import datetime
from enum import Enum
from typing import Optional

from .config import PatternConfig, TimeOfDayConfig


class TrafficState(str, Enum):
    """Traffic pattern states."""

    BURST = "BURST"
    STEADY = "STEADY"
    IDLE = "IDLE"


class PatternEngine:
    """Controls traffic timing based on patterns and time-of-day.

    States: BURST, STEADY, IDLE
    - BURST: Send 3-10 requests rapidly (100-500ms apart), then pause 5-30s
    - STEADY: Send requests every 1-3 seconds for 5-15 minutes
    - IDLE: Do nothing for 60-300 seconds (10% probability after burst)

    State transitions:
    1. Start in BURST
    2. After burst completes: 10% -> IDLE, 90% -> STEADY
    3. After IDLE -> BURST
    4. After STEADY duration -> BURST
    """

    def __init__(self, patterns: PatternConfig, time_of_day: TimeOfDayConfig):
        """Initialize pattern engine with configuration.

        Args:
            patterns: Traffic pattern configuration (burst, steady, idle)
            time_of_day: Time-of-day multiplier configuration
        """
        self._patterns = patterns
        self._time_of_day = time_of_day
        self._state = TrafficState.BURST

        # BURST state tracking
        self._burst_count = 0
        self._burst_target = 0

        # STEADY state tracking
        self._steady_start: Optional[float] = None
        self._steady_end: Optional[float] = None

    @property
    def current_state(self) -> str:
        """Returns 'BURST', 'STEADY', or 'IDLE'"""
        return self._state.value

    async def get_next_delay(self) -> float:
        """Returns seconds to wait before next request.

        Applies time-of-day multiplier to base delay.
        Handles state transitions automatically.

        Returns:
            Seconds to wait before sending next request
        """
        # Get base delay from current state
        if self._state == TrafficState.BURST:
            base_delay = self._burst_delay()
        elif self._state == TrafficState.STEADY:
            base_delay = self._steady_delay()
        else:  # IDLE
            base_delay = self._idle_delay()

        # Apply time-of-day multiplier (lower multiplier = longer delays = less traffic)
        hour = datetime.now().hour
        multiplier = self._time_of_day.get_multiplier(hour)

        if multiplier > 0:
            return base_delay / multiplier
        # Avoid division by zero - use very long delay
        return base_delay * 1000

    def _burst_delay(self) -> float:
        """Handle BURST state logic and transitions.

        Returns:
            Base delay in seconds
        """
        # Initialize burst if starting new one
        if self._burst_count == 0:
            min_req, max_req = self._patterns.burst.requests
            self._burst_target = random.randint(min_req, max_req)

        self._burst_count += 1

        # Check if burst is complete
        if self._burst_count >= self._burst_target:
            # Reset for next burst
            self._burst_count = 0

            # Calculate pause duration
            min_pause, max_pause = self._patterns.burst.pause_s
            pause = random.uniform(min_pause, max_pause)

            # Decide next state (10% IDLE, 90% STEADY)
            if random.random() < self._patterns.idle.probability:
                self._state = TrafficState.IDLE
            else:
                # Transition to STEADY and set duration
                self._state = TrafficState.STEADY
                loop = asyncio.get_event_loop()
                self._steady_start = loop.time()
                min_dur, max_dur = self._patterns.steady.duration_m
                duration = random.uniform(min_dur, max_dur) * 60  # Convert minutes to seconds
                self._steady_end = self._steady_start + duration

            return pause

        # Return interval between burst requests
        min_int, max_int = self._patterns.burst.interval_ms
        return random.uniform(min_int, max_int) / 1000.0  # Convert ms to seconds

    def _steady_delay(self) -> float:
        """Handle STEADY state logic and transitions.

        Returns:
            Base delay in seconds
        """
        # Check if steady duration has been exceeded
        loop = asyncio.get_event_loop()
        current_time = loop.time()

        if current_time >= self._steady_end:
            # Transition back to BURST
            self._state = TrafficState.BURST
            self._steady_start = None
            self._steady_end = None
            # Return burst delay for immediate transition
            return self._burst_delay()

        # Return steady interval
        min_int, max_int = self._patterns.steady.interval_s
        return random.uniform(min_int, max_int)

    def _idle_delay(self) -> float:
        """Handle IDLE state logic and transitions.

        Returns full idle duration and transitions to BURST.

        Returns:
            Base delay in seconds
        """
        # Calculate idle duration
        min_dur, max_dur = self._patterns.idle.duration_s
        duration = random.uniform(min_dur, max_dur)

        # Immediately transition to BURST (next call will be in BURST state)
        self._state = TrafficState.BURST

        return duration
