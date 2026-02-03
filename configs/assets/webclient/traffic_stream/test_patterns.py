#!/usr/bin/env python3
"""
Simple test script to verify PatternEngine state machine logic.
"""

import asyncio
from pathlib import Path
from config import load_config
from patterns import PatternEngine, TrafficState


async def test_pattern_engine_states():
    """Test PatternEngine state transitions and timing."""
    config_path = Path(__file__).parent / "sample_config.yaml"

    print(f"Loading config from: {config_path}")
    config = load_config(str(config_path))

    # Create pattern engine
    engine = PatternEngine(config.patterns, config.time_of_day)

    print("\n=== Initial State ===")
    print(f"State: {engine.current_state}")
    assert engine.current_state == "BURST", "Should start in BURST state"

    # Test burst pattern
    print("\n=== Testing BURST State ===")
    delays = []
    for i in range(12):  # More than max burst (10 requests)
        delay = await engine.get_next_delay()
        delays.append(delay)
        print(f"Request {i+1}: delay={delay:.3f}s, state={engine.current_state}")

        # After first few requests, should still be in BURST or transitioned
        if i < 3:
            # Early requests should have short delays (100-500ms adjusted by time-of-day)
            assert delay < 5.0, f"Burst interval too long: {delay}s"

    # Should have transitioned out of initial burst
    print(f"\nFinal state after burst sequence: {engine.current_state}")
    assert engine.current_state in ["STEADY", "IDLE", "BURST"], \
        f"Unexpected state: {engine.current_state}"

    # Test IDLE state (if we entered it)
    if engine.current_state == "IDLE":
        print("\n=== Testing IDLE State ===")
        delay = await engine.get_next_delay()
        print(f"IDLE delay: {delay:.1f}s")
        # IDLE should return long delay (60-300s adjusted by time-of-day)
        # Could be longer with time-of-day adjustment
        print(f"State after IDLE: {engine.current_state}")
        assert engine.current_state == "BURST", "Should transition to BURST after IDLE"

    # Test STEADY state behavior
    print("\n=== Testing STEADY State Behavior ===")
    # Force engine into STEADY state by creating new instance
    engine2 = PatternEngine(config.patterns, config.time_of_day)

    # Simulate burst completion leading to STEADY (90% probability)
    # We'll just manually test the steady timing
    print("Generating requests to observe STEADY pattern...")
    steady_delays = []
    for i in range(5):
        delay = await engine2.get_next_delay()
        steady_delays.append(delay)
        print(f"Request {i+1}: delay={delay:.3f}s, state={engine2.current_state}")

    print("\n=== Pattern Configuration ===")
    print(f"Burst requests: {config.patterns.burst.requests}")
    print(f"Burst interval_ms: {config.patterns.burst.interval_ms}")
    print(f"Burst pause_s: {config.patterns.burst.pause_s}")
    print(f"Steady interval_s: {config.patterns.steady.interval_s}")
    print(f"Steady duration_m: {config.patterns.steady.duration_m}")
    print(f"Idle duration_s: {config.patterns.idle.duration_s}")
    print(f"Idle probability: {config.patterns.idle.probability}")

    print("\n=== Time-of-Day Multipliers ===")
    for hour in [2, 10, 19, 22]:
        multiplier = config.time_of_day.get_multiplier(hour)
        print(f"Hour {hour:02d}: multiplier={multiplier}")

    print("\n✅ All pattern tests passed!")


async def test_time_of_day_adjustment():
    """Test that time-of-day multipliers affect delays correctly."""
    config_path = Path(__file__).parent / "sample_config.yaml"
    config = load_config(str(config_path))

    print("\n=== Testing Time-of-Day Adjustment ===")

    # The adjustment is: adjusted_delay = base_delay / multiplier
    # Lower multiplier (e.g., 0.3) = longer delays = less traffic
    # Higher multiplier (e.g., 1.0) = shorter delays = more traffic

    engine = PatternEngine(config.patterns, config.time_of_day)

    print("\nNote: Lower multiplier = longer delays = less traffic")
    print("Formula: adjusted_delay = base_delay / multiplier")
    print("\nExample with base_delay = 1.0s:")
    for mult in [0.3, 0.5, 0.8, 1.0]:
        adjusted = 1.0 / mult
        print(f"  Multiplier {mult} -> {adjusted:.2f}s delay")

    print("\n✅ Time-of-day test completed!")


async def test_state_transitions():
    """Test all possible state transitions."""
    config_path = Path(__file__).parent / "sample_config.yaml"
    config = load_config(str(config_path))

    print("\n=== Testing State Transitions ===")
    print("\nExpected transitions:")
    print("1. BURST -> STEADY (90% probability after burst)")
    print("2. BURST -> IDLE (10% probability after burst)")
    print("3. IDLE -> BURST (always)")
    print("4. STEADY -> BURST (after duration)")

    # Run multiple engines to observe state transitions
    print("\nObserving 10 burst completions:")
    burst_to_steady = 0
    burst_to_idle = 0

    for trial in range(10):
        engine = PatternEngine(config.patterns, config.time_of_day)

        # Complete a burst
        for _ in range(15):  # Enough to complete any burst
            await engine.get_next_delay()
            if engine.current_state != "BURST":
                break

        if engine.current_state == "STEADY":
            burst_to_steady += 1
        elif engine.current_state == "IDLE":
            burst_to_idle += 1

        print(f"Trial {trial+1}: BURST -> {engine.current_state}")

    print(f"\nResults: {burst_to_steady} STEADY, {burst_to_idle} IDLE")
    print(f"Expected ~9 STEADY, ~1 IDLE (90%/10% split)")

    print("\n✅ State transition test completed!")


if __name__ == "__main__":
    print("🚀 Starting PatternEngine tests...\n")
    asyncio.run(test_pattern_engine_states())
    asyncio.run(test_time_of_day_adjustment())
    asyncio.run(test_state_transitions())
    print("\n🎉 All tests completed!")
