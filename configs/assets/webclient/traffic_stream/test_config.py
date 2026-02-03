#!/usr/bin/env python3
"""
Simple test script to verify config loading and validation.
"""

from pathlib import Path
from config import load_config


def test_load_sample_config():
    """Test loading the sample configuration file."""
    config_path = Path(__file__).parent / "sample_config.yaml"

    print(f"Loading config from: {config_path}")
    config = load_config(str(config_path))

    # Verify defaults
    print("\n=== Defaults ===")
    print(f"TCP Ports: {config.defaults['tcp_ports']}")
    print(f"UDP Ports: {config.defaults['udp_ports']}")
    assert config.defaults["tcp_ports"].echo == 7011
    assert config.defaults["tcp_ports"].http == 7022
    assert config.defaults["udp_ports"].echo == 7111

    # Verify service weights
    print("\n=== Service Weights ===")
    print(f"Weights: {config.service_weights}")
    assert sum(config.service_weights.values()) == 100

    # Verify patterns
    print("\n=== Patterns ===")
    print(f"Burst requests range: {config.patterns.burst.requests}")
    print(f"Burst interval_ms range: {config.patterns.burst.interval_ms}")
    print(f"Steady interval_s range: {config.patterns.steady.interval_s}")
    print(f"Idle duration_s range: {config.patterns.idle.duration_s}")
    print(f"Idle probability: {config.patterns.idle.probability}")
    assert config.patterns.burst.requests == (3, 10)
    assert config.patterns.burst.interval_ms == (100, 500)
    assert config.patterns.steady.interval_s == (1, 3)
    assert config.patterns.idle.duration_s == (60, 300)
    assert config.patterns.idle.probability == 0.1

    # Verify time of day
    print("\n=== Time of Day ===")
    print(f"Multipliers: {config.time_of_day.multipliers}")
    assert config.time_of_day.get_multiplier(10) == 1.0  # 09-17 range
    assert config.time_of_day.get_multiplier(2) == 0.3   # 00-06 range
    assert config.time_of_day.get_multiplier(19) == 0.8  # 17-21 range

    # Verify origins
    print("\n=== Origins ===")
    assert len(config.origins) == 2
    assert config.origins[0].ip == "203.0.113.50"  # RFC 5737 TEST-NET-3
    assert config.origins[1].ip == "192.0.2.55"    # RFC 5737 TEST-NET-1

    # First origin should have default ports
    print(f"Origin 1 TCP ports: {config.origins[0].tcp_ports}")
    assert config.origins[0].tcp_ports.echo == 7011
    assert config.origins[0].tcp_ports.http == 7022

    # Second origin should have overridden TCP ports
    print(f"Origin 2 TCP ports: {config.origins[1].tcp_ports}")
    assert config.origins[1].tcp_ports.echo == 8080
    assert config.origins[1].tcp_ports.http == 8081
    assert config.origins[1].tcp_ports.custom == 8082

    # Second origin should still have default UDP ports
    print(f"Origin 2 UDP ports: {config.origins[1].udp_ports}")
    assert config.origins[1].udp_ports.echo == 7111

    print("\n✅ All tests passed!")


def test_validation_errors():
    """Test that validation errors are caught."""
    print("\n=== Testing Validation ===")

    # Test invalid service weights
    try:
        from pydantic import ValidationError
        from config import StreamConfig

        invalid_config = {
            "defaults": {
                "tcp_ports": {"echo": 7011, "http": 7022, "custom": 7033},
                "udp_ports": {"echo": 7111, "dgram": 7112, "custom": 7113},
            },
            "service_weights": {
                "tcp_http": 50,  # Only sums to 50
            },
            "patterns": {
                "burst": {
                    "requests": "3-10",
                    "interval_ms": "100-500",
                    "pause_s": "5-30",
                },
                "steady": {"interval_s": "1-3", "duration_m": "5-15"},
                "idle": {"duration_s": "60-300", "probability": 0.1},
            },
            "time_of_day": {"09-17": 1.0},
            "origins": [{"ip": "203.0.113.50"}],  # RFC 5737 TEST-NET-3
        }

        StreamConfig(**invalid_config)
        print("❌ Should have raised ValidationError for service_weights")
    except ValidationError as e:
        print(f"✅ Correctly caught service_weights validation error")

    # Test empty origins
    try:
        invalid_config["service_weights"] = {
            "tcp_http": 60,
            "tcp_echo": 15,
            "tcp_custom": 10,
            "udp_echo": 5,
            "udp_dgram": 5,
            "udp_custom": 5,
        }
        invalid_config["origins"] = []
        StreamConfig(**invalid_config)
        print("❌ Should have raised ValidationError for empty origins")
    except ValidationError as e:
        print(f"✅ Correctly caught empty origins validation error")

    # Test invalid IP
    try:
        invalid_config["origins"] = [{"ip": "999.999.999.999"}]
        StreamConfig(**invalid_config)
        print("❌ Should have raised ValidationError for invalid IP")
    except ValidationError as e:
        print(f"✅ Correctly caught invalid IP validation error")


if __name__ == "__main__":
    test_load_sample_config()
    test_validation_errors()
    print("\n🎉 All validation tests completed!")
