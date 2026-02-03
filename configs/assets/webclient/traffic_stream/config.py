"""
Configuration management for traffic stream client.

Loads and validates YAML configuration with per-origin port overrides
and traffic pattern definitions.
"""

import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TCPPortConfig(BaseModel):
    """TCP port configuration with echo, http, and custom ports."""

    echo: int = Field(..., ge=1, le=65535)
    http: int = Field(..., ge=1, le=65535)
    custom: int = Field(..., ge=1, le=65535)


class UDPPortConfig(BaseModel):
    """UDP port configuration with echo, dgram, and custom ports."""

    echo: int = Field(..., ge=1, le=65535)
    dgram: int = Field(..., ge=1, le=65535)
    custom: int = Field(..., ge=1, le=65535)


# Constants
TIME_RANGE_PATTERN = r"^\d{2}-\d{2}$"
DEFAULT_TIME_MULTIPLIER = 1.0
SERVICE_WEIGHTS_TOTAL = 100


def parse_range_value(v: Any) -> Tuple[int, int]:
    """Parse range string or tuple into (min, max) tuple.

    Args:
        v: A range string like "3-10" or a tuple/list of two integers

    Returns:
        Tuple of (min, max) values

    Raises:
        ValueError: If format is invalid or min > max
    """
    if isinstance(v, str):
        if "-" not in v:
            raise ValueError(f"Invalid range format: {v}. Expected 'min-max'")
        parts = v.split("-")
        if len(parts) != 2:
            raise ValueError(f"Invalid range format: {v}. Expected 'min-max'")
        try:
            min_val = int(parts[0])
            max_val = int(parts[1])
        except ValueError:
            raise ValueError(f"Invalid range values: {v}. Both must be integers")
        if min_val > max_val:
            raise ValueError(f"Invalid range: {v}. Min ({min_val}) must be <= max ({max_val})")
        return (min_val, max_val)
    if isinstance(v, (list, tuple)) and len(v) == 2:
        return (int(v[0]), int(v[1]))
    raise ValueError(f"Expected range string or tuple, got {type(v)}")


class BurstPattern(BaseModel):
    """Burst traffic pattern configuration."""

    requests: Tuple[int, int]
    interval_ms: Tuple[int, int]
    pause_s: Tuple[int, int]

    @field_validator("requests", "interval_ms", "pause_s", mode="before")
    @classmethod
    def parse_range(cls, v: Any) -> Tuple[int, int]:
        """Parse range string or tuple into tuple."""
        return parse_range_value(v)


class SteadyPattern(BaseModel):
    """Steady traffic pattern configuration."""

    interval_s: Tuple[int, int]
    duration_m: Tuple[int, int]

    @field_validator("interval_s", "duration_m", mode="before")
    @classmethod
    def parse_range(cls, v: Any) -> Tuple[int, int]:
        """Parse range string or tuple into tuple."""
        return parse_range_value(v)


class IdlePattern(BaseModel):
    """Idle pattern configuration."""

    duration_s: Tuple[int, int]
    probability: float = Field(..., ge=0.0, le=1.0)

    @field_validator("duration_s", mode="before")
    @classmethod
    def parse_range(cls, v: Any) -> Tuple[int, int]:
        """Parse range string or tuple into tuple."""
        return parse_range_value(v)


class PatternConfig(BaseModel):
    """Traffic pattern configuration."""

    burst: BurstPattern
    steady: SteadyPattern
    idle: IdlePattern


class TimeOfDayConfig(BaseModel):
    """Time of day traffic multipliers.

    Maps hour ranges (e.g., "09-17") to multipliers (0.0-1.0).
    Ranges are inclusive of start, exclusive of end: start <= hour < end.
    """

    multipliers: Dict[str, float] = Field(default_factory=dict)

    @field_validator("multipliers", mode="before")
    @classmethod
    def validate_multipliers(cls, v: Any) -> Dict[str, float]:
        """Validate time range format and multiplier values."""
        if not isinstance(v, dict):
            raise ValueError("time_of_day must be a dictionary")

        validated = {}
        for time_range, multiplier in v.items():
            # Validate time range format (e.g., "09-17")
            if not re.match(TIME_RANGE_PATTERN, time_range):
                raise ValueError(
                    f"Invalid time range format: {time_range}. Expected 'HH-HH'"
                )

            # Validate hour values (end can be 24 for ranges like "21-24")
            start_hour, end_hour = map(int, time_range.split("-"))
            if not (0 <= start_hour <= 23 and 0 <= end_hour <= 24):
                raise ValueError(
                    f"Invalid hour range: {time_range}. Start: 00-23, End: 00-24"
                )

            if start_hour >= end_hour:
                raise ValueError(
                    f"Invalid hour range: {time_range}. Start must be < end"
                )

            # Validate multiplier value
            if not isinstance(multiplier, (int, float)):
                raise ValueError(f"Multiplier must be numeric, got {type(multiplier)}")

            if multiplier < 0 or multiplier > 1:
                raise ValueError(
                    f"Multiplier {multiplier} must be between 0.0 and 1.0"
                )

            validated[time_range] = float(multiplier)

        return validated

    def get_multiplier(self, hour: int) -> float:
        """Get multiplier for a given hour (0-23).

        Args:
            hour: Hour of day (0-23)

        Returns:
            Multiplier for that hour, or DEFAULT_TIME_MULTIPLIER if no range matches
        """
        for time_range, multiplier in self.multipliers.items():
            start_hour, end_hour = map(int, time_range.split("-"))
            if start_hour <= hour < end_hour:
                return multiplier
        return DEFAULT_TIME_MULTIPLIER


class OriginConfig(BaseModel):
    """Origin server configuration with optional port overrides.

    When specifying port overrides, all ports for that protocol must be provided.
    Omit tcp_ports/udp_ports entirely to use defaults.
    """

    ip: str
    tcp_ports: Optional[TCPPortConfig] = None
    udp_ports: Optional[UDPPortConfig] = None

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    def merge_with_defaults(
        self, default_tcp: TCPPortConfig, default_udp: UDPPortConfig
    ) -> "OriginConfig":
        """Merge with default port configurations.

        Uses origin-specific ports if provided, otherwise uses defaults.

        Args:
            default_tcp: Default TCP port configuration
            default_udp: Default UDP port configuration

        Returns:
            New OriginConfig with ports filled in
        """
        return OriginConfig(
            ip=self.ip,
            tcp_ports=self.tcp_ports if self.tcp_ports else default_tcp,
            udp_ports=self.udp_ports if self.udp_ports else default_udp,
        )


class DefaultsConfig(BaseModel):
    """Default port configurations for TCP and UDP."""

    tcp_ports: TCPPortConfig
    udp_ports: UDPPortConfig


class StreamConfig(BaseModel):
    """Top-level stream configuration."""

    defaults: DefaultsConfig
    service_weights: Dict[str, int] = Field(default_factory=dict)
    patterns: PatternConfig
    time_of_day: TimeOfDayConfig
    origins: List[OriginConfig]

    @field_validator("time_of_day", mode="before")
    @classmethod
    def parse_time_of_day(cls, v: Any) -> Dict[str, Any]:
        """Wrap time_of_day dictionary in expected structure."""
        if isinstance(v, dict) and "multipliers" not in v:
            # Raw time ranges dict from YAML, wrap it
            return {"multipliers": v}
        return v

    @field_validator("service_weights")
    @classmethod
    def validate_service_weights(cls, v: Dict[str, int]) -> Dict[str, int]:
        """Validate service weights sum to SERVICE_WEIGHTS_TOTAL (100)."""
        if not v:
            raise ValueError("service_weights cannot be empty")
        total = sum(v.values())
        if total != SERVICE_WEIGHTS_TOTAL:
            raise ValueError(
                f"service_weights must sum to {SERVICE_WEIGHTS_TOTAL}, got {total}. "
                f"Weights: {v}"
            )
        return v

    @field_validator("origins")
    @classmethod
    def validate_origins(cls, v: List[OriginConfig]) -> List[OriginConfig]:
        """Validate origins list is not empty."""
        if not v:
            raise ValueError("origins list must not be empty")
        return v

    @model_validator(mode="after")
    def merge_origin_defaults(self) -> "StreamConfig":
        """Merge default ports with origin-specific overrides."""
        default_tcp = self.defaults.tcp_ports
        default_udp = self.defaults.udp_ports

        # Merge each origin with defaults
        merged_origins = []
        for origin in self.origins:
            merged = origin.merge_with_defaults(default_tcp, default_udp)
            merged_origins.append(merged)

        self.origins = merged_origins
        return self


def load_config(path: str) -> StreamConfig:
    """
    Load and validate traffic stream configuration from YAML file.

    Args:
        path: Path to YAML configuration file

    Returns:
        Validated StreamConfig object

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If configuration is invalid
        yaml.YAMLError: If YAML parsing fails
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(config_path, "r") as f:
        raw_config = yaml.safe_load(f)

    if not isinstance(raw_config, dict):
        raise ValueError("Configuration must be a YAML dictionary")

    return StreamConfig(**raw_config)
