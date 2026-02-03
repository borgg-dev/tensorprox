"""
Protocol definitions for TensorProx subnet communication.

Defines Synapse classes for validator-miner communication:
- PingSynapse: Availability and capability queries
- ChallengeSynapse: Challenge task instructions
- HealthReportSynapse: Scrubber health reporting
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, model_validator
import bittensor as bt


class ScrubberConfig(BaseModel):
    """
    Configuration for a miner's scrubber infrastructure.

    Describes the cloud provider, region, and capacity of
    the miner's DDoS protection infrastructure.
    """

    # Cloud provider info
    provider: Optional[str] = Field(
        default=None,
        description="Cloud provider (aws, linode)"
    )
    region: Optional[str] = Field(
        default=None,
        description="Cloud region for scrubbers"
    )

    # Scrubber capacity
    num_scrubbers: int = Field(
        default=2,
        ge=1,
        le=8,
        description="Number of active scrubbers"
    )
    max_scrubbers: int = Field(
        default=8,
        description="Maximum scrubbers this miner can support"
    )

    # Instance configuration
    instance_type: Optional[str] = Field(
        default=None,
        description="Scrubber instance type"
    )

    # Network configuration
    vpc_id: Optional[str] = Field(
        default=None,
        description="VPC ID for scrubbers"
    )
    subnet_id: Optional[str] = Field(
        default=None,
        description="Subnet ID for scrubbers"
    )

    # Shard information
    shard_id: Optional[str] = Field(
        default=None,
        description="Current shard assignment"
    )
    active_nodes: List[str] = Field(
        default_factory=list,
        description="List of active scrubber node IDs"
    )

    # Capability flags
    supports_layer4: bool = Field(
        default=True,
        description="Supports L4 DDoS mitigation"
    )
    supports_layer7: bool = Field(
        default=True,
        description="Supports L7 DDoS mitigation"
    )
    supports_syn_cookies: bool = Field(
        default=True,
        description="Supports SYN cookie challenges"
    )

    @model_validator(mode='after')
    def infer_provider_from_region(self) -> 'ScrubberConfig':
        """Infer provider from region format if not explicitly set."""
        if self.provider is None and self.region:
            # AWS regions end with -N (number): us-east-1, eu-central-1
            # Linode regions are simpler: us-east, eu-central
            import re
            if re.search(r'-\d+$', self.region):
                self.provider = "aws"
            else:
                self.provider = "linode"
        return self

    def serialize(self) -> Dict[str, Any]:
        """Serialize to dictionary for transmission."""
        return self.model_dump()

    @classmethod
    def deserialize(cls, data: Dict[str, Any]) -> "ScrubberConfig":
        """Deserialize from dictionary."""
        return cls(**data)


class PingSynapse(bt.Synapse):
    """
    Synapse for querying miner availability and capabilities.

    Validators use this to check which miners are online and
    what scrubbing capacity they can provide.
    """

    # Bootstrap token for TPM registration (validator -> miner)
    # Allows miners to register with TPM using validator-issued token
    bootstrap_token: Optional[str] = Field(
        default=None,
        description="TPM bootstrap token for miner registration (issued by validator)"
    )

    # Miner's maximum scrubber count (immutable after set)
    max_scrubbers: int = Field(
        default=0,
        description="Maximum scrubbers miner can deploy"
    )

    # Full scrubber configuration
    scrubber_config: Optional[ScrubberConfig] = Field(
        default=None,
        description="Detailed scrubber configuration"
    )

    # Availability status
    is_available: bool = Field(
        default=False,
        description="Whether miner is available for challenges"
    )

    # Last health timestamp
    last_health_update: Optional[float] = Field(
        default=None,
        description="Timestamp of last health report"
    )

    # Note: Don't override deserialize() here - let bt.Synapse handle it
    # so the full PingSynapse with is_available is returned to validators


class ChallengeSynapse(bt.Synapse):
    """
    Synapse for sending challenge tasks to miners.

    Validators send these to instruct miners to perform
    specific operations during validation rounds.
    """

    # Task identification
    task: str = Field(
        default="",
        description="Task name (setup, challenge, lockdown, etc.)"
    )

    # Task configuration as JSON string
    state: str = Field(
        default="",
        description="Task state/configuration as JSON"
    )

    # Challenge parameters
    origin_id: Optional[str] = Field(
        default=None,
        description="Origin ID for this challenge"
    )
    origin_ip: Optional[str] = Field(
        default=None,
        description="Origin IP to protect"
    )
    duration_seconds: int = Field(
        default=900,
        description="Challenge duration in seconds"
    )

    # Traffic configuration
    traffic_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Traffic generation parameters"
    )

    # Response fields (filled by miner)
    success: bool = Field(
        default=False,
        description="Whether task succeeded"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if failed"
    )
    result_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Task result data"
    )


class HealthReportSynapse(bt.Synapse):
    """
    Synapse for miners to report scrubber health metrics.

    Contains real-time performance data from the scrubber's
    eBPF programs and system resources.
    """

    # Node identification
    node_id: str = Field(
        default="",
        description="Scrubber node ID"
    )
    miner_uid: int = Field(
        default=-1,
        description="Miner's network UID"
    )

    # System metrics
    cpu_percent: float = Field(
        default=0.0,
        description="CPU utilization percentage"
    )
    memory_percent: float = Field(
        default=0.0,
        description="Memory utilization percentage"
    )
    uptime_seconds: int = Field(
        default=0,
        description="Node uptime in seconds"
    )

    # ==========================================================================
    # XDP statistics (from xdp_wan_stats map, indices match common.h enum)
    # ==========================================================================

    # Index 0: Passed packets
    xdp_pass: int = Field(default=0, description="Packets passed through XDP")

    # Index 1: Whitelist bypass
    xdp_whitelist_bypass: int = Field(default=0, description="Packets bypassed via whitelist")

    # Index 2: Blacklist drops
    xdp_drop_blacklist: int = Field(default=0, description="Packets dropped by blacklist (Spamhaus/EmergingThreats)")

    # Index 3: Invalid IP header
    xdp_drop_invalid_ip: int = Field(default=0, description="Packets with invalid IP header")

    # Index 4: Invalid TCP header
    xdp_drop_invalid_tcp: int = Field(default=0, description="Packets with invalid TCP header")

    # Index 5: Generic rate limit (catch-all)
    xdp_drop_ratelimit: int = Field(default=0, description="Packets dropped by generic rate limiter")

    # Index 6: Temporary blacklist
    xdp_drop_temp_blacklist: int = Field(default=0, description="Packets dropped by temporary blacklist")

    # Index 7: SYN cookie challenge
    xdp_syncookie_challenge: int = Field(default=0, description="Packets challenged with SYN cookie")

    # Index 8: SYN cookie validated
    xdp_syncookie_validated: int = Field(default=0, description="SYN cookies successfully validated")

    # Index 9: SYN cookie allow
    xdp_syncookie_allow: int = Field(default=0, description="Connections allowed after SYN cookie")

    # Index 10: SYN cookie reject
    xdp_syncookie_reject: int = Field(default=0, description="Connections rejected after SYN cookie failure")

    # Index 11: Quarantine drops
    xdp_drop_quarantine: int = Field(default=0, description="Packets dropped by quarantine")

    # Index 12: Bypass allowed
    xdp_bypass_allowed: int = Field(default=0, description="Packets allowed via bypass rules")

    # Index 13: Bogon source drops
    xdp_drop_bogon: int = Field(default=0, description="Packets from bogon/reserved IP ranges")

    # Index 14-17: TCP flag anomaly attacks
    xdp_drop_tcp_xmas: int = Field(default=0, description="TCP XMAS attack (all flags set)")
    xdp_drop_tcp_null: int = Field(default=0, description="TCP NULL attack (no flags)")
    xdp_drop_tcp_synfin: int = Field(default=0, description="Invalid SYN+FIN combination")
    xdp_drop_tcp_synrst: int = Field(default=0, description="Invalid SYN+RST combination")

    # Index 18: SYN flood
    xdp_drop_syn_flood: int = Field(default=0, description="SYN flood attack drops")

    # Index 19: UDP amplification
    xdp_drop_udp_amp: int = Field(default=0, description="UDP amplification attack (DNS/NTP/SSDP/etc)")

    # Index 20: ICMP flood
    xdp_drop_icmp_flood: int = Field(default=0, description="ICMP flood attack drops")

    # Index 21: Fragmentation attack
    xdp_drop_frag: int = Field(default=0, description="Fragmentation attack (tiny/overlapping frags)")

    # Index 22-24: More TCP attacks
    xdp_drop_tcp_fin: int = Field(default=0, description="FIN-only scan drops")
    xdp_drop_tcp_rst: int = Field(default=0, description="RST flood drops")
    xdp_drop_tcp_ack: int = Field(default=0, description="ACK flood drops (no established state)")

    # Index 25: UDP flood
    xdp_drop_udp_flood: int = Field(default=0, description="Generic UDP flood drops")

    # Index 26: Malformed packets
    xdp_drop_malformed: int = Field(default=0, description="Malformed packet drops (bad headers)")

    # Index 27-28: L7 attacks (detected via patterns)
    xdp_drop_http_flood: int = Field(default=0, description="HTTP flood (PSH+ACK to HTTP ports)")
    xdp_drop_slowloris: int = Field(default=0, description="Slowloris attack (SYN flood to HTTP ports)")

    # Index 29: Land attack
    xdp_drop_land: int = Field(default=0, description="Land attack (src IP == dst IP)")

    # Legacy field for backwards compatibility
    whitelist_bypass: int = Field(default=0, description="Alias for xdp_whitelist_bypass")

    # Per-origin statistics
    origin_stats: Dict[str, Dict[str, int]] = Field(
        default_factory=dict,
        description="Per-origin traffic statistics"
    )

    # Timestamp
    timestamp: float = Field(
        default=0.0,
        description="Report timestamp"
    )

    def get_total_dropped(self) -> int:
        """Get total dropped packets across all categories."""
        return (
            # Blacklist/quarantine
            self.xdp_drop_blacklist
            + self.xdp_drop_temp_blacklist
            + self.xdp_drop_quarantine
            + self.xdp_drop_bogon
            # Invalid packets
            + self.xdp_drop_invalid_ip
            + self.xdp_drop_invalid_tcp
            + self.xdp_drop_malformed
            # TCP flag attacks
            + self.xdp_drop_tcp_xmas
            + self.xdp_drop_tcp_null
            + self.xdp_drop_tcp_synfin
            + self.xdp_drop_tcp_synrst
            + self.xdp_drop_tcp_fin
            + self.xdp_drop_tcp_rst
            + self.xdp_drop_tcp_ack
            # Flood attacks
            + self.xdp_drop_syn_flood
            + self.xdp_drop_udp_flood
            + self.xdp_drop_icmp_flood
            + self.xdp_drop_udp_amp
            # L7 attacks
            + self.xdp_drop_http_flood
            + self.xdp_drop_slowloris
            # Other
            + self.xdp_drop_frag
            + self.xdp_drop_land
            + self.xdp_drop_ratelimit
        )

    def get_total_processed(self) -> int:
        """Get total packets processed."""
        return self.xdp_pass + self.get_total_dropped()


class AuditChallengeSynapse(bt.Synapse):
    """
    Synapse for real traffic audit challenge-response.

    SCALABLE FLOW (2 round-trips instead of 3):
    1. Validator sends START with tunnel config - miner sets up tunnel AND snapshots XDP stats
    2. Validator sends REAL packets to scrubber via tunnel
    3. Validator sends COLLECT - miner returns XDP stats delta

    The START phase combines tunnel setup + stats snapshot into ONE operation,
    eliminating the separate tunnel setup round-trip for scalability.

    This ensures miners are ACTUALLY filtering traffic with XDP,
    not just returning fake results.
    """

    # Challenge identification
    challenge_id: str = Field(
        default="",
        description="Unique challenge ID for this audit round"
    )

    # Challenge phase
    phase: str = Field(
        default="start",
        description="Phase: 'start' (setup tunnel + snapshot stats), 'collect' (return results)"
    )

    # Scrubber IP to test (validator tells miner which IP it's testing)
    scrubber_ip: str = Field(
        default="",
        description="Scrubber IP being tested"
    )

    # Challenge configuration (sent with 'start')
    expected_duration_seconds: int = Field(
        default=30,
        description="Expected duration of packet sending"
    )

    # === TUNNEL SETUP FIELDS (sent with 'start' phase) ===
    # Validator provides its WG config, miner sets up tunnel and returns scrubber config

    validator_pubkey: str = Field(
        default="",
        description="Validator's WireGuard public key for tunnel setup"
    )
    validator_ip: str = Field(
        default="",
        description="Validator's public IP for tunnel endpoint"
    )
    validator_port: int = Field(
        default=0,
        description="Validator's WireGuard listen port"
    )
    validator_uid: int = Field(
        default=0,
        description="Validator's UID for unique tunnel addressing"
    )

    # === TUNNEL RESPONSE FIELDS (filled by miner during 'start') ===

    scrubber_pubkey: str = Field(
        default="",
        description="Scrubber's WireGuard public key"
    )
    scrubber_port: int = Field(
        default=0,
        description="Scrubber's WireGuard listen port"
    )
    tunnel_ip_validator: str = Field(
        default="",
        description="Validator's tunnel interface IP"
    )
    tunnel_ip_scrubber: str = Field(
        default="",
        description="Scrubber's tunnel interface IP (traffic destination)"
    )

    # Challenge nonce for verification (proves miner saw traffic)
    # Validator embeds this in packet payloads, miner must extract it
    challenge_nonce: str = Field(
        default="",
        description="Nonce embedded in test packets for verification"
    )

    # === MINER RESPONSE FIELDS (filled during 'collect') ===

    # XDP stats at start of challenge
    stats_before: Dict[str, int] = Field(
        default_factory=dict,
        description="XDP stats snapshot at challenge start"
    )

    # XDP stats at end of challenge
    stats_after: Dict[str, int] = Field(
        default_factory=dict,
        description="XDP stats snapshot at challenge end"
    )

    # Delta (what happened during challenge)
    stats_delta: Dict[str, int] = Field(
        default_factory=dict,
        description="XDP stats delta during challenge"
    )

    # Packets seen with challenge nonce (proves real traffic was processed)
    nonce_packets_seen: int = Field(
        default=0,
        description="Number of packets containing the challenge nonce"
    )

    # Per-type breakdown (what miner's XDP reported)
    reported_blocked: Dict[str, int] = Field(
        default_factory=dict,
        description="Miner's report: packets blocked by category"
    )
    reported_passed: int = Field(
        default=0,
        description="Miner's report: packets passed through"
    )

    # Response metadata
    success: bool = Field(
        default=False,
        description="Whether miner successfully handled the challenge"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if failed"
    )
    response_timestamp: float = Field(
        default=0.0,
        description="Timestamp when miner collected stats"
    )


class SetupTunnelSynapse(bt.Synapse):
    """
    Synapse for validator to request WireGuard tunnel setup from miner.

    The validator requests the miner to set up a WireGuard tunnel on its scrubber.
    This ensures miners control their own infrastructure - validators never SSH
    to miner scrubbers.

    Flow:
    1. Validator generates WG keypair locally
    2. Validator sends this synapse with its public key and endpoint
    3. Miner configures WireGuard on its scrubber (miner SSH's to own infra)
    4. Miner responds with scrubber's WG public key and endpoint
    5. Validator configures its LOCAL WireGuard interface
    6. Tunnel is established

    This maintains clear security boundaries - each party controls only their
    own machines.
    """

    # === REQUEST FIELDS (sent by validator) ===

    # Validator's WireGuard public key
    validator_pubkey: str = Field(
        default="",
        description="Validator's WireGuard public key"
    )

    # Validator's public IP (for scrubber to connect back)
    validator_ip: str = Field(
        default="",
        description="Validator's public IP address"
    )

    # Validator's WireGuard listen port
    validator_port: int = Field(
        default=0,
        description="Validator's WireGuard listen port"
    )

    # Validator UID (for multi-validator tunnel addressing)
    validator_uid: int = Field(
        default=0,
        description="Validator's network UID"
    )

    # Scrubber IP to set up tunnel on (validator specifies which scrubber)
    scrubber_ip: str = Field(
        default="",
        description="Target scrubber IP to configure"
    )

    # Action: 'setup' or 'teardown'
    action: str = Field(
        default="setup",
        description="Action: 'setup' to create tunnel, 'teardown' to remove"
    )

    # === RESPONSE FIELDS (filled by miner) ===

    # Scrubber's WireGuard public key
    scrubber_pubkey: str = Field(
        default="",
        description="Scrubber's WireGuard public key"
    )

    # Scrubber's WireGuard listen port
    scrubber_port: int = Field(
        default=0,
        description="Scrubber's WireGuard listen port"
    )

    # Tunnel configuration for validator
    tunnel_ip_validator: str = Field(
        default="",
        description="IP address for validator's tunnel interface"
    )
    tunnel_ip_scrubber: str = Field(
        default="",
        description="IP address for scrubber's tunnel interface"
    )

    # Response status
    success: bool = Field(
        default=False,
        description="Whether tunnel setup succeeded"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error message if failed"
    )


class AuditSynapse(bt.Synapse):
    """
    Audit synapse for traffic-based scrubber testing.

    Phases:
    - 'start': Validator notifies miner that audit is beginning
    - 'collect': Validator requests XDP stats delta after traffic sent

    The validator sends test traffic through WireGuard tunnel and
    scores the miner based on XDP stats delta.

    Expected stats_delta keys (from XDP stat counters):
    - xdp_pass: Packets passed through
    - xdp_drop_blacklist: Blacklist drops (Spamhaus/EmergingThreats)
    - xdp_drop_temp_blacklist: Temporary blacklist drops
    - xdp_drop_bogon: Bogon/reserved IP drops
    - xdp_drop_quarantine: Quarantine drops
    - xdp_drop_invalid_ip: Invalid IP header drops
    - xdp_drop_invalid_tcp: Invalid TCP header drops
    - xdp_drop_malformed: Malformed packet drops
    - xdp_drop_tcp_xmas: TCP XMAS attack drops
    - xdp_drop_tcp_null: TCP NULL attack drops
    - xdp_drop_tcp_synfin: SYN+FIN invalid combo drops
    - xdp_drop_tcp_synrst: SYN+RST invalid combo drops
    - xdp_drop_tcp_fin: FIN-only scan drops
    - xdp_drop_tcp_rst: RST flood drops
    - xdp_drop_tcp_ack: ACK flood drops
    - xdp_drop_syn_flood: SYN flood drops
    - xdp_drop_udp_flood: UDP flood drops
    - xdp_drop_icmp_flood: ICMP flood drops
    - xdp_drop_udp_amp: UDP amplification drops
    - xdp_drop_http_flood: HTTP flood drops (L7)
    - xdp_drop_slowloris: Slowloris drops (L7)
    - xdp_drop_frag: Fragmentation attack drops
    - xdp_drop_land: Land attack drops (src==dst)
    - xdp_drop_ratelimit: Generic rate limit drops
    """

    # === CHALLENGE IDENTIFICATION ===
    challenge_id: str = Field(
        default="",
        description="Unique challenge ID for correlation"
    )

    phase: str = Field(
        default="start",
        description="Phase: 'start', 'collect'"
    )

    # === START PHASE FIELDS (validator -> miner) ===
    scrubber_ip: str = Field(
        default="",
        description="Scrubber IP to be tested"
    )

    expected_duration_seconds: int = Field(
        default=30,
        description="Expected duration of traffic sending"
    )

    throughput_level: int = Field(
        default=1,
        description="Throughput level: 0=light(150), 1=normal(750), 2=heavy(3000), 3=stress(7500)"
    )

    # === MINER RESPONSE FIELDS ===

    # XDP stats delta during audit (see docstring for expected keys)
    stats_delta: Dict[str, int] = Field(
        default_factory=dict,
        description="XDP stats delta during audit window - includes all 30 XDP stat counters"
    )

    # Response metadata
    success: bool = Field(
        default=False,
        description="Whether miner successfully handled the phase"
    )

    error_message: Optional[str] = Field(
        default=None,
        description="Error message if failed"
    )


class GraduatedAuditSynapse(bt.Synapse):
    """
    Synapse for graduated throughput testing.

    Tests scrubber at progressively higher loads to measure:
    - Maximum sustainable throughput
    - Accuracy degradation under load
    - Breaking point (where accuracy drops below threshold)

    Used to differentiate high-capacity vs low-capacity scrubbers.
    """

    challenge_id: str = Field(
        default="",
        description="Unique challenge ID"
    )

    phase: str = Field(
        default="start",
        description="Phase: 'start', 'level_N', 'complete'"
    )

    # Current level being tested (0-3)
    current_level: int = Field(
        default=0,
        description="Current throughput level being tested"
    )

    # Results per level
    level_results: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Results for each completed level"
    )

    # Final throughput score (0-1)
    throughput_score: float = Field(
        default=0.0,
        description="Computed throughput capacity score"
    )

    # Maximum level achieved with >50% accuracy
    max_level_achieved: int = Field(
        default=0,
        description="Highest throughput level passed"
    )

    # Response fields
    success: bool = Field(default=False)
    error_message: Optional[str] = Field(default=None)


class MetricsReport(BaseModel):
    """
    Aggregated metrics from a challenge round.

    Used by validators to score miner performance.
    """

    # Traffic volume
    total_packets_sent: int = 0
    total_benign_sent: int = 0
    total_attack_sent: int = 0

    # Delivery rates
    total_reaching_packets: int = 0
    total_reaching_benign: int = 0
    total_reaching_attack: int = 0

    # Latency
    avg_rtt_ms: float = 0.0
    min_rtt_ms: float = 0.0  # Baseline for distance-normalized scoring
    p95_rtt_ms: float = 0.0
    p99_rtt_ms: float = 0.0

    # Calculated metrics
    benign_delivery_rate: float = 0.0  # BDR
    attack_mitigation_accuracy: float = 0.0  # AMA
    selective_processing_score: float = 0.0  # SPS

    # XDP drop breakdown
    drop_breakdown: Dict[str, int] = Field(default_factory=dict)

    def calculate_derived_metrics(self):
        """Calculate derived metrics from raw data."""
        if self.total_benign_sent > 0:
            self.benign_delivery_rate = (
                self.total_reaching_benign / self.total_benign_sent
            )

        if self.total_attack_sent > 0:
            self.attack_mitigation_accuracy = 1.0 - (
                self.total_reaching_attack / self.total_attack_sent
            )

        if self.total_reaching_packets > 0:
            self.selective_processing_score = (
                self.total_reaching_benign / self.total_reaching_packets
            )
