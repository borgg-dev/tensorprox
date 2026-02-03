"""Pydantic models for request/response validation"""
from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional, Literal, Dict, List, Any
from datetime import datetime
from uuid import UUID, uuid4


# ============================================================================
# Scrubber Models (Miner)
# ============================================================================

class ScrubberDeployRequest(BaseModel):
    """Request to deploy scrubber. Defaults from tp.env if None.

    NOTE: Only AWS is currently supported for scrubber deployment and management.
    Scrubbers depend on AWS-specific features (ENI, EIP, ens5 interface, EC2
    metadata service) that have no Linode equivalent implemented yet.
    """
    origin_id: UUID
    region: Optional[str] = None
    instance_type: Optional[str] = None
    cloud_provider: Literal["aws"] = "aws"


class ScrubberResponse(BaseModel):
    """Scrubber deployment response"""
    scrubber_id: UUID
    origin_id: UUID
    instance_id: str
    entry_ip: str
    internal_ip: str
    region: str
    instance_type: str
    status: Literal["deploying", "healthy", "unhealthy", "terminated"]
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Exit Hub Models (TensorProx Management)
# ============================================================================

def _default_exit_ports() -> List[int]:
    return [80, 443]


class ExitHubDeployRequest(BaseModel):
    """Request to deploy exit hub"""
    client_id: Optional[str] = None
    client_name: Optional[str] = None
    miner_id: Optional[str] = None
    origin_ip: str
    origin_id: Optional[str] = None
    emn_ip: Optional[str] = None  # Miner IP for origin registration callback (auto-selected if not provided)
    emn_port: Optional[int] = None  # Miner port for origin registration callback
    ports: List[int] = Field(default_factory=_default_exit_ports)
    region: Optional[str] = None
    shard_id: Optional[str] = None  # Miner shard ID (defaults to region if not set)
    instance_type: Optional[str] = None
    cloud_provider: Optional[str] = None

    @field_validator('ports', mode='before')
    @classmethod
    def _coerce_ports(cls, value: Any) -> List[int]:
        """
        Accept either the legacy {tcp, udp} dict or a flat list and normalize
        into a single list of ports.
        """
        if value is None:
            return _default_exit_ports()
        if isinstance(value, dict):
            combined = list(value.get('tcp', [])) + list(value.get('udp', []))
            return [int(port) for port in combined]
        if isinstance(value, list):
            return [int(port) for port in value]
        raise ValueError("ports must be a list of integers or a {tcp, udp} dict")


class ExitHubResponse(BaseModel):
    """Exit hub deployment response"""
    exit_hub_id: UUID
    client_id: Optional[str] = None
    instance_id: str
    exit_hub_ip: str
    origin_ip: str
    origin_id: str
    wg_interface: str
    region: str
    instance_type: str
    status: Literal["deploying", "active", "failed", "terminating", "terminated"]
    secret: Optional[str] = None
    miner_id: Optional[str] = None
    miner_ip: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Origin Models (Traffic Manager)
# ============================================================================

class OriginDeployRequest(BaseModel):
    """Request to deploy origin with default test service ports"""
    ports: Dict[str, List[int]] = {
        "tcp": [9001, 8080, 9003],  # Echo, HTTP, Custom (from origin/variables.tf)
        "udp": [9101, 9102, 9103]   # Echo, Datagram, Custom
    }
    region: Optional[str] = None
    instance_type: Optional[str] = None


class OriginResponse(BaseModel):
    """Origin deployment response"""
    origin_id: UUID
    instance_id: str
    origin_ip: str
    ports: Dict[str, List[int]]
    region: str
    instance_type: str
    status: Literal["deploying", "running", "terminated"]
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Attacker Models (Traffic Manager)
# ============================================================================

class AttackerDeployRequest(BaseModel):
    """Request to deploy attacker"""
    region: Optional[str] = None
    instance_type: Optional[str] = None


class AttackerResponse(BaseModel):
    """Attacker deployment response"""
    attacker_id: UUID
    instance_id: str
    attacker_ip: str
    region: str
    instance_type: str
    status: Literal["deploying", "ready", "terminated"]
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Webclient Models (Traffic Manager)
# ============================================================================

class WebclientDeployRequest(BaseModel):
    """Request to deploy webclient"""
    region: Optional[str] = None
    instance_type: Optional[str] = None


class WebclientResponse(BaseModel):
    """Webclient deployment response"""
    webclient_id: UUID
    instance_id: str
    webclient_ip: str
    region: str
    instance_type: str
    status: Literal["deploying", "ready", "terminated"]
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# Demo Test Models (Traffic Manager)
# ============================================================================

class DemoTestRequest(BaseModel):
    """Request payload to orchestrate a demo traffic test"""
    origin_ip: str
    ports: Dict[str, List[int]] = Field(
        default_factory=lambda: {"tcp": [7011, 7022, 7033], "udp": [7111, 7112, 7113]}
    )
    duration: int = 30
    keep_webclient: bool = False
    region: Optional[str] = None
    instance_type: Optional[str] = None
    icmp_count: int = 10
    tcp_iterations: int = 10
    udp_iterations: int = 10


# ============================================================================
# Provider Models
# ============================================================================

class InstanceCreateResult(BaseModel):
    """Result from provider.create_instance()"""
    instance_id: str
    public_ip: str
    private_ip: Optional[str] = None
    status: str
    resource_id: Optional[str] = None


class InstanceDeleteResult(BaseModel):
    """Result from provider.delete_instance()"""
    instance_id: str
    success: bool
    message: Optional[str] = None


# ============================================================================
# Scrubber Stats Models (Miner)
# ============================================================================

class ScrubberStats(BaseModel):
    """XDP statistics from a scrubber node."""
    node_id: str
    xdp_pass: int = 0
    xdp_drop_blacklist: int = 0
    xdp_drop_ratelimit: int = 0
    xdp_drop_quarantine: int = 0
    xdp_drop_bogon: int = 0
    xdp_syncookie_challenge: int = 0
    whitelist_bypass: int = 0

    # Extended stats (from xdp_wg_audit.c)
    xdp_drop_invalid_ip: int = 0
    xdp_drop_tcp_xmas: int = 0
    xdp_drop_tcp_null: int = 0
    xdp_drop_tcp_synfin: int = 0
    xdp_drop_tcp_synrst: int = 0
    xdp_drop_syn_flood: int = 0
    xdp_drop_udp_amp: int = 0
    xdp_drop_icmp_flood: int = 0
    xdp_drop_frag: int = 0
    xdp_drop_tcp_fin: int = 0
    xdp_drop_tcp_rst: int = 0
    xdp_drop_tcp_ack: int = 0
    xdp_drop_udp_flood: int = 0
    xdp_drop_malformed: int = 0

    @property
    def total_drops(self) -> int:
        """Total packets dropped by XDP."""
        return (
            self.xdp_drop_blacklist +
            self.xdp_drop_ratelimit +
            self.xdp_drop_quarantine +
            self.xdp_drop_bogon +
            self.xdp_drop_invalid_ip +
            self.xdp_drop_tcp_xmas +
            self.xdp_drop_tcp_null +
            self.xdp_drop_tcp_synfin +
            self.xdp_drop_tcp_synrst +
            self.xdp_drop_syn_flood +
            self.xdp_drop_udp_amp +
            self.xdp_drop_icmp_flood +
            self.xdp_drop_frag +
            self.xdp_drop_tcp_fin +
            self.xdp_drop_tcp_rst +
            self.xdp_drop_tcp_ack +
            self.xdp_drop_udp_flood +
            self.xdp_drop_malformed
        )
