"""Configuration management using Pydantic Settings"""
from functools import lru_cache
from pathlib import Path
from typing import Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator, field_validator


def _detect_public_ip() -> Optional[str]:
    """
    Detect public IP address using external services.
    Returns None if detection fails.
    """
    import socket
    import urllib.request

    # List of services to try (in order)
    services = [
        'https://ifconfig.me/ip',
        'https://api.ipify.org',
        'https://icanhazip.com',
        'https://checkip.amazonaws.com',
    ]

    for url in services:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                ip = response.read().decode('utf-8').strip()
                # Basic validation: should look like an IP
                socket.inet_aton(ip)  # Raises on invalid IP
                return ip
        except Exception:
            continue

    return None


class TensorProxSettings(BaseSettings):
    """
    Global TensorProx configuration loaded from tp.env or .env.
    All cloud provider credentials and node type defaults.
    """

    # AWS Configuration (optional - only needed for AWS deployments)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "eu-central-1"
    aws_ssh_key_name: str = "tensorprox-key"
    aws_security_group_id: str = ""  # Required for scrubber deployment
    aws_subnet_id: str = ""  # Required for scrubber deployment
    aws_eip_quota_per_region: int = 5  # EIP quota per region (default AWS limit)

    # Linode Configuration (optional - only needed for Linode deployments)
    linode_token: Optional[str] = None
    linode_region: str = "us-east"

    # SSH Configuration
    ssh_key_path: str = "~/.ssh/id_rsa"

    # Node Provider Settings (for multi-provider support)
    # NOTE: Only AWS is currently supported for scrubbers. See SCRUBBER_SUPPORTED_PROVIDERS.
    scrubber_provider: str = "aws"
    exit_hub_provider: str = "linode"
    origin_provider: str = "linode"
    attacker_provider: str = "linode"
    webclient_provider: str = "linode"

    # Service Ports
    tensorprox_host: str = "127.0.0.1"
    tensorprox_port: int = 5001
    tp_miner_bootstrap_token: Optional[str] = None
    traffic_manager_port: int = 5002
    miner_port: int = 8000

    # Miner Control Plane Configuration
    emn_ip: str = "127.0.0.1"
    emn_port: int = 8000
    traffic_manager_db_path: str = "~/.tensorprox/traffic_manager.db"

    # Metrics / aggregation push
    data_push_url: Optional[str] = None
    data_aggregation_interval: int = 30
    redis_url: Optional[str] = None  # env var: TP_REDIS_URL
    metrics_channel: str = "metrics.aggregated"

    # Bandwidth QoS Configuration
    qos_buffer_percent: int = 20  # % of bandwidth reserved as buffer
    qos_enforce_mode: str = 'monitor'  # 'monitor' or 'enforce'
    qos_default_quota_mbps: Optional[int] = None  # Override fair-share calculation

    # Miner database (ecp_state)
    db_name: str = "ecp_state"
    db_user: str = "ecp_api"
    db_pass: Optional[str] = None  # REQUIRED: Set via TP_DB_PASS environment variable
    db_host: str = "localhost"
    db_port: int = 5432

    # Node Type Defaults (from Terraform variables.tf files)
    scrubber_instance_type: str = "t3.medium"
    scrubber_region: str = "eu-central-1"

    exit_hub_instance_type: str = "g6-nanode-1"
    exit_hub_region: str = "us-east"

    origin_instance_type: str = "g6-nanode-1"
    origin_region: str = "us-east"

    attacker_instance_type: str = "g6-nanode-1"
    attacker_region: str = "us-east"

    webclient_instance_type: str = "g6-nanode-1"
    webclient_region: str = "us-east"

    @field_validator('scrubber_provider')
    @classmethod
    def validate_scrubber_provider(cls, v: str) -> str:
        """Enforce AWS-only for scrubbers.

        Only AWS is currently supported for scrubber deployment and management.
        Scrubbers depend on AWS-specific features: ENI/EIP networking, ens5
        interface naming, EC2 metadata service, and security group management.
        """
        from shared.providers import SCRUBBER_SUPPORTED_PROVIDERS
        if v.lower() not in SCRUBBER_SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported scrubber provider: '{v}'. "
                f"Only AWS is currently supported for scrubber deployment. "
                f"Supported: {list(SCRUBBER_SUPPORTED_PROVIDERS)}"
            )
        return v.lower()

    @model_validator(mode='after')
    def auto_detect_emn_ip(self) -> 'TensorProxSettings':
        """Auto-detect public IP if emn_ip is the default localhost value."""
        if self.emn_ip == "127.0.0.1":
            detected_ip = _detect_public_ip()
            if detected_ip:
                object.__setattr__(self, 'emn_ip', detected_ip)
        return self

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        env_prefix='TP_',
        case_sensitive=False,
        extra='ignore'
    )


def _preprocess_env_vars():
    """Map TP_ prefixed env vars to non-prefixed settings before loading config."""
    import os
    prefix_mappings = {
        'TP_AWS_ACCESS_KEY_ID': 'AWS_ACCESS_KEY_ID',
        'TP_AWS_SECRET_ACCESS_KEY': 'AWS_SECRET_ACCESS_KEY',
        'TP_AWS_REGION': 'AWS_REGION',
        'TP_LINODE_TOKEN': 'LINODE_TOKEN',
        'TP_SSH_KEY_PATH': 'SSH_KEY_PATH',
        'TP_SCRUBBER_PROVIDER': 'SCRUBBER_PROVIDER',
        'TP_SCRUBBER_REGION': 'SCRUBBER_REGION',
        'TP_SCRUBBER_INSTANCE_TYPE': 'SCRUBBER_INSTANCE_TYPE',
    }
    for tp_var, setting in prefix_mappings.items():
        if tp_var in os.environ and setting not in os.environ:
            os.environ[setting] = os.environ[tp_var]


class TensorProxManagementSettings(BaseSettings):
    """Dedicated config for tensorprox_management service."""

    # Logging
    tpm_log_level: str = "INFO"
    tpm_log_dir: str = "~/.tensorprox/logs"

    tp_db_name: str = "tp_state"
    tp_db_user: str = "tp_api"
    tp_db_pass: Optional[str] = None  # REQUIRED: Set via TP_DB_PASS environment variable
    tp_db_host: str = "localhost"
    tp_db_port: int = 5432

    tp_redis_url: str = "redis://127.0.0.1:6379/0"
    tp_redis_external_host: Optional[str] = None  # External Redis host for miners
    tp_redis_external_port: int = 6379  # External Redis port for miners
    tp_redis_password: Optional[str] = None  # Redis password (shared with miners during registration)
    tp_exit_hub_notifier_enabled: bool = False
    tp_metrics_ingest_url: Optional[str] = None
    tp_metrics_api_key: Optional[str] = None
    tp_miner_bootstrap_token: Optional[str] = None
    tpm_credentials_encryption_key: Optional[str] = None  # Fernet key for cloud creds at rest
    tpm_private_key_path: Optional[str] = None  # Path to TPM X25519 private key
    cloud_deploy_timeout_seconds: int = 480  # 8 minutes for full deployment
    tp_request_timeout_seconds: int = 60
    tp_deploy_worker_threads: int = 4
    tp_deploy_queue_size: int = 32
    tp_auto_start_local_services: bool = False
    exit_hub_bootstrap_grace_seconds: int = 60
    exit_hub_ssh_timeout_seconds: int = 360

    # API security (tp-webapp ↔ TPM)
    api_secret_key: Optional[str] = None
    allowed_api_ips: List[str] = []
    enforce_api_key: bool = False
    enforce_ip_whitelist: bool = False

    # Egress routing - external URL for origin callbacks
    tpm_external_url: Optional[str] = None  # e.g., https://tpm.tensorprox.io

    metrics_channel: str = "metrics.aggregated"

    # MaxMind GeoLite2 for IP geolocation
    tpm_maxmind_license_key: Optional[str] = None
    tpm_geolite2_db_path: str = "/var/lib/GeoIP/GeoLite2-City.mmdb"

    # TP Data Database (Linode/Akamai Managed PostgreSQL for time-series metrics)
    tp_data_db_host: Optional[str] = None
    tp_data_db_port: int = 14457
    tp_data_db_name: str = "defaultdb"
    tp_data_db_user: str = "akmadmin"
    tp_data_db_password: Optional[str] = None
    tp_data_db_sslmode: str = "verify-full"
    tp_data_db_sslrootcert: Optional[str] = None

    # AWS credentials for exit hub deployment
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: str = "us-east-1"

    # Linode credentials for exit hub deployment
    linode_token: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file='tensorprox_management/tp_m.env',
        env_file_encoding='utf-8',
        case_sensitive=False,
        extra='ignore'
        # No env_prefix - field names already have appropriate prefixes (tp_, tpm_, webapp_)
    )


@lru_cache()
def get_settings() -> TensorProxSettings:
    """Load and cache settings from tp.env or .env"""
    import os
    # Preprocess TP_ prefixed vars
    _preprocess_env_vars()
    # Try multiple env file locations
    for env_file in ['tp.env', '.env']:
        if Path(env_file).exists():
            return TensorProxSettings(_env_file=env_file)
    # Fallback to default
    env_file = os.getenv('TP_ENV_FILE', '.env')
    return TensorProxSettings(_env_file=env_file)


@lru_cache()
def get_tp_management_settings() -> TensorProxManagementSettings:
    """Load TensorProx management-specific settings.

    Tries multiple locations for config file:
    1. .env (for embedded TPM-Lite in validators)
    2. tp.env (alternative location)
    3. tensorprox_management/tp_m.env (centralized TPM)

    Falls back to environment variables with TP_ prefix if no file exists.
    """
    import os
    _preprocess_env_vars()

    # Try multiple env file locations
    for env_file in ['.env', 'tp.env', 'tensorprox_management/tp_m.env']:
        env_path = Path(env_file)
        if not env_path.is_absolute():
            env_path = Path(__file__).resolve().parents[1] / env_file
        if env_path.exists():
            return TensorProxManagementSettings(_env_file=str(env_path))

    # No file found - use environment variables only
    return TensorProxManagementSettings()


# Aliases for backwards compatibility with tensorprox_subnet
SharedSettings = TensorProxSettings
get_shared_settings = get_settings
