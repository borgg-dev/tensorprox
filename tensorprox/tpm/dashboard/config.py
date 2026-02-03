"""Dashboard configuration module.

Loads configuration from dashboard.env file located in the same directory.
"""

import os
import urllib.parse
from pathlib import Path

from dotenv import load_dotenv


def _parse_int(value: str, name: str, default: int) -> int:
    """Parse an integer from string with error handling.

    Args:
        value: String value to parse
        name: Environment variable name for error messages
        default: Default value if parsing fails

    Returns:
        Parsed integer value

    Raises:
        ValueError: If value cannot be parsed as integer
    """
    try:
        return int(value)
    except ValueError as e:
        raise ValueError(
            f"Invalid value for {name}: '{value}' is not a valid integer"
        ) from e


# Load dashboard.env from the same directory as this file
_env_path = Path(__file__).parent / "dashboard.env"
load_dotenv(_env_path)


class DashboardConfig:
    """Configuration for the TPM metrics dashboard.

    Attributes:
        db_host: PostgreSQL host
        db_port: PostgreSQL port
        db_name: Database name
        db_user: Database user for dashboard (read-only)
        db_password: Database password
        user: Dashboard login username
        password: Dashboard login password
        session_secret: Secret key for session signing
        session_hours: Session expiration in hours
    """

    # Database configuration
    db_host: str = os.getenv("DASHBOARD_DB_HOST", "localhost")
    db_port: int = _parse_int(
        os.getenv("DASHBOARD_DB_PORT", "5432"), "DASHBOARD_DB_PORT", 5432
    )
    db_name: str = os.getenv("DASHBOARD_DB_NAME", "tp_state")
    db_user: str = os.getenv("DASHBOARD_DB_USER", "tp_dashboard")
    db_password: str = os.getenv("DASHBOARD_DB_PASSWORD", "")

    # Authentication configuration
    user: str = os.getenv("DASHBOARD_USER", "admin")
    password: str = os.getenv("DASHBOARD_PASSWORD", "")

    # Session configuration
    session_secret: str = os.getenv("DASHBOARD_SESSION_SECRET", "")
    session_hours: int = _parse_int(
        os.getenv("DASHBOARD_SESSION_HOURS", "8"), "DASHBOARD_SESSION_HOURS", 8
    )

    @classmethod
    def get_db_url(cls) -> str:
        """Return PostgreSQL connection URL."""
        encoded_password = urllib.parse.quote_plus(cls.db_password)
        return f"postgresql://{cls.db_user}:{encoded_password}@{cls.db_host}:{cls.db_port}/{cls.db_name}"

    @classmethod
    def validate(cls) -> list[str]:
        """Validate required configuration values.

        Returns:
            List of missing configuration keys (empty if all valid).
        """
        missing = []
        if not cls.db_user:
            missing.append("DASHBOARD_DB_USER")
        if not cls.db_password:
            missing.append("DASHBOARD_DB_PASSWORD")
        if not cls.password:
            missing.append("DASHBOARD_PASSWORD")
        if not cls.session_secret:
            missing.append("DASHBOARD_SESSION_SECRET")
        return missing
