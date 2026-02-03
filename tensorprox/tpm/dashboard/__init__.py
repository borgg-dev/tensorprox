"""TPM dashboard for web-based monitoring and management UI."""

from tensorprox.tpm.dashboard.app import create_dashboard_app
from tensorprox.tpm.dashboard.config import DashboardConfig
from tensorprox.tpm.dashboard.repository import DashboardRepository
from tensorprox.tpm.dashboard.api import bp as dashboard_bp

__all__ = [
    "create_dashboard_app",
    "DashboardConfig",
    "DashboardRepository",
    "dashboard_bp",
]
