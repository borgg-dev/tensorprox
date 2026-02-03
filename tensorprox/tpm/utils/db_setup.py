"""Utility helpers for TensorProx database setup."""
from __future__ import annotations

from pathlib import Path

try:
    from alembic import command
    from alembic.config import Config
    ALEMBIC_AVAILABLE = True
except ImportError:
    ALEMBIC_AVAILABLE = False

from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


def run_db_migrations() -> None:
    """
    Apply Alembic migrations (idempotent).

    Executed automatically on service startup so a fresh machine only needs tp.env
    and Postgres credentials to be able to run tensorprox_management.

    Note: Alembic is optional. If not available, migrations are skipped.
    """
    if not ALEMBIC_AVAILABLE:
        logger.warning("Alembic not available, skipping database migrations")
        return

    migrations_dir = Path(__file__).resolve().parents[1] / "repositories" / "migrations"
    alembic_cfg_path = migrations_dir / "alembic.ini"

    settings = get_tp_management_settings()

    cfg = Config(str(alembic_cfg_path))
    cfg.set_main_option("script_location", str(migrations_dir))
    cfg.set_main_option(
        "sqlalchemy.url",
        f"postgresql+psycopg2://{settings.tp_db_user}:{settings.tp_db_pass}"
        f"@{settings.tp_db_host}:{settings.tp_db_port}/{settings.tp_db_name}"
    )

    logger.info("Applying TensorProx migrations (alembic head)...")
    command.upgrade(cfg, "head")
    logger.info("TensorProx migrations applied successfully")
