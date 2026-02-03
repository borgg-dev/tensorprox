"""Administrative cleanup endpoint (local-only).

Provides a safe way to reset TPM state for testing. Clears all data tables
while preserving system tables (migrations, crypto keys).
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from shared.database import get_tp_db_connection
from shared.config import get_tp_management_settings
from shared.utils.logging import get_logger

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover
    redis = None

bp = Blueprint("tp_admin_cleanup", __name__, url_prefix="/admin")
logger = get_logger(__name__)

# Tables to clear on cleanup (order matters for FK constraints - dependents first)
# Add new data tables here as they are created
CLEANUP_TABLES = [
    "tensorprox_miner_operations",  # FK to miners - operation queue
    "tensorprox_exit_hubs",         # FK to clients, origins, miners
    "tensorprox_origins",           # FK to clients, miner_shards
    "tensorprox_miner_shards",      # FK to miners
    "miner_shard_capacity",         # FK to miners
    "billing_sync_backlog",         # Billing queue
    "tensorprox_clients",           # Base table
    "tensorprox_miners",            # Base table
]

# Tables that must NEVER be cleared (system/infrastructure)
PROTECTED_TABLES = frozenset({
    "alembic_version",   # Migration state - clearing breaks schema tracking
    "tpm_crypto_keys",   # TPM's X25519 keypair - clearing breaks envelope encryption
})


def _is_local_request() -> bool:
    """Only allow calls from localhost/loopback."""
    return request.remote_addr in {"127.0.0.1", "::1"}


def _get_all_tables(cursor) -> set[str]:
    """Get all user tables in public schema."""
    cursor.execute("""
        SELECT tablename FROM pg_tables
        WHERE schemaname = 'public'
    """)
    return {row[0] for row in cursor.fetchall()}


@bp.route("/cleanup", methods=["POST"])
def cleanup():
    """Clear all TPM data tables and flush Redis.

    - Only accessible from localhost (127.0.0.1, ::1)
    - Truncates all data tables with CASCADE RESTART IDENTITY
    - Preserves system tables (alembic_version, tpm_crypto_keys)
    - Warns if new tables are detected that aren't in CLEANUP_TABLES
    """
    if not _is_local_request():
        return jsonify({"error": "forbidden"}), 403

    conn = get_tp_db_connection()
    tables_cleared = []
    warnings = []

    try:
        with conn.cursor() as cur:
            # Check for untracked tables (new tables not in cleanup or protected list)
            all_tables = _get_all_tables(cur)
            known_tables = set(CLEANUP_TABLES) | PROTECTED_TABLES
            untracked = all_tables - known_tables
            if untracked:
                warnings.append(f"Untracked tables (add to CLEANUP_TABLES or PROTECTED_TABLES): {sorted(untracked)}")
                logger.warning("Cleanup: %s", warnings[-1])

            # Filter to only tables that exist (handles schema evolution)
            tables_to_clear = [t for t in CLEANUP_TABLES if t in all_tables]

            if tables_to_clear:
                table_list = ", ".join(tables_to_clear)
                cur.execute(f"TRUNCATE {table_list} RESTART IDENTITY CASCADE;")
                tables_cleared = tables_to_clear

        conn.conn.commit()
    except Exception as exc:
        conn.conn.rollback()
        logger.error("Cleanup failed: %s", exc)
        return jsonify({"error": "cleanup_failed", "message": str(exc)}), 500
    finally:
        conn.close()

    # Flush Redis (best-effort)
    redis_flushed = False
    if redis:
        try:
            settings = get_tp_management_settings()
            r = redis.Redis.from_url(settings.tp_redis_url)
            r.flushdb()
            redis_flushed = True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Redis flush failed during cleanup: %s", exc)
            warnings.append(f"Redis flush failed: {exc}")

    logger.info(
        "Admin cleanup complete: cleared %d tables%s",
        len(tables_cleared),
        ", flushed Redis" if redis_flushed else ""
    )

    response = {
        "status": "ok",
        "tables_cleared": tables_cleared,
        "redis_flushed": redis_flushed,
    }
    if warnings:
        response["warnings"] = warnings

    return jsonify(response)


@bp.route("/sweep-orphans", methods=["POST"])
def sweep_orphans():
    """Scan AWS for orphaned exit_hub instances and terminate them.

    - Only accessible from localhost (127.0.0.1, ::1)
    - Finds instances tagged as exit_hub that TPM doesn't track
    - Terminates orphaned instances automatically
    """
    if not _is_local_request():
        return jsonify({"error": "forbidden"}), 403

    from tensorprox.tpm.services.orphan_sweeper import sweep_orphans_now

    try:
        result = sweep_orphans_now()
        logger.info("Admin sweep-orphans: %s", result)
        return jsonify({"status": "ok", **result})
    except Exception as exc:
        logger.error("Sweep orphans failed: %s", exc, exc_info=True)
        return jsonify({"error": "sweep_failed", "message": str(exc)}), 500


@bp.route("/purge-expired", methods=["POST"])
def purge_expired():
    """Purge exit_hub records that have exceeded their purge_after timestamp.

    - Only accessible from localhost (127.0.0.1, ::1)
    - Deletes exit_hub records marked for deferred deletion
    - Used by background sweeper or manual cleanup
    """
    if not _is_local_request():
        return jsonify({"error": "forbidden"}), 403

    from tensorprox.tpm.repositories.exit_hub_repository import ExitHubRepository

    repo = ExitHubRepository()
    purged_count = 0
    purged_ids = []

    try:
        purgeable = repo.get_purgeable_exit_hubs()
        for record in purgeable:
            exit_hub_id = str(record["exit_hub_id"])
            try:
                repo.delete_exit_hub(exit_hub_id)
                purged_count += 1
                purged_ids.append(exit_hub_id)
                logger.info("Purged expired exit hub: %s", exit_hub_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to purge exit hub %s: %s", exit_hub_id, exc)

        logger.info("Admin purge-expired: purged %d exit hubs", purged_count)
        return jsonify({
            "status": "ok",
            "purged_count": purged_count,
            "purged_ids": purged_ids,
        })
    except Exception as exc:
        logger.error("Purge expired failed: %s", exc, exc_info=True)
        return jsonify({"error": "purge_failed", "message": str(exc)}), 500
