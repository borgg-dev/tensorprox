#!/usr/bin/env python3
from shared.database import get_db_connection
"""
Database Maintenance Module for EMN
Handles periodic cleanup of health heartbeat data to prevent bloat
"""

import threading
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from miner_control_plane.services.scrubber_sync import scrubber_sync, SyncOperation
from miner_control_plane.services.state_manager import state_manager
from shared.utils.bpf_helpers import ip_to_hex, delete_bpf_map, get_map_path
from shared.utils.ssh import ssh_exec
from shared.config import get_settings

logger = logging.getLogger('emn-db-maintenance')
settings = get_settings()

def cleanup_old_health_records(retention_hours=24):
    """
    Delete health records older than retention period

    Args:
        retention_hours: Number of hours to retain health data (default: 24)
    """
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Delete old node health records
        cur.execute("""
            DELETE FROM health_node
            WHERE last_seen < NOW() - INTERVAL '%s hours'
        """, (retention_hours,))
        node_deleted = cur.rowcount

        # Delete old origin health records
        cur.execute("""
            DELETE FROM health_origin
            WHERE last_probe_ts < NOW() - INTERVAL '%s hours'
        """, (retention_hours,))
        origin_deleted = cur.rowcount

        conn.commit()

        if node_deleted > 0 or origin_deleted > 0:
            logger.info(f"Database maintenance: Deleted {node_deleted} node health records and {origin_deleted} origin health records older than {retention_hours}h")

        cur.close()

    except Exception as e:
        logger.error(f"Database maintenance failed: {e}")
    finally:
        if db:
            db.close()

def cleanup_old_metrics(retention_days=90):
    """
    Delete DDoS metrics older than retention period (separate from health - longer retention for analytics)

    Args:
        retention_days: Number of days to retain metrics data (default: 90)
    """
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Delete old DDoS metrics
        cur.execute("""
            DELETE FROM ddos_metrics
            WHERE timestamp < NOW() - INTERVAL '%s days'
        """, (retention_days,))
        ddos_deleted = cur.rowcount

        # PHASE 3: Delete old IP attack signatures (90-day retention)
        cur.execute("""
            DELETE FROM ip_attack_signatures
            WHERE timestamp < NOW() - INTERVAL '%s days'
        """, (retention_days,))
        sig_deleted = cur.rowcount

        # PHASE 3: Delete old origin metrics (90-day retention)
        cur.execute("""
            DELETE FROM origin_metrics
            WHERE timestamp < NOW() - INTERVAL '%s days'
        """, (retention_days,))
        origin_deleted = cur.rowcount

        conn.commit()

        if ddos_deleted > 0 or sig_deleted > 0 or origin_deleted > 0:
            logger.info(f"Database maintenance: Deleted {ddos_deleted} DDoS metrics, {sig_deleted} attack signatures, {origin_deleted} origin metrics (>{retention_days}d)")

        cur.close()

    except Exception as e:
        logger.error(f"Metrics cleanup failed: {e}")
    finally:
        if db:
            db.close()

def cleanup_expired_temp_blacklist():
    """
    PHASE 3: Remove expired temporary blacklist entries from database
    """
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Delete expired entries from database
        cur.execute("""
            DELETE FROM temp_blacklist
            WHERE expires_at < NOW()
        """)
        deleted_count = cur.rowcount

        conn.commit()

        if deleted_count > 0:
            logger.info(f"Temp blacklist cleanup: Removed {deleted_count} expired entries from database")

        cur.close()

    except Exception as e:
        logger.error(f"Temp blacklist cleanup failed: {e}")
    finally:
        if db:
            db.close()

def cleanup_expired_per_origin_reputation():
    """
    Remove expired per-origin whitelist/blacklist entries from DB and scrubbers.
    Called periodically by db_maintenance thread.
    """
    db = None
    try:
        db = get_db_connection()
        expired_count = 0

        # Tables with expires_at: origin_whitelist, origin_blacklist, temp_blacklist
        for list_type, table in [
            ('whitelist', 'origin_whitelist'),
            ('blacklist', 'origin_blacklist'),
        ]:
            # Find expired entries
            expired = db.query_all(f"""
                SELECT origin_id, ip_address
                FROM {table}
                WHERE expires_at IS NOT NULL AND expires_at < NOW()
            """)

            for row in expired:
                origin_id = row['origin_id']
                ip = str(row['ip_address'])

                # Get origin data (EIP and shard_id)
                origin = state_manager.get_origin(origin_id)
                if not origin:
                    continue
                eip = origin['eip']
                shard_id = origin.get('shard_id')
                if not shard_id:
                    logger.warning(f"Origin {origin_id} has no shard_id, skipping cleanup")
                    continue

                # Build compound key and remove from shard's scrubbers only
                key_hex = f"{ip_to_hex(ip)} {ip_to_hex(eip)}"

                try:
                    scrubber_sync.apply_atomic_to_shard(
                        SyncOperation(
                            map_name=f'origin_{list_type}_map',
                            key_hex=key_hex,
                            value_hex=None,
                            action='delete',
                            origin_id=origin_id,
                            ip_address=ip,
                            list_type=list_type
                        ),
                        shard_id=shard_id
                    )
                    expired_count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove expired {list_type} entry: {e}")

            # Delete expired from database
            db.execute(f"""
                DELETE FROM {table}
                WHERE expires_at IS NOT NULL AND expires_at < NOW()
            """)

        # Also clean expired temp_blacklist
        expired_temp = db.query_all("""
            SELECT origin_id, ip_address
            FROM temp_blacklist
            WHERE expires_at < NOW()
        """)

        for row in expired_temp:
            origin_id = row['origin_id']
            ip = str(row['ip_address'])

            origin = state_manager.get_origin(origin_id)
            if not origin:
                continue
            eip = origin['eip']
            shard_id = origin.get('shard_id')
            if not shard_id:
                logger.warning(f"Origin {origin_id} has no shard_id, skipping temp_blacklist cleanup")
                continue

            key_hex = f"{ip_to_hex(ip)} {ip_to_hex(eip)}"

            # Remove from shard's scrubbers only (best effort)
            for node_name, node in state_manager.nodes_db.items():
                # Only process nodes in this origin's shard
                if node.get('shard_id') != shard_id:
                    continue
                try:
                    delete_bpf_map(
                        host=node['public_ip'],
                        map_path=get_map_path('temp_blacklist'),
                        key_hex=key_hex,
                        ssh_key_path=settings.ssh_key_path,
                        provider=node.get('provider', 'aws')
                    )
                except Exception:
                    pass  # Best effort

            expired_count += 1

        # Delete expired temp_blacklist from DB
        db.execute("DELETE FROM temp_blacklist WHERE expires_at < NOW()")

        if expired_count > 0:
            logger.info(f"Cleaned {expired_count} expired per-origin reputation entries")

    except Exception as e:
        logger.error(f"Failed to cleanup expired per-origin reputation: {e}")
    finally:
        if db:
            db.close()

def cleanup_old_ratelimit_stats(retention_days=7):
    """
    LAYER 3: Remove old rate limit statistics (7-day retention)
    """
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Delete old entries
        cur.execute("""
            DELETE FROM ratelimit_stats
            WHERE timestamp < NOW() - INTERVAL '%s days'
        """, (retention_days,))
        deleted_count = cur.rowcount

        conn.commit()

        if deleted_count > 0:
            logger.info(f"Rate limit stats cleanup: Removed {deleted_count} entries older than {retention_days}d")

        cur.close()

    except Exception as e:
        logger.error(f"Rate limit stats cleanup failed: {e}")
    finally:
        if db:
            db.close()

def cleanup_old_baselines(retention_days=90):
    """
    LAYER 6: Remove old baseline history (keep current + 90 days)
    """
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Delete old baselines (keep current + last 90 days)
        cur.execute("""
            DELETE FROM traffic_baselines
            WHERE is_current = FALSE
              AND computed_at < NOW() - INTERVAL '%s days'
        """, (retention_days,))
        deleted_count = cur.rowcount

        conn.commit()

        if deleted_count > 0:
            logger.info(f"Baseline cleanup: Removed {deleted_count} old baselines (>{retention_days}d, non-current)")

        cur.close()

    except Exception as e:
        logger.error(f"Baseline cleanup failed: {e}")
    finally:
        if db:
            db.close()

def cleanup_old_attack_events(retention_days=90):
    """
    LAYER 7: Remove old attack events (90-day retention)
    """
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        # Delete old attack events
        cur.execute("""
            DELETE FROM attack_events
            WHERE detected_at < NOW() - INTERVAL '%s days'
        """, (retention_days,))
        deleted_count = cur.rowcount

        conn.commit()

        if deleted_count > 0:
            logger.info(f"Attack events cleanup: Removed {deleted_count} events older than {retention_days}d")

        cur.close()

    except Exception as e:
        logger.error(f"Attack events cleanup failed: {e}")
    finally:
        if db:
            db.close()

def cleanup_old_syncookie_metrics(retention_days=7):
    """
    Layer 4: remove syncookie_metrics entries older than retention_days.
    """
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        cur.execute(
            """
            DELETE FROM syncookie_metrics
            WHERE timestamp < NOW() - INTERVAL '%s days'
            """,
            (retention_days,)
        )
        deleted_count = cur.rowcount

        conn.commit()

        if deleted_count > 0:
            logger.info(
                "Syncookie metrics cleanup: removed %s rows older than %sd",
                deleted_count,
                retention_days,
            )

        cur.close()

    except Exception as e:
        logger.error(f"Syncookie metrics cleanup failed: {e}")
    finally:
        if db:
            db.close()

def cleanup_old_latency_measurements(retention_days=30):
    """Delete latency measurements older than 30 days"""
    db = None
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        cur.execute("""
            DELETE FROM latency_measurements
            WHERE timestamp < NOW() - INTERVAL '%s days'
        """, (retention_days,))
        deleted_count = cur.rowcount

        conn.commit()

        if deleted_count > 0:
            logger.info(f"Latency cleanup: Removed {deleted_count} entries older than {retention_days}d")

        cur.close()

    except Exception as e:
        logger.error(f"Latency cleanup failed: {e}")
    finally:
        if db:
            db.close()


def cleanup_expired_ratelimit_penalties():
    """
    Remove expired penalty entries from ratelimit_map on all scrubbers and DB.

    Called hourly by maintenance thread.
    Prevents stale penalties from accumulating.
    """
    logger.info("Starting ratelimit penalty cleanup...")

    db = None
    try:
        db = get_db_connection()
        cur = db.conn.cursor(cursor_factory=RealDictCursor)

        # 1. Find expired penalties in database
        cur.execute("""
            SELECT id, ip_address, origin_id
            FROM mitigation_actions
            WHERE action_type = 'ratelimit_penalty'
            AND expires_at IS NOT NULL
            AND expires_at < NOW()
        """)
        expired = cur.fetchall()

        if not expired:
            logger.debug("No expired ratelimit penalties to clean")
            cur.close()
            return

        logger.info(f"Found {len(expired)} expired ratelimit penalties")

        # 2. Get all active scrubbers
        scrubbers = [n for n in state_manager.nodes_db.values()
                     if n.get('node_type') == 'scrubber' and n.get('status') == 'running']

        # 3. For each expired penalty, delete from BPF maps
        cleaned_count = 0
        for penalty in expired:
            ip_addr = penalty['ip_address']
            if not ip_addr:
                continue

            # Convert IP to hex for bpftool key (little-endian format)
            key_hex = ip_to_hex(str(ip_addr))

            # Delete from each scrubber's ratelimit_map
            for scrubber in scrubbers:
                try:
                    # Just delete the entry - XDP will recreate on next packet
                    delete_cmd = (
                        f"sudo bpftool map delete pinned "
                        f"/sys/fs/bpf/tc/globals/ratelimit_map key hex {key_hex} 2>/dev/null || true"
                    )
                    ssh_exec(
                        host=scrubber.get('public_ip'),
                        command=delete_cmd,
                        ssh_key_path=settings.ssh_key_path,
                        nodes_db=state_manager.nodes_db,
                        timeout=10
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to clear penalty on {scrubber.get('public_ip')} "
                        f"for {ip_addr}: {e}"
                    )

            cleaned_count += 1

        # 4. Delete from database
        cur.execute("""
            DELETE FROM mitigation_actions
            WHERE action_type = 'ratelimit_penalty'
            AND expires_at IS NOT NULL
            AND expires_at < NOW()
        """)
        db.conn.commit()

        logger.info(f"Cleaned {cleaned_count} expired ratelimit penalties")

        cur.close()

    except Exception as e:
        logger.error(f"Penalty cleanup error: {e}", exc_info=True)
    finally:
        if db:
            db.close()


def start_maintenance_thread(interval_seconds=3600, retention_hours=24, metrics_retention_days=90):
    """
    Start periodic database maintenance in background thread

    Args:
        interval_seconds: Seconds between maintenance runs (default: 3600 = 1 hour)
        retention_hours: Hours to retain health data (default: 24)
        metrics_retention_days: Days to retain DDoS metrics (default: 90)
    """
    def maintenance_loop():
        cleanup_old_health_records(retention_hours)
        cleanup_old_metrics(metrics_retention_days)
        cleanup_expired_temp_blacklist()  # PHASE 3: Cleanup expired temp blacklist
        cleanup_expired_per_origin_reputation()  # Per-origin reputation cleanup
        cleanup_old_ratelimit_stats()  # LAYER 3: Cleanup old rate limit stats (7d)
        cleanup_old_baselines()  # LAYER 6: Cleanup old baseline history (90d)
        cleanup_old_attack_events()  # LAYER 7: Cleanup old attack events (90d)
        cleanup_old_syncookie_metrics()  # LAYER 4: Cleanup syncookie telemetry (7d)
        cleanup_old_latency_measurements()  # NEW: Cleanup latency measurements (30d)
        cleanup_expired_ratelimit_penalties()  # Rate limit penalty cleanup from BPF + DB
        # Schedule next run
        threading.Timer(interval_seconds, maintenance_loop).start()

    # Run first cleanup immediately
    threading.Thread(target=cleanup_old_health_records, args=(retention_hours,), daemon=True).start()
    threading.Thread(target=cleanup_old_metrics, args=(metrics_retention_days,), daemon=True).start()
    threading.Thread(target=cleanup_expired_temp_blacklist, daemon=True).start()  # PHASE 3
    threading.Thread(target=cleanup_expired_per_origin_reputation, daemon=True).start()  # Per-origin reputation
    threading.Thread(target=cleanup_old_ratelimit_stats, daemon=True).start()  # LAYER 3
    threading.Thread(target=cleanup_old_baselines, daemon=True).start()  # LAYER 6
    threading.Thread(target=cleanup_old_attack_events, daemon=True).start()  # LAYER 7
    threading.Thread(target=cleanup_old_syncookie_metrics, daemon=True).start()  # LAYER 4
    threading.Thread(target=cleanup_old_latency_measurements, daemon=True).start()  # NEW
    threading.Thread(target=cleanup_expired_ratelimit_penalties, daemon=True).start()  # Penalties

    # Schedule periodic runs
    threading.Timer(interval_seconds, maintenance_loop).start()

    logger.info(
        "Database maintenance thread started: cleanup every %ss, health %sh, "
        "metrics %sd, temp_blacklist auto-expire, per-origin reputation auto-expire, "
        "ratelimit_stats 7d, baselines 90d, attack_events 90d, syncookie_metrics 7d, "
        "latency 30d, ratelimit_penalties auto-expire",
        interval_seconds,
        retention_hours,
        metrics_retention_days,
    )
