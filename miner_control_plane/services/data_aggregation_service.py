"""Central Data Aggregation Service - Aggregates and pushes data"""
import logging
import threading
import json
import requests
from datetime import datetime, timezone
import psycopg2.extras
from shared.database import get_db_connection
from shared.config import get_settings
from miner_control_plane.services.miner_identity import miner_identity
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services import latency_measurement

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover
    redis = None

logger = logging.getLogger(__name__)


class DataAggregationService:
    """Central orchestrator - aggregates data and pushes to configured destination"""

    def __init__(self):
        self.settings = get_settings()
        # NOTE: Connection acquired per-method, not held for service lifetime
        # This prevents connection pool exhaustion during long-running operations
        # Single configurable interval for ALL data collection
        self.aggregation_interval = getattr(
            self.settings, 'data_aggregation_interval', 30
        )

        # Push destination (HTTP fallback)
        self.push_url = getattr(self.settings, 'data_push_url', None)

        # Redis client - prefer credentials from TPM registration, fall back to env
        self.redis_client = None
        self.redis_channel = None
        self._init_redis_client()

    def _init_redis_client(self) -> None:
        """Initialize Redis client from TPM credentials or fallback to env."""
        if not redis:
            logger.warning("redis library not installed, metrics publishing disabled")
            return

        # Try TPM-provided credentials first
        tpm_redis = miner_identity.redis_config
        if tpm_redis:
            try:
                self.redis_client = redis.Redis(
                    host=tpm_redis["host"],
                    port=tpm_redis["port"],
                    password=tpm_redis.get("password"),
                    decode_responses=True,
                )
                # Use metrics channel from TPM config
                channels = tpm_redis.get("channels", {})
                self.redis_channel = channels.get(
                    "metrics",
                    getattr(self.settings, 'metrics_channel', 'metrics.aggregated')
                )
                logger.info(
                    "Redis client initialized from TPM credentials (host=%s, channel=%s)",
                    tpm_redis["host"],
                    self.redis_channel,
                )
                return
            except Exception as exc:
                logger.warning("Failed to init Redis from TPM credentials: %s", exc)

        # Fallback to TP_REDIS_URL from environment
        redis_url = getattr(self.settings, 'redis_url', None)
        if redis_url:
            try:
                self.redis_client = redis.Redis.from_url(redis_url)
                self.redis_channel = getattr(
                    self.settings, 'metrics_channel', 'metrics.aggregated'
                )
                logger.info(
                    "Redis client initialized from TP_REDIS_URL fallback (channel=%s)",
                    self.redis_channel,
                )
            except Exception as exc:
                logger.warning(
                    "Failed to init Redis from TP_REDIS_URL (%s): %s", redis_url, exc
                )
        else:
            logger.info("No Redis credentials available, metrics publishing disabled")

    def _calculate_z_scores(self, metrics: dict, baseline: dict) -> dict:
        """
        Calculate Z-scores for key traffic metrics

        Args:
            metrics: Current metrics dict
            baseline: Baseline dict with mean/stddev values

        Returns:
            Dict with pps, cps, syn_ratio Z-scores
        """
        if not baseline or not metrics:
            return None

        pps_stddev = baseline['pps_stddev'] or 1
        cps_stddev = baseline['cps_stddev'] or 1
        syn_stddev = float(baseline['syn_ratio_stddev'] or 1)

        pps_z = None
        if metrics.get('pps') and baseline.get('pps_mean'):
            pps_z = round((metrics['pps'] - baseline['pps_mean']) / pps_stddev, 2)

        cps_z = None
        if metrics.get('cps') and baseline.get('cps_mean'):
            cps_z = round((metrics['cps'] - baseline['cps_mean']) / cps_stddev, 2)

        syn_z = None
        if metrics.get('syn_synack_ratio') and baseline.get('syn_ratio_mean'):
            syn_current = float(metrics['syn_synack_ratio'] or 0)
            syn_mean = float(baseline['syn_ratio_mean'] or 0)
            syn_z = round((syn_current - syn_mean) / syn_stddev, 2)

        return {
            'pps': pps_z,
            'cps': cps_z,
            'syn_ratio': syn_z,
        }

    def aggregate_origin_data(self, origin_id: str) -> dict:
        """
        Aggregate all data for a single origin from multiple sources

        Returns complete dataset ready for web app
        """
        db = None
        try:
            # Use get_origin() which has DB fallback on cache miss
            origin = state_manager.get_origin(origin_id)
            if not origin:
                return None

            db = get_db_connection()
            conn = db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Get latest metrics (from last aggregation cycle) - all fields in single query
            cur.execute("""
                SELECT
                    -- Traffic metrics
                    pps, cps, bps, active_connections,
                    syn_synack_ratio,
                    -- Raw counters for detailed analysis
                    ingress_syn_count, egress_synack_count, fin_count, rst_count,
                    -- Infrastructure metrics
                    cpu_pct, memory_pct,
                    -- Billing metrics
                    volume_ingress, volume_egress,
                    -- Security drops (global)
                    drop_blacklist, drop_temp_blacklist, drop_ratelimit,
                    drop_quarantine, drop_bogon,
                    -- Per-origin reputation stats
                    drop_origin_blacklist, origin_whitelist_bypass, origin_override_used,
                    timestamp
                FROM origin_metrics
                WHERE origin_id = %s
                  AND timestamp > NOW() - INTERVAL '%s seconds'
                ORDER BY timestamp DESC LIMIT 1
            """, (origin_id, self.aggregation_interval * 2))
            metrics = cur.fetchone()

            # Get latest latency (from last aggregation cycle)
            cur.execute("""
                SELECT latency_ms FROM latency_measurements
                WHERE origin_id = %s
                  AND timestamp > NOW() - INTERVAL '%s seconds'
                ORDER BY timestamp DESC LIMIT 1
            """, (origin_id, self.aggregation_interval * 2))
            latency_row = cur.fetchone()

            # Get spike detection state + active attack
            cur.execute("""
                SELECT
                    ads.current_challenge_level,
                    ads.active_attack_event_id,
                    ae.attack_type,
                    ae.confidence,
                    ae.peak_pps,
                    ae.peak_cps,
                    ae.detected_at,
                    ae.baseline_deviation_zscore,
                    ae.details
                FROM anomaly_detection_state ads
                LEFT JOIN attack_events ae ON ae.event_id = ads.active_attack_event_id
                WHERE ads.origin_id = %s
            """, (origin_id,))
            spike_state = cur.fetchone()

            # Get current baseline
            cur.execute("""
                SELECT pps_mean, pps_stddev, pps_p95,
                       cps_mean, cps_stddev, cps_p95,
                       syn_ratio_mean, syn_ratio_stddev, syn_ratio_p95,
                       confidence_score, sample_count
                FROM traffic_baselines
                WHERE origin_id = %s AND is_current = TRUE
            """, (origin_id,))
            baseline = cur.fetchone()

            # Get syncookie metrics (by origin's private_ip)
            cur.execute("""
                SELECT
                    sm.cookie_mode,
                    sm.cookie_validates,
                    sm.cookie_rejects,
                    sm.challenged_clients,
                    sm.allow_list_size,
                    sm.pending_cookies,
                    sm.false_positives
                FROM syncookie_metrics sm
                JOIN origins o ON sm.vip_ip = o.private_ip::inet
                WHERE o.origin_id = %s
                  AND sm.timestamp > NOW() - INTERVAL '60 seconds'
                ORDER BY sm.timestamp DESC LIMIT 1
            """, (origin_id,))
            syncookie = cur.fetchone()

            cur.close()

            # Calculate Z-scores (if baseline exists)
            z_scores = self._calculate_z_scores(metrics, baseline)

            # Calculate derived metrics
            created_at_raw = origin.get('created_at')
            if isinstance(created_at_raw, str):
                created_at = datetime.fromisoformat(created_at_raw)
            elif isinstance(created_at_raw, (int, float)):
                created_at = datetime.fromtimestamp(created_at_raw, tz=timezone.utc)
            else:
                created_at = created_at_raw

            if isinstance(created_at, datetime):
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                uptime_days = (datetime.now(timezone.utc) - created_at).days
            else:
                uptime_days = 0

            status = 'active' if origin.get('state') == 'IN_SERVICE' else 'stopped'

            origin_ip = origin.get('origin_ip')

            # Multi-region: Get shard and region info
            shard_id = origin.get('shard_id')
            shard = state_manager.shards_db.get(shard_id) if shard_id else None
            region = shard.get('region') if shard else None

            # Bandwidth QoS metrics
            bandwidth_quota = state_manager.bandwidth_quotas.get(origin_ip, {})
            bandwidth_usage = state_manager.bandwidth_usage.get(origin_ip, {})

            quota_bps = bandwidth_quota.get('quota_bps', 0)
            bytes_exceeded = bandwidth_usage.get('bytes_exceeded', 0)
            packets_dropped = bandwidth_usage.get('packets_dropped', 0)

            # Build events array from security drop counters
            blacklist_count = (
                (metrics['drop_blacklist'] or 0) if metrics else 0
            )
            temp_blacklist_count = (
                (metrics['drop_temp_blacklist'] or 0) if metrics else 0
            )
            ratelimit_count = (
                (metrics['drop_ratelimit'] or 0) if metrics else 0
            )
            quarantine_count = (
                (metrics['drop_quarantine'] or 0) if metrics else 0
            )
            bogon_count = (metrics['drop_bogon'] or 0) if metrics else 0
            origin_blacklist_count = (
                (metrics['drop_origin_blacklist'] or 0) if metrics else 0
            )

            events = [
                {'type': 'blacklist', 'count': blacklist_count},
                {'type': 'temp_blacklist', 'count': temp_blacklist_count},
                {'type': 'ratelimit', 'count': ratelimit_count},
                {'type': 'quarantine', 'count': quarantine_count},
                {'type': 'origin_blacklist', 'count': origin_blacklist_count},
                {'type': 'bogon', 'count': bogon_count},
            ]
            events_count = (
                blacklist_count + temp_blacklist_count + ratelimit_count +
                quarantine_count + bogon_count + origin_blacklist_count
            )

            # Leftover metrics (not drops, kept flat for later use)
            origin_whitelist_bypass = (
                (metrics['origin_whitelist_bypass'] or 0) if metrics else 0
            )
            origin_override_used = (
                (metrics['origin_override_used'] or 0) if metrics else 0
            )

            # Aggregate into single dataset (preserve field names for webapp)
            aggregated_data = {
                'origin_id': origin_id,
                'shard_id': shard_id,
                'region': region,
                'eip': origin.get('eip'),
                'status': status,
                'uptime_days': uptime_days,
                # EXISTING fields (preserve names for webapp)
                'bandwidth_usage': (
                    round((metrics['bps'] * 8 / 1_000_000), 2)
                    if metrics and metrics.get('bps')
                    else 0
                ),
                'volume_processed': (
                    round(
                        (
                            (metrics.get('volume_ingress') or 0) +
                            (metrics.get('volume_egress') or 0)
                        ) / 1_000_000_000, 2
                    )
                    if metrics
                    else 0
                ),
                'latency': (
                    round(float(latency_row['latency_ms']), 2)
                    if latency_row and latency_row.get('latency_ms')
                    else None
                ),
                'cpu_usage': (
                    round(float(metrics['cpu_pct']), 1)
                    if metrics and metrics.get('cpu_pct')
                    else None
                ),
                'memory_usage': (
                    round(float(metrics['memory_pct']), 1)
                    if metrics and metrics.get('memory_pct')
                    else None
                ),
                'active_connections': (
                    metrics['active_connections']
                    if metrics and metrics.get('active_connections')
                    else 0
                ),
                'events_count': events_count,
                'events': events,
                'origin_whitelist_bypass': origin_whitelist_bypass,
                'origin_override_used': origin_override_used,
                'last_updated': datetime.now(timezone.utc).isoformat(),
                'volume_ingress': (
                    round(metrics['volume_ingress'] / 1_000_000_000, 6)
                    if metrics and metrics.get('volume_ingress')
                    else 0
                ),
                'volume_egress': (
                    round(metrics['volume_egress'] / 1_000_000_000, 6)
                    if metrics and metrics.get('volume_egress')
                    else 0
                ),
                'bandwidth_qos': {
                    'quota_bps': quota_bps,
                    'quota_mbps': round(quota_bps / 1e6, 1) if quota_bps else 0,
                    'bytes_exceeded': bytes_exceeded,
                    'packets_dropped': packets_dropped,
                    'is_over_quota': bytes_exceeded > 0,
                    'enforce_mode': 'monitor',
                },
                # NEW fields (traffic metrics)
                'pps': metrics['pps'] if metrics and metrics.get('pps') else 0,
                'cps': metrics['cps'] if metrics and metrics.get('cps') else 0,
                'bps': metrics['bps'] if metrics and metrics.get('bps') else 0,
                # NEW fields (attack indicators)
                'syn_synack_ratio': (
                    float(metrics['syn_synack_ratio'])
                    if metrics and metrics.get('syn_synack_ratio')
                    else None
                ),
                'ingress_syn_count': (
                    metrics['ingress_syn_count']
                    if metrics and metrics.get('ingress_syn_count')
                    else 0
                ),
                'egress_synack_count': (
                    metrics['egress_synack_count']
                    if metrics and metrics.get('egress_synack_count')
                    else 0
                ),
                'fin_count': (
                    metrics['fin_count']
                    if metrics and metrics.get('fin_count')
                    else 0
                ),
                'rst_count': (
                    metrics['rst_count']
                    if metrics and metrics.get('rst_count')
                    else 0
                ),
                # Spike alert block
                'spike_alert': {
                    'detected': (
                        spike_state['active_attack_event_id'] is not None
                        if spike_state
                        else False
                    ),
                    'type': (
                        spike_state['attack_type']
                        if spike_state and spike_state.get('attack_type')
                        else None
                    ),
                    'confidence': (
                        round(spike_state['confidence'], 2)
                        if spike_state and spike_state.get('confidence')
                        else None
                    ),
                    'trigger': (
                        (spike_state.get('details') or {}).get('trigger')
                        if spike_state
                        else None
                    ),
                    'challenge_level': (
                        spike_state['current_challenge_level']
                        if spike_state
                        else 0
                    ),
                    'peak_pps': spike_state['peak_pps'] if spike_state else None,
                    'peak_cps': spike_state['peak_cps'] if spike_state else None,
                    'started_at': (
                        spike_state['detected_at'].isoformat()
                        if spike_state and spike_state.get('detected_at')
                        else None
                    ),
                    'z_score': (
                        round(spike_state['baseline_deviation_zscore'], 2)
                        if spike_state and spike_state.get('baseline_deviation_zscore')
                        else None
                    ),
                } if spike_state else {'detected': False, 'challenge_level': 0},
                # Baseline block
                'baseline': {
                    'pps_mean': baseline['pps_mean'] if baseline else None,
                    'pps_p95': baseline['pps_p95'] if baseline else None,
                    'pps_stddev': baseline['pps_stddev'] if baseline else None,
                    'cps_mean': baseline['cps_mean'] if baseline else None,
                    'cps_p95': baseline['cps_p95'] if baseline else None,
                    'syn_ratio_mean': (
                        float(baseline['syn_ratio_mean'])
                        if baseline and baseline.get('syn_ratio_mean')
                        else None
                    ),
                    'syn_ratio_p95': (
                        float(baseline['syn_ratio_p95'])
                        if baseline and baseline.get('syn_ratio_p95')
                        else None
                    ),
                    'confidence': (
                        round(float(baseline['confidence_score']), 2)
                        if baseline and baseline.get('confidence_score')
                        else None
                    ),
                    'sample_count': baseline['sample_count'] if baseline else 0,
                } if baseline else None,
                # Z-scores block
                'z_scores': z_scores,
                # Syncookie block
                'syncookie': {
                    'mode': syncookie['cookie_mode'] if syncookie else 0,
                    'validates': syncookie['cookie_validates'] if syncookie else 0,
                    'rejects': syncookie['cookie_rejects'] if syncookie else 0,
                    'challenged_clients': syncookie['challenged_clients'] if syncookie else 0,
                    'allow_list_size': syncookie['allow_list_size'] if syncookie else 0,
                    'pending': syncookie['pending_cookies'] if syncookie else 0,
                    'false_positives': syncookie['false_positives'] if syncookie else 0,
                } if syncookie else None,
            }

            return aggregated_data

        except Exception as e:
            logger.error(f"Failed to aggregate data for {origin_id}: {e}")
            return None
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

    def _batch_fetch_origin_data(self, origin_ids: list) -> dict:
        """
        Batch fetch all data for multiple origins in optimized queries.

        SCALABILITY FIX: This replaces the N+1 query pattern where each origin
        triggered 5 separate queries. Now we fetch all data in 5 total queries
        regardless of the number of origins.

        Returns:
            Dict mapping origin_id to dict of {metrics, latency, spike_state, baseline, syncookie}
        """
        if not origin_ids:
            return {}

        result = {oid: {} for oid in origin_ids}
        db = None

        try:
            db = get_db_connection()
            conn = db.conn
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            # Query 1: Batch fetch latest metrics for all origins (using DISTINCT ON)
            cur.execute("""
                SELECT DISTINCT ON (origin_id)
                    origin_id,
                    pps, cps, bps, active_connections, syn_synack_ratio,
                    ingress_syn_count, egress_synack_count, fin_count, rst_count,
                    cpu_pct, memory_pct, volume_ingress, volume_egress,
                    drop_blacklist, drop_temp_blacklist, drop_ratelimit,
                    drop_quarantine, drop_bogon, drop_origin_blacklist,
                    origin_whitelist_bypass, origin_override_used, timestamp
                FROM origin_metrics
                WHERE origin_id = ANY(%s)
                  AND timestamp > NOW() - INTERVAL '%s seconds'
                ORDER BY origin_id, timestamp DESC
            """, (origin_ids, self.aggregation_interval * 2))
            for row in cur.fetchall():
                result[row['origin_id']]['metrics'] = row

            # Query 2: Batch fetch latest latency for all origins
            cur.execute("""
                SELECT DISTINCT ON (origin_id)
                    origin_id, latency_ms
                FROM latency_measurements
                WHERE origin_id = ANY(%s)
                  AND timestamp > NOW() - INTERVAL '%s seconds'
                ORDER BY origin_id, timestamp DESC
            """, (origin_ids, self.aggregation_interval * 2))
            for row in cur.fetchall():
                result[row['origin_id']]['latency'] = row

            # Query 3: Batch fetch spike detection state + active attack
            cur.execute("""
                SELECT
                    ads.origin_id,
                    ads.current_challenge_level,
                    ads.active_attack_event_id,
                    ae.attack_type,
                    ae.confidence,
                    ae.peak_pps,
                    ae.peak_cps,
                    ae.detected_at,
                    ae.baseline_deviation_zscore,
                    ae.details
                FROM anomaly_detection_state ads
                LEFT JOIN attack_events ae ON ae.event_id = ads.active_attack_event_id
                WHERE ads.origin_id = ANY(%s)
            """, (origin_ids,))
            for row in cur.fetchall():
                result[row['origin_id']]['spike_state'] = row

            # Query 4: Batch fetch current baselines
            cur.execute("""
                SELECT
                    origin_id,
                    pps_mean, pps_stddev, pps_p95,
                    cps_mean, cps_stddev, cps_p95,
                    syn_ratio_mean, syn_ratio_stddev, syn_ratio_p95,
                    confidence_score, sample_count
                FROM traffic_baselines
                WHERE origin_id = ANY(%s) AND is_current = TRUE
            """, (origin_ids,))
            for row in cur.fetchall():
                result[row['origin_id']]['baseline'] = row

            # Query 5: Batch fetch syncookie metrics (need to join with origins for private_ip)
            cur.execute("""
                SELECT DISTINCT ON (o.origin_id)
                    o.origin_id,
                    sm.cookie_mode,
                    sm.cookie_validates,
                    sm.cookie_rejects,
                    sm.challenged_clients,
                    sm.allow_list_size,
                    sm.pending_cookies,
                    sm.false_positives
                FROM origins o
                JOIN syncookie_metrics sm ON sm.vip_ip = o.private_ip::inet
                WHERE o.origin_id = ANY(%s)
                  AND sm.timestamp > NOW() - INTERVAL '60 seconds'
                ORDER BY o.origin_id, sm.timestamp DESC
            """, (origin_ids,))
            for row in cur.fetchall():
                result[row['origin_id']]['syncookie'] = row

            cur.close()

            logger.debug(
                f"Batch fetched data for {len(origin_ids)} origins in 5 queries"
            )

        except Exception as e:
            logger.error(f"Batch fetch failed: {e}")
        finally:
            if db:
                try:
                    db.close()
                except Exception:
                    pass

        return result

    def aggregate_all_origins_batch(self) -> list:
        """
        Aggregate data for all origins using batch queries.

        SCALABILITY FIX: Uses _batch_fetch_origin_data() to fetch all data
        in 5 queries instead of N*5 queries.

        Returns:
            List of aggregated data dicts for all origins
        """
        origin_ids = list(state_manager.origins_db.keys())
        if not origin_ids:
            return []

        # Batch fetch all data
        batch_data = self._batch_fetch_origin_data(origin_ids)

        aggregated_list = []

        for origin_id in origin_ids:
            try:
                origin = state_manager.get_origin(origin_id)
                if not origin:
                    continue

                data = batch_data.get(origin_id, {})
                metrics = data.get('metrics')
                latency_row = data.get('latency')
                spike_state = data.get('spike_state')
                baseline = data.get('baseline')
                syncookie = data.get('syncookie')

                # Calculate Z-scores
                z_scores = self._calculate_z_scores(metrics, baseline)

                # Calculate derived metrics (same logic as aggregate_origin_data)
                created_at_raw = origin.get('created_at')
                if isinstance(created_at_raw, str):
                    created_at = datetime.fromisoformat(created_at_raw)
                elif isinstance(created_at_raw, (int, float)):
                    created_at = datetime.fromtimestamp(created_at_raw, tz=timezone.utc)
                else:
                    created_at = created_at_raw

                if isinstance(created_at, datetime):
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)
                    uptime_days = (datetime.now(timezone.utc) - created_at).days
                else:
                    uptime_days = 0

                status = 'active' if origin.get('state') == 'IN_SERVICE' else 'stopped'
                origin_ip = origin.get('origin_ip')
                shard_id = origin.get('shard_id')
                shard = state_manager.shards_db.get(shard_id) if shard_id else None
                region = shard.get('region') if shard else None

                # Bandwidth QoS metrics
                bandwidth_quota = state_manager.bandwidth_quotas.get(origin_ip, {})
                bandwidth_usage = state_manager.bandwidth_usage.get(origin_ip, {})
                quota_bps = bandwidth_quota.get('quota_bps', 0)
                bytes_exceeded = bandwidth_usage.get('bytes_exceeded', 0)
                packets_dropped = bandwidth_usage.get('packets_dropped', 0)

                # Build events array from security drop counters
                blacklist_count = (metrics['drop_blacklist'] or 0) if metrics else 0
                temp_blacklist_count = (metrics['drop_temp_blacklist'] or 0) if metrics else 0
                ratelimit_count = (metrics['drop_ratelimit'] or 0) if metrics else 0
                quarantine_count = (metrics['drop_quarantine'] or 0) if metrics else 0
                bogon_count = (metrics['drop_bogon'] or 0) if metrics else 0
                origin_blacklist_count = (metrics['drop_origin_blacklist'] or 0) if metrics else 0

                events = [
                    {'type': 'blacklist', 'count': blacklist_count},
                    {'type': 'temp_blacklist', 'count': temp_blacklist_count},
                    {'type': 'ratelimit', 'count': ratelimit_count},
                    {'type': 'quarantine', 'count': quarantine_count},
                    {'type': 'origin_blacklist', 'count': origin_blacklist_count},
                    {'type': 'bogon', 'count': bogon_count},
                ]
                events_count = (
                    blacklist_count + temp_blacklist_count + ratelimit_count +
                    quarantine_count + bogon_count + origin_blacklist_count
                )

                origin_whitelist_bypass = (metrics['origin_whitelist_bypass'] or 0) if metrics else 0
                origin_override_used = (metrics['origin_override_used'] or 0) if metrics else 0

                # Build aggregated data (same structure as aggregate_origin_data)
                aggregated_data = {
                    'origin_id': origin_id,
                    'shard_id': shard_id,
                    'region': region,
                    'eip': origin.get('eip'),
                    'status': status,
                    'uptime_days': uptime_days,
                    'bandwidth_usage': (
                        round((metrics['bps'] * 8 / 1_000_000), 2)
                        if metrics and metrics.get('bps') else 0
                    ),
                    'volume_processed': (
                        round(((metrics.get('volume_ingress') or 0) + (metrics.get('volume_egress') or 0)) / 1_000_000_000, 2)
                        if metrics else 0
                    ),
                    'latency': (
                        round(float(latency_row['latency_ms']), 2)
                        if latency_row and latency_row.get('latency_ms') else None
                    ),
                    'cpu_usage': (
                        round(float(metrics['cpu_pct']), 1)
                        if metrics and metrics.get('cpu_pct') else None
                    ),
                    'memory_usage': (
                        round(float(metrics['memory_pct']), 1)
                        if metrics and metrics.get('memory_pct') else None
                    ),
                    'active_connections': (
                        metrics['active_connections']
                        if metrics and metrics.get('active_connections') else 0
                    ),
                    'events_count': events_count,
                    'events': events,
                    'origin_whitelist_bypass': origin_whitelist_bypass,
                    'origin_override_used': origin_override_used,
                    'last_updated': datetime.now(timezone.utc).isoformat(),
                    'volume_ingress': (
                        round(metrics['volume_ingress'] / 1_000_000_000, 6)
                        if metrics and metrics.get('volume_ingress') else 0
                    ),
                    'volume_egress': (
                        round(metrics['volume_egress'] / 1_000_000_000, 6)
                        if metrics and metrics.get('volume_egress') else 0
                    ),
                    'bandwidth_qos': {
                        'quota_bps': quota_bps,
                        'quota_mbps': round(quota_bps / 1e6, 1) if quota_bps else 0,
                        'bytes_exceeded': bytes_exceeded,
                        'packets_dropped': packets_dropped,
                        'is_over_quota': bytes_exceeded > 0,
                        'enforce_mode': 'monitor',
                    },
                    'pps': metrics['pps'] if metrics and metrics.get('pps') else 0,
                    'cps': metrics['cps'] if metrics and metrics.get('cps') else 0,
                    'bps': metrics['bps'] if metrics and metrics.get('bps') else 0,
                    'syn_synack_ratio': (
                        float(metrics['syn_synack_ratio'])
                        if metrics and metrics.get('syn_synack_ratio') else None
                    ),
                    'ingress_syn_count': (
                        metrics['ingress_syn_count']
                        if metrics and metrics.get('ingress_syn_count') else 0
                    ),
                    'egress_synack_count': (
                        metrics['egress_synack_count']
                        if metrics and metrics.get('egress_synack_count') else 0
                    ),
                    'fin_count': (
                        metrics['fin_count']
                        if metrics and metrics.get('fin_count') else 0
                    ),
                    'rst_count': (
                        metrics['rst_count']
                        if metrics and metrics.get('rst_count') else 0
                    ),
                    'spike_alert': {
                        'detected': spike_state['active_attack_event_id'] is not None if spike_state else False,
                        'type': spike_state['attack_type'] if spike_state and spike_state.get('attack_type') else None,
                        'confidence': round(spike_state['confidence'], 2) if spike_state and spike_state.get('confidence') else None,
                        'trigger': (spike_state.get('details') or {}).get('trigger') if spike_state else None,
                        'challenge_level': spike_state['current_challenge_level'] if spike_state else 0,
                        'peak_pps': spike_state['peak_pps'] if spike_state else None,
                        'peak_cps': spike_state['peak_cps'] if spike_state else None,
                        'started_at': spike_state['detected_at'].isoformat() if spike_state and spike_state.get('detected_at') else None,
                        'z_score': round(spike_state['baseline_deviation_zscore'], 2) if spike_state and spike_state.get('baseline_deviation_zscore') else None,
                    } if spike_state else {'detected': False, 'challenge_level': 0},
                    'baseline': {
                        'pps_mean': baseline['pps_mean'] if baseline else None,
                        'pps_p95': baseline['pps_p95'] if baseline else None,
                        'pps_stddev': baseline['pps_stddev'] if baseline else None,
                        'cps_mean': baseline['cps_mean'] if baseline else None,
                        'cps_p95': baseline['cps_p95'] if baseline else None,
                        'syn_ratio_mean': float(baseline['syn_ratio_mean']) if baseline and baseline.get('syn_ratio_mean') else None,
                        'syn_ratio_p95': float(baseline['syn_ratio_p95']) if baseline and baseline.get('syn_ratio_p95') else None,
                        'confidence': round(float(baseline['confidence_score']), 2) if baseline and baseline.get('confidence_score') else None,
                        'sample_count': baseline['sample_count'] if baseline else 0,
                    } if baseline else None,
                    'z_scores': z_scores,
                    'syncookie': {
                        'mode': syncookie['cookie_mode'] if syncookie else 0,
                        'validates': syncookie['cookie_validates'] if syncookie else 0,
                        'rejects': syncookie['cookie_rejects'] if syncookie else 0,
                        'challenged_clients': syncookie['challenged_clients'] if syncookie else 0,
                        'allow_list_size': syncookie['allow_list_size'] if syncookie else 0,
                        'pending': syncookie['pending_cookies'] if syncookie else 0,
                        'false_positives': syncookie['false_positives'] if syncookie else 0,
                    } if syncookie else None,
                }

                aggregated_list.append(aggregated_data)

            except Exception as e:
                logger.error(f"Failed to aggregate data for {origin_id}: {e}")
                continue

        return aggregated_list

    def push_aggregated_data(self):
        """Push aggregated data to configured destination using batch queries"""
        if not self.push_url and not self.redis_client:
            logger.debug("No push destination configured, skipping push")
            return

        try:
            # Use batch aggregation to avoid N+1 queries
            all_aggregated = self.aggregate_all_origins_batch()
            pushed_count = 0

            for aggregated in all_aggregated:
                origin_id = aggregated.get('origin_id')

                if self.redis_client:
                    try:
                        # Add miner identity for TPM-side validation
                        if miner_identity.miner_id and miner_identity._miner_secret:
                            aggregated["miner_id"] = miner_identity.miner_id
                            aggregated["auth_token"] = (
                                miner_identity._miner_secret
                            )
                        self.redis_client.publish(
                            self.redis_channel,
                            json.dumps(aggregated, default=str)
                        )
                        pushed_count += 1
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "Redis publish failed for %s: %s", origin_id, exc
                        )
                        continue
                elif self.push_url:
                    response = requests.post(
                        self.push_url,
                        json=aggregated,
                        timeout=5
                    )

                    if response.status_code == 200:
                        pushed_count += 1
                    else:
                        logger.warning(
                            f"Push failed for {origin_id}: "
                            f"HTTP {response.status_code}"
                        )

            if self.redis_client:
                logger.info(
                    "Published %s origins to Redis channel %s",
                    pushed_count,
                    self.redis_channel
                )
            elif self.push_url:
                logger.info(f"Pushed {pushed_count} origins to {self.push_url}")

        except Exception as e:
            logger.error(f"Failed to push aggregated data: {e}")

    def run_aggregation_cycle(self):
        """
        Single aggregation cycle - runs all collection tasks

        Orchestrates:
        1. Latency measurement (triggers SSH pings)
        2. Read latest origin_metrics (already collected by health.py)
        3. Aggregate all data in memory
        4. Push to configured destination
        """
        try:
            # Step 1: Trigger latency measurements (on-demand, not continuous)
            latency_measurement.measure_all_origins()

            # Step 2: Aggregate data and push to configured destination
            self.push_aggregated_data()

        except Exception as e:
            logger.error(f"Aggregation cycle failed: {e}")


def start_data_aggregation_thread(interval_seconds=30):
    """
    Start data aggregation service

    This is the ONLY service with a loop - all others are called by this.
    """
    service = DataAggregationService()

    def aggregation_loop():
        service.run_aggregation_cycle()
        threading.Timer(interval_seconds, aggregation_loop).start()

    # Run immediately
    threading.Thread(target=service.run_aggregation_cycle, daemon=True).start()

    # Schedule periodic runs
    threading.Timer(interval_seconds, aggregation_loop).start()

    logger.info(
        f"Data aggregation service started: collecting every {interval_seconds}s"
    )
