"""Health API Blueprint - Scrubber health and metrics reporting

Endpoints for ecp-agent to report health, metrics, and attack signatures.
"""
import json
import logging
import time
import ipaddress
import threading
from datetime import datetime, timezone
import psycopg2.extras
from flask import Blueprint, request, jsonify
from shared.database import get_db_connection
from shared.config import get_settings
from miner_control_plane.services.attack_detection import calculate_attack_signature, calculate_confidence
from miner_control_plane.services.state_manager import state_manager

bp = Blueprint('health', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)
settings = get_settings()

# In-memory heartbeat tracking for fast failover detection
# Key: node_id, Value: timestamp of last heartbeat
_heartbeat_tracker: dict = {}
_heartbeat_lock = threading.Lock()


def _get_infrastructure_ips():
    ips = set()
    if settings.emn_ip:
        ips.add(settings.emn_ip)

    for node in state_manager.nodes_db.values():
        ip = node.get('public_ip')
        if ip:
            ips.add(ip)

    for origin in state_manager.origins_db.values():
        ip = origin.get('origin_ip')
        if ip:
            ips.add(ip)

    return ips


def _should_skip_source_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
            ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified):
        return True

    if ip_str in _get_infrastructure_ips():
        return True

    return False


# Cumulative counter fields that need lifetime tracking
# NOTE: drop_bogon is NOT included - it's calculated directly as (global_bogon - baseline)
CUMULATIVE_COUNTER_FIELDS = [
    'conn_opened_total', 'conn_closed_total', 'packets_total',
    'ingress_syn_count', 'egress_synack_count', 'fin_count', 'rst_count',
    'volume_ingress', 'volume_egress',
    'drop_blacklist', 'drop_temp_blacklist', 'drop_ratelimit', 'drop_quarantine',
    'drop_origin_blacklist', 'origin_whitelist_bypass', 'origin_override_used'
]


def calculate_lifetime_values(origin_id: str, current_bpf: dict, cur) -> dict:
    """
    Calculate lifetime values for cumulative counters.

    Handles failover by detecting counter resets (current < last).
    Returns dict with lifetime values for all cumulative counters.

    Args:
        origin_id: The origin identifier
        current_bpf: Dict of current BPF counter values from ecp-agent
        cur: Database cursor (must be within a transaction)

    Returns:
        Dict with lifetime values for all CUMULATIVE_COUNTER_FIELDS
    """
    # Get last BPF values and last stored metrics for this origin
    cur.execute("""
        SELECT o.last_bpf_values,
               (SELECT row_to_json(m.*) FROM origin_metrics m
                WHERE m.origin_id = o.origin_id
                ORDER BY m.timestamp DESC LIMIT 1) as last_metrics
        FROM origins o
        WHERE o.origin_id = %s
    """, (origin_id,))
    row = cur.fetchone()

    if not row:
        # Origin not found, return current values as-is
        return {field: current_bpf.get(field, 0) or 0 for field in CUMULATIVE_COUNTER_FIELDS}

    last_bpf = row['last_bpf_values'] or {}
    last_metrics = row['last_metrics'] or {}

    lifetime_values = {}
    new_bpf_values = {}

    for field in CUMULATIVE_COUNTER_FIELDS:
        current_val = current_bpf.get(field, 0) or 0
        last_bpf_val = last_bpf.get(field, 0) or 0
        last_stored_val = last_metrics.get(field, 0) or 0

        # Handle missing data: if current=0 but last>0, data source may be missing
        # (e.g., origin not in eip_security_stats_map). Preserve last values.
        if current_val == 0 and last_bpf_val > 0:
            # Missing data - preserve last lifetime value, don't update BPF tracking
            lifetime_values[field] = last_stored_val
            new_bpf_values[field] = last_bpf_val  # Keep old BPF value
            continue

        # Detect restart: current BPF value is less than last seen (and current > 0)
        if current_val < last_bpf_val:
            # Restart detected - delta is the new count since restart
            delta = current_val
            logger.info(
                f"Restart detected for {origin_id}.{field}: "
                f"{last_bpf_val} -> {current_val}, delta={delta}"
            )
        else:
            # Normal operation - delta is the difference
            delta = current_val - last_bpf_val

        # Lifetime = last stored + delta
        lifetime_values[field] = last_stored_val + delta
        new_bpf_values[field] = current_val

    # Update last_bpf_values in origins table
    cur.execute("""
        UPDATE origins
        SET last_bpf_values = %s
        WHERE origin_id = %s
    """, (json.dumps(new_bpf_values), origin_id))

    return lifetime_values


def get_heartbeat_tracker() -> dict:
    """Get reference to heartbeat tracker for health monitor."""
    return _heartbeat_tracker


def get_last_heartbeat(node_id: str) -> float:
    """Get last heartbeat timestamp for a node (0.0 if never seen)."""
    with _heartbeat_lock:
        return _heartbeat_tracker.get(node_id, 0.0)


def clear_heartbeat(node_id: str) -> None:
    """Clear heartbeat for a node (used during cleanup)."""
    with _heartbeat_lock:
        _heartbeat_tracker.pop(node_id, None)


@bp.route('/health/heartbeat', methods=['POST'])
def receive_heartbeat():
    """
    Ultra-lightweight heartbeat endpoint for fast failover detection.

    This endpoint is called every 5 seconds by ecp-agent, separate from
    the heavy metrics collection (30s). Updates both in-memory tracker
    AND health_node.last_seen for standby nodes that skip heavy metrics.

    Request body:
    {
        "node_id": "i-0123456789abcdef0",
        "timestamp": 1699999999.123
    }

    Response:
    {"status": "ok", "server_time": 1699999999.456}
    """
    try:
        data = request.json
        node_id = data.get('node_id')

        if not node_id:
            return jsonify({'status': 'error', 'message': 'node_id required'}), 400

        now = time.time()

        with _heartbeat_lock:
            _heartbeat_tracker[node_id] = now

        # Sync node IP if request source differs from stored IP
        # This runs on every heartbeat (5s) for fast IP change detection
        _sync_node_ip_from_request(node_id)

        # Update health_node.last_seen so standby nodes (which skip heavy metrics)
        # still show as "ready" for shard readiness checks
        try:
            db = get_db_connection()
            cur = db.conn.cursor()
            cur.execute("""
                INSERT INTO health_node (node_id, last_seen)
                VALUES (%s, CURRENT_TIMESTAMP)
                ON CONFLICT (node_id) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
            """, (node_id,))
            db.conn.commit()
            cur.close()
        except Exception as db_err:
            logger.debug(f"Heartbeat DB update failed (non-fatal): {db_err}")

        # Ultra-minimal response - just acknowledge receipt
        return jsonify({'status': 'ok', 'server_time': now}), 200

    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        return jsonify({'status': 'error'}), 500


def _get_request_source_ip() -> str:
    """Get real client IP from request, handling proxies."""
    # Check X-Forwarded-For header first (if behind reverse proxy)
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        # Take the first IP in the chain (original client)
        return forwarded.split(',')[0].strip()
    # Fall back to direct remote address
    return request.remote_addr or ''


def _sync_node_ip_from_request(node_id: str) -> None:
    """
    Sync node IP if request source differs from stored IP.

    This provides real-time IP detection - when a scrubber reports health,
    we learn its actual IP from the TCP connection.
    """
    request_ip = _get_request_source_ip()
    if not request_ip:
        return

    # Skip private/loopback IPs (local testing)
    try:
        ip_obj = ipaddress.ip_address(request_ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return
    except ValueError:
        return

    # Check if stored IP differs
    node = state_manager.nodes_db.get(node_id)
    if not node:
        return

    stored_ip = node.get('public_ip')
    if stored_ip != request_ip:
        logger.warning(
            f"Node {node_id} IP mismatch detected: "
            f"stored={stored_ip}, request_source={request_ip}"
        )
        # Update both DB and cache
        state_manager.update_node_ip(node_id, request_ip)


@bp.route('/health/node', methods=['POST'])
def receive_node_health():
    """
    Receive health report from ecp-agent on Scrubber

    Request body:
    {
        "node_id": "eu-central-1-a",
        "wireguard_interfaces": [
            {"interface": "wg-O1", "up": true, "handshake_age_seconds": 45},
            ...
        ],
        "system_metrics": {"cpu_percent": 12.5, ...},
        "origin_stats": {
            "10.20.30.40": {
                "conn_opened_total": 1234,
                "conn_closed_total": 1230,
                "packets_total": 567890,
                "ingress_syn_count": 500,
                "egress_synack_count": 495,
                "fin_count": 100,
                "rst_count": 5
            }
        },
        "source_ip_behavior": {
            "1.2.3.4": {
                "syn_count": 1000,
                "rst_count": 995,
                "packets_total": 1000,
                "burst_count": 50
            }
        },
        "timestamp": 1699999999.123
    }

    """
    try:
        data = request.json
        node_id = data['node_id']
        wg_interfaces = data.get('wireguard_interfaces', [])
        system_metrics = data.get('system_metrics', {})
        origin_stats = data.get('origin_stats', {})
        eip_security = data.get('eip_security', {})
        report_timestamp = data.get('timestamp', time.time())

        # Sync node IP if request source differs from stored IP
        # This provides real-time IP detection without AWS API calls
        _sync_node_ip_from_request(node_id)

        # Extract egress_billing data for AWS billing tracking
        # Billing data is now stored directly in origin_metrics table (volume_ingress, volume_egress)
        egress_billing = data.get('egress_billing', {})

        # Filter eip_security to only include actual origin private IPs
        # The XDP program tracks security stats for ALL destination IPs (including scrubber's
        # own management IP), but we only want to report/process stats for origin IPs.
        if eip_security:
            # Build set of valid origin private IPs from state
            valid_origin_private_ips = set()
            for origin in state_manager.origins_db.values():
                if origin.get('private_ip'):
                    valid_origin_private_ips.add(origin['private_ip'])
                if origin.get('private_ip_standby'):
                    valid_origin_private_ips.add(origin['private_ip_standby'])

            # Filter to only include origin IPs (exclude scrubber management IPs)
            original_count = len(eip_security)
            eip_security = {
                ip: stats for ip, stats in eip_security.items()
                if ip in valid_origin_private_ips
            }
            filtered_count = original_count - len(eip_security)
            if filtered_count > 0:
                logger.debug(
                    f"Filtered {filtered_count} non-origin IPs from eip_security "
                    f"(scrubber management IPs)"
                )

        logger.info(f"Health report from {node_id}: {len(wg_interfaces)} tunnels, "
                   f"CPU: {system_metrics.get('cpu_percent', 0)}%")

        if eip_security:
            logger.info(f"EIP security stats from {node_id}: {len(eip_security)} origins")

        if egress_billing:
            total_egress_bytes = sum(s.get('total_egress_bytes', 0) for s in egress_billing.values())
            logger.info(f"Egress billing from {node_id}: {len(egress_billing)} origins, "
                       f"total_egress={total_egress_bytes} bytes")

        # Process bandwidth capacity from scrubber (from bootstrap-discovered config)
        bandwidth_capacity = data.get('bandwidth_capacity', {})
        if bandwidth_capacity:
            state_manager.bandwidth_capacity[node_id] = bandwidth_capacity
            bandwidth_bps = bandwidth_capacity.get('bandwidth_bps', 0)
            logger.debug(f"Node {node_id} bandwidth capacity: {bandwidth_bps/1e9:.2f} Gbps "
                        f"({bandwidth_capacity.get('instance_type', 'unknown')})")

        # Process per-origin bandwidth usage from BPF maps
        bandwidth_usage = data.get('bandwidth_usage', {})
        if bandwidth_usage:
            for origin_ip, usage in bandwidth_usage.items():
                # Store in bandwidth usage cache (keyed by origin_ip)
                state_manager.bandwidth_usage[origin_ip] = usage

                # Check for over-quota condition and log warning
                bytes_exceeded = usage.get('bytes_exceeded', 0)
                packets_dropped = usage.get('packets_dropped', 0)

                if bytes_exceeded > 0:
                    quota_bps = usage.get('quota_bps', 0)
                    logger.warning(
                        f"Origin {origin_ip} OVER BANDWIDTH QUOTA: "
                        f"exceeded={bytes_exceeded} bytes, "
                        f"quota={quota_bps/1e6:.1f} Mbps, "
                        f"dropped={packets_dropped} packets"
                    )

        # Update health_node table
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            # Upsert node health
            cur.execute("""
                INSERT INTO health_node (
                    node_id, cpu_pct, memory_pct, bpf_loaded, last_seen,
                    conntrack_count, interface_rx_bytes, interface_tx_bytes
                )
                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, %s, %s, %s)
                ON CONFLICT (node_id) DO UPDATE SET
                    cpu_pct = EXCLUDED.cpu_pct,
                    memory_pct = EXCLUDED.memory_pct,
                    bpf_loaded = EXCLUDED.bpf_loaded,
                    last_seen = CURRENT_TIMESTAMP,
                    conntrack_count = EXCLUDED.conntrack_count,
                    interface_rx_bytes = EXCLUDED.interface_rx_bytes,
                    interface_tx_bytes = EXCLUDED.interface_tx_bytes
            """, (
                node_id,
                system_metrics.get('cpu_percent'),
                system_metrics.get('memory_percent'),
                system_metrics.get('bpf_loaded', False),
                system_metrics.get('conntrack_count'),
                system_metrics.get('interface_rx_bytes'),
                system_metrics.get('interface_tx_bytes')
            ))

            # Update health_origin for each WireGuard interface
            for wg in wg_interfaces:
                # Extract origin_id from interface name (wgO1 → O1)
                if_name = wg.get('interface', '')
                if if_name.startswith('wg'):
                    origin_id = if_name[2:]  # Remove 'wg' prefix

                    tunnel_ok = wg.get('up', False) and wg.get('handshake_age_seconds') is not None
                    handshake_age = wg.get('handshake_age_seconds', 999999)

                    # Update health_origin - only if origin exists (avoid FK constraint error)
                    # Use INSERT ... SELECT to skip if origin doesn't exist
                    cur.execute("""
                        INSERT INTO health_origin (origin_id, last_tcp_ok, last_probe_ts)
                        SELECT %s, %s, CURRENT_TIMESTAMP
                        WHERE EXISTS (SELECT 1 FROM origins WHERE origin_id = %s)
                        ON CONFLICT (origin_id) DO UPDATE SET
                            last_tcp_ok = EXCLUDED.last_tcp_ok,
                            last_probe_ts = CURRENT_TIMESTAMP
                    """, (origin_id, tunnel_ok and handshake_age < 180, origin_id))

            # Get current global bogon count for per-origin calculation
            # Per-origin bogon = current_global - origin.bogon_baseline
            # NOTE: ddos_metrics stores CUMULATIVE values from BPF map, so we need
            # the LATEST value (not SUM, which would massively inflate the count)
            cur.execute("""
                SELECT COALESCE(xdp_drop_bogon, 0) as total_bogon
                FROM ddos_metrics
                WHERE node_id = %s
                ORDER BY timestamp DESC
                LIMIT 1
            """, (node_id,))
            bogon_row = cur.fetchone()
            current_global_bogon = bogon_row['total_bogon'] if bogon_row else 0

            # Process origin_stats: Calculate rates from lifetime counter deltas
            for origin_ip, stats in origin_stats.items():
                # Calculate active connections (self-healing property)
                active_conns = stats.get('conn_opened_total', 0) - stats.get('conn_closed_total', 0)

                # Get origin info including last_bpf_values for rate calculation
                # Rate calculation must use raw BPF values (not lifetime values from origin_metrics)
                cur.execute("""
                    SELECT origin_id, private_ip, private_ip_standby, last_bpf_values,
                           bogon_baseline,
                           (SELECT timestamp FROM origin_metrics m
                            WHERE m.origin_id = o.origin_id
                            ORDER BY timestamp DESC LIMIT 1) as last_timestamp
                    FROM origins o
                    WHERE origin_ip = %s LIMIT 1
                """, (origin_ip,))
                priv_row = cur.fetchone()

                # Get billing data for this origin (keyed by origin_ip)
                # MUST be before rate calculation - bps uses volume deltas
                billing = egress_billing.get(origin_ip, {})
                volume_ingress = billing.get('to_origin_bytes', 0)
                volume_egress = billing.get('to_client_bytes', 0)

                # Calculate rates using last_bpf_values (raw BPF values, not lifetime)
                # This avoids negative rates when comparing raw BPF vs lifetime values
                pps = None
                cps = None
                bps = None
                syn_synack_ratio = None

                if priv_row and priv_row['last_bpf_values'] and priv_row['last_timestamp']:
                    last_bpf = priv_row['last_bpf_values']
                    dt = report_timestamp - priv_row['last_timestamp'].timestamp()
                    if dt > 5:  # Require at least 5 seconds between samples
                        # Calculate rates from raw BPF deltas (handles restarts correctly)
                        packets_delta = stats.get('packets_total', 0) - last_bpf.get('packets_total', 0)
                        conn_delta = stats.get('conn_opened_total', 0) - last_bpf.get('conn_opened_total', 0)

                        # Calculate volume deltas (bidirectional bandwidth)
                        volume_ingress_delta = volume_ingress - last_bpf.get('volume_ingress', 0)
                        volume_egress_delta = volume_egress - last_bpf.get('volume_egress', 0)

                        # On restart, current < last, so delta is negative - use current as delta
                        if packets_delta < 0:
                            packets_delta = stats.get('packets_total', 0)
                        if conn_delta < 0:
                            conn_delta = stats.get('conn_opened_total', 0)
                        if volume_ingress_delta < 0:
                            volume_ingress_delta = volume_ingress
                        if volume_egress_delta < 0:
                            volume_egress_delta = volume_egress

                        total_bytes_delta = volume_ingress_delta + volume_egress_delta

                        pps = int(packets_delta / dt)
                        cps = int(conn_delta / dt)
                        bps = int(total_bytes_delta / dt)

                # Calculate SYN/SYN-ACK ratio (ingress_syn / egress_synack)
                if stats.get('egress_synack_count', 0) > 0:
                    syn_synack_ratio = round(stats['ingress_syn_count'] / stats['egress_synack_count'], 2)
                elif stats.get('ingress_syn_count', 0) > 0:
                    syn_synack_ratio = 999.99  # Infinite ratio = likely SYN flood

                # Get security drops for this origin's private IP
                # Try active private_ip first, then standby (for failover scenarios)
                security = {}
                origin_id = None
                if priv_row:
                    origin_id = priv_row['origin_id']
                    if priv_row['private_ip']:
                        security = eip_security.get(priv_row['private_ip'], {})
                    if not security and priv_row['private_ip_standby']:
                        security = eip_security.get(priv_row['private_ip_standby'], {})

                # Calculate per-origin bogon: global_bogon - origin's baseline at deployment
                # This gives each origin their "share" of bogon drops since they were deployed
                bogon_baseline = priv_row.get('bogon_baseline', 0) or 0 if priv_row else 0
                origin_bogon = max(0, current_global_bogon - bogon_baseline)

                # Build current_bpf dict from all sources (origin stats, billing, security)
                # This contains raw BPF counter values that will be converted to lifetime values
                current_bpf = {
                    # From origin_stats (stats dict)
                    'conn_opened_total': stats.get('conn_opened_total', 0) or 0,
                    'conn_closed_total': stats.get('conn_closed_total', 0) or 0,
                    'packets_total': stats.get('packets_total', 0) or 0,
                    'ingress_syn_count': stats.get('ingress_syn_count', 0) or 0,
                    'egress_synack_count': stats.get('egress_synack_count', 0) or 0,
                    'fin_count': stats.get('fin_count', 0) or 0,
                    'rst_count': stats.get('rst_count', 0) or 0,
                    # From egress_billing (billing dict)
                    'volume_ingress': volume_ingress or 0,
                    'volume_egress': volume_egress or 0,
                    # From eip_security (security dict)
                    'drop_blacklist': security.get('drop_blacklist', 0) or 0,
                    'drop_temp_blacklist': security.get('drop_temp_blacklist', 0) or 0,
                    'drop_ratelimit': security.get('drop_ratelimit', 0) or 0,
                    'drop_quarantine': security.get('drop_quarantine', 0) or 0,
                    'drop_bogon': origin_bogon,  # Calculated from global - baseline
                    'drop_origin_blacklist': security.get('drop_origin_blacklist', 0) or 0,
                    'origin_whitelist_bypass': security.get('origin_whitelist_bypass', 0) or 0,
                    'origin_override_used': security.get('origin_override_used', 0) or 0,
                }

                # Calculate lifetime values (handles failover/restart counter resets)
                # Returns dict with lifetime values for all cumulative counter fields
                if not origin_id:
                    # Skip metrics for unknown origins - INSERT would fail with NULL origin_id
                    logger.warning(f"Skipping metrics for unknown origin_ip={origin_ip} (not in origins table)")
                    continue

                lifetime_values = calculate_lifetime_values(origin_id, current_bpf, cur)

                # Insert into origin_metrics table
                cur.execute("""
                    INSERT INTO origin_metrics (
                        origin_id, timestamp,
                        pps, cps, bps, active_connections, syn_synack_ratio,
                        conn_opened_total, conn_closed_total, packets_total,
                        ingress_syn_count, egress_synack_count, fin_count, rst_count,
                        cpu_pct, memory_pct,
                        volume_ingress, volume_egress,
                        drop_blacklist, drop_temp_blacklist, drop_ratelimit, drop_quarantine, drop_bogon,
                        drop_origin_blacklist, origin_whitelist_bypass, origin_override_used
                    )
                    VALUES (
                        (SELECT origin_id FROM origins WHERE origin_ip = %s LIMIT 1),
                        to_timestamp(%s),
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s,
                        %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s
                    )
                """, (
                    origin_ip, report_timestamp,
                    # Instantaneous values (unchanged) - calculated rates and current state
                    pps, cps, bps, active_conns, syn_synack_ratio,
                    # Lifetime values (from calculate_lifetime_values) - cumulative counters
                    lifetime_values.get('conn_opened_total', 0),
                    lifetime_values.get('conn_closed_total', 0),
                    lifetime_values.get('packets_total', 0),
                    lifetime_values.get('ingress_syn_count', 0),
                    lifetime_values.get('egress_synack_count', 0),
                    lifetime_values.get('fin_count', 0),
                    lifetime_values.get('rst_count', 0),
                    # Instantaneous values (unchanged) - system state
                    system_metrics.get('cpu_percent'),
                    system_metrics.get('memory_percent'),
                    # Lifetime values (from calculate_lifetime_values) - billing counters
                    lifetime_values.get('volume_ingress', 0),
                    lifetime_values.get('volume_egress', 0),
                    # Lifetime values (from calculate_lifetime_values) - security drop counters
                    lifetime_values.get('drop_blacklist', 0),
                    lifetime_values.get('drop_temp_blacklist', 0),
                    lifetime_values.get('drop_ratelimit', 0),
                    lifetime_values.get('drop_quarantine', 0),
                    origin_bogon,  # Directly calculated: global_bogon - origin.bogon_baseline
                    lifetime_values.get('drop_origin_blacklist', 0),
                    lifetime_values.get('origin_whitelist_bypass', 0),
                    lifetime_values.get('origin_override_used', 0)
                ))

                # Log if suspicious activity detected and enough samples collected
                ingress_syn = stats.get('ingress_syn_count', 0)
                if syn_synack_ratio and syn_synack_ratio > 10 and ingress_syn >= 100000:
                    logger.warning(
                        f"Potential SYN flood detected on {origin_ip}: "
                        f"SYN/SYN-ACK ratio = {syn_synack_ratio} (SYN count={ingress_syn})"
                    )
                if pps:
                    logger.debug(f"Origin {origin_ip} metrics: {pps} pps, {cps} cps, "
                               f"{active_conns} active conns")

            # Process source_ip_behavior for attack fingerprinting
            source_ip_behavior = data.get('source_ip_behavior', {})
            if source_ip_behavior:
                # Get origin-level syn/synack ratio for corroboration and origin_ip
                origin_ratio = None
                first_origin_ip = None
                if origin_stats:
                    first_origin_ip = next(iter(origin_stats.keys()), None)
                    first_origin_stats = next(iter(origin_stats.values()), None)
                    if first_origin_stats:
                        ingress_syn = first_origin_stats.get('ingress_syn_count', 0)
                        egress_synack = first_origin_stats.get('egress_synack_count', 0)
                        if egress_synack > 0:
                            origin_ratio = ingress_syn / egress_synack

                # Analyze each IP and store signatures
                for src_ip, behavior in source_ip_behavior.items():
                    if _should_skip_source_ip(src_ip):
                        continue
                    # Calculate attack signature
                    attack_score, attack_types = calculate_attack_signature(behavior, origin_ratio)

                    # Only store if attack detected (score > 0)
                    if attack_score > 0:
                        confidence = calculate_confidence(behavior)

                        # Store in ip_attack_signatures table
                        cur.execute("""
                            INSERT INTO ip_attack_signatures (
                                ip_address, origin_id, timestamp,
                                syn_count, rst_count, packets_total, burst_rate,
                                attack_score, attack_types, confidence
                            )
                            VALUES (
                                %s,
                                (SELECT origin_id FROM origins WHERE origin_ip = %s LIMIT 1),
                                to_timestamp(%s),
                                %s, %s, %s, %s, %s, %s, %s
                            )
                        """, (
                            src_ip, first_origin_ip, report_timestamp,
                            behavior.get('syn_count'), behavior.get('rst_count'),
                            behavior.get('packets_total'), behavior.get('burst_count'),
                            attack_score, attack_types, confidence
                        ))

            # Process tunnel discrepancies (context-sensitive validation from ecp-agent)
            tunnel_discrepancies = data.get('tunnel_discrepancies', {})
            missing_tunnels = tunnel_discrepancies.get('missing', [])
            orphaned_tunnels = tunnel_discrepancies.get('orphaned', [])

            if missing_tunnels:
                logger.critical(
                    f"MISSING TUNNELS on {node_id}: {missing_tunnels} "
                    f"(expected tunnels not found on scrubber - configuration failure or tunnel down)"
                )

                # Mark missing tunnels as unhealthy in health_origin
                for origin_id in missing_tunnels:
                    try:
                        cur.execute("""
                            INSERT INTO health_origin (origin_id, last_tcp_ok, last_probe_ts)
                            VALUES (%s, false, CURRENT_TIMESTAMP)
                            ON CONFLICT (origin_id) DO UPDATE SET
                                last_tcp_ok = false,
                                last_probe_ts = CURRENT_TIMESTAMP
                        """, (origin_id,))
                    except Exception as e:
                        # FK constraint violation if origin doesn't exist in origins table
                        logger.debug(f"Skipping missing tunnel {origin_id} (not in origins table): {e}")

                # Log to operations_journal for audit trail
                try:
                    cur.execute("""
                        INSERT INTO operations_journal (
                            op_type, origin_id, requested_by, status, error_text
                        )
                        VALUES ('TUNNEL_VALIDATION', %s, 'ecp-agent', 'error', %s)
                    """, (node_id, f"Missing tunnels: {', '.join(missing_tunnels)}"))
                except Exception as e:
                    logger.debug(f"Failed to log missing tunnels to operations_journal: {e}")

            if orphaned_tunnels:
                logger.warning(
                    f"ORPHANED TUNNELS on {node_id}: {orphaned_tunnels} "
                    f"(tunnels exist on scrubber but not in expected state - cleanup failure or manual config)"
                )

            conn.commit()
            return jsonify({'status': 'success'}), 200

        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to process health report: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/metrics', methods=['POST'])
def receive_ddos_metrics():
    """
    Receive DDoS metrics from ecp-agent (separate from health)

    Request body:
    {
        "node_id": "eu-central-1-a",
        "xdp_metrics": {
            "xdp_pass": 1000000,
            "xdp_whitelist_bypass": 100,
            "xdp_drop_blacklist": 50,
            "xdp_drop_invalid_ip": 10,
            "xdp_drop_invalid_tcp": 5,
            "xdp_drop_ratelimit": 200,
            "xdp_drop_temp_blacklist": 15
        },
        "timestamp": 1699999999.123
    }

    """
    try:
        data = request.json
        node_id = data['node_id']
        xdp_metrics = data.get('xdp_metrics', {})
        syncookie_metrics = data.get('syncookie_metrics', [])
        cookie_failures = data.get('cookie_failures', [])

        # Log significant events (drops)
        total_drops = (xdp_metrics.get('xdp_drop_blacklist', 0) +
                      xdp_metrics.get('xdp_drop_invalid_ip', 0) +
                      xdp_metrics.get('xdp_drop_invalid_tcp', 0) +
                      xdp_metrics.get('xdp_drop_ratelimit', 0) +
                      xdp_metrics.get('xdp_drop_bogon', 0))

        if total_drops > 0:
            logger.info(f"DDoS metrics from {node_id}: {total_drops} total drops "
                       f"(blacklist={xdp_metrics.get('xdp_drop_blacklist', 0)}, "
                       f"bogon={xdp_metrics.get('xdp_drop_bogon', 0)}, "
                       f"invalid_tcp={xdp_metrics.get('xdp_drop_invalid_tcp', 0)})")

        # Store in ddos_metrics table
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        try:
            # Skip metrics from unknown nodes (old scrubbers still reporting)
            cur.execute("SELECT 1 FROM nodes WHERE node_id = %s", (node_id,))
            if not cur.fetchone():
                logger.warning(f"Ignoring metrics from unknown node_id={node_id}")
                cur.close()
                return jsonify({'status': 'ignored', 'message': 'unknown node'}), 200

            cur.execute("""
                INSERT INTO ddos_metrics (
                    node_id, timestamp,
                    xdp_pass, xdp_whitelist_bypass, xdp_drop_blacklist,
                    xdp_drop_invalid_ip, xdp_drop_invalid_tcp, xdp_drop_ratelimit,
                    xdp_drop_temp_blacklist, xdp_drop_bogon
                ) VALUES (%s, to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                node_id,
                data.get('timestamp', time.time()),
                xdp_metrics.get('xdp_pass', 0),
                xdp_metrics.get('xdp_whitelist_bypass', 0),
                xdp_metrics.get('xdp_drop_blacklist', 0),
                xdp_metrics.get('xdp_drop_invalid_ip', 0),
                xdp_metrics.get('xdp_drop_invalid_tcp', 0),
                xdp_metrics.get('xdp_drop_ratelimit', 0),
                xdp_metrics.get('xdp_drop_temp_blacklist', 0),
                xdp_metrics.get('xdp_drop_bogon', 0)
            ))

            if syncookie_metrics:
                records = [
                    (
                        node_id,
                        (entry.get('vip_ip') or '').strip(),
                        datetime.fromtimestamp(
                            data.get('timestamp', time.time()),
                            tz=timezone.utc
                        ),
                        entry.get('incoming_syn', 0),
                        entry.get('cookie_validates', 0),
                        entry.get('cookie_rejects', 0),
                        entry.get('handshake_completes', 0),
                        entry.get('challenged_clients', 0),
                        entry.get('pending_cookies', 0),
                        entry.get('allow_list_size', 0),
                        entry.get('syn_retransmits', 0),
                        entry.get('false_positives', 0),
                        entry.get('outgoing_synack', 0),
                        entry.get('last_update_ts', 0),
                        entry.get('cookie_mode', 0)
                    )
                    for entry in syncookie_metrics
                    if entry.get('vip_ip')
                ]
                if records:
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO syncookie_metrics (
                            node_id, vip_ip, timestamp,
                            incoming_syn, cookie_validates, cookie_rejects,
                            handshake_completes, challenged_clients,
                            pending_cookies, allow_list_size,
                            syn_retransmits, false_positives,
                            outgoing_synack, last_update_ts, cookie_mode
                        ) VALUES %s
                        """,
                        records
                    )
                    unique_vips = sorted({rec[1] for rec in records})
                    logger.info(
                        "Stored %s syncookie_metrics rows for VIPs=%s",
                        len(records),
                        unique_vips
                    )

            if cookie_failures:
                for entry in cookie_failures:
                    vip_ip = entry.get('vip_ip')
                    src_ip = entry.get('src_ip')
                    if not vip_ip or not src_ip:
                        continue

                    cur.execute("""
                        INSERT INTO source_state (
                            src_ip, vip_ip, cookie_failures, cookie_successes, last_seen
                        ) VALUES (%s, %s, %s, %s, NOW())
                        ON CONFLICT (src_ip, vip_ip) DO UPDATE SET
                            cookie_failures = EXCLUDED.cookie_failures,
                            cookie_successes = EXCLUDED.cookie_successes,
                            last_seen = NOW()
                    """, (
                        src_ip,
                        vip_ip,
                        entry.get('failure_count', 0),
                        entry.get('success_count', 0)
                    ))

            conn.commit()
            return jsonify({'status': 'success'}), 200

        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to process metrics: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/ratelimit/stats', methods=['POST'])
def receive_ratelimit_stats():
    """
    Receive rate limit statistics from ecp-agent

    Request body:
    {
        "node_id": "eu-central-1-a",
        "top_blocked": [
            {"ip": "1.2.3.4", "blocked_count": 1000},
            {"ip": "5.6.7.8", "blocked_count": 500}
        ]
    }

    """
    try:
        data = request.json
        node_id = data['node_id']
        top_blocked = data.get('top_blocked', [])

        if not top_blocked:
            return jsonify({'status': 'success', 'inserted': 0}), 200

        # Store in ratelimit_stats table
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()

        try:
            for entry in top_blocked:
                cur.execute("""
                    INSERT INTO ratelimit_stats (node_id, ip_address, blocked_count)
                    VALUES (%s, %s, %s)
                """, (node_id, entry['ip'], entry['blocked_count']))

            conn.commit()
            logger.debug(f"Stored {len(top_blocked)} rate limit stats from {node_id}")
            return jsonify({'status': 'success', 'inserted': len(top_blocked)}), 200

        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to process rate limit stats: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/layer4/stats', methods=['POST'])
def receive_layer4_stats():
    """
    Receive Layer 4 (quarantine/bypass) statistics from ecp-agent

    Request body:
    {
        "node_id": "eu-central-1-a",
        "quarantine": {
            "count": 5,
            "entries": [
                {"src_ip": 16909060, "vip_ip": 673059850, "score": 50}
            ]
        },
        "bypass": {
            "count": 10,
            "entries": []
        }
    }

    """
    try:
        data = request.json
        node_id = data['node_id']
        quarantine_stats = data.get('quarantine', {})
        bypass_stats = data.get('bypass', {})

        # Log significant events
        q_count = quarantine_stats.get('count', 0)
        b_count = bypass_stats.get('count', 0)

        if q_count > 0 or b_count > 0:
            logger.info(f"Layer 4 stats from {node_id}: {q_count} quarantined, {b_count} bypassed")

        # Store quarantine entries in source_state
        db = get_db_connection()
        for entry in quarantine_stats.get('entries', []):
            try:
                import socket
                import struct
                src_ip = socket.inet_ntoa(struct.pack('<I', entry['src_ip']))
                vip_ip = socket.inet_ntoa(struct.pack('<I', entry['vip_ip']))

                conn = db.conn
                cur = conn.cursor()
                try:
                    cur.execute("""
                        INSERT INTO source_state (src_ip, vip_ip, score, last_seen)
                        VALUES (%s, %s, %s, NOW())
                        ON CONFLICT (src_ip, vip_ip) DO UPDATE SET
                            last_seen = NOW()
                    """, (src_ip, vip_ip, entry.get('score', 0)))
                    conn.commit()
                finally:
                    cur.close()
            except Exception as e:
                logger.error(f"Failed to process quarantine entry: {e}")
                pass

        return jsonify({'status': 'success'}), 200

    except Exception as e:
        logger.error(f"Failed to process layer4 stats: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.route('/health', methods=['GET'])
def get_system_health():
    """
    Get system-wide health status (multi-region)

    Returns:
    {
        "status": "healthy|degraded|critical",
        "shards": {
            "eu-central-1": {
                "active_node": "i-xxx",
                "standby_node": "i-yyy",
                "status": "healthy",
                "origins_count": 2
            }
        },
        "total_origins": 5,
        "total_nodes": 4,
        "timestamp": 1699999999.123
    }

    Multi-region: Returns per-shard health breakdown.
    """
    shards_health = {}
    overall_status = 'healthy'

    for shard_id, shard in state_manager.shards_db.items():
        shard_state = state_manager.get_shard_state(shard_id)
        active_node = state_manager.get_active_node(shard_id)
        standby_node = state_manager.get_standby_node(shard_id)
        origins = state_manager.get_origins_for_shard(shard_id)

        # Determine shard status
        shard_status = 'healthy'
        if not active_node:
            shard_status = 'critical'
            overall_status = 'critical'
        elif not standby_node:
            shard_status = 'degraded'
            if overall_status != 'critical':
                overall_status = 'degraded'

        shards_health[shard_id] = {
            'region': shard.get('region'),
            'status': shard_status,
            'active_node': active_node.get('node_id') if active_node else None,
            'standby_node': standby_node.get('node_id') if standby_node else None,
            'origins_count': len(origins)
        }

    return jsonify({
        'status': overall_status,
        'shards': shards_health,
        'total_origins': len(state_manager.origins_db),
        'total_nodes': len(state_manager.nodes_db),
        'timestamp': time.time()
    })


@bp.route('/health/shards/<shard_id>', methods=['GET'])
def get_shard_health(shard_id: str):
    """
    Get health status for a specific shard

    Returns:
    {
        "shard_id": "eu-central-1",
        "region": "eu-central-1",
        "status": "healthy",
        "active_node": {...},
        "standby_node": {...},
        "origins": [...],
        "timestamp": 1699999999.123
    }

    Multi-region: Returns detailed health for one shard.
    """
    shard = state_manager.get_shard(shard_id)
    if not shard:
        return jsonify({'status': 'error', 'message': f'Shard {shard_id} not found'}), 404

    shard_state = state_manager.get_shard_state(shard_id)
    active_node = state_manager.get_active_node(shard_id)
    standby_node = state_manager.get_standby_node(shard_id)
    origins = state_manager.get_origins_for_shard(shard_id)

    # Get node health from database
    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    node_health = {}
    for node in [active_node, standby_node]:
        if not node:
            continue
        node_id = node.get('node_id')
        cur.execute("""
            SELECT cpu_pct, memory_pct, bpf_loaded, last_seen
            FROM health_node
            WHERE node_id = %s
        """, (node_id,))
        health = cur.fetchone()
        if health:
            node_health[node_id] = {
                'cpu_pct': health['cpu_pct'],
                'memory_pct': health['memory_pct'],
                'bpf_loaded': health['bpf_loaded'],
                'last_seen': health['last_seen'].isoformat() if health['last_seen'] else None
            }

    cur.close()

    # Determine status
    status = 'healthy'
    if not active_node:
        status = 'critical'
    elif not standby_node:
        status = 'degraded'

    return jsonify({
        'shard_id': shard_id,
        'region': shard.get('region'),
        'status': status,
        'active_node': {
            'node_id': active_node.get('node_id'),
            'public_ip': active_node.get('public_ip'),
            'instance_name': active_node.get('instance_name'),
            'health': node_health.get(active_node.get('node_id'))
        } if active_node else None,
        'standby_node': {
            'node_id': standby_node.get('node_id'),
            'public_ip': standby_node.get('public_ip'),
            'instance_name': standby_node.get('instance_name'),
            'health': node_health.get(standby_node.get('node_id'))
        } if standby_node else None,
        'origins': [{'origin_id': o['origin_id'], 'eip': o.get('eip')} for o in origins],
        'timestamp': time.time()
    })
