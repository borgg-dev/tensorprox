#!/usr/bin/env python3

"""
PHASE 5: Automated Mitigation Engine
Applies layered response based on attack signatures and severity
"""

import json
import logging
import struct
import threading
import time
import ipaddress
import psycopg2
import subprocess
from shared.config import get_settings
from shared.database import get_db_connection as get_db, get_dict_cursor
from shared.utils.bpf_helpers import get_map_path, ip_to_hex, update_bpf_map, lookup_bpf_map
from miner_control_plane.services.scrubber_utils import get_scrubber_nodes
from miner_control_plane.services.state_manager import state_manager

logger = logging.getLogger('emn-auto-mitigation')

# SSH key path from tp.env
ssh_key_path = get_settings().ssh_key_path

RATELIMIT_STRUCT = struct.Struct('<QQI B 3x I B 3x')  # Matches struct ratelimit_state in eBPF
MAX_U32 = 0xFFFFFFFF
MIN_SYN_THRESHOLD = 100000
TESTING_MODE = False
TESTING_MODE_LOCK = threading.Lock()


def set_testing_mode(enabled: bool) -> bool:
    """Enable/disable mitigation testing mode at runtime."""
    global TESTING_MODE
    enabled = bool(enabled)
    with TESTING_MODE_LOCK:
        if TESTING_MODE == enabled:
            logger.info(
                "Automated mitigation testing mode already %s",
                "ENABLED" if TESTING_MODE else "disabled"
            )
            return TESTING_MODE
        TESTING_MODE = enabled

    logger.warning(
        "Automated mitigation testing mode %s",
        "ENABLED" if TESTING_MODE else "disabled"
    )
    return TESTING_MODE


def is_testing_mode() -> bool:
    """Return current mitigation testing mode flag."""
    with TESTING_MODE_LOCK:
        return TESTING_MODE

def ssh_exec(host, command):
    """Execute command via SSH"""
    try:
        result = subprocess.run(
            ['ssh', '-i', ssh_key_path, '-o', 'StrictHostKeyChecking=no',
             '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR',
             f'ubuntu@{host}', command],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        logger.error(f"SSH exec failed to {host}: {e}")
        return -1, '', str(e)


def _update_map_on_nodes(nodes, map_name, key_hex, value_hex, context_msg, verify=True):
    """Utility to push BPF map updates across nodes with logging."""
    map_path = get_map_path(map_name)
    updated = []
    for node in nodes:
        host_ip = node.get('host_ip')
        if not host_ip:
            continue
        provider = node.get('provider', 'aws')
        success, error = update_bpf_map(
            host=host_ip,
            map_path=map_path,
            key_hex=key_hex,
            value_hex=value_hex,
            ssh_key_path=ssh_key_path,
            provider=provider,
            verify=verify
        )
        if success:
            updated.append(node['node_id'])
            logger.info("%s on %s", context_msg, node['node_id'])
        else:
            logger.error("%s failed on %s: %s", context_msg, node['node_id'], error)
    return updated

def apply_temp_blacklist(ip_address, origin_id, attack_score, attack_types, duration_seconds=3600):
    """
    PHASE 4 Layer 2: Apply temporary blacklist to BPF map and database

    Args:
        ip_address: IP to blacklist
        origin_id: Origin ID (or None for global)
        attack_score: Attack score
        attack_types: List of attack types
        duration_seconds: Blacklist duration (default 1 hour)
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor()

        # Calculate expiration
        expires_at = time.time() + duration_seconds
        expires_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(expires_at))

        # Insert into database
        cur.execute("""
            INSERT INTO temp_blacklist (ip_address, origin_id, attack_score, attack_types, reason, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s::timestamptz)
            ON CONFLICT (ip_address) DO UPDATE SET
                attack_score = EXCLUDED.attack_score,
                attack_types = EXCLUDED.attack_types,
                expires_at = EXCLUDED.expires_at
        """, (ip_address, origin_id, attack_score, attack_types,
              f'Auto-mitigation: {", ".join(attack_types)}', expires_ts))

        # Log to mitigation_actions
        cur.execute("""
            INSERT INTO mitigation_actions (
                ip_address, origin_id, action_type, severity, attack_score,
                duration_seconds, expires_at, auto_triggered
            )
            VALUES (%s, %s, 'temp_blacklist', 'medium', %s, %s, %s::timestamptz, true)
        """, (ip_address, origin_id, attack_score, duration_seconds, expires_ts))

        conn.commit()
        cur.close()

    except Exception as e:
        logger.error(f"Failed to apply temp blacklist for {ip_address}: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    # Push to BPF map on all scrubbers (outside DB block)
    origin = state_manager.get_origin(origin_id)
    if origin:
        push_temp_blacklist_to_bpf(ip_address, duration_seconds, origin_id, origin['eip'])
    else:
        logger.error(f"Cannot apply temp blacklist: origin {origin_id} not found")
        return False

    logger.info(f"Temp blacklist applied: {ip_address} (score={attack_score}, duration={duration_seconds}s)")
    return True

def apply_ratelimit_penalty(ip_address, penalty_level, duration_seconds=300):
    """
    PHASE 4 Layer 1: Apply per-IP ratelimit penalty

    Args:
        ip_address: IP to penalize
        penalty_level: 1=soft(50%), 2=medium(20%), 3=hard(5%)
        duration_seconds: Penalty duration (default 5 minutes)
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor()

        expires_at = time.time() + duration_seconds
        expires_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(expires_at))

        # Log action
        severity_map = {1: 'soft', 2: 'medium', 3: 'hard'}
        severity = severity_map.get(penalty_level, 'soft')

        cur.execute("""
            INSERT INTO mitigation_actions (
                ip_address, action_type, severity, duration_seconds, expires_at, auto_triggered
            )
            VALUES (%s, 'ratelimit_penalty', %s, %s, %s::timestamptz, true)
        """, (ip_address, severity, duration_seconds, expires_ts))

        conn.commit()
        cur.close()

    except Exception as e:
        logger.error(f"Failed to apply ratelimit penalty for {ip_address}: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

    if not push_ratelimit_penalty_to_bpf(ip_address, penalty_level, duration_seconds):
        logger.warning(
            f"Failed to push ratelimit penalty to scrubbers for {ip_address}"
        )

    logger.info(f"Ratelimit penalty applied: {ip_address} level={penalty_level} duration={duration_seconds}s")
    return True

def add_to_permanent_blacklist(ip_address, attack_types, attack_score):
    """
    PHASE 4 Layer 3: Add IP to permanent blacklist

    Args:
        ip_address: IP to blacklist permanently
        attack_types: List of attack types
        attack_score: Attack score
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = conn.cursor()

        network = ipaddress.ip_network(f"{ip_address}/32", strict=False)

        # Add to blacklist_entries
        cur.execute("""
            INSERT INTO blacklist_entries (network, source, reputation_score, added_at)
            VALUES (%s, 'auto_mitigation', %s, NOW())
            ON CONFLICT (network) DO UPDATE SET
                reputation_score = EXCLUDED.reputation_score,
                added_at = NOW()
        """, (str(network), min(attack_score, 100)))

        # Log action
        cur.execute("""
            INSERT INTO mitigation_actions (
                ip_address, action_type, severity, attack_score, auto_triggered
            )
            VALUES (%s, 'perm_blacklist', 'hard', %s, true)
        """, (ip_address, attack_score))

        conn.commit()
        cur.close()

        logger.warning(f"Permanent blacklist applied: {ip_address} (score={attack_score}, types={attack_types})")
        return True

    except Exception as e:
        logger.error(f"Failed to add {ip_address} to permanent blacklist: {e}")
        return False
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def set_origin_challenge_via_bpf(origin_ip, challenge_level):
    """
    PHASE 4 Layer 4: Set per-origin challenge level via BPF

    Args:
        origin_ip: Origin IP address
        challenge_level: Challenge level 0-4
    """
    try:
        nodes = get_scrubber_nodes()
        if not nodes:
            logger.error("No scrubbers available for origin challenge update")
            return False

        # Convert IP to hex for bpftool
        import ipaddress
        ip_int = int(ipaddress.IPv4Address(origin_ip))
        ip_hex = ' '.join([f'{(ip_int >> (i*8)) & 0xFF:02x}' for i in range(4)])

        # Pack challenge level as little-endian 32-bit
        level_hex = f"{challenge_level:02x} 00 00 00"

        updated = _update_map_on_nodes(
            nodes,
            'origin_challenge',
            ip_hex,
            level_hex,
            f"Origin challenge level set to {challenge_level} for {origin_ip}"
        )

        return len(updated) > 0

    except Exception as e:
        logger.error(f"Failed to set origin challenge for {origin_ip}: {e}")
        return False

def set_global_challenge_via_bpf(challenge_level):
    """
    PHASE 4 Layer 5: Set global challenge level via BPF

    Args:
        challenge_level: Challenge level 0-4
    """
    try:
        nodes = get_scrubber_nodes()
        if not nodes:
            logger.error("No scrubbers available for global challenge update")
            return False

        # Pack level as little-endian 32-bit integer
        level_hex = f"{challenge_level:02x} 00 00 00"

        updated = _update_map_on_nodes(
            nodes,
            'challenge_level',
            "00 00 00 00",
            level_hex,
            f"Global challenge level set to {challenge_level}"
        )

        return len(updated) > 0

    except Exception as e:
        logger.error(f"Failed to set global challenge level: {e}")
        return False

def push_temp_blacklist_to_bpf(ip_address: str, duration_seconds: int, origin_id: str, eip: str):
    """
    Push temp_blacklist entry to BPF map on all scrubbers.

    CHANGED: Now uses compound key {src_ip, dst_eip} for per-origin blocking.

    Args:
        ip_address: IP to blacklist
        duration_seconds: Duration in seconds
        origin_id: Origin ID (required - no more global temp blacklist)
        eip: Origin's EIP (destination IP for compound key)
    """
    if not origin_id or not eip:
        logger.error("push_temp_blacklist_to_bpf requires origin_id and eip")
        return False

    try:
        nodes = get_scrubber_nodes()
        if not nodes:
            logger.error("No scrubbers available for temp blacklist push")
            return False

        # Build compound key: {src_ip (4 bytes), dst_eip (4 bytes)}
        key_hex = f"{ip_to_hex(ip_address)} {ip_to_hex(eip)}"

        # Calculate expiration timestamp
        expires_at = int(time.time()) + duration_seconds

        # Build value: origin_rep_value struct
        # {active: u8, reason_code: u8, cidr_prefix: u16, expires_at: u32}
        value_hex = (
            "01 "  # active = 1
            "01 "  # reason_code = 1 (auto-mitigation)
            "20 00 "  # cidr_prefix = 32 (little-endian)
            f"{(expires_at >> 0) & 0xFF:02x} "
            f"{(expires_at >> 8) & 0xFF:02x} "
            f"{(expires_at >> 16) & 0xFF:02x} "
            f"{(expires_at >> 24) & 0xFF:02x}"
        )

        updated = _update_map_on_nodes(
            nodes,
            'temp_blacklist',
            key_hex,
            value_hex,
            f"Temp blacklist pushed for {ip_address} targeting {eip} (origin={origin_id}, expires in {duration_seconds}s)"
        )

        return len(updated) > 0

    except Exception as e:
        logger.error(f"Failed to push temp blacklist for {ip_address}: {e}")
        return False

def push_ratelimit_penalty_to_bpf(ip_address, penalty_level, duration_seconds):
    """
    Push per-IP ratelimit penalty to ratelimit_map on all scrubbers.

    Args:
        ip_address: IP to penalize
        penalty_level: 1=soft, 2=medium, 3=hard
        duration_seconds: Penalty duration in seconds
    """
    try:
        nodes = get_scrubber_nodes()
        if not nodes:
            logger.error("No scrubbers available for ratelimit penalty push")
            return False

        key_hex = ip_to_hex(ip_address)
        map_path = get_map_path('ratelimit')
        penalty_expires = int(time.time()) + duration_seconds
        penalty_expires = max(0, min(penalty_expires, MAX_U32))
        default_last_refill_ns = int(time.time() * 1_000_000_000)

        updated = []
        for node in nodes:
            host_ip = node.get('host_ip')
            if not host_ip:
                continue

            tokens = 0
            last_refill_ns = default_last_refill_ns
            blocked_count = 0
            pad = 0

            success_lookup, payload, error_lookup = lookup_bpf_map(
                host_ip,
                map_path,
                key_hex,
                ssh_key_path,
                provider=node.get('provider', 'aws')
            )
            if success_lookup and payload:
                try:
                    formatted = payload.get('formatted', {})
                    value = formatted.get('value', {})
                    tokens = int(value.get('tokens', tokens))
                    last_refill_ns = int(value.get('last_refill_ns', last_refill_ns))
                    blocked_count = int(value.get('blocked_count', blocked_count))
                    pad = int(value.get('pad', pad))
                except Exception as exc:
                    logger.warning("Failed to parse ratelimit entry on %s: %s", node['node_id'], exc)
            elif error_lookup and 'key not found' not in (error_lookup or '').lower():
                logger.error("Failed to lookup ratelimit_map on %s: %s", node['node_id'], error_lookup)

            value_bytes = RATELIMIT_STRUCT.pack(
                tokens,
                last_refill_ns,
                blocked_count,
                penalty_level,
                penalty_expires,
                pad
            )
            value_hex = ' '.join(f'{b:02x}' for b in value_bytes)

            success_update, error_update = update_bpf_map(
                host=host_ip,
                map_path=map_path,
                key_hex=key_hex,
                value_hex=value_hex,
                ssh_key_path=ssh_key_path,
                provider=node.get('provider', 'aws')
            )
            if success_update:
                updated.append(node['node_id'])
                logger.info(
                    "Ratelimit penalty level %s applied to %s on %s (expires in %ss)",
                    penalty_level,
                    ip_address,
                    node['node_id'],
                    duration_seconds
                )
            else:
                logger.error("Failed to update ratelimit_map on %s: %s", node['node_id'], error_update)

        if not updated:
            logger.error("Failed to push ratelimit penalty for %s to any scrubber", ip_address)
            return False

        return True

    except Exception as e:
        logger.error(f"Failed to push ratelimit penalty for {ip_address}: {e}")
        return False

def get_min_score_for_origin(origin_id: str) -> int:
    """
    Get minimum attack score threshold based on current challenge level (Layer 7 coordination)

    Logic:
    - If challenge_level >= 3: Only blacklist high-confidence IPs (score >= 80)
    - If challenge_level >= 2: Moderate threshold (score >= 60)
    - Otherwise: Normal threshold (score >= 40)

    This prevents conflict between challenge-level mitigation and per-IP actions.
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = get_dict_cursor(conn)
        cur.execute("""
            SELECT current_challenge_level
            FROM anomaly_detection_state
            WHERE origin_id = %s
        """, (origin_id,))
        row = cur.fetchone()
        cur.close()

        if row:
            challenge_level = row['current_challenge_level']
            if challenge_level >= 3:
                return 80  # STRICT - Only high-confidence IPs
            elif challenge_level >= 2:
                return 60  # ACTIVE - Moderate threshold
            else:
                return 40  # NORMAL - Standard threshold
        else:
            return 40  # Default if no state found

    except Exception as e:
        logger.error(f"Failed to get challenge level for {origin_id}: {e}")
        return 40  # Safe default
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def automated_mitigation_loop():
    """
    PHASE 8: Complete decision matrix with ratio-based gating and escalation
    LAYER 7 Enhancement: Coordinates with anomaly detector to avoid conflicts
    Runs every 60 seconds
    """
    db = None
    try:
        db = get_db()
        conn = db.conn
        cur = get_dict_cursor(conn)

        # STEP 1: RATIO-BASED GATING - Check origin SYN/SYN-ACK ratios
        cur.execute("""
            SELECT origin_id, syn_synack_ratio, ingress_syn_count, egress_synack_count
            FROM origin_metrics
            WHERE timestamp > NOW() - INTERVAL '2 minutes'
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        origin_metrics = cur.fetchall()

        origins_under_attack = {}
        for metric in origin_metrics:
            origin_id = metric['origin_id']
            ratio = float(metric['syn_synack_ratio']) if metric['syn_synack_ratio'] else 0
            ingress_syn = metric.get('ingress_syn_count') or 0

            if ingress_syn < MIN_SYN_THRESHOLD:
                if TESTING_MODE:
                    logger.debug(
                        "Origin %s: ratio=%.2f but SYN count=%s < %s (testing mode - continuing)",
                        origin_id,
                        ratio,
                        ingress_syn,
                        MIN_SYN_THRESHOLD
                    )
                else:
                    logger.debug(
                        "Origin %s: ratio=%.2f but SYN count=%s < %s, skipping",
                        origin_id,
                        ratio,
                        ingress_syn,
                        MIN_SYN_THRESHOLD
                    )
                    continue

            # PHASE 8 Decision Tree Step 1: Ratio-based gating
            if ratio < 5:
                if TESTING_MODE:
                    logger.debug(
                        "Origin %s: ratio=%.2f below threshold, but testing mode - continuing",
                        origin_id,
                        ratio
                    )
                    origins_under_attack[origin_id] = {'ratio': ratio, 'status': 'testing'}
                else:
                    # Normal traffic - no action needed
                    logger.debug(f"Origin {origin_id}: Normal ratio={ratio:.2f}")
                    continue
            elif ratio < 10:
                # Suspicious - log but don't mitigate yet
                logger.info(f"Origin {origin_id}: Suspicious ratio={ratio:.2f}")
                origins_under_attack[origin_id] = {'ratio': ratio, 'status': 'suspicious'}
            else:
                # Attack detected - proceed with mitigation
                logger.warning(f"Origin {origin_id}: ATTACK DETECTED ratio={ratio:.2f}")
                origins_under_attack[origin_id] = {'ratio': ratio, 'status': 'attack'}

        if not origins_under_attack:
            logger.debug("No attacks detected based on SYN/SYN-ACK ratios")
            cur.close()
            return

        # STEP 2: GET ATTACKING IPs FROM SIGNATURES
        cur.execute("""
            WITH flattened AS (
                SELECT ip_address, origin_id, attack_score, unnest(attack_types) as attack_type, confidence
                FROM ip_attack_signatures
                WHERE timestamp > NOW() - INTERVAL '2 minutes' AND attack_score >= 20
            )
            SELECT ip_address,
                   origin_id,
                   MAX(attack_score) as max_score,
                   array_agg(DISTINCT attack_type) as all_types,
                   AVG(confidence) as avg_confidence,
                   COUNT(*) as occurrence_count
            FROM flattened
            GROUP BY ip_address, origin_id
            ORDER BY MAX(attack_score) DESC
        """)
        attackers = cur.fetchall()

        logger.info(f"Automated mitigation: Processing {len(attackers)} attacking IPs across {len(origins_under_attack)} origins")

        # STEP 3: APPLY PER-IP LAYERED MITIGATION
        # LAYER 7 Enhancement: Adjust thresholds based on challenge level
        attacker_counts_per_origin = {}
        origin_min_scores = {}  # Cache min scores per origin

        for attacker in attackers:
            ip = str(attacker['ip_address'])
            origin_id = attacker['origin_id']
            score = attacker['max_score']
            types = attacker['all_types'] or []

            # Track attacker count per origin
            if origin_id not in attacker_counts_per_origin:
                attacker_counts_per_origin[origin_id] = 0
            attacker_counts_per_origin[origin_id] += 1

            # Check if already blacklisted
            cur.execute("SELECT 1 FROM temp_blacklist WHERE ip_address = %s", (ip,))
            if cur.fetchone():
                continue

            # LAYER 7 Coordination: Get adaptive threshold based on challenge level
            if origin_id not in origin_min_scores:
                origin_min_scores[origin_id] = get_min_score_for_origin(origin_id)

            min_score = origin_min_scores[origin_id]

            # Skip if score below adaptive threshold
            if score < min_score:
                logger.debug(f"Skipping {ip} (score={score} < min_threshold={min_score} for {origin_id})")
                continue

            # Layer 3: Permanent blacklist (score >= 70)
            if score >= 70:
                add_to_permanent_blacklist(ip, types, score)
            # Layer 2: Temporary blacklist (score 40-70, adjusted by min_score)
            elif score >= max(40, min_score):
                apply_temp_blacklist(ip, origin_id, score, types, duration_seconds=3600)
            # Layer 1: Soft ratelimit (score 20-40, adjusted by min_score)
            elif score >= max(20, min_score):
                penalty_level = 1 if score < 30 else 2
                apply_ratelimit_penalty(ip, penalty_level, duration_seconds=300)

        # STEP 4: ATTACKER COUNT-BASED ORIGIN ESCALATION
        for origin_id, count in attacker_counts_per_origin.items():
            logger.info(f"Origin {origin_id}: {count} unique attacking IPs")

            # Get origin IP from database for BPF mapping
            cur.execute("SELECT origin_ip FROM origins WHERE origin_id = %s", (origin_id,))
            origin_row = cur.fetchone()
            if not origin_row:
                continue
            origin_ip = origin_row['origin_ip']

            if count < 10:
                # Few attackers - per-IP actions only (already done above)
                logger.info(f"Origin {origin_id}: Using per-IP mitigation only ({count} attackers)")
            elif count <= 100:
                # Moderate distributed attack - escalate to ACTIVE (level 2)
                logger.warning(f"Origin {origin_id}: Distributed attack detected, escalating to ACTIVE level")
                set_origin_challenge_via_bpf(origin_ip, 2)
            else:
                # Heavy distributed attack - escalate to STRICT (level 3)
                logger.error(f"Origin {origin_id}: HEAVY distributed attack, escalating to STRICT level")
                set_origin_challenge_via_bpf(origin_ip, 3)

        # STEP 5: MULTI-ORIGIN GLOBAL ESCALATION
        origins_with_significant_attacks = len([o for o, c in attacker_counts_per_origin.items() if c >= 10])

        if origins_with_significant_attacks > 3:
            # Platform-wide attack - escalate global challenge
            logger.critical(f"PLATFORM-WIDE ATTACK: {origins_with_significant_attacks} origins under attack - EMERGENCY level")
            set_global_challenge_via_bpf(4)  # EMERGENCY
        elif origins_with_significant_attacks > 0:
            # Some origins under attack but not platform-wide - use origin-specific response
            logger.info(f"Origin-specific mitigation active for {origins_with_significant_attacks} origins")

        cur.close()

    except Exception as e:
        logger.error(f"Automated mitigation loop failed: {e}")
    finally:
        if db:
            try:
                db.close()
            except Exception:
                pass

def start_automated_mitigation_thread(interval_seconds=60):
    """
    Start PHASE 5 automated mitigation background thread

    Args:
        interval_seconds: Seconds between mitigation cycles (default: 60)
    """
    # Ensure mitigation starts in production-safe mode; tests can toggle via API later.
    set_testing_mode(False)

    def mitigation_loop():
        automated_mitigation_loop()
        # Schedule next run
        threading.Timer(interval_seconds, mitigation_loop).start()

    # Run first cycle after 60 seconds (let system stabilize)
    threading.Timer(60, mitigation_loop).start()

    logger.info(f"Automated mitigation thread started: analyzing attacks every {interval_seconds}s")
