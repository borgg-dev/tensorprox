"""Reputation API Blueprint

Whitelist and blacklist management (Layer 1 reputation filtering).
"""
import ipaddress
import struct
import psycopg2.extras
from flask import Blueprint, request, jsonify
from shared.database import get_db_connection
from shared.utils.ssh import ssh_exec
from shared.utils.logging import get_logger, OperationContext
from shared.utils.bpf_helpers import update_bpf_map, delete_bpf_map, ip_to_hex, cidr_to_lpm_key, get_map_path
from shared.config import get_settings
from miner_control_plane.services.state_manager import state_manager

bp = Blueprint('reputation', __name__, url_prefix='/api/v1')
logger = get_logger(__name__)
settings = get_settings()


@bp.post('/whitelist', strict_slashes=False)
def add_whitelist():
    """
    Add IP to global whitelist (bypasses all DDoS filtering).
    """
    try:
        data = request.json
        ip = data['ip']
        origin_id = data.get('origin_id')
        reason = data.get('reason', 'Manual')

        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO whitelist_entries (ip_address, origin_id, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT (ip_address) DO UPDATE SET
                    origin_id = EXCLUDED.origin_id,
                    reason = EXCLUDED.reason
            """, (ip, origin_id, reason))
            conn.commit()
        finally:
            cur.close()

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No edge nodes available'}), 500

        active_edge = state_manager.get_active_edge()
        standby_edge = state_manager.get_standby_edge()
        active_ip = state_manager.nodes_db[active_edge]['public_ip']
        standby_ip = state_manager.nodes_db[standby_edge]['public_ip']

        # Update whitelist on both scrubbers using centralized helper
        for node_name, node_ip in [(active_edge, active_ip), (standby_edge, standby_ip)]:
            node_data = state_manager.nodes_db[node_name]
            success, error = update_bpf_map(
                host=node_ip,
                map_path=get_map_path('whitelist'),
                key_hex=ip_to_hex(ip),
                value_hex="01",
                ssh_key_path=settings.ssh_key_path,
                provider=node_data['provider']  # SSH user auto-resolved from provider
            )
            if not success:
                logger.error(f"Failed to update whitelist on {node_name}: {error}")
            else:
                logger.info(f"Whitelist updated on {node_name}: {ip}")

        return jsonify({'status': 'success', 'ip': ip, 'reason': reason})

    except Exception as e:
        logger.error(f"Failed to add whitelist: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.delete('/whitelist/<ip>')
def delete_whitelist(ip: str):
    """Remove IP from global whitelist."""
    try:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP address'}), 400

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM whitelist_entries WHERE ip_address = %s", (ip,))
            deleted_count = cur.rowcount
            conn.commit()
        finally:
            cur.close()

        if deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'IP not in whitelist'}), 404

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No edge nodes available'}), 500

        active_edge = state_manager.get_active_edge()
        standby_edge = state_manager.get_standby_edge()
        active_ip = state_manager.nodes_db[active_edge]['public_ip']
        standby_ip = state_manager.nodes_db[standby_edge]['public_ip']

        # Delete whitelist from both scrubbers using centralized helper
        for node_name, node_ip in [(active_edge, active_ip), (standby_edge, standby_ip)]:
            node_data = state_manager.nodes_db[node_name]
            success, error = delete_bpf_map(
                host=node_ip,
                map_path=get_map_path('whitelist'),
                key_hex=ip_to_hex(ip),
                ssh_key_path=settings.ssh_key_path,
                provider=node_data['provider']  # SSH user auto-resolved from provider
            )
            if not success:
                logger.error(f"Failed to delete whitelist on {node_name}: {error}")
            else:
                logger.info(f"Whitelist removed from {node_name}: {ip}")

        return jsonify({'status': 'success', 'ip': ip})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/whitelist', strict_slashes=False)
def list_whitelist():
    """List all whitelisted IPs."""
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute("SELECT ip_address, origin_id, reason, added_at FROM whitelist_entries ORDER BY added_at DESC")
            entries = cur.fetchall()
            return jsonify({
                'entries': [
                    {
                        'ip': str(row['ip_address']),
                        'origin_id': row['origin_id'],
                        'reason': row['reason'],
                        'added_at': row['added_at'].isoformat() if row['added_at'] else None
                    }
                    for row in entries
                ]
            })
        finally:
            cur.close()

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.post('/admin/refresh-blacklist')
def refresh_blacklist_api():
    """Refresh blacklist on all scrubbers."""
    try:
        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No scrubbers available'}), 500

        refreshed = []
        for edge_name, node in state_manager.nodes_db.items():
            host_ip = node['public_ip']
            provider = node['provider']

            # Import ssh for provider-aware user resolution
            from shared.utils.ssh import get_ssh_user_for_provider

            rc, stdout, stderr = ssh_exec(
                host_ip,
                "sudo /opt/tensorprox/bin/populate-blacklist.py",
                settings.ssh_key_path,
                user=get_ssh_user_for_provider(provider),
                timeout=120  # Blacklist download can take time
            )

            if rc == 0:
                entry_count = 0
                for line in stdout.split('\n'):
                    if 'entries added' in line:
                        try:
                            entry_count = int(line.split('entries added')[0].split()[-1])
                        except:
                            pass
                        break
                refreshed.append({'edge': edge_name, 'entries': entry_count, 'status': 'success'})
            else:
                refreshed.append({'edge': edge_name, 'status': 'failed', 'error': stderr[:200]})

        success_count = sum(1 for r in refreshed if r.get('status') == 'success')
        return jsonify({'status': 'success' if success_count > 0 else 'error', 'refreshed': refreshed})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.post('/blacklist', strict_slashes=False)
def add_blacklist():
    """Add IP/CIDR to blacklist."""
    try:
        data = request.json
        ip_or_cidr = data['ip']
        reason = data.get('reason', 'Manual')
        reputation_score = data.get('reputation_score', 10)

        try:
            if '/' in ip_or_cidr:
                network = ipaddress.IPv4Network(ip_or_cidr, strict=False)
                ip_str = str(network.network_address)
                prefixlen = network.prefixlen
            else:
                ipaddress.IPv4Address(ip_or_cidr)
                ip_str = ip_or_cidr
                prefixlen = 32
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP or CIDR'}), 400

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO blacklist_entries (network, source, reputation_score, expires_at)
                VALUES (%s, %s, %s, NULL)
                ON CONFLICT (network) DO UPDATE SET source = EXCLUDED.source, reputation_score = EXCLUDED.reputation_score
            """, (ip_or_cidr, 'manual', reputation_score))
            conn.commit()
        finally:
            cur.close()

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No edge nodes available'}), 500

        active_edge = state_manager.get_active_edge()
        standby_edge = state_manager.get_standby_edge()
        active_ip = state_manager.nodes_db[active_edge]['public_ip']
        standby_ip = state_manager.nodes_db[standby_edge]['public_ip']

        score_hex = f'{reputation_score:02x}'

        # Update blacklist on both scrubbers using centralized helper
        for node_name, node_ip in [(active_edge, active_ip), (standby_edge, standby_ip)]:
            node_data = state_manager.nodes_db[node_name]
            success, error = update_bpf_map(
                host=node_ip,
                map_path=get_map_path('blacklist'),
                key_hex=cidr_to_lpm_key(ip_or_cidr),
                value_hex=score_hex,
                ssh_key_path=settings.ssh_key_path,
                provider=node_data['provider']  # SSH user auto-resolved from provider
            )
            if not success:
                logger.error(f"Failed to update blacklist on {node_name}: {error}")
            else:
                logger.info(f"Blacklist updated on {node_name}: {ip_or_cidr}")

        return jsonify({'status': 'success', 'ip': ip_or_cidr, 'prefixlen': prefixlen, 'reputation_score': reputation_score})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.get('/blacklist', strict_slashes=False)
def list_blacklist():
    """
    List all blacklisted IPs/CIDRs from database
    """
    try:
        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute("""
                SELECT network, source, reputation_score, added_at, expires_at
                FROM blacklist_entries
                WHERE expires_at IS NULL OR expires_at > NOW()
                ORDER BY added_at DESC
            """)
            entries = cur.fetchall()
            return jsonify({
                'entries': [
                    {
                        'ip': str(row['network']),
                        'source': row['source'],
                        'reputation_score': row['reputation_score'],
                        'added_at': row['added_at'].isoformat() if row['added_at'] else None,
                        'expires_at': row['expires_at'].isoformat() if row['expires_at'] else None
                    }
                    for row in entries
                ]
            })
        finally:
            cur.close()

    except Exception as e:
        logger.error(f"Failed to list blacklist: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@bp.delete('/blacklist/<path:ip_or_cidr>')
def delete_blacklist(ip_or_cidr: str):
    """Remove IP/CIDR from blacklist."""
    try:
        try:
            if '/' in ip_or_cidr:
                network = ipaddress.IPv4Network(ip_or_cidr, strict=False)
                ip_str = str(network.network_address)
                prefixlen = network.prefixlen
            else:
                ipaddress.IPv4Address(ip_or_cidr)
                ip_str = ip_or_cidr
                prefixlen = 32
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid IP or CIDR'}), 400

        db = get_db_connection()
        conn = db.conn
        cur = conn.cursor()
        try:
            cur.execute("DELETE FROM blacklist_entries WHERE network = %s", (ip_or_cidr,))
            deleted_count = cur.rowcount
            conn.commit()
        finally:
            cur.close()

        if deleted_count == 0:
            return jsonify({'status': 'error', 'message': 'IP/CIDR not in blacklist'}), 404

        if not state_manager.nodes_db:
            return jsonify({'status': 'error', 'message': 'No edge nodes available'}), 500

        active_edge = state_manager.get_active_edge()
        standby_edge = state_manager.get_standby_edge()
        active_ip = state_manager.nodes_db[active_edge]['public_ip']
        standby_ip = state_manager.nodes_db[standby_edge]['public_ip']

        # Delete blacklist from both scrubbers using centralized helper
        for node_name, node_ip in [(active_edge, active_ip), (standby_edge, standby_ip)]:
            node_data = state_manager.nodes_db[node_name]
            success, error = delete_bpf_map(
                host=node_ip,
                map_path=get_map_path('blacklist'),
                key_hex=cidr_to_lpm_key(ip_or_cidr),
                ssh_key_path=settings.ssh_key_path,
                provider=node_data['provider']  # SSH user auto-resolved from provider
            )
            if not success:
                logger.error(f"Failed to delete blacklist on {node_name}: {error}")
            else:
                logger.info(f"Blacklist removed from {node_name}: {ip_or_cidr}")

        return jsonify({'status': 'success', 'ip': ip_or_cidr})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
