"""Per-Origin Reputation API Blueprint

Client-controlled whitelist/blacklist management per origin.
All operations are ATOMIC - either succeed on ALL scrubbers or rollback.
"""
import ipaddress
from datetime import datetime, timezone
from typing import Optional
from flask import Blueprint, request, jsonify
import psycopg2.extras
from shared.database import get_db_connection
from shared.utils.logging import get_logger
from miner_control_plane.api.auth import require_tpm_auth
from miner_control_plane.services.state_manager import state_manager
from miner_control_plane.services.scrubber_sync import scrubber_sync, SyncOperation, SyncResult

bp = Blueprint('origin_reputation', __name__, url_prefix='/api/v1/origins')
logger = get_logger(__name__)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _validate_ip(ip_str: str) -> tuple:
    """Validate IP address. Returns (is_valid, error_message, normalized_ip)."""
    try:
        # Handle CIDR
        if '/' in ip_str:
            network = ipaddress.IPv4Network(ip_str, strict=False)
            return True, None, str(network.network_address), network.prefixlen
        else:
            addr = ipaddress.IPv4Address(ip_str)
            return True, None, str(addr), 32
    except ValueError as e:
        return False, str(e), None, None


def _get_origin_eip(origin_id: str) -> Optional[str]:
    """Get EIP for origin from state manager (with DB fallback)."""
    origin = state_manager.get_origin(origin_id)
    return origin['eip'] if origin else None


def _get_origin_private_ip(origin_id: str) -> Optional[str]:
    """Get private_ip for origin (used for BPF map keys after AWS NAT).

    IMPORTANT: XDP sees packets AFTER AWS NAT, so dst_ip is the private_ip
    (e.g., 10.0.1.50) not the public EIP (e.g., 63.176.44.16).
    Per-origin BPF map compound keys must use private_ip.
    """
    origin = state_manager.get_origin(origin_id)
    return origin.get('private_ip') if origin else None


def _get_origin_shard_id(origin_id: str) -> Optional[str]:
    """Get shard_id for origin (used to scope BPF operations to correct scrubbers)."""
    origin = state_manager.get_origin(origin_id)
    return origin.get('shard_id') if origin else None


def _log_reputation_action(origin_id: str, list_type: str, action: str,
                           ip_address: str, cidr_prefix: int, reason: str,
                           performed_by: str, scrubbers_updated: list,
                           success: bool, error_message: str = None):
    """Log reputation change to audit table."""
    db = get_db_connection()
    try:
        db.execute("""
            INSERT INTO origin_reputation_log
            (origin_id, list_type, action, ip_address, cidr_prefix, reason,
             performed_by, scrubbers_updated, success, error_message)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (origin_id, list_type, action, ip_address, cidr_prefix, reason,
              performed_by, scrubbers_updated, success, error_message))
    finally:
        db.close()


def _build_success_response(origin_id: str, ip: str, action: str,
                            list_type: str, scrubbers_updated: list) -> dict:
    """Build standardized success response."""
    return {
        'status': 'success',
        'origin_id': origin_id,
        'ip': ip,
        'action': action,
        'list_type': list_type,
        'scrubbers_updated': scrubbers_updated,
        'persisted_at': datetime.now(timezone.utc).isoformat()
    }


def _build_error_response(message: str, code: str = None) -> dict:
    """Build standardized error response."""
    resp = {
        'status': 'error',
        'message': message
    }
    if code:
        resp['error_code'] = code
    return resp


# =============================================================================
# WHITELIST ENDPOINTS
# =============================================================================

@bp.get('/<origin_id>/whitelist')
@require_tpm_auth
def get_origin_whitelist(origin_id: str):
    """Get all whitelist entries for an origin."""
    if not state_manager.get_origin(origin_id):
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    try:
        entries = db.query_all("""
            SELECT ip_address, cidr_prefix, reason, created_by, created_at, expires_at
            FROM origin_whitelist
            WHERE origin_id = %s
            ORDER BY created_at DESC
        """, (origin_id,))

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'count': len(entries),
            'entries': [
                {
                    'ip': str(row['ip_address']),
                    'cidr_prefix': row['cidr_prefix'],
                    'reason': row['reason'],
                    'created_by': row['created_by'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                    'expires_at': row['expires_at'].isoformat() if row['expires_at'] else None
                }
                for row in entries
            ]
        })
    finally:
        db.close()


@bp.post('/<origin_id>/whitelist')
@require_tpm_auth
def add_origin_whitelist(origin_id: str):
    """
    Add IP to origin's whitelist.

    Request: {"ip": "1.2.3.4", "reason": "Customer VPN", "expires_at": null}

    Response on success:
    {
        "status": "success",
        "origin_id": "O1",
        "ip": "1.2.3.4",
        "action": "add",
        "list_type": "whitelist",
        "scrubbers_updated": ["i-abc123", "i-def456"],
        "persisted_at": "2025-12-12T22:00:00Z"
    }
    """
    data = request.json or {}
    ip_str = data.get('ip')
    reason = data.get('reason', 'Manual')
    expires_at = data.get('expires_at')  # ISO timestamp or null

    if not ip_str:
        return jsonify(_build_error_response('ip is required', 'MISSING_IP')), 400

    # Validate IP
    valid, err, ip_normalized, cidr_prefix = _validate_ip(ip_str)
    if not valid:
        return jsonify(_build_error_response(f'Invalid IP: {err}', 'INVALID_IP')), 400

    # Get origin private_ip and shard_id (for scoped BPF operations)
    private_ip = _get_origin_private_ip(origin_id)
    shard_id = _get_origin_shard_id(origin_id)
    if not private_ip or not shard_id:
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()

    try:
        # Parse expires_at if provided
        expires_ts = None
        if expires_at:
            try:
                expires_ts = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            except ValueError:
                return jsonify(_build_error_response(
                    'Invalid expires_at format', 'INVALID_EXPIRES'
                )), 400

        # Step 1: Apply to shard's scrubbers atomically (not all scrubbers)
        key_hex = scrubber_sync._build_compound_key(ip_normalized, private_ip)
        expires_unix = int(expires_ts.timestamp()) if expires_ts else 0
        value_hex = scrubber_sync._build_value(expires_at=expires_unix)

        sync_result = scrubber_sync.apply_atomic_to_shard(
            SyncOperation(
                map_name='origin_whitelist_map',
                key_hex=key_hex,
                value_hex=value_hex,
                action='update',
                origin_id=origin_id,
                ip_address=ip_normalized,
                list_type='whitelist'
            ),
            shard_id=shard_id
        )

        if sync_result.result != SyncResult.SUCCESS:
            # Rollback happened or failed - don't persist to DB
            _log_reputation_action(
                origin_id, 'whitelist', 'add', ip_normalized, cidr_prefix,
                reason, 'tpm', [], False, sync_result.error_message
            )
            return jsonify(_build_error_response(
                f'Failed to apply to scrubbers: {sync_result.error_message}',
                'SCRUBBER_SYNC_FAILED'
            )), 500

        # Step 2: Persist to database (scrubbers already updated)
        cur.execute("""
            INSERT INTO origin_whitelist
            (origin_id, ip_address, cidr_prefix, reason, created_by, expires_at)
            VALUES (%s, %s, %s, %s, 'tpm', %s)
            ON CONFLICT (origin_id, ip_address, cidr_prefix) DO UPDATE SET
                reason = EXCLUDED.reason,
                expires_at = EXCLUDED.expires_at
        """, (origin_id, ip_normalized, cidr_prefix, reason, expires_ts))
        conn.commit()

        # Step 3: Log success
        _log_reputation_action(
            origin_id, 'whitelist', 'add', ip_normalized, cidr_prefix,
            reason, 'tpm', sync_result.scrubbers_updated, True
        )

        return jsonify(_build_success_response(
            origin_id, ip_normalized, 'add', 'whitelist',
            sync_result.scrubbers_updated
        )), 201

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to add whitelist entry: {e}")
        return jsonify(_build_error_response(str(e), 'INTERNAL_ERROR')), 500
    finally:
        cur.close()
        db.close()


@bp.delete('/<origin_id>/whitelist/<ip>')
@require_tpm_auth
def delete_origin_whitelist(origin_id: str, ip: str):
    """Remove IP from origin's whitelist."""
    # Validate IP
    valid, err, ip_normalized, cidr_prefix = _validate_ip(ip)
    if not valid:
        return jsonify(_build_error_response(f'Invalid IP: {err}', 'INVALID_IP')), 400

    private_ip = _get_origin_private_ip(origin_id)
    shard_id = _get_origin_shard_id(origin_id)
    if not private_ip or not shard_id:
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()

    try:
        # Check entry exists
        cur.execute(
            "SELECT 1 FROM origin_whitelist WHERE origin_id = %s AND ip_address = %s",
            (origin_id, ip_normalized)
        )
        if not cur.fetchone():
            return jsonify(_build_error_response(
                'Entry not found', 'ENTRY_NOT_FOUND'
            )), 404

        # Step 1: Remove from shard's scrubbers atomically
        key_hex = scrubber_sync._build_compound_key(ip_normalized, private_ip)

        sync_result = scrubber_sync.apply_atomic_to_shard(
            SyncOperation(
                map_name='origin_whitelist_map',
                key_hex=key_hex,
                value_hex=None,
                action='delete',
                origin_id=origin_id,
                ip_address=ip_normalized,
                list_type='whitelist'
            ),
            shard_id=shard_id
        )

        if sync_result.result != SyncResult.SUCCESS:
            _log_reputation_action(
                origin_id, 'whitelist', 'remove', ip_normalized, cidr_prefix,
                None, 'tpm', [], False, sync_result.error_message
            )
            return jsonify(_build_error_response(
                f'Failed to remove from scrubbers: {sync_result.error_message}',
                'SCRUBBER_SYNC_FAILED'
            )), 500

        # Step 2: Delete from database
        cur.execute(
            "DELETE FROM origin_whitelist WHERE origin_id = %s AND ip_address = %s",
            (origin_id, ip_normalized)
        )
        conn.commit()

        # Step 3: Log success
        _log_reputation_action(
            origin_id, 'whitelist', 'remove', ip_normalized, cidr_prefix,
            None, 'tpm', sync_result.scrubbers_updated, True
        )

        return jsonify(_build_success_response(
            origin_id, ip_normalized, 'remove', 'whitelist',
            sync_result.scrubbers_updated
        ))

    finally:
        cur.close()
        db.close()


# =============================================================================
# BLACKLIST ENDPOINTS
# =============================================================================

@bp.get('/<origin_id>/blacklist')
@require_tpm_auth
def get_origin_blacklist(origin_id: str):
    """Get all blacklist entries for an origin."""
    if not state_manager.get_origin(origin_id):
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    try:
        entries = db.query_all("""
            SELECT ip_address, cidr_prefix, reason, created_by, created_at, expires_at
            FROM origin_blacklist
            WHERE origin_id = %s
            ORDER BY created_at DESC
        """, (origin_id,))

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'count': len(entries),
            'entries': [
                {
                    'ip': str(row['ip_address']),
                    'cidr_prefix': row['cidr_prefix'],
                    'reason': row['reason'],
                    'created_by': row['created_by'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                    'expires_at': row['expires_at'].isoformat() if row['expires_at'] else None
                }
                for row in entries
            ]
        })
    finally:
        db.close()


@bp.post('/<origin_id>/blacklist')
@require_tpm_auth
def add_origin_blacklist(origin_id: str):
    """Add IP to origin's blacklist."""
    data = request.json or {}
    ip_str = data.get('ip')
    reason = data.get('reason', 'Manual')
    expires_at = data.get('expires_at')

    if not ip_str:
        return jsonify(_build_error_response('ip is required', 'MISSING_IP')), 400

    valid, err, ip_normalized, cidr_prefix = _validate_ip(ip_str)
    if not valid:
        return jsonify(_build_error_response(f'Invalid IP: {err}', 'INVALID_IP')), 400

    private_ip = _get_origin_private_ip(origin_id)
    shard_id = _get_origin_shard_id(origin_id)
    if not private_ip or not shard_id:
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()

    try:
        expires_ts = None
        if expires_at:
            try:
                expires_ts = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            except ValueError:
                return jsonify(_build_error_response(
                    'Invalid expires_at format', 'INVALID_EXPIRES'
                )), 400

        # Apply atomically to shard's scrubbers
        key_hex = scrubber_sync._build_compound_key(ip_normalized, private_ip)
        expires_unix = int(expires_ts.timestamp()) if expires_ts else 0
        value_hex = scrubber_sync._build_value(expires_at=expires_unix)

        sync_result = scrubber_sync.apply_atomic_to_shard(
            SyncOperation(
                map_name='origin_blacklist_map',
                key_hex=key_hex,
                value_hex=value_hex,
                action='update',
                origin_id=origin_id,
                ip_address=ip_normalized,
                list_type='blacklist'
            ),
            shard_id=shard_id
        )

        if sync_result.result != SyncResult.SUCCESS:
            _log_reputation_action(
                origin_id, 'blacklist', 'add', ip_normalized, cidr_prefix,
                reason, 'tpm', [], False, sync_result.error_message
            )
            return jsonify(_build_error_response(
                f'Failed to apply to scrubbers: {sync_result.error_message}',
                'SCRUBBER_SYNC_FAILED'
            )), 500

        # Persist to database
        cur.execute("""
            INSERT INTO origin_blacklist
            (origin_id, ip_address, cidr_prefix, reason, created_by, expires_at)
            VALUES (%s, %s, %s, %s, 'tpm', %s)
            ON CONFLICT (origin_id, ip_address, cidr_prefix) DO UPDATE SET
                reason = EXCLUDED.reason,
                expires_at = EXCLUDED.expires_at
        """, (origin_id, ip_normalized, cidr_prefix, reason, expires_ts))
        conn.commit()

        _log_reputation_action(
            origin_id, 'blacklist', 'add', ip_normalized, cidr_prefix,
            reason, 'tpm', sync_result.scrubbers_updated, True
        )

        return jsonify(_build_success_response(
            origin_id, ip_normalized, 'add', 'blacklist',
            sync_result.scrubbers_updated
        )), 201

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to add blacklist entry: {e}")
        return jsonify(_build_error_response(str(e), 'INTERNAL_ERROR')), 500
    finally:
        cur.close()
        db.close()


@bp.delete('/<origin_id>/blacklist/<ip>')
@require_tpm_auth
def delete_origin_blacklist(origin_id: str, ip: str):
    """Remove IP from origin's blacklist."""
    valid, err, ip_normalized, cidr_prefix = _validate_ip(ip)
    if not valid:
        return jsonify(_build_error_response(f'Invalid IP: {err}', 'INVALID_IP')), 400

    private_ip = _get_origin_private_ip(origin_id)
    shard_id = _get_origin_shard_id(origin_id)
    if not private_ip or not shard_id:
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT 1 FROM origin_blacklist WHERE origin_id = %s AND ip_address = %s",
            (origin_id, ip_normalized)
        )
        if not cur.fetchone():
            return jsonify(_build_error_response('Entry not found', 'ENTRY_NOT_FOUND')), 404

        key_hex = scrubber_sync._build_compound_key(ip_normalized, private_ip)

        sync_result = scrubber_sync.apply_atomic_to_shard(
            SyncOperation(
                map_name='origin_blacklist_map',
                key_hex=key_hex,
                value_hex=None,
                action='delete',
                origin_id=origin_id,
                ip_address=ip_normalized,
                list_type='blacklist'
            ),
            shard_id=shard_id
        )

        if sync_result.result != SyncResult.SUCCESS:
            _log_reputation_action(
                origin_id, 'blacklist', 'remove', ip_normalized, cidr_prefix,
                None, 'tpm', [], False, sync_result.error_message
            )
            return jsonify(_build_error_response(
                f'Failed to remove from scrubbers: {sync_result.error_message}',
                'SCRUBBER_SYNC_FAILED'
            )), 500

        cur.execute(
            "DELETE FROM origin_blacklist WHERE origin_id = %s AND ip_address = %s",
            (origin_id, ip_normalized)
        )
        conn.commit()

        _log_reputation_action(
            origin_id, 'blacklist', 'remove', ip_normalized, cidr_prefix,
            None, 'tpm', sync_result.scrubbers_updated, True
        )

        return jsonify(_build_success_response(
            origin_id, ip_normalized, 'remove', 'blacklist',
            sync_result.scrubbers_updated
        ))

    finally:
        cur.close()
        db.close()


# =============================================================================
# BLACKLIST OVERRIDE ENDPOINTS
# =============================================================================

@bp.get('/<origin_id>/blacklist-override')
@require_tpm_auth
def get_origin_blacklist_override(origin_id: str):
    """Get all blacklist override entries for an origin."""
    if not state_manager.get_origin(origin_id):
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    try:
        entries = db.query_all("""
            SELECT ip_address, cidr_prefix, reason, created_by, created_at
            FROM origin_blacklist_override
            WHERE origin_id = %s
            ORDER BY created_at DESC
        """, (origin_id,))

        return jsonify({
            'status': 'success',
            'origin_id': origin_id,
            'count': len(entries),
            'entries': [
                {
                    'ip': str(row['ip_address']),
                    'cidr_prefix': row['cidr_prefix'],
                    'reason': row['reason'],
                    'created_by': row['created_by'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else None
                }
                for row in entries
            ]
        })
    finally:
        db.close()


@bp.post('/<origin_id>/blacklist-override')
@require_tpm_auth
def add_origin_blacklist_override(origin_id: str):
    """
    Override global blacklist for this origin.

    NOTE: This allows traffic from a globally-blacklisted IP to this origin.
    Reason is REQUIRED - must justify why override is needed.
    """
    data = request.json or {}
    ip_str = data.get('ip')
    reason = data.get('reason')

    if not ip_str:
        return jsonify(_build_error_response('ip is required', 'MISSING_IP')), 400

    if not reason:
        return jsonify(_build_error_response(
            'reason is required for blacklist override', 'MISSING_REASON'
        )), 400

    valid, err, ip_normalized, cidr_prefix = _validate_ip(ip_str)
    if not valid:
        return jsonify(_build_error_response(f'Invalid IP: {err}', 'INVALID_IP')), 400

    private_ip = _get_origin_private_ip(origin_id)
    shard_id = _get_origin_shard_id(origin_id)
    if not private_ip or not shard_id:
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    # Verify IP is actually in global blacklist
    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()

    try:
        cur.execute("SELECT 1 FROM blacklist_entries WHERE network >>= %s", (ip_normalized,))
        if not cur.fetchone():
            return jsonify(_build_error_response(
                'IP is not in global blacklist - no override needed',
                'NOT_IN_GLOBAL_BLACKLIST'
            )), 400

        # Apply atomically to shard's scrubbers
        key_hex = scrubber_sync._build_compound_key(ip_normalized, private_ip)
        value_hex = scrubber_sync._build_value()

        sync_result = scrubber_sync.apply_atomic_to_shard(
            SyncOperation(
                map_name='origin_override_map',
                key_hex=key_hex,
                value_hex=value_hex,
                action='update',
                origin_id=origin_id,
                ip_address=ip_normalized,
                list_type='override'
            ),
            shard_id=shard_id
        )

        if sync_result.result != SyncResult.SUCCESS:
            _log_reputation_action(
                origin_id, 'override', 'add', ip_normalized, cidr_prefix,
                reason, 'tpm', [], False, sync_result.error_message
            )
            return jsonify(_build_error_response(
                f'Failed to apply to scrubbers: {sync_result.error_message}',
                'SCRUBBER_SYNC_FAILED'
            )), 500

        cur.execute("""
            INSERT INTO origin_blacklist_override
            (origin_id, ip_address, cidr_prefix, reason, created_by)
            VALUES (%s, %s, %s, %s, 'tpm')
            ON CONFLICT (origin_id, ip_address, cidr_prefix) DO UPDATE SET
                reason = EXCLUDED.reason
        """, (origin_id, ip_normalized, cidr_prefix, reason))
        conn.commit()

        _log_reputation_action(
            origin_id, 'override', 'add', ip_normalized, cidr_prefix,
            reason, 'tpm', sync_result.scrubbers_updated, True
        )

        return jsonify(_build_success_response(
            origin_id, ip_normalized, 'add', 'override',
            sync_result.scrubbers_updated
        )), 201

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to add override: {e}")
        return jsonify(_build_error_response(str(e), 'INTERNAL_ERROR')), 500
    finally:
        cur.close()
        db.close()


@bp.delete('/<origin_id>/blacklist-override/<ip>')
@require_tpm_auth
def delete_origin_blacklist_override(origin_id: str, ip: str):
    """Remove override - IP will be blocked by global blacklist again."""
    valid, err, ip_normalized, cidr_prefix = _validate_ip(ip)
    if not valid:
        return jsonify(_build_error_response(f'Invalid IP: {err}', 'INVALID_IP')), 400

    private_ip = _get_origin_private_ip(origin_id)
    shard_id = _get_origin_shard_id(origin_id)
    if not private_ip or not shard_id:
        return jsonify(_build_error_response('Origin not found', 'ORIGIN_NOT_FOUND')), 404

    db = get_db_connection()
    conn = db.conn
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT 1 FROM origin_blacklist_override WHERE origin_id = %s AND ip_address = %s",
            (origin_id, ip_normalized)
        )
        if not cur.fetchone():
            return jsonify(_build_error_response('Override not found', 'ENTRY_NOT_FOUND')), 404

        key_hex = scrubber_sync._build_compound_key(ip_normalized, private_ip)

        sync_result = scrubber_sync.apply_atomic_to_shard(
            SyncOperation(
                map_name='origin_override_map',
                key_hex=key_hex,
                value_hex=None,
                action='delete',
                origin_id=origin_id,
                ip_address=ip_normalized,
                list_type='override'
            ),
            shard_id=shard_id
        )

        if sync_result.result != SyncResult.SUCCESS:
            _log_reputation_action(
                origin_id, 'override', 'remove', ip_normalized, cidr_prefix,
                None, 'tpm', [], False, sync_result.error_message
            )
            return jsonify(_build_error_response(
                f'Failed to remove from scrubbers: {sync_result.error_message}',
                'SCRUBBER_SYNC_FAILED'
            )), 500

        cur.execute(
            "DELETE FROM origin_blacklist_override WHERE origin_id = %s AND ip_address = %s",
            (origin_id, ip_normalized)
        )
        conn.commit()

        _log_reputation_action(
            origin_id, 'override', 'remove', ip_normalized, cidr_prefix,
            None, 'tpm', sync_result.scrubbers_updated, True
        )

        return jsonify(_build_success_response(
            origin_id, ip_normalized, 'remove', 'override',
            sync_result.scrubbers_updated
        ))

    finally:
        cur.close()
        db.close()
