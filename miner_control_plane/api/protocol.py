"""Protocol API Blueprint - Protocol information and bogon ranges

Endpoints for querying protocol-level information.
"""
import logging
from flask import Blueprint, jsonify

bp = Blueprint('protocol', __name__, url_prefix='/api/v1')
logger = logging.getLogger(__name__)


@bp.route('/protocol/bogon', methods=['GET'])
def list_bogon_ranges():
    """
    List all bogon ranges currently filtered (informational)
    """
    bogon_ranges = [
        {'range': '0.0.0.0/8', 'description': 'This network (RFC 1122)'},
        {'range': '10.0.0.0/8', 'description': 'RFC 1918 private'},
        {'range': '127.0.0.0/8', 'description': 'Loopback (RFC 1122)'},
        {'range': '169.254.0.0/16', 'description': 'Link-local (RFC 3927)'},
        {'range': '172.16.0.0/12', 'description': 'RFC 1918 private'},
        {'range': '192.0.2.0/24', 'description': 'TEST-NET-1 (RFC 5737)'},
        {'range': '192.168.0.0/16', 'description': 'RFC 1918 private'},
        {'range': '198.51.100.0/24', 'description': 'TEST-NET-2 (RFC 5737)'},
        {'range': '203.0.113.0/24', 'description': 'TEST-NET-3 (RFC 5737)'},
        {'range': '224.0.0.0/4', 'description': 'Multicast (RFC 5771)'},
        {'range': '240.0.0.0/4', 'description': 'Reserved/future use'},
        {'range': '255.255.255.255/32', 'description': 'Broadcast'}
    ]

    return jsonify({
        'status': 'success',
        'bogon_ranges': bogon_ranges,
        'total_ranges': len(bogon_ranges),
        'note': 'These ranges are hardcoded in XDP (check_bogon_source function)'
    })
