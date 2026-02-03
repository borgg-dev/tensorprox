"""Dashboard API endpoints.

Provides a Flask Blueprint with endpoints for dashboard authentication and query execution.
"""

import hmac
import logging
import time
from collections import defaultdict
from functools import wraps
from threading import Lock

from flask import Blueprint, jsonify, request, session

from .config import DashboardConfig
from .queries import QUERIES
from .repository import DashboardRepository

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter.

    Tracks requests per IP within a sliding time window.
    Thread-safe via Lock.
    """

    def __init__(self, max_requests: int = 5, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """Check if request is allowed for the given key.

        Returns:
            (allowed: bool, remaining: int) - whether allowed and remaining attempts
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            # Clean old entries
            self._requests[key] = [t for t in self._requests[key] if t > cutoff]

            current_count = len(self._requests[key])
            remaining = max(0, self.max_requests - current_count)

            if current_count >= self.max_requests:
                return False, 0

            self._requests[key].append(now)
            return True, remaining - 1

    def get_retry_after(self, key: str) -> int:
        """Get seconds until next request is allowed."""
        with self._lock:
            if key not in self._requests or not self._requests[key]:
                return 0
            oldest = min(self._requests[key])
            retry_after = int(oldest + self.window_seconds - time.time())
            return max(0, retry_after)


# Rate limiter: 5 login attempts per minute per IP
login_limiter = RateLimiter(max_requests=5, window_seconds=60)


def get_client_ip() -> str:
    """Get client IP, respecting X-Forwarded-For from nginx."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    if request.headers.get("X-Real-IP"):
        return request.headers["X-Real-IP"]
    return request.remote_addr or "unknown"


def log_login_attempt(username: str, success: bool, rate_limited: bool = False):
    """Log login attempt with all available metadata."""
    client_ip = get_client_ip()
    metadata = {
        "event": "login_attempt",
        "success": success,
        "rate_limited": rate_limited,
        "username": username,
        "ip": client_ip,
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "referer": request.headers.get("Referer", "none"),
        "origin": request.headers.get("Origin", "none"),
        "accept_language": request.headers.get("Accept-Language", "unknown"),
        "content_type": request.content_type,
        "forwarded_for": request.headers.get("X-Forwarded-For", "none"),
        "forwarded_proto": request.headers.get("X-Forwarded-Proto", "none"),
        "host": request.headers.get("Host", "unknown"),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }

    if rate_limited:
        logger.warning("RATE_LIMITED login attempt: %s", metadata)
    elif success:
        logger.info("SUCCESS login: %s", metadata)
    else:
        logger.warning("FAILED login attempt: %s", metadata)

bp = Blueprint("dashboard", __name__, url_prefix="/api/v1/dashboard")

repo = DashboardRepository()


def login_required(fn):
    """Decorator to require dashboard authentication.

    Returns 401 Unauthorized if the session is not authenticated.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("dashboard_authenticated"):
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


@bp.route("/login", methods=["POST"])
def login():
    """Authenticate to the dashboard.

    Request body:
        {"username": "...", "password": "..."}

    Returns:
        {"status": "ok"} on success, 200
        {"error": "Invalid credentials"} on failure, 401
        {"error": "Too many login attempts"} on rate limit, 429
    """
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # Rate limiting by IP
    client_ip = get_client_ip()
    allowed, remaining = login_limiter.is_allowed(client_ip)

    if not allowed:
        retry_after = login_limiter.get_retry_after(client_ip)
        log_login_attempt(username, success=False, rate_limited=True)
        response = jsonify({
            "error": "Too many login attempts. Try again later.",
            "retry_after": retry_after
        })
        response.headers["Retry-After"] = str(retry_after)
        return response, 429

    # Validate credentials
    if hmac.compare_digest(username, DashboardConfig.user) and hmac.compare_digest(password, DashboardConfig.password):
        session["dashboard_authenticated"] = True
        session.permanent = True
        log_login_attempt(username, success=True)
        return jsonify({"status": "ok"})

    log_login_attempt(username, success=False)
    return jsonify({"error": "Invalid credentials"}), 401


@bp.route("/logout", methods=["POST"])
def logout():
    """Log out of the dashboard.

    Clears the session.

    Returns:
        {"status": "ok"}
    """
    session.clear()
    return jsonify({"status": "ok"})


@bp.route("/queries", methods=["GET"])
@login_required
def list_queries():
    """List available queries.

    Returns:
        {"query_name": {"description": "..."}, ...}
    """
    result = {}
    for name, (_, description) in QUERIES.items():
        result[name] = {"description": description}
    return jsonify(result)


@bp.route("/query", methods=["POST"])
@login_required
def execute_query():
    """Execute a predefined query.

    Request body:
        {"query": "query_name", "params": {...}}

    Returns:
        {"query": "...", "results": [...], "count": N} on success, 200
        {"error": "Unknown query: ..."} if query not found, 400
    """
    data = request.get_json() or {}
    query_name = data.get("query", "")
    params = data.get("params", {})
    if not isinstance(params, dict):
        params = {}

    if query_name not in QUERIES:
        return jsonify({"error": f"Unknown query: {query_name}"}), 400

    sql_builder, _ = QUERIES[query_name]
    sql, query_params = sql_builder(params)
    try:
        results = repo.execute(sql, query_params)
    except Exception as e:
        logger.error("Query execution failed for %s: %s", query_name, e)
        return jsonify({"error": "Query execution failed"}), 500

    return jsonify({"query": query_name, "results": results, "count": len(results)})
