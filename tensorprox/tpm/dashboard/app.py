"""Standalone Dashboard Application - runs independently from TPM."""
import os
from datetime import timedelta
from pathlib import Path

from flask import Flask, send_from_directory

from .api import bp as dashboard_bp
from .config import DashboardConfig


def create_dashboard_app() -> Flask:
    """Create standalone dashboard Flask application."""
    app = Flask(__name__)

    # Configure session
    app.config["SECRET_KEY"] = DashboardConfig.session_secret
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=DashboardConfig.session_hours)
    app.config["JSON_SORT_KEYS"] = False

    # Register dashboard API blueprint
    app.register_blueprint(dashboard_bp)

    # Serve static dashboard HTML
    @app.route("/")
    @app.route("/dashboard")
    @app.route("/dashboard/")
    def serve_dashboard():
        static_dir = Path(__file__).parent / "static"
        return send_from_directory(static_dir, "index.html")

    # Serve static files (CSS, JS)
    @app.route("/dashboard/static/<path:filename>")
    def serve_static(filename):
        static_dir = Path(__file__).parent / "static"
        return send_from_directory(static_dir, filename)

    # Health check
    @app.route("/health")
    def health():
        return {"status": "healthy", "service": "tpm-dashboard"}

    return app


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5002))
    app = create_dashboard_app()
    app.run(host="0.0.0.0", port=port, debug=False)
