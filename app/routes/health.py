"""
app/routes/health.py
Liveness and readiness probe endpoint for container orchestrators and uptime monitors.
"""

from typing import Tuple
from flask import Blueprint, Response, current_app, jsonify


health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check() -> Tuple[Response, int]:
    """
    Returns service status and metadata without invoking rate limits or external dependencies.
    """
    return (
        jsonify(
            {
                "status": "ok",
                "service": current_app.config["SERVICE_NAME"],
                "version": current_app.config["API_VERSION"],
            }
        ),
        200,
    )