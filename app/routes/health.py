"""
app/routes/health.py
Health and root discovery endpoints for container orchestrators and browser visitors.
"""

from typing import Tuple
from flask import Blueprint, Response, jsonify

from app.extensions import limiter


health_bp = Blueprint("health", __name__)


@health_bp.route("/", methods=["GET"])
@limiter.exempt
def index() -> Tuple[Response, int]:
    """
    Returns API metadata and endpoint documentation when visiting the root URL in a browser.
    """
    return (
        jsonify(
            {
                "service": "phishing-url-detection-api",
                "version": "1.0.0",
                "status": "online",
                "endpoints": {
                    "health": "GET /health",
                    "analyze": "POST /api/v1/analyze",
                },
            }
        ),
        200,
    )


@health_bp.route("/health", methods=["GET"])
@limiter.exempt
def health_check() -> Tuple[Response, int]:
    """
    Returns a 200 OK status payload indicating the application is alive.
    Exempt from rate limiting so load balancers can poll freely.
    """
    return (
        jsonify(
            {
                "status": "ok",
                "service": "phishing-url-detection-api",
                "version": "1.0.0",
            }
        ),
        200,
    )