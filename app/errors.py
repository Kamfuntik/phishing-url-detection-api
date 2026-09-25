"""
app/errors.py
Centralized error handling ensuring every HTTP failure returns a deterministic JSON envelope.
"""

import uuid
from typing import Tuple
from flask import Flask, Response, g, jsonify
from werkzeug.exceptions import HTTPException


class APIError(Exception):
    """
    Application-level exception carrying a machine-readable error code and HTTP status.
    """

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _current_request_id() -> str:
    """
    Retrieves the active request ID from Flask's request context, or generates a fallback
    UUID if an error occurred before middleware initialization.
    """
    return getattr(g, "request_id", str(uuid.uuid4()))


def build_error_response(
    code: str, message: str, status_code: int
) -> Tuple[Response, int]:
    """
    Constructs the standard error envelope required across all API endpoints.
    """
    payload = {
        "error": {
            "code": code,
            "message": message,
            "request_id": _current_request_id(),
        }
    }
    return jsonify(payload), status_code


def register_error_handlers(app: Flask) -> None:
    """
    Attaches custom and HTTP exception handlers to the Flask application instance.
    """

    @app.errorhandler(APIError)
    def handle_api_error(exc: APIError) -> Tuple[Response, int]:
        return build_error_response(exc.code, exc.message, exc.status_code)

    @app.errorhandler(400)
    def handle_bad_request(exc: HTTPException) -> Tuple[Response, int]:
        return build_error_response(
            "BAD_REQUEST",
            exc.description or "Malformed request payload.",
            400,
        )

    @app.errorhandler(404)
    def handle_not_found(exc: HTTPException) -> Tuple[Response, int]:
        return build_error_response(
            "NOT_FOUND",
            "The requested endpoint does not exist.",
            404,
        )

    @app.errorhandler(405)
    def handle_method_not_allowed(exc: HTTPException) -> Tuple[Response, int]:
        return build_error_response(
            "METHOD_NOT_ALLOWED",
            "The HTTP method is not allowed for this endpoint.",
            405,
        )

    @app.errorhandler(422)
    def handle_unprocessable_entity(exc: HTTPException) -> Tuple[Response, int]:
        return build_error_response(
            "UNPROCESSABLE_ENTITY",
            exc.description or "Request failed semantic validation.",
            422,
        )

    @app.errorhandler(429)
    def handle_rate_limit_exceeded(exc: HTTPException) -> Tuple[Response, int]:
        return build_error_response(
            "RATE_LIMIT_EXCEEDED",
            f"Rate limit exceeded: {exc.description}.",
            429,
        )

    @app.errorhandler(Exception)
    def handle_unexpected_exception(exc: Exception) -> Tuple[Response, int]:
        if isinstance(exc, HTTPException):
            return build_error_response(
                exc.name.upper().replace(" ", "_"),
                exc.description or "HTTP error occurred.",
                exc.code or 500,
            )
        return build_error_response(
            "INTERNAL_SERVER_ERROR",
            "An unexpected internal error occurred.",
            500,
        )