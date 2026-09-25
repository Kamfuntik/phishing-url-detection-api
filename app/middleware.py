"""
app/middleware.py
Request lifecycle hooks providing correlation IDs, high-resolution latency timing,
and structured single-line request logs.
"""

import time
import uuid
from flask import Flask, Response, g, request

from app.extensions import logger


REQUEST_ID_HEADER = "X-Request-ID"


def register_middleware(app: Flask) -> None:
    """
    Registers before_request and after_request hooks on the Flask app.
    """

    @app.before_request
    def start_request_trace() -> None:
        g.start_time = time.perf_counter()
        incoming_id = request.headers.get(REQUEST_ID_HEADER, "").strip()
        g.request_id = incoming_id if incoming_id else str(uuid.uuid4())

    @app.after_request
    def finalize_request_trace(response: Response) -> Response:
        start_time = getattr(g, "start_time", None)
        latency_ms = (
            round((time.perf_counter() - start_time) * 1000, 2)
            if start_time is not None
            else 0.0
        )
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        response.headers[REQUEST_ID_HEADER] = request_id

        logger.info(
            "method=%s path=%s status=%s latency_ms=%.2f request_id=%s",
            request.method,
            request.path,
            response.status_code,
            latency_ms,
            request_id,
        )
        return response
