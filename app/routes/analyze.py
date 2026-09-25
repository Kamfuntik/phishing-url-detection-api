"""
app/routes/analyze.py
Controller for POST /api/v1/analyze.
"""

import uuid
from typing import Tuple
from flask import Blueprint, Response, current_app, g, jsonify, request
from pydantic import ValidationError
from werkzeug.exceptions import BadRequest

from app.config import Config
from app.engine.scorer import evaluate_url
from app.errors import APIError
from app.extensions import limiter
from app.schemas import AnalyzeRequest, AnalyzeResponse


analyze_bp = Blueprint("analyze", __name__, url_prefix="/api/v1")


@analyze_bp.route("/analyze", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_ANALYZE"])
def analyze_url() -> Tuple[Response, int]:
    """
    Validates a submitted URL and returns a normalized phishing risk score
    alongside individual heuristic signal explanations.
    """
    if not request.is_json:
        raise APIError(
            code="INVALID_CONTENT_TYPE",
            message="Content-Type header must be application/json.",
            status_code=400,
        )

    try:
        payload = request.get_json(silent=False)
    except BadRequest as exc:
        raise APIError(
            code="MALFORMED_JSON",
            message="Request body contains invalid JSON syntax.",
            status_code=400,
        ) from exc

    if not isinstance(payload, dict):
        raise APIError(
            code="INVALID_PAYLOAD",
            message="Request JSON body must be an object.",
            status_code=400,
        )

    if "url" not in payload or not isinstance(payload.get("url"), str):
        raise APIError(
            code="MISSING_URL",
            message="Request body must include a string field named 'url'.",
            status_code=400,
        )

    try:
        validated = AnalyzeRequest.model_validate(payload)
    except ValidationError as exc:
        first_err = exc.errors()[0]
        raw_msg = first_err.get("msg", "Invalid URL provided.")
        clean_msg = raw_msg.removeprefix("Value error, ")
        raise APIError(
            code="INVALID_URL",
            message=clean_msg,
            status_code=422,
        ) from exc

    request_id = getattr(g, "request_id", str(uuid.uuid4()))
    risk_score, risk_level, analysis_body = evaluate_url(validated.url, Config)

    response_model = AnalyzeResponse(
        url=validated.url,
        risk_score=risk_score,
        risk_level=risk_level,
        analysis=analysis_body,
        request_id=request_id,
    )

    return jsonify(response_model.model_dump()), 200
