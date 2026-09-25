"""
tests/integration/test_analyze_route.py
End-to-end HTTP integration tests for /health, /api/v1/analyze, error envelopes, and rate limiting.
"""

from app import create_app
from app.config import Config


class RateLimitTestConfig(Config):
    TESTING = True
    RATELIMIT_ANALYZE = "2 per minute"


def test_health_endpoint_returns_200_and_service_metadata() -> None:
    app = create_app(Config)
    client = app.test_client()

    response = client.get("/health")
    data = response.get_json()

    assert response.status_code == 200
    assert data["status"] == "ok"
    assert data["service"] == "phishing-url-detection-api"
    assert "X-Request-ID" in response.headers


def test_analyze_route_returns_explainable_signals_for_phishing_url() -> None:
    app = create_app(Config)
    client = app.test_client()

    response = client.post(
        "/api/v1/analyze",
        json={"url": "http://paypa1.tk/secure-login"},
        headers={"X-Request-ID": "integration-req-101"},
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["request_id"] == "integration-req-101"
    assert data["risk_score"] == 43
    assert data["risk_level"] == "MEDIUM"
    assert data["analysis"]["mode"] == "lexical"
    assert data["analysis"]["total_signals_evaluated"] == 9
    assert data["analysis"]["triggered_count"] == 3

    triggered_names = {
        sig["name"] for sig in data["analysis"]["signals"] if sig["triggered"]
    }
    assert triggered_names == {"brand_lookalike", "suspicious_tld", "missing_https"}


def test_analyze_route_rejects_url_without_scheme_with_422_envelope() -> None:
    app = create_app(Config)
    client = app.test_client()

    response = client.post("/api/v1/analyze", json={"url": "paypa1.com/login"})
    data = response.get_json()

    assert response.status_code == 422
    assert data["error"]["code"] == "INVALID_URL"
    assert "scheme" in data["error"]["message"]
    assert "request_id" in data["error"]


def test_analyze_route_rejects_missing_url_field_with_400_envelope() -> None:
    app = create_app(Config)
    client = app.test_client()

    response = client.post("/api/v1/analyze", json={"target": "https://example.com"})
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"]["code"] == "MISSING_URL"
    assert "request_id" in data["error"]


def test_analyze_route_rejects_non_json_content_type_with_400_envelope() -> None:
    app = create_app(Config)
    client = app.test_client()

    response = client.post(
        "/api/v1/analyze",
        data="url=https://example.com",
        content_type="text/plain",
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"]["code"] == "INVALID_CONTENT_TYPE"
    assert data["error"]["message"] == "Content-Type header must be application/json."


def test_analyze_route_rejects_malformed_json_syntax_with_400_envelope() -> None:
    app = create_app(Config)
    client = app.test_client()

    response = client.post(
        "/api/v1/analyze",
        data='{"url": "https://example.com"',
        content_type="application/json",
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"]["code"] == "MALFORMED_JSON"


def test_analyze_route_rejects_get_method_with_405_envelope() -> None:
    app = create_app(Config)
    client = app.test_client()

    response = client.get("/api/v1/analyze")
    data = response.get_json()

    assert response.status_code == 405
    assert data["error"]["code"] == "METHOD_NOT_ALLOWED"


def test_rate_limiter_enforces_429_with_standard_error_envelope() -> None:
    app = create_app(RateLimitTestConfig)
    client = app.test_client()

    assert client.post("/api/v1/analyze", json={"url": "https://example.com"}).status_code == 200
    assert client.post("/api/v1/analyze", json={"url": "https://example.com"}).status_code == 200

    throttled = client.post("/api/v1/analyze", json={"url": "https://example.com"})
    data = throttled.get_json()

    assert throttled.status_code == 429
    assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "request_id" in data["error"]
