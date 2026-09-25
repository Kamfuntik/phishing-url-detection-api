"""
tests/unit/test_scorer.py
Behavioral unit tests for score normalization, threshold classification, and full URL evaluation.
"""

from app.config import Config
from app.engine.scorer import (
    calculate_normalized_score,
    classify_risk_level,
    evaluate_url,
)
from app.schemas import SignalResult


def test_normalization_when_all_signals_triggered_equals_100() -> None:
    signals = [
        SignalResult(name="sig_a", triggered=True, weight=25, description="A"),
        SignalResult(name="sig_b", triggered=True, weight=20, description="B"),
        SignalResult(name="sig_c", triggered=True, weight=15, description="C"),
    ]
    assert calculate_normalized_score(signals) == 100


def test_normalization_when_signal_removed_still_scales_to_100() -> None:
    # Even if only a subset of signals is active (total possible = 50), triggering half (25) yields 50
    signals = [
        SignalResult(name="sig_a", triggered=True, weight=25, description="A"),
        SignalResult(name="sig_b", triggered=False, weight=25, description="B"),
    ]
    assert calculate_normalized_score(signals) == 50


def test_normalization_against_full_115_weight_denominator() -> None:
    # Triggering brand_lookalike (25) + suspicious_tld (15) + missing_https (10) = 50 / 115 -> round(43.48) = 43
    score, level, analysis = evaluate_url("http://paypa1.tk/login", Config)
    assert analysis.total_signals_evaluated == 9
    assert analysis.triggered_count == 3
    assert score == round((50 / 115) * 100)
    assert level == "MEDIUM"


def test_risk_level_threshold_boundaries() -> None:
    assert classify_risk_level(0, Config) == "LOW"
    assert classify_risk_level(30, Config) == "LOW"
    assert classify_risk_level(31, Config) == "MEDIUM"
    assert classify_risk_level(60, Config) == "MEDIUM"
    assert classify_risk_level(61, Config) == "HIGH"
    assert classify_risk_level(100, Config) == "HIGH"


def test_clean_https_official_domain_scores_zero_and_low() -> None:
    score, level, analysis = evaluate_url("https://www.paypal.com/myaccount", Config)
    assert score == 0
    assert level == "LOW"
    assert analysis.triggered_count == 0


def test_heavily_obfuscated_phishing_url_scores_high() -> None:
    malicious_url = (
        "http://login.secure.account.verify.paypa1-support-998811.tk/"
        "auth@evil.tk/index.php?session_token=1234567890abcdef"
    )
    score, level, analysis = evaluate_url(malicious_url, Config)
    assert score >= 61
    assert level == "HIGH"
    assert analysis.triggered_count >= 6
