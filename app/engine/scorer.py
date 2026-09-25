"""
app/engine/scorer.py
Aggregates heuristic signals and normalizes raw weights into a 0-100 risk score.
"""

from typing import List, Literal, Tuple, Type
from urllib.parse import urlsplit

from app.config import Config
from app.engine.brands import check_brand_lookalike
from app.engine.lexical import extract_lexical_signals
from app.schemas import AnalysisBody, SignalResult


RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


def calculate_normalized_score(signals: List[SignalResult]) -> int:
    """
    Normalizes triggered signal weights against the sum of all evaluated signal weights:
        score = round((triggered_weight / total_possible_weight) * 100)

    Normalizing against the dynamic sum of evaluated weights (rather than a hardcoded
    denominator) guarantees the score remains bounded on a 0-100 scale even if signals
    are added, re-weighted in config, or skipped during degraded host checks.
    """
    if not signals:
        return 0

    total_possible_weight = sum(signal.weight for signal in signals)
    if total_possible_weight <= 0:
        return 0

    triggered_weight = sum(signal.weight for signal in signals if signal.triggered)
    normalized = round((triggered_weight / total_possible_weight) * 100)
    return max(0, min(100, normalized))


def classify_risk_level(
    score: int, config: Type[Config] = Config
) -> RiskLevel:
    """
    Maps a 0-100 normalized score to LOW, MEDIUM, or HIGH using configured thresholds.
    """
    if score <= config.SCORE_THRESHOLD_LOW:
        return "LOW"
    if score <= config.SCORE_THRESHOLD_MEDIUM:
        return "MEDIUM"
    return "HIGH"


def evaluate_url(
    url: str, config: Type[Config] = Config
) -> Tuple[int, RiskLevel, AnalysisBody]:
    """
    Executes all lexical and brand lookalike heuristics against a validated URL
    and returns (risk_score, risk_level, analysis_body).
    """
    parsed = urlsplit(url.strip())
    hostname = parsed.hostname or ""

    # Combine brand lookalike (weight 25) + 8 structural lexical signals (weights = 90) -> 115 total
    signals: List[SignalResult] = [
        check_brand_lookalike(hostname, config),
        *extract_lexical_signals(url, config),
    ]

    risk_score = calculate_normalized_score(signals)
    risk_level = classify_risk_level(risk_score, config)
    triggered_count = sum(1 for signal in signals if signal.triggered)

    analysis = AnalysisBody(
        mode="lexical",
        triggered_count=triggered_count,
        total_signals_evaluated=len(signals),
        signals=signals,
    )

    return risk_score, risk_level, analysis
