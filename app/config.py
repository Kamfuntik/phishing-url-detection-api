"""
app/config.py
Centralized configuration for heuristic weights, risk thresholds, and operational limits.
Keeping all tunable parameters here prevents magic numbers inside detection engines.
"""

import os
from pathlib import Path
from typing import Dict, FrozenSet


BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """
    Base configuration loaded from environment variables with deterministic defaults.
    Thresholds are illustrative starting points for heuristic triage; in a production
    deployment, these weights would be tuned against labeled phishing/benign datasets.
    """

    SERVICE_NAME: str = "phishing-url-detection-api"
    API_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("FLASK_ENV", "production").lower() == "development"

    # Rate Limiting (Flask-Limiter syntax)
    RATELIMIT_DEFAULT: str = os.getenv("RATE_LIMIT_DEFAULT", "60 per minute")
    RATELIMIT_ANALYZE: str = os.getenv("RATE_LIMIT_ANALYZE", "30 per minute")
    RATELIMIT_STORAGE_URI: str = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

    # Normalized score thresholds (0-100 scale)
    SCORE_THRESHOLD_LOW: int = int(os.getenv("SCORE_THRESHOLD_LOW", "30"))
    SCORE_THRESHOLD_MEDIUM: int = int(os.getenv("SCORE_THRESHOLD_MEDIUM", "60"))

    # Lexical Heuristic Weights (Sum of all possible weights = 115)
    SIGNAL_WEIGHTS: Dict[str, int] = {
        "ip_in_domain": 20,
        "brand_lookalike": 25,
        "suspicious_tld": 15,
        "at_symbol_in_url": 15,
        "url_shortener": 10,
        "missing_https": 10,
        "excessive_subdomains": 10,
        "excessive_url_length": 5,
        "high_digit_hyphen_density": 5,
    }

    # Feature-specific detection parameters
    MAX_SUBDOMAIN_COUNT: int = 3
    MAX_URL_LENGTH: int = 75
    DOMAIN_DIGIT_HYPHEN_RATIO_THRESHOLD: float = 0.30
    BRAND_MAX_EDIT_DISTANCE: int = 2

    # High-abuse and free top-level domains frequently used in disposable campaigns
    SUSPICIOUS_TLDS: FrozenSet[str] = frozenset(
        {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "zip"}
    )

    # Known URL shortener hosts that obscure the final redirect destination
    KNOWN_SHORTENERS: FrozenSet[str] = frozenset(
        {
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rebrand.ly",
            "cutt.ly",
            "shorturl.at",
        }
    )

    KNOWN_BRANDS_PATH: Path = BASE_DIR / "data" / "known_brands.json"