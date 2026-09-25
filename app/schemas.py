"""
app/schemas.py
Pydantic schemas enforcing strict input validation and response structure.
"""

from typing import Any, Dict, List, Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_INPUT_URL_LENGTH = 2048


class AnalyzeRequest(BaseModel):
    """
    Validates incoming URL analysis requests.
    Enforces explicit http/https schemes and non-empty hostnames before the URL
    reaches the heuristic engine, preventing ambiguous parsing downstream.
    """

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="Target URL to evaluate for phishing indicators.")

    @field_validator("url")
    @classmethod
    def validate_url_structure(cls, raw_url: str) -> str:
        cleaned = raw_url.strip()
        if not cleaned:
            raise ValueError("URL cannot be empty.")

        if len(cleaned) > MAX_INPUT_URL_LENGTH:
            raise ValueError(
                f"URL exceeds maximum supported length of {MAX_INPUT_URL_LENGTH} characters."
            )

        if any(char.isspace() for char in cleaned):
            raise ValueError("URL must not contain whitespace characters.")

        parsed = urlsplit(cleaned)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("URL must include a scheme (http/https).")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must include a valid domain or IP host.")

        return cleaned


class SignalResult(BaseModel):
    """
    Represents a single heuristic check outcome for response explainability.
    """

    name: str
    triggered: bool
    weight: int
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)


class AnalysisBody(BaseModel):
    """
    Container for transparency metadata and per-signal explainability breakdown.
    """

    mode: Literal["lexical", "lexical+host"]
    triggered_count: int
    total_signals_evaluated: int
    signals: List[SignalResult]


class AnalyzeResponse(BaseModel):
    """
    Top-level response contract for /api/v1/analyze.
    """

    url: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    analysis: AnalysisBody
    request_id: str