"""
app/engine/brands.py
Brand impersonation and typosquatting detection using Levenshtein edit distance.
Brand definitions are loaded from data/known_brands.json rather than hardcoded.
"""

from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Dict, List, Type

from app.config import Config
from app.engine.lexical import _split_domain_parts, is_ip_address
from app.schemas import SignalResult


@lru_cache(maxsize=4)
def load_known_brands(brands_path_str: str) -> List[Dict[str, Any]]:
    """
    Loads and caches the target brand catalog from disk so file I/O occurs once per worker.
    Uses utf-8-sig to transparently handle both standard UTF-8 and Windows BOM files.
    """
    path = Path(brands_path_str)
    with path.open("r", encoding="utf-8-sig") as file_handle:
        payload = json.load(file_handle)
    return payload.get("brands", [])


def levenshtein_distance(source: str, target: str) -> int:
    """
    Computes the minimum number of single-character edits (insertions, deletions,
    or substitutions) required to transform source into target.
    """
    if source == target:
        return 0
    if not source:
        return len(target)
    if not target:
        return len(source)

    if len(source) < len(target):
        source, target = target, source

    previous_row = list(range(len(target) + 1))
    for i, src_char in enumerate(source, start=1):
        current_row = [i]
        for j, tgt_char in enumerate(target, start=1):
            insert_cost = previous_row[j] + 1
            delete_cost = current_row[j - 1] + 1
            replace_cost = previous_row[j - 1] + (0 if src_char == tgt_char else 1)
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row

    return previous_row[-1]


def check_brand_lookalike(hostname: str, config: Type[Config] = Config) -> SignalResult:
    """
    Flags domains within edit-distance 2 of a known brand name, or unauthorized
    domains embedding an exact brand token inside subdomains or hyphenated labels.
    Distance 2 catches common typosquats (paypa1, arnazon) while avoiding false
    positives on legitimately similar domains.
    """
    weight = config.SIGNAL_WEIGHTS["brand_lookalike"]
    max_distance = config.BRAND_MAX_EDIT_DISTANCE

    if not hostname or is_ip_address(hostname):
        return SignalResult(
            name="brand_lookalike",
            triggered=False,
            weight=weight,
            description="Skipped brand lookalike check because host is not a domain name.",
            details={"matched_brand": None, "edit_distance": None},
        )

    subdomains, registrable_label, tld_suffix = _split_domain_parts(hostname)
    registrable_domain = (
        f"{registrable_label}.{tld_suffix}" if tld_suffix else registrable_label
    )

    brands = load_known_brands(str(config.KNOWN_BRANDS_PATH))

    # 1. Whitelist official brand domains so legitimate traffic never triggers a false alarm
    for brand in brands:
        official_set = {d.lower() for d in brand.get("official_domains", [])}
        if registrable_domain in official_set or hostname.lower() in official_set:
            return SignalResult(
                name="brand_lookalike",
                triggered=False,
                weight=weight,
                description=f"Domain '{registrable_domain}' is a verified official domain for '{brand['name']}'.",
                details={
                    "matched_brand": brand["name"],
                    "official_domain": True,
                    "edit_distance": 0,
                },
            )

    # 2. Extract candidate tokens from the registrable label and any subdomain labels
    candidate_tokens: List[str] = [registrable_label]
    for label in [registrable_label] + subdomains:
        for part in label.split("-"):
            if part and part not in candidate_tokens:
                candidate_tokens.append(part)

    best_match: Dict[str, Any] | None = None

    for token in candidate_tokens:
        for brand in brands:
            brand_name = brand["name"].lower()

            # Exact brand token embedded in an unauthorized domain (e.g., paypal-secure.com or paypal.com.evil.tk)
            if token == brand_name:
                return SignalResult(
                    name="brand_lookalike",
                    triggered=True,
                    weight=weight,
                    description=(
                        f"Unauthorized domain '{registrable_domain}' embeds protected brand token '{brand_name}'."
                    ),
                    details={
                        "matched_brand": brand_name,
                        "suspicious_token": token,
                        "edit_distance": 0,
                        "impersonation_type": "exact_brand_token_on_unaffiliated_domain",
                    },
                )

            # Fuzzy typosquat comparison against the registrable label and substantive tokens
            if len(token) < 5 or abs(len(token) - len(brand_name)) > max_distance:
                continue

            distance = levenshtein_distance(token, brand_name)
            if 1 <= distance <= max_distance:
                if best_match is None or distance < best_match["edit_distance"]:
                    best_match = {
                        "matched_brand": brand_name,
                        "suspicious_token": token,
                        "edit_distance": distance,
                        "impersonation_type": "levenshtein_typosquat",
                    }

    if best_match is not None:
        return SignalResult(
            name="brand_lookalike",
            triggered=True,
            weight=weight,
            description=(
                f"Domain token '{best_match['suspicious_token']}' is within Levenshtein edit "
                f"distance {best_match['edit_distance']} of known brand '{best_match['matched_brand']}'."
            ),
            details=best_match,
        )

    return SignalResult(
        name="brand_lookalike",
        triggered=False,
        weight=weight,
        description="No brand typosquatting or lookalike tokens detected.",
        details={"matched_brand": None, "edit_distance": None},
    )
