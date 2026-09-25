"""
tests/unit/test_brands.py
Behavioral unit tests for Levenshtein edit distance and brand lookalike detection.
"""

from app.config import Config
from app.engine.brands import check_brand_lookalike, levenshtein_distance


def test_levenshtein_distance_computes_exact_edit_operations() -> None:
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("amazon", "arnazon") == 2
    assert levenshtein_distance("microsoft", "example") > 2


def test_typosquatted_domains_within_distance_two_trigger_brand_signal() -> None:
    paypal_squat = check_brand_lookalike("paypa1.com", Config)
    amazon_squat = check_brand_lookalike("arnazon.com", Config)

    assert paypal_squat.triggered is True
    assert paypal_squat.details["matched_brand"] == "paypal"
    assert paypal_squat.details["edit_distance"] == 1

    assert amazon_squat.triggered is True
    assert amazon_squat.details["matched_brand"] == "amazon"
    assert amazon_squat.details["edit_distance"] == 2


def test_official_brand_domains_do_not_trigger_false_positive() -> None:
    official_root = check_brand_lookalike("paypal.com", Config)
    official_sub = check_brand_lookalike("login.microsoft.com", Config)

    assert official_root.triggered is False
    assert official_root.details.get("official_domain") is True
    assert official_sub.triggered is False
    assert official_sub.details.get("official_domain") is True


def test_exact_brand_in_subdomain_on_unaffiliated_domain_triggers_signal() -> None:
    spoofed_sub = check_brand_lookalike("paypal.com.secure-verify.tk", Config)
    hyphen_combo = check_brand_lookalike("netflix-billing-update.com", Config)

    assert spoofed_sub.triggered is True
    assert spoofed_sub.details["matched_brand"] == "paypal"
    assert spoofed_sub.details["edit_distance"] == 0

    assert hyphen_combo.triggered is True
    assert hyphen_combo.details["matched_brand"] == "netflix"


def test_unrelated_benign_domain_does_not_trigger_brand_signal() -> None:
    benign = check_brand_lookalike("wikipedia.org", Config)
    assert benign.triggered is False
    assert benign.details["matched_brand"] is None


def test_ip_address_skips_brand_lookalike_check() -> None:
    ip_host = check_brand_lookalike("192.168.1.1", Config)
    assert ip_host.triggered is False
