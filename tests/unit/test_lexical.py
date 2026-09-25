"""
tests/unit/test_lexical.py
Behavioral unit tests for structural URL lexical signal extractors.
"""

from app.config import Config
from app.engine.lexical import (
    check_at_symbol_in_url,
    check_digit_hyphen_density,
    check_excessive_subdomains,
    check_excessive_url_length,
    check_ip_in_domain,
    check_missing_https,
    check_suspicious_tld,
    check_url_shortener,
)


def test_ip_address_url_triggers_ip_signal() -> None:
    signal = check_ip_in_domain("192.168.15.42", Config)
    assert signal.triggered is True
    assert signal.weight == Config.SIGNAL_WEIGHTS["ip_in_domain"]


def test_standard_domain_does_not_trigger_ip_signal() -> None:
    signal = check_ip_in_domain("login.microsoft.com", Config)
    assert signal.triggered is False


def test_free_freenom_tld_triggers_suspicious_tld_signal() -> None:
    signal = check_suspicious_tld("secure-verify-account.tk", Config)
    assert signal.triggered is True
    assert signal.details["tld"] == "tk"


def test_ip_address_skips_suspicious_tld_and_density_signals() -> None:
    tld_signal = check_suspicious_tld("10.0.0.1", Config)
    density_signal = check_digit_hyphen_density("10.0.0.1", Config)
    assert tld_signal.triggered is False
    assert density_signal.triggered is False


def test_at_symbol_in_authority_triggers_redirect_signal() -> None:
    signal = check_at_symbol_in_url("https://google.com@malicious-host.org/login", Config)
    assert signal.triggered is True


def test_known_shortener_domain_triggers_shortener_signal() -> None:
    signal = check_url_shortener("bit.ly", Config)
    assert signal.triggered is True
    assert signal.details["service"] == "bit.ly"


def test_http_scheme_triggers_missing_https_signal() -> None:
    http_sig = check_missing_https("http", Config)
    https_sig = check_missing_https("https", Config)
    assert http_sig.triggered is True
    assert https_sig.triggered is False


def test_four_subdomains_triggers_excessive_subdomains_signal() -> None:
    signal = check_excessive_subdomains("a.b.c.d.example.com", Config)
    assert signal.triggered is True
    assert signal.details["subdomain_count"] == 4


def test_compound_cctld_does_not_inflate_subdomain_count() -> None:
    # 'portal.bank.co.zm' has only 1 real subdomain ('portal'), not 2
    signal = check_excessive_subdomains("portal.bank.co.zm", Config)
    assert signal.triggered is False
    assert signal.details["subdomain_count"] == 1


def test_url_over_75_characters_triggers_length_signal() -> None:
    long_url = "https://example.com/auth/login?session=" + ("a" * 50)
    signal = check_excessive_url_length(long_url, Config)
    assert signal.triggered is True
    assert signal.details["length"] > Config.MAX_URL_LENGTH


def test_heavy_numeric_hyphenated_domain_triggers_density_signal() -> None:
    signal = check_digit_hyphen_density("secure-123-auth-9988-login.com", Config)
    assert signal.triggered is True
    assert signal.details["ratio"] > Config.DOMAIN_DIGIT_HYPHEN_RATIO_THRESHOLD
