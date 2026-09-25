"""
app/engine/lexical.py
Lexical heuristic extractors that evaluate URL structure without performing network I/O.
All weights and thresholds are injected from Config to avoid inline magic numbers.
"""

import ipaddress
from typing import List, Type
from urllib.parse import urlsplit

from app.config import Config
from app.schemas import SignalResult


# Common compound public suffixes so regional domains (e.g., example.co.uk, bank.co.zm)
# do not have their second-level registry label miscounted as a subdomain.
COMPOUND_PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.za",
        "co.zm",
        "org.zm",
        "co.jp",
        "com.br",
        "co.in",
    }
)


def is_ip_address(hostname: str) -> bool:
    """
    Determines whether a parsed hostname is an IPv4 or IPv6 literal.
    """
    cleaned = hostname.strip("[]")
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def _split_domain_parts(hostname: str) -> tuple[List[str], str, str]:
    """
    Splits a lowercase hostname into (subdomains, registrable_domain_label, tld_suffix).
    Accounts for compound ccTLDs so subdomain counts remain accurate across regions.
    """
    labels = [label for label in hostname.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return [], hostname.lower(), ""

    last_two = f"{labels[-2]}.{labels[-1]}"
    if last_two in COMPOUND_PUBLIC_SUFFIXES and len(labels) >= 3:
        tld_suffix = last_two
        registrable_label = labels[-3]
        subdomains = labels[:-3]
    else:
        tld_suffix = labels[-1]
        registrable_label = labels[-2]
        subdomains = labels[:-2]

    return subdomains, registrable_label, tld_suffix


def check_ip_in_domain(hostname: str, config: Type[Config] = Config) -> SignalResult:
    """
    Flags URLs that use a raw IPv4 or IPv6 address instead of a domain name.
    Phishing kits frequently host short-lived credential harvesters on raw IPs
    to bypass domain registration logs and DNS blocklists.
    """
    triggered = is_ip_address(hostname)
    return SignalResult(
        name="ip_in_domain",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["ip_in_domain"],
        description=(
            "URL host is a raw IP address rather than a registered domain name."
            if triggered
            else "URL uses a standard domain name."
        ),
        details={"hostname": hostname},
    )


def check_suspicious_tld(hostname: str, config: Type[Config] = Config) -> SignalResult:
    """
    Flags top-level domains with historically high phishing-to-benign registration
    ratios (such as free Freenom TLDs or low-cost bulk gTLDs).
    """
    if is_ip_address(hostname):
        return SignalResult(
            name="suspicious_tld",
            triggered=False,
            weight=config.SIGNAL_WEIGHTS["suspicious_tld"],
            description="Skipped TLD check because host is an IP address.",
            details={"tld": None},
        )

    labels = hostname.lower().strip(".").split(".")
    tld = labels[-1] if len(labels) >= 2 else ""
    triggered = tld in config.SUSPICIOUS_TLDS

    return SignalResult(
        name="suspicious_tld",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["suspicious_tld"],
        description=(
            f"Top-level domain '.{tld}' is on the high-abuse TLD watch list."
            if triggered
            else f"Top-level domain '.{tld}' is not on the high-abuse watch list."
        ),
        details={"tld": tld},
    )


def check_at_symbol_in_url(url: str, config: Type[Config] = Config) -> SignalResult:
    """
    Flags '@' characters in the URL. Under RFC 3986, text preceding '@' in the
    authority component is treated as userinfo, allowing 'https://trusted.com@evil.com'
    to visually deceive users while routing the browser to 'evil.com'.
    """
    triggered = "@" in url
    return SignalResult(
        name="at_symbol_in_url",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["at_symbol_in_url"],
        description=(
            "URL contains an '@' symbol, which can obscure the actual destination host."
            if triggered
            else "No '@' symbol obfuscation detected."
        ),
        details={"contains_at_symbol": triggered},
    )


def check_url_shortener(hostname: str, config: Type[Config] = Config) -> SignalResult:
    """
    Flags known link-shortening services because they conceal the final landing domain
    from static inspection prior to HTTP redirection.
    """
    normalized_host = hostname.lower().removeprefix("www.")
    triggered = normalized_host in config.KNOWN_SHORTENERS
    return SignalResult(
        name="url_shortener",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["url_shortener"],
        description=(
            f"Host '{normalized_host}' is a known URL shortening service."
            if triggered
            else "Host is not a known URL shortener."
        ),
        details={"service": normalized_host if triggered else None},
    )


def check_missing_https(scheme: str, config: Type[Config] = Config) -> SignalResult:
    """
    Flags unencrypted HTTP schemes. Kept intentionally low-weight (10) because most
    modern phishing campaigns provision free automated TLS certificates via Let's Encrypt;
    lack of HTTPS is a weak standalone indicator but compounds risk when paired with others.
    """
    normalized_scheme = scheme.lower()
    triggered = normalized_scheme != "https"
    return SignalResult(
        name="missing_https",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["missing_https"],
        description=(
            "URL uses unencrypted HTTP rather than HTTPS."
            if triggered
            else "URL uses HTTPS."
        ),
        details={"scheme": normalized_scheme},
    )


def check_excessive_subdomains(
    hostname: str, config: Type[Config] = Config
) -> SignalResult:
    """
    Flags hostnames with more than MAX_SUBDOMAIN_COUNT subdomains. Attackers often
    prepend target brand names as deep subdomains (e.g., 'login.secure.paypal.com.evil.tk')
    so mobile address bars truncate the actual registrable domain.
    """
    if is_ip_address(hostname):
        return SignalResult(
            name="excessive_subdomains",
            triggered=False,
            weight=config.SIGNAL_WEIGHTS["excessive_subdomains"],
            description="Skipped subdomain count because host is an IP address.",
            details={"subdomain_count": 0, "threshold": config.MAX_SUBDOMAIN_COUNT},
        )

    subdomains, _, _ = _split_domain_parts(hostname)
    # Exclude a leading 'www' from inflating the subdomain depth count
    effective_subdomains = [
        sub for idx, sub in enumerate(subdomains) if not (idx == 0 and sub == "www")
    ]
    count = len(effective_subdomains)
    triggered = count > config.MAX_SUBDOMAIN_COUNT

    return SignalResult(
        name="excessive_subdomains",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["excessive_subdomains"],
        description=(
            f"Hostname contains {count} subdomains (exceeds threshold of {config.MAX_SUBDOMAIN_COUNT})."
            if triggered
            else f"Hostname contains {count} subdomain(s) (within threshold of {config.MAX_SUBDOMAIN_COUNT})."
        ),
        details={
            "subdomain_count": count,
            "subdomains": effective_subdomains,
            "threshold": config.MAX_SUBDOMAIN_COUNT,
        },
    )


def check_excessive_url_length(url: str, config: Type[Config] = Config) -> SignalResult:
    """
    Flags unusually long URLs (> MAX_URL_LENGTH). Phishing URLs frequently embed
    base64-encoded victim emails, session tokens, or deep redirect parameters.
    """
    length = len(url)
    triggered = length > config.MAX_URL_LENGTH
    return SignalResult(
        name="excessive_url_length",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["excessive_url_length"],
        description=(
            f"URL length ({length} chars) exceeds threshold of {config.MAX_URL_LENGTH}."
            if triggered
            else f"URL length ({length} chars) is within normal threshold ({config.MAX_URL_LENGTH})."
        ),
        details={"length": length, "threshold": config.MAX_URL_LENGTH},
    )


def check_digit_hyphen_density(
    hostname: str, config: Type[Config] = Config
) -> SignalResult:
    """
    Flags domains where digits and hyphens exceed DOMAIN_DIGIT_HYPHEN_RATIO_THRESHOLD
    of the domain body. Automated phishing domain generators frequently combine
    brand prefixes with numeric/hyphenated suffixes (e.g., 'secure-auth-01-login-99.com').
    """
    if is_ip_address(hostname):
        return SignalResult(
            name="high_digit_hyphen_density",
            triggered=False,
            weight=config.SIGNAL_WEIGHTS["high_digit_hyphen_density"],
            description="Skipped digit/hyphen density check because host is an IP address.",
            details={
                "ratio": 0.0,
                "threshold": config.DOMAIN_DIGIT_HYPHEN_RATIO_THRESHOLD,
            },
        )

    subdomains, registrable_label, _ = _split_domain_parts(hostname)
    domain_body = "".join(subdomains + [registrable_label])
    if not domain_body:
        ratio = 0.0
    else:
        noisy_chars = sum(1 for ch in domain_body if ch.isdigit() or ch == "-")
        ratio = round(noisy_chars / len(domain_body), 3)

    triggered = ratio > config.DOMAIN_DIGIT_HYPHEN_RATIO_THRESHOLD
    return SignalResult(
        name="high_digit_hyphen_density",
        triggered=triggered,
        weight=config.SIGNAL_WEIGHTS["high_digit_hyphen_density"],
        description=(
            f"Domain digit/hyphen density ({ratio:.2f}) exceeds threshold of {config.DOMAIN_DIGIT_HYPHEN_RATIO_THRESHOLD:.2f}."
            if triggered
            else f"Domain digit/hyphen density ({ratio:.2f}) is within normal bounds."
        ),
        details={
            "ratio": ratio,
            "threshold": config.DOMAIN_DIGIT_HYPHEN_RATIO_THRESHOLD,
        },
    )


def extract_lexical_signals(
    url: str, config: Type[Config] = Config
) -> List[SignalResult]:
    """
    Runs all 8 structural lexical checks against a validated URL.
    """
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme
    hostname = parsed.hostname or ""

    return [
        check_ip_in_domain(hostname, config),
        check_suspicious_tld(hostname, config),
        check_at_symbol_in_url(url, config),
        check_url_shortener(hostname, config),
        check_missing_https(scheme, config),
        check_excessive_subdomains(hostname, config),
        check_excessive_url_length(url, config),
        check_digit_hyphen_density(hostname, config),
    ]
