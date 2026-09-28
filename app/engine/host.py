"""
app/engine/host.py
Optional host-based enrichment helpers (DNS resolution and TLS certificate validation).
Designed to degrade gracefully on network timeouts so external infrastructure failures
never crash lexical evaluation.
"""

import socket
import ssl
from typing import Any, Dict


DEFAULT_SOCKET_TIMEOUT_SECONDS = 2.0


def check_dns_resolution(
    hostname: str, timeout: float = DEFAULT_SOCKET_TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """
    Attempts to resolve a hostname via OS socket lookup within a strict timeout budget.
    Returns structured status metadata rather than raising on NXDOMAIN or timeout.
    """
    if not hostname:
        return {"resolved": False, "error": "empty_hostname"}

    previous_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        records = socket.getaddrinfo(hostname, None)
        addresses = sorted({record[4][0] for record in records if record[4]})
        return {"resolved": bool(addresses), "addresses": addresses[:5], "error": None}
    except (socket.gaierror, socket.timeout, OSError) as exc:
        return {"resolved": False, "addresses": [], "error": type(exc).__name__}
    finally:
        socket.setdefaulttimeout(previous_timeout)


def check_tls_certificate(
    hostname: str, port: int = 443, timeout: float = DEFAULT_SOCKET_TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """
    Performs a bounded TLS handshake to verify whether the remote host presents
    a certificate chain trusted by the system CA store.
    """
    if not hostname:
        return {"valid_tls": False, "error": "empty_hostname"}

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                return {
                    "valid_tls": bool(cert),
                    "not_after": cert.get("notAfter") if cert else None,
                    "error": None,
                }
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return {"valid_tls": False, "not_after": None, "error": type(exc).__name__}
