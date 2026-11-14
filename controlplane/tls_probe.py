"""Read-only TLS/SNI probe of the local Nginx origin, never an arbitrary URL.

Does not expose private keys or make DNS/network requests to user-supplied IPs.
The operator sees the certificate actually served by 127.0.0.1:443 for SNI.
This does not test NSIN's public edge or external client reachability.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from .core import hostname, matches


def probe_local_tls(domain: str, *, timeout: float = 2.5) -> dict:
    """Inspect certificate metadata and verify chain+hostname independently."""
    domain = hostname(domain)
    report = {
        "domain": domain,
        "endpoint": "127.0.0.1:443 (local origin, not NSIN/CDN)",
        "status": "unreachable",
        "expires": None,
        "matches_hostname": False,
        "sha256": None,
        "issuer": None,
        "reason": "",
    }
    try:
        # Unverified handshake here is only to inspect metadata; verification
        # is always performed in a separate connection below.
        raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        raw_ctx.check_hostname = False
        raw_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", 443), timeout=timeout) as sock:
            with raw_ctx.wrap_socket(sock, server_hostname=domain) as conn:
                der = conn.getpeercert(binary_form=True)
        if not der:
            raise ValueError("TLS server did not present a certificate")
        cert = x509.load_der_x509_certificate(der)
        report["sha256"] = hashlib.sha256(der).hexdigest()[:24]
        report["expires"] = cert.not_valid_after_utc.isoformat()
        report["issuer"] = cert.issuer.rfc4514_string()[:200]
        try:
            sans = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        report["matches_hostname"] = any(matches(n, domain) for n in sans)
        if cert.not_valid_after_utc <= dt.datetime.now(dt.timezone.utc):
            report["status"] = "expired"
            report["reason"] = "Local origin serves an expired certificate"
            return report
        if not report["matches_hostname"]:
            report["status"] = "hostname-mismatch"
            report["reason"] = "Certificate SAN does not cover this hostname"
            return report

        verified_ctx = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", 443), timeout=timeout) as sock:
            with verified_ctx.wrap_socket(sock, server_hostname=domain):
                pass
        report["status"] = "valid"
        report["reason"] = "Trusted local origin TLS certificate for SNI"
    except ssl.SSLCertVerificationError as exc:
        report["status"] = "untrusted"
        report["reason"] = str(exc)[:250]
    except (OSError, ValueError, ssl.SSLError) as exc:
        report["reason"] = f"{type(exc).__name__}: {str(exc)[:210]}"
    return report
