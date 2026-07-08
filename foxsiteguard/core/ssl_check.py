"""
SSL certificate validation for a domain.
"""

import ssl
import socket
from datetime import datetime


def check_ssl(domain: str) -> dict:
    """
    Check SSL certificate of *domain*.

    Returns:
        valid (bool): certificate is not expired
        match (bool): domain matches certificate CN / SAN
        issuer (str): issuer org name (if available)
        expire_days (int): days until expiry
        error (str): error message if check failed
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert["subject"])
        not_after = cert["notAfter"]

        expire = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expire_days = (expire - datetime.now()).days

        # Check CN and SAN
        cn_match = domain in subject.get("commonName", "")
        san_match = False
        if "subjectAltName" in cert:
            for entry in cert["subjectAltName"]:
                if entry[1] == domain or entry[1].startswith("*.") and domain.endswith(entry[1][1:]):
                    san_match = True
                    break

        issuer = dict(x[0] for x in cert.get("issuer", []))
        issuer_name = issuer.get("organizationName", "")

        return {
            "valid": expire > datetime.now(),
            "match": cn_match or san_match,
            "issuer": issuer_name,
            "expire_days": max(expire_days, 0),
            "error": "",
        }

    except Exception as e:
        return {
            "valid": False,
            "match": False,
            "issuer": "",
            "expire_days": 0,
            "error": str(e),
        }
