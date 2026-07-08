"""
WHOIS-based domain age lookup with timeout and caching.
"""
import socket
import whois
from datetime import datetime

_cache: dict[str, int] = {}
_WHOIS_TIMEOUT = 8  # seconds


def get_age(domain: str) -> int:
    """Return domain age in days. Returns 9999 on timeout/failure."""
    if domain in _cache:
        return _cache[domain]

    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(_WHOIS_TIMEOUT)
        try:
            w = whois.whois(domain)
        finally:
            socket.setdefaulttimeout(old_timeout)

        cd = w.creation_date

        if isinstance(cd, list):
            cd = cd[0]

        if not cd:
            _cache[domain] = 9999
            return 9999

        age = (datetime.now() - cd).days
        if age < 0:
            age = 0
        _cache[domain] = age
        return age

    except Exception:
        _cache[domain] = 9999
        return 9999
