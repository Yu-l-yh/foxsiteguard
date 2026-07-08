"""
IOC (Indicators of Compromise) detection.
Loads known phishing domains from file; supports pattern matching.
"""

import os
import re

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
_IOC_FILE = os.path.join(_DATA_DIR, "ioc_domains.txt")

# Built-in fallback IOC
_FALLBACK_IOC: set[str] = {
    "micr0soft-login.net",
    "bank-secure-update.com",
    "app1e-id-verify.com",
    "goog1e-account.com",
    "paypa1-secure.com",
    "amaz0n-payment.com",
    "chase-banking-verify.com",
    "alipay-protect.cc",
    "taobao-security.cc",
    "ic1c-bank.com",
}

_IOC_SET: set[str] | None = None
_IOC_PATTERNS: list[re.Pattern] | None = None


def _load_ioc() -> tuple[set[str], list[re.Pattern]]:
    """Load IOC domains and patterns from data file."""
    domains: set[str] = set()
    patterns: list[re.Pattern] = []
    try:
        with open(_IOC_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("re:"):
                    patterns.append(re.compile(line[3:], re.IGNORECASE))
                else:
                    domains.add(line.lower())
    except (FileNotFoundError, OSError):
        pass

    if not domains and not patterns:
        domains = _FALLBACK_IOC.copy()
    return domains, patterns


def check_ioc(domain: str) -> dict:
    """
    Check a domain against IOC lists.

    Returns a dict:
        matched (bool): whether the domain matches any IOC
        type (str): "domain", "pattern", or "none"
        match (str): the specific match if found
    """
    global _IOC_SET, _IOC_PATTERNS
    if _IOC_SET is None or _IOC_PATTERNS is None:
        _IOC_SET, _IOC_PATTERNS = _load_ioc()

    clean = domain.lower()

    # Exact match
    if clean in _IOC_SET:
        return {"matched": True, "type": "domain", "match": clean}

    # Pattern match
    for p in _IOC_PATTERNS:
        m = p.search(clean)
        if m:
            return {"matched": True, "type": "pattern", "match": m.group()}

    return {"matched": False, "type": "none", "match": ""}
