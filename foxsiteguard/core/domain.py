"""
Domain analysis: similarity checking, typosquatting detection, subdomain inspection.
Loads official domains from file; falls back to a built-in list.

Detection approaches:
1. Full-domain fuzzy matching (original)
2. Token-based brand matching: split domain by "-" and ".", check each token
   against known brand names to catch "pr-{brand}.com" patterns
"""

import re
import os
from rapidfuzz import fuzz, utils as fuzz_utils


_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
_OFFICIAL_FILE = os.path.join(_DATA_DIR, "official_domains.txt")

# Built-in fallback — expanded with Chinese companies
_FALLBACK_OFFICIAL = [
    "microsoft.com",    "apple.com",       "google.com",
    "bankofchina.com",  "chase.com",       "paypal.com",
    "amazon.com",       "alibaba.com",     "taobao.com",
    "tmall.com",        "weibo.com",       "qq.com",
    "alipay.com",       "tencent.com",     "baidu.com",
    "jd.com",           "dianping.com",    "meituan.com",
    "163.com",          "sina.com.cn",     "sohu.com",
    "github.com",       "gitlab.com",      "dropbox.com",
    "outlook.com",      "live.com",        "bing.com",
    "cloudflare.com",   "adobe.com",       "spotify.com",
    "netflix.com",      "twitter.com",     "facebook.com",
    "instagram.com",    "linkedin.com",    "whatsapp.com",
    "telegram.org",     "huorong.com",     "360.cn",
    "zhihu.com",        "douyin.com",      "kuaishou.com",
    "xiaomi.com",       "huawei.com",      "zte.com.cn",
    "ctrip.com",        "didi.com",        "meitu.com",
    "vivo.com",         "oppo.com",        "bytedance.com",
]

# Common impersonation prefixes — when a domain uses "prefix-brand.com"
# to impersonate "brand.com"
_PHISHING_PREFIXES = {
    "pr", "secure", "login", "account", "verify", "support",
    "help", "update", "service", "portal", "my", "id", "auth",
    "app", "web", "online", "home", "new", "admin", "signin",
    "signup", "verify", "confirm", "validate", "authenticate",
    "security", "safe", "protect", "guard", "ssl", "https",
}


_OFFICIAL: list[str] | None = None
# Cache of "name" parts (before first dot) for quick lookups
_OFFICIAL_NAMES: set[str] | None = None


def _load_official() -> list[str]:
    """Load official domains from data file, falling back to built-in list."""
    try:
        with open(_OFFICIAL_FILE, encoding="utf-8") as f:
            domains = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
        if domains:
            return domains
    except (FileNotFoundError, OSError):
        pass
    return _FALLBACK_OFFICIAL


def get_extracted_domain(url: str) -> str:
    """Extract the registrable domain from a URL (scheme, subdomain stripped)."""
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.split(":")[0]
    domain = re.sub(r"^www\d*\.", "", domain)
    return domain.lower()


def _get_name(domain: str) -> str:
    """Get the name part of a domain (before the first dot)."""
    return domain.split(".")[0]


def _load_once():
    """Lazy-load official domains and cache their name parts."""
    global _OFFICIAL, _OFFICIAL_NAMES
    if _OFFICIAL is None:
        _OFFICIAL = _load_official()
        _OFFICIAL_NAMES = {_get_name(d) for d in _OFFICIAL}


def domain_similarity(domain: str) -> float:
    """
    Return a similarity score (0.0–1.0) between *domain* and known official domains.

    Uses two strategies:
    A. Full-domain fuzzy matching
    B. Token-based brand matching (catches "pr-{brand}.com" patterns)
    """
    _load_once()
    assert _OFFICIAL is not None
    assert _OFFICIAL_NAMES is not None

    clean_domain = domain.lower()
    best = 0.0

    # --- Strategy A: Full-domain fuzzy matching ---
    for o in _OFFICIAL:
        score = fuzz.ratio(clean_domain, o, processor=fuzz_utils.default_process) / 100
        best = max(best, score)

    # --- Strategy B: Token-based brand matching ---
    # Split domain into tokens by "." and "-"
    # e.g., "pr-huorong.com.cn" → ["pr", "huorong", "com", "cn"]
    tokens = re.split(r"[.\-]", clean_domain)

    # Filter out TLD-like tokens
    tlds = {"com", "cn", "net", "org", "cc", "xyz", "top", "site", "info", "online",
            "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "io", "me", "co"}
    significant = [t for t in tokens if t not in tlds and len(t) >= 2]

    for token in significant:
        for official_name in _OFFICIAL_NAMES:
            # Exact token match against a brand name
            if token == official_name:
                # Check if this token is a known brand
                best = max(best, 0.92)
                continue

            # Fuzzy token match
            token_score = fuzz.ratio(token, official_name, processor=fuzz_utils.default_process) / 100
            if token_score >= 0.85:
                best = max(best, token_score)

    return best



_COMMON_PHISHING_PREFIXES = frozenset({
    "pr", "hr", "secure", "login", "account", "verify", "support",
    "help", "update", "service", "portal", "my", "id", "auth",
    "app", "web", "online", "home", "new", "admin", "signin",
    "signup", "confirm", "validate", "authenticate",
    "security", "safe", "protect", "guard", "ssl", "https",
    "mail", "info", "shop", "store", "pay",
})

# Common suffixes appended to brand names to create phishing domains
# e.g. "huorongAPP", "googleLOGIN", "appleID"
_PHISHING_SUFFIXES = frozenset({
    "app", "login", "secure", "verify", "support", "help",
    "update", "service", "portal", "account", "auth", "id",
    "online", "web", "home", "pay", "shop", "store", "info",
    "center", "signin", "signup", "confirm", "validate",
})




_KNOWN_SUBDOMAINS = frozenset({
    "www", "mail", "m", "mobile", "api", "dev", "test",
    "blog", "news", "shop", "store", "help", "support",
    "forum", "wiki", "status", "docs", "cdn", "static",
    "media", "video", "images", "img", "css", "js",
})


def detect_impersonation(domain: str) -> dict:
    """
    Detect if a domain is using a known impersonation pattern.
    Skips legitimate subdomains like www.google.com.

    Returns:
        brand_match (str): the brand name being impersonated (or "")
        prefix_used (str): the phishing prefix detected (or "")
        score (float): additional risk score from 0 to 35
    """
    _load_once()
    assert _OFFICIAL is not None
    assert _OFFICIAL_NAMES is not None

    clean = domain.lower()

    # --- Quick exit: domain IS an official domain or subdomain of one ---
    for o in _OFFICIAL:
        if clean == o or clean.endswith("." + o):
            return {"brand_match": "", "prefix_used": "", "score": 0}

    tokens = re.split(r"[.\-]", clean)
    tlds = {"com", "cn", "net", "org", "cc", "xyz", "top", "site",
            "info", "online", "io", "me", "co"}
    significant = [t for t in tokens if t not in tlds and len(t) >= 2]

    brand_match = ""
    prefix_used = ""

    # Find brand tokens (exact match first, substring suffix, fuzzy fallback)
    for token in significant:
        # Exact match
        if token in _OFFICIAL_NAMES:
            brand_match = token
            break
        # Substring match: token STARTS WITH brand name + phishing suffix
        # e.g. "huorongapp" starts with "huorong" with suffix "app"
        for official_name in _OFFICIAL_NAMES:
            if token.startswith(official_name) and len(token) > len(official_name):
                suffix = token[len(official_name):]
                if suffix in _PHISHING_SUFFIXES:
                    brand_match = official_name
                    break
            # Also check: token ENDS WITH brand name (prefix-brand pattern)
            if token.endswith(official_name) and len(token) > len(official_name):
                prefix = token[:-len(official_name)]
                if prefix in _COMMON_PHISHING_PREFIXES:
                    brand_match = official_name
                    break
        if brand_match:
            break
        # Fuzzy fallback
        for official_name in _OFFICIAL_NAMES:
            token_score = fuzz.ratio(token, official_name, processor=fuzz_utils.default_process) / 100
            if token_score >= 0.90:
                brand_match = official_name
                break
        if brand_match:
            break

    if not brand_match:
        return {"brand_match": "", "prefix_used": "", "score": 0}

    # Find phishing prefixes among other significant tokens
    other_tokens = [t for t in significant if t != brand_match and t not in _OFFICIAL_NAMES]

    if other_tokens:
        for t in other_tokens:
            if t in _COMMON_PHISHING_PREFIXES:
                prefix_used = t
                break

        # If no phishing prefix but only known subdomains -> legitimate
        if not prefix_used:
            unknown = [t for t in other_tokens if t not in _KNOWN_SUBDOMAINS]
            if not unknown:
                return {"brand_match": "", "prefix_used": "", "score": 0}

    # Score calculation
    extra = 35 if brand_match and prefix_used else (20 if brand_match else 0)

    return {
        "brand_match": brand_match,
        "prefix_used": prefix_used,
        "score": extra,
    }
