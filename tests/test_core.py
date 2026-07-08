import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from foxsiteguard.core.domain import get_extracted_domain, domain_similarity, detect_impersonation
from foxsiteguard.core.ioc import check_ioc
from foxsiteguard.core.scoring import score

# ---- Domain extraction ----
def test_domain_https_www():
    assert get_extracted_domain("https://www.google.com/search") == "google.com"

def test_domain_http():
    assert get_extracted_domain("http://example.com/page") == "example.com"

def test_domain_com_cn():
    assert get_extracted_domain("https://www.hr-huorongapp.com.cn/") == "hr-huorongapp.com.cn"

def test_domain_ip():
    assert get_extracted_domain("https://192.168.1.1/admin") == "192.168.1.1"

# ---- Domain similarity ----
def test_sim_exact():
    assert domain_similarity("google.com") >= 0.95

def test_sim_pr_huorong():
    assert domain_similarity("pr-huorong.com.cn") >= 0.85

def test_sim_hr_huorongapp():
    assert domain_similarity("hr-huorongapp.com.cn") >= 0.50

def test_sim_random():
    assert domain_similarity("totally-random.xyz") < 0.55

# ---- Impersonation detection ----
def test_imp_login_google():
    imp = detect_impersonation("login-google.com")
    assert imp["brand_match"] == "google"
    assert imp["prefix_used"] == "login"
    assert imp["score"] == 35

def test_imp_hr_huorongapp():
    imp = detect_impersonation("hr-huorongapp.com.cn")
    assert imp["brand_match"] == "huorong"
    assert imp["prefix_used"] == "hr"

def test_imp_www_not_false_positive():
    imp = detect_impersonation("www.google.com")
    assert imp["brand_match"] == ""
    assert imp["score"] == 0

def test_imp_google_self():
    imp = detect_impersonation("google.com")
    assert imp["brand_match"] == ""

def test_imp_apple_support():
    imp = detect_impersonation("apple-id-support.xyz")
    assert imp["brand_match"] == "apple"
    assert imp["prefix_used"] == "id"

# ---- IOC detection ----
def test_ioc_matched():
    assert check_ioc("micr0soft-login.net")["matched"] is True

def test_ioc_google():
    assert check_ioc("google.com")["matched"] is False

def test_ioc_pr_huorong():
    assert check_ioc("pr-huorong.com.cn")["matched"] is True

def test_ioc_hr_huorongapp():
    assert check_ioc("hr-huorongapp.com.cn")["matched"] is True

# ---- Scoring ----
def test_score_ioc():
    r = score({"similar": 0, "age": 9999, "ssl_valid": True,
        "ioc": {"matched": True, "type": "domain"},
        "impersonation": {"brand_match": "", "prefix_used": "", "score": 0}})
    assert r["score"] == 100
    assert r["level"] == "CRITICAL"

def test_score_safe():
    r = score({"similar": 0.5, "age": 9999, "ssl_valid": True,
        "ioc": {"matched": False},
        "impersonation": {"brand_match": "", "prefix_used": "", "score": 0}})
    assert r["level"] == "SAFE"

def test_score_impersonation():
    r = score({"similar": 0.92, "age": 9999, "ssl_valid": True,
        "ioc": {"matched": False},
        "impersonation": {"brand_match": "google", "prefix_used": "login", "score": 35}})
    assert r["score"] >= 50

def test_score_high_sim_only():
    r = score({"similar": 0.96, "age": 9999, "ssl_valid": True,
        "ioc": {"matched": False},
        "impersonation": {"brand_match": "", "prefix_used": "", "score": 0}})
    assert r["score"] == 40

# ---- API End-to-End ----
class TestAPI:
    def _client(self):
        from fastapi.testclient import TestClient
        from foxsiteguard.core.api import app
        return TestClient(app)

    def test_health(self):
        r = self._client().get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_analyze_safe_mode(self):
        r = self._client().post("/analyze", json={"url": "https://www.google.com", "safe_mode": True})
        assert r.status_code == 200
        assert r.json()["mode"] == "safe"

    def test_analyze_ioc(self):
        r = self._client().post("/analyze", json={"url": "https://pr-huorong.com.cn", "safe_mode": True})
        assert r.json()["result"]["level"] == "CRITICAL"

    def test_analyze_impersonation(self):
        r = self._client().post("/analyze", json={"url": "https://login-google.com", "safe_mode": True})
        imp = r.json()["features"]["impersonation"]
        assert imp["brand_match"] == "google"
        assert imp["prefix_used"] == "login"
