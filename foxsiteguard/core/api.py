"""
FastAPI backend for FoxSiteGuard — URL phishing risk analysis API.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from foxsiteguard.core.domain import domain_similarity, detect_impersonation, get_extracted_domain
from foxsiteguard.core.whois import get_age
from foxsiteguard.core.ssl_check import check_ssl
from foxsiteguard.core.ioc import check_ioc
from foxsiteguard.core.scoring import score

app = FastAPI(
    title="FoxSiteGuard API",
    version="2.0.0",
    description="Anti-phishing URL analysis backend.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str
    safe_mode: bool = True


class AnalyzeResponse(BaseModel):
    url: str
    domain: str
    features: dict
    result: dict
    mode: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """
    Analyze a URL for phishing risk.

    safe_mode=True (default): only local checks (IOC, similarity, impersonation).
    No network requests are made to the target domain.
    """
    domain = get_extracted_domain(req.url)

    similar = domain_similarity(domain)
    ioc_result = check_ioc(domain)
    impersonation = detect_impersonation(domain)

    if req.safe_mode:
        # Safe mode: no network requests
        ssl_result = {"valid": True, "match": True, "issuer": "", "expire_days": 0, "error": "skipped (safe mode)"}
        age = 9999
        mode = "safe"
    else:
        # Deep mode: includes SSL handshake and WHOIS lookup
        ssl_result = check_ssl(domain)
        age = 9999 if ioc_result.get("matched") else get_age(domain)
        mode = "deep"

    features = {
        "similar": similar,
        "age": age,
        "ssl_valid": ssl_result["valid"] and ssl_result["match"],
        "ioc": ioc_result,
        "impersonation": impersonation,
    }

    result = score(features)

    return {
        "url": req.url,
        "domain": domain,
        "features": {
            "similarity": round(similar, 4),
            "age_days": age,
            "ssl": ssl_result,
            "ioc": ioc_result,
            "impersonation": impersonation,
        },
        "result": result,
        "mode": mode,
    }
