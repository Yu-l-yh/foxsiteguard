"""
FoxSiteGuard — Anti-phishing URL analysis server.

Usage:
    python -m foxsiteguard.main
    # or
    uvicorn foxsiteguard.core.api:app --host 127.0.0.1 --port 8000
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "foxsiteguard.core.api:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
    )
