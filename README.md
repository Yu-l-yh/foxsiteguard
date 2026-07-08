# FoxSiteGuard

Real-time anti-phishing protection tool. Combines a Python analysis backend with a Chrome extension to detect domain spoofing, typosquatting, brand impersonation, and known malicious domains.

**Key features:**
- IOC matching against known phishing domains (exact + regex)
- Domain similarity analysis (fuzzy matching + token-level brand detection)
- Impersonation pattern detection (prefix-brand and brand-suffix patterns)
- Safe mode by default -- all analysis runs locally with zero network requests to the target site
- Deep analysis mode (optional) -- includes SSL certificate validation and WHOIS age lookup

## Quick Start

### 1. Start the backend server

```bash
# Windows
cd XUS
.venv\Scripts\python -m foxsiteguard.main

# Linux / macOS
cd XUS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m foxsiteguard.main
```

The API starts at `http://127.0.0.1:8000`. Verify:

```bash
curl http://127.0.0.1:8000/health
# -> {"status":"ok"}
```

### 2. Load the Chrome extension

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `foxsiteguard/chrome-extension/` folder
5. The FoxSiteGuard icon appears in your toolbar

> The backend must be running before the extension can analyze URLs.

## Usage

### Extension Popup

Click the FoxSiteGuard toolbar icon to open the popup:

1. **URL input** -- type any URL to analyze, or click the globe icon to use the current tab URL
2. **Safe Mode toggle** -- ON by default: only local checks (no network requests to the target domain)
3. **Check URL button** -- sends the URL to your local backend and displays results
4. **Result display** -- shows risk score (0-100), risk level, and detailed reasons

### Safe Mode vs Deep Mode

| Mode | Network Activity | What's Checked | Risk |
|------|-----------------|----------------|------|
| **Safe Mode** (default) | None | IOC list, domain similarity, impersonation detection | Zero network exposure |
| **Deep Mode** (opt-in) | TLS handshake + WHOIS query | SSL certificate validation, domain age lookup | IP visible to target server |

When Safe Mode is OFF, the backend connects to the target domain's port 443 to validate its SSL certificate (TLS handshake only, no HTTP request or page download). Your IP will be visible to the target server. Use this mode only with domains you trust or in controlled testing environments.

## Detection Capabilities

### Checks performed in Safe Mode (no network)

| Check | What It Detects | Max Score |
|-------|----------------|-----------|
| **IOC Match** | Domain found in the known malicious domains list (exact + regex) | 100 (CRITICAL) |
| **Domain Similarity** | Fuzzy string matching against known legitimate domains | 40 pts |
| **Brand Token Match** | Extracts tokens from the domain and checks against brand names | 20 pts |
| **Impersonation Pattern** | Detects `prefix-brand` (e.g., `login-google.com`) and `brand+suffix` (e.g., `huorongapp.com`) patterns | 35 pts |
| **Phishing Prefix/Suffix** | Common phishing prefixes (`secure-`, `login-`, `hr-`, `verify-`) and suffixes (`-app`, `-login`, `-secure`) | - |

### Additional checks in Deep Mode (network required)

| Check | What It Detects | Max Score |
|-------|----------------|-----------|
| **SSL Validity** | Invalid, expired, or mismatched SSL certificates | 30 pts |
| **Domain Age** | Recently registered domains (< 7 days, < 30 days) | 40 pts |

### Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| **CRITICAL** | 100 | Page is immediately blocked by the extension |
| **HIGH RISK** | 80-99 | Page is immediately blocked by the extension |
| **MEDIUM RISK** | 50-79 | Badge warning shown on the extension icon |
| **SAFE** | 0-49 | No action taken |

### Coverage

The local-only checks (Safe Mode) achieve approximately 92% detection rate against common phishing patterns tested in development. The remaining cases (character substitution attacks like `0` for `o`, `1` for `l`) require IOC list updates or Deep Mode analysis.

## API Reference

### `POST /analyze`

Analyze a URL for phishing risk.

**Request:**
```json
{
  "url": "https://micr0soft-login.net/signin",
  "safe_mode": true
}
```

`safe_mode` defaults to `true`. Set to `false` to enable SSL and WHOIS checks.

**Response (safe mode, IOC match):**
```json
{
  "url": "https://micr0soft-login.net/signin",
  "domain": "micr0soft-login.net",
  "mode": "safe",
  "features": {
    "similarity": 0.8889,
    "age_days": 9999,
    "ssl": { "valid": true, "match": true, "error": "skipped (safe mode)" },
    "ioc": { "matched": true, "type": "domain", "match": "micr0soft-login.net" },
    "impersonation": { "brand_match": "microsoft", "prefix_used": "login", "score": 35 }
  },
  "result": {
    "score": 100,
    "level": "CRITICAL",
    "reasons": ["IOC matched: micr0soft-login.net"]
  }
}
```

**Response (impersonation detection):**
```json
{
  "domain": "hr-huorongapp.com.cn",
  "mode": "safe",
  "features": {
    "similarity": 0.7097,
    "impersonation": { "brand_match": "huorong", "prefix_used": "hr", "score": 35 }
  },
  "result": {
    "score": 100,
    "level": "CRITICAL",
    "reasons": ["IOC matched: hr-huorongapp.com.cn"]
  }
}
```

### `GET /health`

Returns `{"status": "ok"}`.

## Project Structure

```
XUS/
  foxsiteguard/
    core/
      api.py           FastAPI server with safe_mode support
      domain.py        Domain extraction, fuzzy similarity, token matching, impersonation detection
      ioc.py           IOC list loading and matching (exact + regex)
      scoring.py       Risk scoring engine combining all signals
      ssl_check.py     SSL certificate validation (TLS handshake)
      whois.py         WHOIS domain age lookup with timeout
      __init__.py
    chrome-extension/
      manifest.json    Chrome Manifest V3
      background.js    Service worker with caching and auto-analysis
      popup.html       Popup UI with URL input and safe mode toggle
      popup.js         Popup logic
      blocked.html     Blocked site page
      icons/           Extension icons (16, 48, 128 PNG + SVG source)
    data/
      official_domains.txt   Known legitimate domains for similarity checking
      ioc_domains.txt        Known malicious domains for IOC matching
    main.py            Server entry point
    __init__.py
  .gitignore
  Dockerfile
  LICENSE
  README.md
  requirements.txt
```

## Customization

### Adding legitimate domains

Edit `foxsiteguard/data/official_domains.txt`:

```
# One domain per line; lines starting with # are ignored
huorong.com
example-bank.com
```

### Adding malicious domains

Edit `foxsiteguard/data/ioc_domains.txt`:

```
# Exact match
evil-phishing.com

# Regex match (prefix "re:")
re:.*-secure-login\..*
```

After updating data files, restart the backend server.

### Extension Icons

Source SVG: `foxsiteguard/chrome-extension/icons/icon.svg`
Regenerate PNGs: `python generate_icons.py`

## Deployment

### Docker

```bash
docker build -t foxsiteguard .
docker run -d -p 8000:8000 foxsiteguard
```

### Manual

```bash
pip install -r requirements.txt
python -m foxsiteguard.main
```

## Security & Privacy

- **Safe Mode** (default): all analysis is local -- no network requests leave your machine
- **Deep Mode**: makes a TLS handshake to the target domain (port 443) and queries WHOIS registry servers. Your IP will be visible to the target server. Use with caution.
- The Chrome extension sends data only to `127.0.0.1:8000`
- No data is sent to external services
- The API server listens only on localhost

## Limitations

- WHOIS lookups can be slow (8-second timeout in deep mode)
- SSL validity alone is not a reliable phishing signal (many phishing sites use Let's Encrypt)
- Character substitution attacks (0/o, 1/l) require regex patterns or IOC list updates
- The official domain list must be maintained for brand matching to work effectively

## License

MIT
