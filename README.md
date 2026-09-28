# Phishing URL Detection API

![CI Status](https://github.com/Kamfuntik/phishing-url-detection-api/actions/workflows/ci.yml/badge.svg)

A stateless REST API in Python (Flask) that evaluates URLs for structural and lexical phishing indicators. The service parses submitted URLs, evaluates nine configurable heuristic signals (including Levenshtein edit-distance typosquatting detection against a target brand catalog), normalizes the triggered weight onto a `0-100` scale, and returns signal-level explanations alongside a correlation `request_id`.

---

## Architecture

```text
phishing-api/
├── app/
│   ├── __init__.py           # Application factory and blueprint wiring
│   ├── config.py             # Heuristic weights, thresholds, rate limits (env-overridable)
│   ├── extensions.py         # Flask-Limiter and structured stdout logger initialization
│   ├── routes/
│   │   ├── health.py         # GET /health liveness probe
│   │   └── analyze.py        # POST /api/v1/analyze controller
│   ├── engine/
│   │   ├── lexical.py        # 8 structural URL heuristic extractors
│   │   ├── brands.py         # Levenshtein distance brand impersonation detector
│   │   ├── host.py           # Timeout-bounded DNS/TLS enrichment helpers
│   │   └── scorer.py         # Weight normalization and risk classification
│   ├── schemas.py            # Pydantic request/response validation contracts
│   ├── errors.py             # Centralized JSON error envelope handler
│   └── middleware.py         # X-Request-ID correlation and latency logging
├── data/
│   └── known_brands.json     # Target brand names and whitelisted official domains
├── tests/
│   ├── unit/                 # Behavioral unit tests for lexical, brand, and scorer modules
│   └── integration/          # End-to-end HTTP route, validation, and rate-limit tests
├── Procfile                  # Gunicorn production entrypoint
├── render.yaml               # Render PaaS blueprint specification
├── requirements.txt
└── run.py
```

---

## Local Setup & Testing

```bash
python -m venv venv
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

pip install -r requirements.txt
pytest -v
python run.py
```

---

## API Reference

### 1. `GET /health`
Liveness probe for container orchestrators and uptime checks. Exempt from rate limiting.

```bash
curl -i [http://127.0.0.1:5000/health](http://127.0.0.1:5000/health)
```

**Response (`200 OK`):**
```json
{
  "service": "phishing-url-detection-api",
  "status": "ok",
  "version": "1.0.0"
}
```

---

### 2. `POST /api/v1/analyze`
Evaluates a single URL and returns a normalized risk score, risk category, and per-signal breakdown.

**Request:**
```bash
curl -X POST [http://127.0.0.1:5000/api/v1/analyze](http://127.0.0.1:5000/api/v1/analyze) \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: req-demo-001" \
  -d '{"url": "[http://paypa1.tk/secure-login](http://paypa1.tk/secure-login)"}'
```

**Response (`200 OK`):**
```json
{
  "analysis": {
    "mode": "lexical",
    "signals": [
      {
        "description": "Domain token 'paypa1' is within Levenshtein edit distance 1 of known brand 'paypal'.",
        "details": {
          "edit_distance": 1,
          "impersonation_type": "levenshtein_typosquat",
          "matched_brand": "paypal",
          "suspicious_token": "paypa1"
        },
        "name": "brand_lookalike",
        "triggered": true,
        "weight": 25
      },
      {
        "description": "Top-level domain '.tk' is on the high-abuse TLD watch list.",
        "details": {
          "tld": "tk"
        },
        "name": "suspicious_tld",
        "triggered": true,
        "weight": 15
      },
      {
        "description": "URL uses unencrypted HTTP rather than HTTPS.",
        "details": {
          "scheme": "http"
        },
        "name": "missing_https",
        "triggered": true,
        "weight": 10
      }
    ],
    "total_signals_evaluated": 9,
    "triggered_count": 3
  },
  "request_id": "req-demo-001",
  "risk_level": "MEDIUM",
  "risk_score": 43,
  "url": "[http://paypa1.tk/secure-login](http://paypa1.tk/secure-login)"
}
```

---

### 3. Error Envelope (`400` / `404` / `405` / `422` / `429` / `500`)
All errors return a consistent JSON shape with the active `request_id`:

```json
{
  "error": {
    "code": "INVALID_URL",
    "message": "URL must include a scheme (http/https).",
    "request_id": "5168e1dc-e64b-4550-8fa0-c0ad21ca4391"
  }
}
```

---

## How Scoring Works

### Heuristic Signal Weights
All weights and thresholds are configured in `app/config.py` and `data/known_brands.json`:

| Signal | Weight | Rationale |
|---|---|---|
| `brand_lookalike` | 25 | Flags domains within Levenshtein edit distance <= 2 of a known brand or embedding an exact brand token on an unaffiliated host. |
| `ip_in_domain` | 20 | Raw IPv4/IPv6 literal used in place of a registered DNS hostname. |
| `suspicious_tld` | 15 | High-abuse or free top-level domain (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.work`, `.click`, `.zip`). |
| `at_symbol_in_url` | 15 | `@` character in the URL authority/path used to obscure the destination host. |
| `url_shortener` | 10 | Known link shortener (`bit.ly`, `tinyurl.com`, `t.co`, etc.) hiding the final landing domain. |
| `missing_https` | 10 | Unencrypted `http://` scheme. Kept intentionally low-weight because modern phishing sites routinely use automated TLS certificates. |
| `excessive_subdomains` | 10 | More than 3 effective subdomains (excluding leading `www` and accounting for compound ccTLDs such as `.co.uk` and `.co.zm`). |
| `excessive_url_length` | 5 | Total URL length exceeds 75 characters. |
| `high_digit_hyphen_density` | 5 | Digits and hyphens exceed 30% of the domain body. |

### Score Normalization Formula
Raw weights sum to a maximum possible weight of `115`. The scorer normalizes triggered weights onto a `0-100` integer scale:

```text
risk_score = round((sum_of_triggered_weights / sum_of_all_evaluated_weights) * 100)
```

Normalized scores map to three risk tiers configured in `app/config.py`:
* **`LOW` (`0-30`)**
* **`MEDIUM` (`31-60`)**
* **`HIGH` (`61-100`)**

*Note on weights and thresholds:* These weights and cutoff thresholds are illustrative starting points for heuristic triage, not coefficients derived from a labeled dataset. In a production environment, weights and decision boundaries would be calibrated against a corpus of verified phishing and benign URLs to optimize precision and recall.

---

## Threat Model & Limitations

### Risk Indicators, Not a Definitive Verdict
This service evaluates static lexical indicators in the URL string itself. A high score indicates that a URL exhibits structural patterns commonly used in credential-harvesting campaigns; a low score does **not** guarantee that the destination page is benign.

* **Compromised Legitimate Domains:** A phishing kit hosted on a compromised legitimate site (`https://trusted-business.com/wp-content/login.html`) will score `0` (`LOW`) under lexical analysis because the domain structure is clean.
* **Homograph / IDN Punycode Attacks:** Unicode lookalikes (`xn--pple-43d.com`) require Punycode decoding and confusable-glyph mapping beyond basic ASCII Levenshtein distance.
* **Client-Side Cloaking & Open Redirects:** Attackers frequently abuse open redirects on reputable domains or render phishing forms dynamically via JavaScript.

### Why Host-Based Signals Are Disabled by Default (`analysis.mode: "lexical"`)
While `app/engine/host.py` provides bounded DNS resolution and TLS certificate helpers, active network enrichment (WHOIS domain age, live DNS lookups, and TLS handshakes) is disabled in the default synchronous request path for three operational reasons:
1. **Latency & Availability:** Synchronous WHOIS and external DNS queries add hundreds of milliseconds to several seconds of tail latency per request and fail frequently under upstream rate limits.
2. **Attacker Tip-Off (OPSEC):** Directly probing a suspected phishing server from the API's IP address alerts the attacker's server logs and can trigger single-use phishing links to self-destruct.
3. **SSRF & Network Isolation:** Allowing unauthenticated users to trigger outbound TCP connections from the API server introduces Server-Side Request Forgery (SSRF) risks against internal infrastructure unless strictly egress-filtered.