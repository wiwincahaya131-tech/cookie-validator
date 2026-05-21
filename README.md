# Cookie Validator

Production-grade DigitalOcean cookie validation tool with robust parsing, realistic browser fingerprinting, and comprehensive threat detection.

## Features

### 🍪 Robust Cookie Parsing
- ✅ Auto-detect format (Netscape TXT vs JSON)
- ✅ Support `#HttpOnly_` prefix
- ✅ Handle malformed spacing and tabs
- ✅ Support Cookie-Editor, EditThisCookie, Chromium exports
- ✅ Graceful error handling
- ✅ Local expiry validation

### 🔐 Authentication Detection
- ✅ Multi-signal scoring (0-9)
- ✅ Critical auth cookie detection (_digitalocean2_session_v4, _digitalocean_remember_me)
- ✅ API response validation
- ✅ User data indicators
- ✅ Dashboard accessibility

### 🎭 Browser Fingerprinting
- ✅ Realistic Chrome profiles
- ✅ Modern Sec-CH-UA headers
- ✅ HTTP/2 support
- ✅ Rotating user agents
- ✅ Consistent session profiles

### 🚨 Threat Detection
- ✅ Cloudflare challenge detection
- ✅ CAPTCHA detection (reCAPTCHA, hCaptcha, Turnstile)
- ✅ Rate limiting detection (429, 503)
- ✅ Login redirect detection
- ✅ Anti-bot page detection

### 📊 Comprehensive Reporting
- ✅ Status classification:
  - `VALID` - Authenticated and working
  - `PARTIAL_AUTH` - Some auth signals detected
  - `INVALID` - Not authenticated
  - `EXPIRED` - Redirected to login
  - `CHALLENGED` - CAPTCHA/challenge required
  - `FORBIDDEN` - 403 Forbidden
  - `RATE_LIMITED` - 429/503 responses
  - `NETWORK_ERROR` - Connection failed

- ✅ JSON export with full metadata
- ✅ Human-readable TXT export
- ✅ Auto-save valid/invalid cookies
- ✅ Colored terminal output

## Architecture

### Modular Design
```
src/
├── models.py          # Data schemas and enums
├── parser.py          # Cookie format detection and parsing
├── fingerprint.py     # Browser profile generation
├── detector.py        # Authentication and threat detection
├── validator.py       # Validation engine with provider routing
├── exporter.py        # Result exporters (JSON, TXT, etc)
├── logger.py          # Colored logging
└── __init__.py        # Package exports

main.py               # CLI entry point with GUI folder selection
```

### Key Components

#### Parser (`parser.py`)
- Detects format based on structure (7+ tab-separated columns for Netscape)
- Parses Netscape format with `#HttpOnly_` prefix support
- Parses JSON format (Chrome, Firefox, EditThisCookie exports)
- Auto-detects provider from cookie domains
- Extracts root domains

#### Fingerprint (`fingerprint.py`)
- Generates stable, reproducible browser profiles
- Modern Chrome user agents (v129-131)
- Sec-CH-UA headers
- Platform-specific profiles (Windows, macOS, Linux)
- Both document and API request headers

#### Detector (`detector.py`)
- Detects Cloudflare challenges
- CAPTCHA detection with type identification
- Login redirect detection
- Rate limit detection
- Anti-bot page detection
- Authenticated response analysis

#### Validator (`validator.py`)
- Provider-based routing (DigitalOcean)
- Multi-endpoint validation strategy
- Session warmup requests
- Signal-based scoring
- Async concurrent validation

## Installation

```bash
# Clone repository
git clone https://github.com/wiwincahaya131-tech/cookie-validator.git
cd cookie-validator

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

## Usage

### Basic Usage
```bash
python main.py
```

1. **GUI folder selection** opens automatically
2. Select folder with `.txt` and `.json` cookie files
3. Validation runs concurrently (max 3 parallel)
4. Results displayed in terminal with colors
5. Results exported to `cookie_validation_results/`

### Example Output
```
[VALID          ] cookie_session_v4.txt                    (Score: 8/9, Time: 1.24s)
  └─ Auth cookies: _digitalocean2_session_v4, _digitalocean_remember_me
  └─ Endpoint: /v2/account

[EXPIRED        ] old_cookie.txt                            (Score: 0/9, Time: 0.89s)
  └─ Detected: Login redirect

[CHALLENGED     ] rate_limited.txt                          (Score: 2/9, Time: 2.15s)
  └─ Detected: Rate limit

[INVALID        ] invalid_cookie.json                       (Score: 1/9, Time: 0.95s)
  └─ Error: No auth cookies found
```

## Output Structure

```
cookie_validation_results/
├── results/
│   ├── validation_results_20250521_143022.json
│   └── validation_results_20250521_143022.txt
├── valid_cookies/
│   ├── cookie1_valid.json
│   └── cookie2_valid.json
└── invalid_cookies/
    ├── cookie3_invalid.json
    └── cookie4_invalid.json
```

## JSON Export Format

```json
{
  "timestamp": "2025-05-21T14:30:22.123456",
  "total_validations": 4,
  "valid_count": 1,
  "results": [
    {
      "file": "/path/to/cookie.txt",
      "provider": "digitalocean",
      "status": "VALID",
      "score": 8,
      "cookies_count": 15,
      "auth_cookies_count": 2,
      "valid_cookies_count": 14,
      "detections": {
        "login_redirect": false,
        "captcha": false,
        "rate_limit": false,
        "anti_bot": false
      },
      "endpoint_used": "/v2/account",
      "elapsed_time": 1.24,
      "signals": [
        {
          "name": "has_auth_cookie",
          "detected": true,
          "score": 1,
          "details": "Found 2 auth cookies"
        }
      ],
      "error": null
    }
  ]
}
```

## Configuration

### Concurrency
Edit `main.py` to adjust max concurrent validations:
```python
self.validator = CookieValidator(max_concurrency=5)  # Default: 3
```

### Timeout
Adjust in `validator.py`:
```python
response = await client.get(url, timeout=15.0)  # Default: 10.0
```

### Endpoints Priority
Edit `DigitalOceanValidator.get_endpoints()` in `src/validator.py`

## Debugging

Enable verbose logging:
```python
setup_logging(verbose=True)
```

Or by editing `main.py`:
```python
setup_logging(verbose=True, log_file="validation.log")
```

## Technical Details

### Cookie Format Detection
- **Netscape**: Counts tab-separated columns (must be ≥6)
- **JSON**: Attempts JSON parsing
- Fallback: Tries Netscape format

### Authentication Scoring
Each signal: 1 point (max 9)
- Auth cookie presence
- HTTP 200 response
- API response structure
- User data fields (email, account, etc)
- No login redirect
- No CAPTCHA detected
- No rate limit
- Response time normal
- Authenticated content indicators

### Validation Strategy
1. **Warmup**: Request homepage to establish session
2. **Endpoints**: Try endpoints in priority order
3. **Detection**: Analyze responses for auth state
4. **Classification**: Map detections to status

## Known Limitations

- Cloudflare challenges cannot be bypassed (expected behavior)
- JavaScript-required pages will show as unauthenticated
- Cookie-secured-by-origin detection relies on domain matching

## Security Notes

- Cookies are validated against remote servers (DigitalOcean)
- No cookies stored locally except export files
- Consider credentials sensitive - store safely
- Use only for authorized accounts

## License

MIT

## Author

wiwincahaya131-tech
