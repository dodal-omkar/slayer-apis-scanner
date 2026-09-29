# slayer_apis_scanner v5.1

Google API Key Misconfiguration Scanner — a security assessment tool for detecting exposed and misconfigured Google API keys.

[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-research-red.svg)](https://github.com/dodal-omkar/slayer-apis-scanner)
[![Version](https://img.shields.io/badge/version-v5.1-orange.svg)](https://github.com/dodal-omkar/slayer-apis-scanner)

<img width="1359" height="685" alt="image" src="https://github.com/user-attachments/assets/67f96aad-7177-43ee-889a-a9cd45588dde" />


## 🎯 Overview

**slayer_apis_scanner** is a specialized security tool for offensive security testing and API key exposure detection. It systematically probes Google API endpoints to identify misconfigurations, unrestricted access, and potential security vulnerabilities in API key implementations.

### Key Features

- **20–33 Endpoint Coverage** — Tests Google Maps, YouTube, Gemini AI, Vision, Speech, Natural Language, Drive, Translate, and Firebase-related checks across four scan profiles
- **Batch Scanning** — Supply a file of keys with `-K`; each key gets a full independent scan with a timestamped separator
- **Multi-threaded** — Concurrent endpoint testing with configurable thread count (default: 8)
- **Smart Detection** — Structured status taxonomy that differentiates INVALID_KEY, RESTRICTED, API_NOT_ENABLED, QUOTA_EXCEEDED, and ACCESSIBLE
- **PoC Generation** — Auto-generates sanitized curl commands for every accessible endpoint with `--poc`
- **Output Capture** — Save a clean ANSI-stripped copy of all terminal output with `-o` (like nmap `-oN`)
- **GCP Project Attribution** — Extracts and surfaces the GCP project ID from Google error responses automatically
- **Security-First** — API keys are masked in terminal output, verbose output, and generated PoC commands

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/dodal-omkar/slayer-apis-scanner.git
cd slayer-apis-scanner
pip install -r requirements.txt
```

### Basic Usage

```bash
# Interactive mode (prompts for key)
python slayer_apis_scanner_v5.1.py

# Direct scan
python slayer_apis_scanner_v5.1.py -a AIzaSyABC123...

# Quick profile — no AI/ML traffic
python slayer_apis_scanner_v5.1.py -a AIzaSyABC123... --profile quick

# Full deep scan with PoC generation
python slayer_apis_scanner_v5.1.py -a AIzaSyABC123... --profile deep --poc

# Batch scan from file, skip confirmation
python slayer_apis_scanner_v5.1.py -K keys.txt --profile standard -y

# Save output to file
python slayer_apis_scanner_v5.1.py -a AIzaSyABC123... --profile standard -o results.txt

# With Firebase RT DB + project-scoped checks
python slayer_apis_scanner_v5.1.py -a AIzaSyABC123... --profile standard \
  --firebase-url https://myapp-default-rtdb.firebaseio.com \
  --project-id my-gcp-project-123
```

## 🔧 Command-Line Options

| Option | Description |
|---|---|
| `-a`, `--api-key` | Google API key to test. |
| `-K`, `--keys-file` | Batch mode — one key per line, `#` lines skipped. |
| `-o`, `--output` | Save ANSI-stripped output to file (overwrites with warning). |
| `--profile` | `quick` / `standard` / `deep` / `custom`. Default: `custom`. |
| `-y`, `--yes` | Skip confirmation prompt (useful for CI/automation). |
| `-v`, `--verbose` | Show sanitized HTTP request/response details. |
| `--debug` | Print a status line for every endpoint. |
| `--poc` | Generate curl PoCs for accessible endpoints. |
| `--no-ai` | Skip Gemini, TTS, STT, and Natural Language checks. |
| `--no-maps` | Skip all 14 Maps Platform endpoints. |
| `--no-state-change` | Skip Firebase signUp (creates a real account if open). |
| `--no-experimental` | Skip the undocumented translate-pa probe. |
| `--firebase-url` | Add Firebase RT DB world-read probes (no API key used). |
| `--project-id` | Add Cloud Storage List + Firebase Remote Config checks. |
| `-t`, `--threads` | Concurrent threads. Default: `8`. |
| `--retries` | Extra retries on timeout/connection failures. Default: `0`. |
| `--delay-ms` | Delay in ms before each request. Default: `0`. |

## 📊 Scan Profiles

| Profile | AI/ML | State change | Experimental | Maps | Endpoints |
|---|---|---|---|---|---:|
| `quick` | ❌ | ❌ | ❌ | ✅ | 20 |
| `standard` | ✅ | ❌ | ❌ | ✅ | 31 |
| `deep` | ✅ | ✅ | ✅ | ✅ | 33 |
| `custom` | ✅ | ✅ | ✅ | ✅ | 33 |

`--project-id` adds 2 endpoints. `--firebase-url` adds 2 endpoints.

### Endpoint Inventory

**`quick` (20):** Custom Search, Translate v2, YouTube ×2, Maps ×14 (Static Maps, Streetview, Directions, Geocode, Distance Matrix, Find Place, Autocomplete, Elevation, Timezone, Roads nearestRoads, Roads snapToRoads, Geolocate, Routes v2, Address Validation), Vision, Drive.

**`standard` adds 11:** Text-to-Speech, Gemini List Files, Gemini List Models, Gemini generateContent, Gemini generateContent (vision), Gemini embedContent, Gemini countTokens, Speech-to-Text, NL Sentiment, NL Entities, NL Syntax.

**`deep` adds 2:** Firebase signUp, Translate-PA (undocumented internal endpoint).

**`custom`** — Same baseline as `deep`; use `--no-*` flags to disable selected modules.

## 📈 Output Interpretation

The scanner classifies every endpoint into a structured status — it does not treat every non-200 as a vulnerability.

✅ **ACCESSIBLE** — Request succeeded; endpoint is usable with this key. Confirm impact manually.  
⚠️ **API_NOT_ENABLED** — Key is valid but the API is not enabled for this project.  
⚠️ **RESTRICTED** — Key is restricted by IP, Referer, or permission policy.  
⚠️ **QUOTA_EXCEEDED** — Key valid but quota exhausted (after one adaptive retry).  
⚠️ **KEY_VALID_NO_FINDING** — Key reached the service but the probe didn't establish accessible access.  
⚠️ **BAD_TEST_DATA** — Service usable but test payload rejected as invalid input.  
❌ **INVALID_KEY** — Key rejected as invalid by Google.  
❌ **ENDPOINT_NOT_FOUND** — Endpoint or model not available — not a key finding.  
❌ **REQUEST_FAILED / TIMEOUT / HTTP_ERROR / UNKNOWN** — Infrastructure or classification failure.

## ⚡ Performance Tips

1. **Skip Maps** if not in scope — saves 14 requests: `--no-maps`
2. **Skip AI/ML** if not needed — saves 11 requests: `--no-ai`
3. **Increase threads** for faster scanning: `-t 16`
4. **Throttle for rate-sensitive targets**: `-t 4 --retries 2 --delay-ms 250`
5. **Batch + auto-confirm** for multi-key automation: `-K keys.txt -y`

## 🔍 Detection Logic

- **200/201 with valid JSON** (no error field) → `ACCESSIBLE`
- **200 with JSON null** (empty but accessible Firebase DB) → `ACCESSIBLE`
- **403 `accessNotConfigured`** → `API_NOT_ENABLED`
- **403 `quotaExceeded`** → `QUOTA_EXCEEDED` (retried once after 3 s)
- **403 `refererNotAllowed` / `ipRefererBlocked`** → `RESTRICTED`
- **400/403 `invalidApiKey`** → `INVALID_KEY`
- **Key auth fallback** — if query-param returns `INVALID_KEY` or `API_NOT_ENABLED`, retries with `X-Goog-Api-Key` header automatically
- **GCP project attribution** — project ID/name extracted from Google error prose and surfaced in the summary

## ⚠️ Notes

- **Firebase signUp** (`deep`/`custom`) can create a real Firebase auth account. Use `--no-state-change` if account creation isn't authorized.
- **Firebase RT DB probes** don't use the API key — they test unauthenticated reads controlled by Firebase Rules.
- **Maps and AI/ML endpoints** may consume quota and incur billing. Review the target project's billing setup before testing.
- **Custom Search** uses a fixed example `cx` engine ID — tests key access to that engine only.
- **`--project-id`** enables project-scoped probes for Cloud Storage and Firebase Remote Config. These results should be interpreted separately from API-key exposure because authorization may also depend on project/IAM configuration.

## 📝 Changelog

### v5.1 — Correctness & Hardening

- Removed FCM Legacy HTTP API probe (`fcm.googleapis.com/fcm/send`) — shut down by Google on July 22, 2024. The replacement FCM v1 API requires OAuth2, out of scope for an API key scanner. `--no-legacy-fcm` and all related wiring removed.
- Removed PaLM 2 `text-bison-001:generateText` probe — PaLM API fully decommissioned by Google.
- Updated Gemini models: `gemini-1.5-flash` → `gemini-2.5-flash`, `text-embedding-004` (retired Jan 14, 2026) → `gemini-embedding-2`.
- Corrected Translate v2 from GET to POST with JSON request body.
- Moved Gemini List Files / List Models inside the `--no-ai` gate.
- Fixed API-key masking for short keys (≤4 chars previously exposed full key).
- Fixed Routes v2 PoC to sanitize key in curl output.
- Fixed Firebase RT DB false negative — empty but accessible databases (JSON null) now correctly score `ACCESSIBLE`.
- Fixed Vision batch-response handling — partial success no longer discarded.
- Protected accessible-endpoint list with output lock (thread safety).
- Hardened curl PoC shell escaping for single quotes and header values.
- Output file now uses overwrite mode with a warning instead of silently appending.
- Hardened GCP project attribution locking.
- Removed dead warning filter; simplified `_TeeWriter.fileno()`.

### v5.0 — Expansion & Automation

- Batch scanning with `-K / --keys-file`.
- Output capture with `-o / --output`.
- GCP project attribution from Google error messages.
- Firebase Realtime Database world-read probes (`--firebase-url`).
- Firebase Remote Config read (`--project-id`).
- `--no-maps` flag.
- Maps Routes API v2 (`routes.googleapis.com`).
- Maps Address Validation.
- Maps Roads snapToRoads.
- Adaptive `QUOTA_EXCEEDED` retry.
- Improved banner and summary output.

### v4.2 — Reliability & Accuracy

- Every endpoint produces a persistent result record.
- Structured JSON error as primary classification path.
- Firebase signUp email derived from SHA-256 of the API key (deterministic).
- Header fallback auth (`X-Goog-Api-Key`) when query-param fails.
- Thread-local `requests.Session` per worker.

## In Action

<img width="1904" alt="slayer_apis_scanner in action" src="https://github.com/user-attachments/assets/730571b8-4108-4bb4-aa73-3239938cf0e2" />

---

**Disclaimer**: This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this tool.
