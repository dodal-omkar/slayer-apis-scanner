# Slayer APIs Scanner
Slayer APIs Scanner is a focused security assessment tool designed to detect misconfigured, overly permissive, or abusable Google API keys by validating real-world access across multiple Google services.

Unlike simple key validators, this tool classifies API key behavior to distinguish between:
invalid or revoked keys
valid keys with disabled APIs
quota-exhausted keys
restricted keys (IP / referer limited)
keys that allow successful, billable API access

The scanner interacts with actual Google API endpoints and evaluates responses semantically rather than relying solely on HTTP status codes, reducing false positives and false negatives commonly seen in automated checks.

✨ **Key Features**

Multi-service validation across Google APIs (Maps, YouTube, Vision, Translate, Drive, etc.)
Intelligent error parsing and response classification
Supports API keys via query parameters, X-Goog-Api-Key, and authorization headers
Detects successful data access, image responses, redirects, and non-JSON success cases
Threaded scanning with clean, deterministic output
Verbose mode for request/response inspection
Report-friendly PoC output and summary

🎯 **Use Cases**

Security assessments & VAPT engagements
Mobile and web application backend reviews
API key leakage validation
Defensive testing of API key restrictions
Internal security tooling & automation

⚠️ Responsible Use

This tool sends real requests to Google APIs and may incur quota usage or billing depending on the key configuration.
Use only:
on keys you own
with explicit authorization
in controlled testing environments

The author assumes no responsibility for misuse.

**Basic Usage**

python3 slayer_apis_scanner_v3.1.py -a YOUR_GOOGLE_API_KEY

**Help Menu**

$ python3 slayer_apis_scanner_v3.1.py -h

usage: slayer_apis_scanner [-h] [-a API_KEY] [-v] [--no-ai] [--no-fcm]
                           [--project-id PROJECT_ID] [-t THREADS]

Slayer APIs Scanner v3.1

optional arguments:
  -h, --help            show this help message and exit
  -a API_KEY, --api-key API key to test
  -v, --verbose         Print verbose HTTP requests/responses
  --no-ai               Skip AI-related API checks (Vision, TTS)
  --no-fcm              Skip Firebase Cloud Messaging checks
  --project-id PROJECT_ID
                        GCP Project ID for Cloud Storage checks
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 8)


**Common Options**

Verbose mode (print requests & responses)
python3 slayer_apis_scanner_v3.1.py -a KEY -v

Skip AI-related APIs (Vision / TTS)
python3 slayer_apis_scanner_v3.1.py -a KEY --no-ai

Skip Firebase Cloud Messaging checks
python3 slayer_apis_scanner_v3.1.py -a KEY --no-fcm

Include Cloud Storage checks (requires project ID)
python3 slayer_apis_scanner_v3.1.py -a KEY --project-id my-gcp-project

Control concurrency
python3 slayer_apis_scanner_v3.1.py -a KEY -t 4
