# slayer-apis-scanner
Slayer APIs Scanner is a focused security assessment tool designed to detect misconfigured, overly permissive, or abusable Google API keys by validating real-world access across multiple Google services.

Unlike simple key validators, this tool classifies API key behavior to distinguish between:
invalid or revoked keys
valid keys with disabled APIs
quota-exhausted keys
restricted keys (IP / referer limited)
keys that allow successful, billable API access

The scanner interacts with actual Google API endpoints and evaluates responses semantically rather than relying solely on HTTP status codes, reducing false positives and false negatives commonly seen in automated checks.

✨ Key Features

Multi-service validation across Google APIs (Maps, YouTube, Vision, Translate, Drive, etc.)
Intelligent error parsing and response classification
Supports API keys via query parameters, X-Goog-Api-Key, and authorization headers
Detects successful data access, image responses, redirects, and non-JSON success cases
Threaded scanning with clean, deterministic output
Verbose mode for request/response inspection
Report-friendly PoC output and summary

🎯 Use Cases

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
