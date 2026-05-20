# Slayer APIs Scanner 

Slayer APIs Scanner is a focused security assessment tool designed to assess exposure and effective access scope of Google API keys by validating real-world access across multiple Google services.

The scanner distinguishes between:

- Invalid or revoked keys
- Valid keys with disabled APIs
- Quota-exhausted keys
- Restricted keys (IP / referer limited)
- Keys that allow successful billable API access

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

## Detection Coverage
- Firebase API testing
- Google Maps API checks
- Generative AI endpoint checks
- translate-pa detection
- Header fallback logic
- Multi-threaded scanning


## Disclaimer
Authorized security testing only.

The author assumes no responsibility for misuse.

## Usage
python slayer_apis_scanner_v4.py -a API_KEY

## PoC Mode
python slayer_apis_scanner_v4.py -a API_KEY --poc

**Help Menu**

$ python3 slayer_apis_scanner_v4.0.py -h

usage: slayer_apis_scanner [-h] [-a API_KEY] [-v] [--no-ai] [--no-fcm]
                           [--project-id PROJECT_ID] [-t THREADS]

Slayer APIs Scanner v4.0

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

<img width="1781" height="455" alt="image" src="https://github.com/user-attachments/assets/2919a658-fa56-4512-b272-727003f25d61" />


  **Common Options**

Verbose mode (print requests & responses)

Skip AI-related APIs (Vision / TTS)

Skip Firebase Cloud Messaging checks

Include Cloud Storage checks (requires project ID)

Control concurrency


## In Action

<img width="1904" height="913" alt="image" src="https://github.com/user-attachments/assets/730571b8-4108-4bb4-aa73-3239938cf0e2" />


