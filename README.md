# slayer_apis_scanner v4.1

Google API Key Misconfiguration Scanner — A comprehensive security tool for detecting exposed and misconfigured Google API keys.

[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-research-red.svg)](https://github.com/dodal-omkar/slayer-apis-scanner)

## 🎯 Overview

**slayer_apis_scanner** is a specialized security tool designed for offensive security testing and API key exposure detection. It systematically probes Google API endpoints to identify misconfigurations, unrestricted access, and potential security vulnerabilities in API key implementations.

### Key Features

- **35 Endpoint Coverage**: Tests critical Google services including Maps, YouTube, Firebase, Gemini AI, Vision, Translation, and more
- **Multi-threaded Scanning**: Concurrent endpoint testing for faster results (configurable up to 16+ threads)
- **Smart Detection**: Differentiates between invalid keys, valid-but-restricted keys, and exploitable access
- **PoC Generation**: Automatic curl command generation with API key sanitization
- **Zero False Positives**: Advanced error classification to eliminate misleading results
- **Security-First Design**: API keys are masked in all output to prevent accidental leakage

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/dodal-omkar/slayer-apis-scanner.git
cd slayer-apis-scanner

# Make executable
chmod +x slayer_apis_scanner_v4_1.py
```

### Basic Usage

```bash
# Interactive mode
python3 slayer_apis_scanner_v4_1.py

# Direct scan
python3 slayer_apis_scanner_v4_1.py -a AIzaSyABC123...

# Full scan with PoC generation
python3 slayer_apis_scanner_v4_1.py -a AIzaSyABC123... --poc

# Verbose mode with 16 threads
python3 slayer_apis_scanner_v4_1.py -a AIzaSyABC123... -v -t 16

# With GCP/firebase project ID for storage checks
python3 slayer_apis_scanner_v4_1.py -a AIzaSyABC123... --project-id my-project-12345
```

## 🔧 Command-Line Options
usage: slayer_apis_scanner_v4_1.py [-h] [-a API_KEY] [-v] [--poc] [--no-ai]
[--no-fcm] [--project-id PROJECT_ID]
[-t THREADS]
options:
-a, --api-key         Google API key to test
-v, --verbose         Print verbose HTTP requests/responses
--poc                 Generate curl PoC commands for vulnerabilities
--no-ai               Skip AI/ML checks (Gemini, TTS, Vision, etc.)
--no-fcm              Skip FCM checks
--project-id          GCP Project ID for Cloud Storage checks
-t, --threads         Number of concurrent threads (default: 8)
-h, --help            Show this help message and exit


## 📈 Output Interpretation

### Finding Categories

The scanner classifies API responses into several categories:

✅ **[VULN]** - Endpoint is accessible and returned valid data  
⚠️ **Valid Key but API not enabled** - Key is valid but API needs to be enabled in GCP console  
⚠️ **Valid Key but Quota Exceeded** - Key is valid but has hit rate limits  
⚠️ **Valid Key but IP/Referer Restricted** - Key exists but is properly restricted  
❌ **Invalid Key** - Key is not recognized by Google's API infrastructure  



## 📝 Changelog

### v4.1 (Current)
- [CRITICAL SECURITY] API key sanitization in PoC output
- [CRITICAL FIX] Removed permission_denied from API-not-enabled classification
- [CRITICAL FIX] Removed misleading endpoints (Calendar /users/me, Sheets, Compute Engine, Cloud Tasks)
- [Feature] Comprehensive Gemini AI testing (generateContent, embedContent, countTokens)
- [Feature] Gemini model listing and file operations
- [Feature] PaLM 2 text generation endpoint
- [Feature] Speech-to-Text API
- [Feature] Natural Language API (sentiment, entities, syntax)
- [Improvement] 35 reliable endpoints (removed 4 weak probes)
- [Security] All curl commands now mask API keys
- [Security] All responses mask API keys
- [Accuracy] permission_denied correctly classified as restricted_key

### v4.0
- [CRITICAL FIX] Removed createAuthUri false positive
- [CRITICAL FIX] EMAIL_EXISTS detection for Firebase signUp
- [Feature] --poc flag for curl command generation
- [Feature] Generative Language API endpoint
- [Feature] 8 new Maps API endpoints (Distance Matrix, Geolocate, Find Place, etc.)
- [Improvement] Better output formatting with color codes
- [Fix] Improved error detection for API responses
- [Fix] Proper JSON error field checking

### v3.1
- Show PoC URL in vulnerability output
- Restore detailed error-token parsing
- Use print_info() for thread-safe output
- Masked API key in banner
- Minor cleanups and comments

### v3.0
- Multi-threaded scanning with --threads flag
- Safer URL parameter handling with urllib.parse
- Improved error visibility for non-200 responses
- Better image response detection


## ⚡ Performance Tips

1. **Increase threads** for faster scanning: `-t 16`
2. **Skip AI checks** if not needed: `--no-ai` (saves ~13 API calls)
3. **Skip FCM** if not testing server keys: `--no-fcm`
4. **Use verbose mode** only for debugging: `-v` (slower due to output)

## 🔍 Detection Logic

The scanner uses intelligent classification:
- **200/201 with valid JSON** (no error field) → Vulnerable
- **200/201 with error field** → Not vulnerable (API limitation)
- **403 with accessNotConfigured** → Valid key, API not enabled
- **403 with quotaExceeded** → Valid key, quota limit hit
- **403 with refererNotAllowed/ipRefererBlocked** → Valid key, properly restricted
- **400/403 with invalidApiKey** → Invalid key
- **Other errors** → Logged for manual review


**Disclaimer**: This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this tool.


<img width="1781" height="455" alt="image" src="https://github.com/user-attachments/assets/2919a658-fa56-4512-b272-727003f25d61" />


## In Action

<img width="1904" height="913" alt="image" src="https://github.com/user-attachments/assets/730571b8-4108-4bb4-aa73-3239938cf0e2" />


