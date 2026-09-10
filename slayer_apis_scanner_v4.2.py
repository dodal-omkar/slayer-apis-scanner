#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  slayer_apis_scanner - Google API Key Misconfiguration Scanner
  Version : v4.2

  Author  : Slayer
  Role    : Security Research / Offensive Testing
  Scope   : Google API key exposure & misconfiguration detection

═══════════════════════════════════════════════════════════════

Changelog v4.2 (Reliability & Accuracy overhaul):

--- Round 1 (threading/reporting reliability) ---
 - [CRITICAL FIX] Failed/timeout/exception requests are no longer silently
   discarded. Every endpoint produces a persistent result record with an
   explicit final status.
 - [CRITICAL FIX] try_get()/try_post() distinguish timeout / DNS / TLS /
   proxy / connection errors instead of collapsing everything to `None`.
 - [CRITICAL FIX] Worker-thread exceptions are always captured and turned
   into an UNKNOWN result, never silently dropped.
 - [CRITICAL FIX] Final summary is derived from ALL tested endpoints, not
   just the ones that produced a finding.
 - [Accuracy] Error classification primarily parses Google's structured
   JSON error object; text/substring matching is only a fallback.
 - [Determinism] Firebase signUp test identifier derived from
   hashlib.sha256(apikey), not Python's randomized hash().

--- Round 2 (correctness/semantics overhaul - this pass) ---
 - [CRITICAL FIX] Endpoint inventory is no longer a fixed "35" claim.
   The banner now prints the ACTUAL scheduled test count, broken down by
   category (core / AI / legacy-FCM / state-changing / experimental /
   project-scoped), computed from the live task list every run.
 - [CRITICAL FIX] Renamed the `[VULN]` label to `[ACCESSIBLE]` everywhere.
   A successful API call is evidence the key can invoke that endpoint -
   it is NOT automatically a vulnerability. The summary explicitly says
   so and groups accessible endpoints by Google service family instead
   of listing them as N independent "vulnerabilities".
 - [Transparency] Firebase `accounts:signUp` is state-changing (it can
   create a real account), and the legacy FCM server-key test uses a
   different credential mechanism than a Google API key. Both are ON by
   default (along with everything else) so the tool tests everything it
   can out of the box, but each is clearly called out on the startup
   screen with the exact flag to turn it off (`--no-state-change`,
   `--no-legacy-fcm`), along with `--no-experimental` for the weak/
   undocumented `translate-pa` probe.
 - [CRITICAL FIX] Verbose/--debug output now sanitizes the API key out of
   headers, request bodies, response snippets, AND exception messages
   (previously only PoC/summary output was sanitized - verbose mode could
   still leak the raw key to a terminal/log).
 - [Accuracy] Added a distinct `BAD_TEST_DATA` status for responses where
   Google's structured error is `INVALID_ARGUMENT` (e.g. the Vision/STT/
   Gemini-Vision synthetic payloads are deliberately tiny/minimal). This
   means "the key/auth passed, the service is enabled, our synthetic
   payload was rejected" is no longer lumped into the generic, misleading
   HTTP_ERROR bucket, and is not mistaken for a key/auth problem.
 - [Accuracy] Vision API test now sends a small inline base64 image
   instead of an `imageUri` pointing at Wikimedia, removing a third-party
   network dependency that could fail independently of the API key.
 - [Accuracy] Static Maps / Street View 302/303 responses are only
   treated as accessible if the redirect target is a Google-owned host
   (googleapis.com/gstatic.com); a redirect elsewhere is now classified
   as an inconclusive HTTP_ERROR instead of an automatic finding.
 - [Accuracy] Removed the standalone `"blocked"` substring match from the
   text-based classification fallback (too broad -> false RESTRICTED).
 - [Accuracy] Updated Generative Language model IDs to currently-serving
   models; retired/unavailable models now cleanly resolve to
   ENDPOINT_NOT_FOUND (explicitly labeled "not a key finding") rather
   than being confused with an invalid key.
 - [Reliability] Added `--retries N` (default 0) with linear backoff,
   applied only to TIMEOUT/REQUEST_FAILED outcomes, and `--delay-ms N`
   to pace requests and reduce concurrency-induced rate limiting.
 - [Reliability] Requests now go through a shared `requests.Session()`
   with an explicit User-Agent, instead of a bare `requests.get/post`
   per call.
 - [Correctness] Exactly one result is now recorded per endpoint: the
   worker returns its result, the main thread performs the single
   `record_result()` call (success or exception path) - removes a
   theoretical double-record edge case.
 - [Correctness] Output ordering is now deterministic regardless of
   thread count/completion order: every task gets a stable index and the
   findings list, service-family breakdown, and debug log are all sorted
   by that index rather than by which thread happened to finish first.
 - [Housekeeping] Narrowed `warnings.filterwarnings` instead of a blanket
   ignore-everything call (SSL verification is `verify=True` everywhere
   and was never the thing generating noisy warnings).

--- Round 3 (defaults + startup UX, this pass) ---
 - [Behavior change] All endpoint categories are ON by default again
   (AI, legacy FCM, state-changing Firebase signUp, experimental
   translate-pa) - the tool tests everything it can out of the box. Each
   category has an explicit, discoverable opt-OUT flag instead
   (`--no-ai`, `--no-legacy-fcm`, `--no-state-change`, `--no-experimental`),
   and the startup screen always shows exactly what's enabled/disabled and
   the flag to change it.
 - [UX] Replaced the old banner + inventory dump with a compact "first 5
   seconds" startup screen: a boxed title, then a `Target` block (masked
   key, test count, AI/state-change/legacy-FCM/experimental/storage
   status with their disable flags, thread count, mode), then risk notes,
   then "Ready to scan."
 - [Safety] The scanner now waits for the tester to press ENTER before
   sending any network traffic (skippable with `-y`/`--yes`, and
   automatically skipped when stdin isn't a TTY, e.g. in CI/pipelines).
   Ctrl+C at that prompt exits cleanly before any request is sent.
 - [UX] Added `--profile {quick,standard,deep,custom}` so a first-time
   user doesn't have to learn every individual `--no-*`/`--*-ms` flag
   just to run a sane scan: `quick` = core APIs only, `standard` = core +
   AI (recommended default), `deep` = everything, `custom` = everything,
   fine-tuned via the individual flags (which always override whatever
   the chosen profile picked). The active profile is shown on the
   startup screen. Not passing `--profile` keeps prior behavior
   (equivalent to `custom`).

--- Round 4 (thread-safety, redirect handling, 404s, no editorializing) ---
 - [CRITICAL FIX] Replaced the single shared `requests.Session()` with a
   thread-local session (`get_session()`), one per worker thread. A
   Session's connection pool/adapters are not documented as safe for
   concurrent use by multiple threads, which could itself have been a
   remaining source of run-to-run inconsistency under `-t > 1`.
 - [CRITICAL FIX] GET requests now pass `allow_redirects=False` for
   image/redirect checks (Static Maps, Street View) instead of the
   default `True`. Previously `requests` followed 302/303 responses
   automatically, so the redirect-target validation added earlier could
   never actually see a 302/303 - it was dead code in practice.
 - [Accuracy] A bare HTTP 404 is no longer classified as
   `ENDPOINT_NOT_FOUND` on its own. Only Google's structured
   `status: "NOT_FOUND"` / `reason: "notFound"` fields do that now; an
   unstructured 404 (or a generic "not found" text match) is reported as
   `HTTP_ERROR` instead, since a 404 alone doesn't prove the endpoint or
   model is actually gone.
 - [Behavior change] Removed every confidence/severity/impact judgment
   from the tool's output: no more "confidence: high/low" field, no
   "NOT automatically a vulnerability" / "review to determine impact"
   commentary, no inconclusive-vs-conclusive framing in the summary.
   The scanner reports the status, HTTP code, and message it observed
   for each endpoint and nothing more - assessing significance is left
   entirely to the tester.

Changelog v4.1:
 - [CRITICAL SECURITY] API key sanitization in PoC output
 - [CRITICAL FIX] Removed permission_denied from API-not-enabled classification (too broad)
 - [CRITICAL FIX] Removed misleading endpoints (Calendar /users/me, Sheets, Compute Engine, Cloud Tasks)
 - [Feature] Added comprehensive Gemini AI testing, PaLM 2, Speech-to-Text, Natural Language API
 - [Security] All curl commands / responses mask API keys
 - [Accuracy] permission_denied correctly classified as restricted_key

Changelog v4.0:
 - [CRITICAL FIX] Removed createAuthUri false positive
 - [CRITICAL FIX] Added EMAIL_EXISTS detection for Firebase signUp
 - [Feature] --poc flag, Generative Language API, 8 new Maps endpoints
 - [Fix] Proper JSON error field checking, dynamic email generation
"""

import requests
import warnings
import sys
import json
import argparse
import threading
import time
import hashlib
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# verify=True is used for every request in this tool, so urllib3's
# InsecureRequestWarning never fires. We only suppress that specific,
# known-noisy category instead of silencing all warnings.
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

TOOL_NAME = "slayer_apis_scanner"
TOOL_VERSION = "v4.2"
DEFAULT_TIMEOUT = 12
MAX_WORKERS = 8

# Global Flags / Locks
VERBOSE_MODE = False
DEBUG_MODE = False
POC_MODE = False
RETRY_COUNT = 0          # extra attempts beyond the first, only for TIMEOUT/REQUEST_FAILED
RETRY_BACKOFF_BASE = 1.0 # seconds; attempt N waits N * this before retrying
REQUEST_DELAY_MS = 0     # optional pacing delay before each request
CURRENT_APIKEY = None    # set at scan start; used ONLY to sanitize verbose/debug/exception output
PRINT_LOCK = threading.Lock()
RESULTS_LOCK = threading.Lock()
ACCESSIBLE_ENDPOINTS = []  # endpoints that returned a working, evaluable response (NOT "vulnerabilities")
ALL_RESULTS = []           # persistent record for EVERY endpoint, regardless of outcome

# requests.Session is NOT documented as thread-safe for concurrent use of
# the same instance (its connection pool / adapters can behave oddly under
# concurrent access), and this scanner's whole point is eliminating
# concurrency-induced inconsistency. Each worker thread gets its own
# Session, lazily created on first use, instead of sharing one.
_THREAD_LOCAL = threading.local()

def get_session():
    if not hasattr(_THREAD_LOCAL, "session"):
        _THREAD_LOCAL.session = requests.Session()
        _THREAD_LOCAL.session.headers.update({"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
    return _THREAD_LOCAL.session

# ----------------- Result status taxonomy ----------------- #
# Every endpoint ends up in exactly one of these buckets. Nothing is
# silently discarded - if we couldn't get a usable answer, it lands in
# REQUEST_FAILED / TIMEOUT / UNKNOWN instead of just disappearing.

STATUS_ACCESSIBLE = "ACCESSIBLE"
STATUS_API_NOT_ENABLED = "API_NOT_ENABLED"
STATUS_RESTRICTED = "RESTRICTED"
STATUS_INVALID_KEY = "INVALID_KEY"
STATUS_QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
STATUS_NOT_FOUND = "ENDPOINT_NOT_FOUND"     # deprecated/retired model or endpoint - NOT a key problem
STATUS_KEY_VALID_NO_FINDING = "KEY_VALID_NO_FINDING"  # e.g. Firebase EMAIL_EXISTS
STATUS_BAD_TEST_DATA = "BAD_TEST_DATA"      # Google's own INVALID_ARGUMENT: auth passed, our synthetic payload didn't
STATUS_REQUEST_FAILED = "REQUEST_FAILED"    # connection/DNS/TLS/proxy/reset errors
STATUS_TIMEOUT = "TIMEOUT"
STATUS_HTTP_ERROR = "HTTP_ERROR"            # got a response, but an unclassifiable non-2xx/error shape
STATUS_UNKNOWN = "UNKNOWN"                  # unexpected exception inside the check itself

STATUS_ORDER = [
    STATUS_ACCESSIBLE, STATUS_API_NOT_ENABLED, STATUS_RESTRICTED,
    STATUS_INVALID_KEY, STATUS_QUOTA_EXCEEDED, STATUS_NOT_FOUND,
    STATUS_KEY_VALID_NO_FINDING, STATUS_BAD_TEST_DATA,
    STATUS_REQUEST_FAILED, STATUS_TIMEOUT, STATUS_HTTP_ERROR, STATUS_UNKNOWN,
]

# Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY = '\033[90m'

STATUS_COLOR = {
    STATUS_ACCESSIBLE: Colors.FAIL,
    STATUS_API_NOT_ENABLED: Colors.WARNING,
    STATUS_RESTRICTED: Colors.WARNING,
    STATUS_INVALID_KEY: Colors.GRAY,
    STATUS_QUOTA_EXCEEDED: Colors.WARNING,
    STATUS_NOT_FOUND: Colors.GRAY,
    STATUS_KEY_VALID_NO_FINDING: Colors.GRAY,
    STATUS_BAD_TEST_DATA: Colors.GRAY,
    STATUS_REQUEST_FAILED: Colors.WARNING,
    STATUS_TIMEOUT: Colors.WARNING,
    STATUS_HTTP_ERROR: Colors.WARNING,
    STATUS_UNKNOWN: Colors.FAIL,
}

# ----------------- Utils ----------------- #

def sanitize_key(text, key):
    """Replace an API key with its masked form anywhere it appears in text."""
    if not text or not key:
        return text
    masked = mask_api_key(key)
    return text.replace(key, masked)

def _san(text):
    """Sanitize using the current scan's API key, if one is set. Used for
    verbose/debug/exception output so the raw key never hits a terminal
    or log even outside of PoC/summary output."""
    if text is None or not CURRENT_APIKEY:
        return text
    return sanitize_key(str(text), CURRENT_APIKEY)

def _enabled_line(label, enabled, disable_flag, extra=None):
    tick = f"{Colors.FAIL}✓ Enabled{Colors.ENDC}" if enabled else f"{Colors.GRAY}✗ Disabled{Colors.ENDC}"
    hint = f" {Colors.GRAY}({disable_flag}){Colors.ENDC}"
    line = f"  {label:<14}{tick}{hint}"
    if extra:
        line += f" {Colors.GRAY}{extra}{Colors.ENDC}"
    return line

def banner(masked_key=None, threads=None, total_tasks=None, run_ai=True, run_fcm=True,
           allow_state_change=True, experimental=True, project_id=None, assume_yes=False,
           profile="custom"):
    """Prints a compact, scannable startup screen - target, test inventory,
    and risk notes should be understandable in the first few seconds,
    before any network traffic goes out. Then (unless --yes / non-interactive)
    waits for the tester to confirm before the scan actually starts."""
    with PRINT_LOCK:
        print(f"\n{Colors.HEADER}{Colors.BOLD}╭──────────────────────────────────────────────────────────────╮{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}│ {TOOL_NAME.upper()} {TOOL_VERSION:<10}{'':<38}│{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}│ Google API Key Security Assessment{'':<29}│{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}╰──────────────────────────────────────────────────────────────╯{Colors.ENDC}")

        print(f"\n{Colors.BOLD}Target{Colors.ENDC}")
        if masked_key is not None:
            print(f"  {'API Key':<14}{masked_key}")
        print(f"  {'Profile':<14}{profile} {Colors.GRAY}(--profile quick|standard|deep|custom){Colors.ENDC}")
        if total_tasks is not None:
            print(f"  {'Tests':<14}{total_tasks} endpoints")
        print(_enabled_line("AI Checks", run_ai, "--no-ai"))
        print(_enabled_line("State Change", allow_state_change, "--no-state-change",
                            extra="(Firebase signUp - can create a real account)" if allow_state_change else None))
        print(_enabled_line("Legacy FCM", run_fcm, "--no-legacy-fcm",
                            extra="(different credential mechanism)" if run_fcm else None))
        print(_enabled_line("Experimental", experimental, "--no-experimental",
                            extra="(weak/undocumented probes)" if experimental else None))
        if project_id:
            print(f"  {'Cloud Storage':<14}{Colors.FAIL}✓ Enabled{Colors.ENDC} {Colors.GRAY}(project: {project_id}){Colors.ENDC}")
        else:
            print(f"  {'Cloud Storage':<14}{Colors.GRAY}✗ Disabled (needs --project-id){Colors.ENDC}")
        if threads is not None:
            print(f"  {'Threads':<14}{threads}")
        mode_bits = ['Debug' if DEBUG_MODE else ('Verbose' if VERBOSE_MODE else 'Standard')]
        print(f"  {'Mode':<14}{' + '.join(mode_bits)} | PoC: {'Enabled' if POC_MODE else 'Disabled'}")

        if allow_state_change:
            print(f"\n{Colors.WARNING}⚠  State-changing test enabled: Firebase signUp may create a real account.{Colors.ENDC}")

        print(f"\n{Colors.BOLD}Ready to scan.{Colors.ENDC}")

    if assume_yes or not sys.stdin.isatty():
        return

    try:
        input(f"{Colors.OKCYAN}Press ENTER to start, or Ctrl+C to cancel...{Colors.ENDC} ")
    except (KeyboardInterrupt, EOFError):
        with PRINT_LOCK:
            print(f"\n{Colors.GRAY}Cancelled by user - no requests were sent.{Colors.ENDC}")
        sys.exit(130)

def verbose_log(method, url, headers, data=None, resp=None):
    if not (VERBOSE_MODE or DEBUG_MODE):
        return
    with PRINT_LOCK:
        print(f"\n{Colors.GRAY}[VERBOSE] > {method} {_san(url)}")
        if headers:
            try:
                print(f"Headers: {_san(json.dumps(headers))}")
            except Exception:
                print(f"Headers: {_san(headers)}")
        if data:
            print(f"Body: {_san(data)}")
        if resp is not None:
            try:
                print(f"< Status: {resp.status_code}")
                snippet = _san(resp.text[:200].replace('\n', ' '))
                print(f"< Resp Body: {snippet}...{Colors.ENDC}")
            except Exception:
                print(f"< Resp Body: (binary/unprintable)...{Colors.ENDC}")

def generate_curl_command(method, url, headers=None, data=None, json_body=None):
    curl_parts = ["curl", "-s"]
    if method.upper() == "POST":
        curl_parts.append("-X POST")
    if headers:
        for key, value in headers.items():
            curl_parts.append(f'-H "{key}: {value}"')
    if data:
        curl_parts.append(f"-d '{data}'")
    elif json_body:
        curl_parts.append(f"-d '{json.dumps(json_body)}'")
    curl_parts.append(f'"{url}"')
    return " ".join(curl_parts)

def print_finding(name, url, note=None, method="GET", headers=None, data=None, json_body=None,
                   response_preview=None, apikey=None, idx=None, family=None):
    """An endpoint returned a working, evaluable response. This is labeled
    [ACCESSIBLE], not [VULN] - whether it is a security issue depends on
    context (was the key meant to be public? is this API meant to be
    reachable? etc.) which only the tester can determine."""
    with PRINT_LOCK:
        print(f"\n{Colors.FAIL}[ACCESSIBLE]{Colors.ENDC} {name}" + (f" {Colors.GRAY}({family}){Colors.ENDC}" if family else ""))

        if POC_MODE:
            curl_cmd = generate_curl_command(method, url, headers, data, json_body)
            if apikey:
                curl_cmd = sanitize_key(curl_cmd, apikey)
            print(f"{Colors.GRAY}       PoC cURL: {Colors.ENDC}{curl_cmd}")
            if response_preview:
                if apikey:
                    response_preview = sanitize_key(response_preview, apikey)
                print(f"{Colors.GRAY}       Response:{Colors.ENDC}")
                print(response_preview)

        if note:
            if apikey:
                note = sanitize_key(note, apikey)
            print(f"{Colors.GRAY}       Note    : {Colors.ENDC}{note}")

        sanitized_curl = None
        sanitized_response = None
        if POC_MODE:
            sanitized_curl = generate_curl_command(method, url, headers, data, json_body)
            if apikey:
                sanitized_curl = sanitize_key(sanitized_curl, apikey)
            if response_preview and apikey:
                sanitized_response = sanitize_key(response_preview, apikey)

        ACCESSIBLE_ENDPOINTS.append({
            "idx": idx, "name": name, "family": family or "Other",
            "url": url, "note": note, "curl": sanitized_curl, "response": sanitized_response,
        })

def print_info(msg, color=None):
    with PRINT_LOCK:
        print(f"{color}{msg}{Colors.ENDC}" if color else msg)

def record_result(result):
    """Persist a per-endpoint result record. Every endpoint gets exactly
    one of these, no matter what happened to it. This is the single
    source of truth the final summary is built from."""
    with RESULTS_LOCK:
        ALL_RESULTS.append(result)

    if DEBUG_MODE:
        color = STATUS_COLOR.get(result["status"], Colors.GRAY)
        with PRINT_LOCK:
            attempts_str = ""
            if len(result.get("attempts", [])) > 1:
                attempts_str = " | attempts: " + " -> ".join(
                    f"{a['auth_method']}={a['status']}" for a in result["attempts"]
                )
            idx_str = f"{result.get('idx'):>2}. " if result.get('idx') is not None else ""
            print(
                f"{Colors.GRAY}[DEBUG] {idx_str}{color}{result['status']:<20}{Colors.ENDC}{Colors.GRAY}"
                f" {result['name']:<38} http={result.get('http_status')} "
                f"reason={_san(result.get('reason'))} "
                f"elapsed={result.get('elapsed_ms')}ms{attempts_str}{Colors.ENDC}"
            )

# ----------------- HTTP helpers (never silently swallow failures) ----------------- #

def _classify_exception(e):
    if isinstance(e, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(e, requests.exceptions.SSLError):
        return "tls_error"
    if isinstance(e, requests.exceptions.ProxyError):
        return "proxy_error"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "connection_error"  # covers DNS errors, reset, refused, etc.
    return "request_failed"

def try_get(url, headers=None, allow_redirects=True, timeout=DEFAULT_TIMEOUT):
    """Returns (resp, err). `err` is a dict with a specific `type` and
    sanitized `message` - never a bare None-means-everything-failed."""
    try:
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("GET", url, headers)
        resp = get_session().get(url, headers=headers, verify=True, allow_redirects=allow_redirects, timeout=timeout)
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("GET", url, headers, resp=resp)
        return resp, None
    except requests.exceptions.RequestException as e:
        err_type = _classify_exception(e)
        msg = _san(str(e))
        if VERBOSE_MODE or DEBUG_MODE:
            with PRINT_LOCK:
                print(f"{Colors.GRAY}[VERBOSE] Request failed ({err_type}): {msg}{Colors.ENDC}")
        return None, {"type": err_type, "message": msg}

def try_post(url, data=None, json_body=None, headers=None, timeout=DEFAULT_TIMEOUT):
    send_data = data
    try:
        if send_data is None and json_body is not None:
            send_data = json.dumps(json_body)
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("POST", url, headers, data=send_data)

        kwargs = {'headers': headers or {}, 'verify': True, 'timeout': timeout}
        if data is not None:
            kwargs['data'] = data
        elif json_body is not None:
            kwargs['json'] = json_body

        resp = get_session().post(url, **kwargs)
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("POST", url, headers, data=send_data, resp=resp)
        return resp, None
    except requests.exceptions.RequestException as e:
        err_type = _classify_exception(e)
        msg = _san(str(e))
        if VERBOSE_MODE or DEBUG_MODE:
            with PRINT_LOCK:
                print(f"{Colors.GRAY}[VERBOSE] Request failed ({err_type}): {msg}{Colors.ENDC}")
        return None, {"type": err_type, "message": msg}

# ----------------- Error parsing & classification ----------------- #

def parse_structured_error(resp):
    """Extract Google's structured JSON error object, if present:
        {"error": {"code":403, "message":"...", "status":"PERMISSION_DENIED",
                   "errors":[{"reason":"accessNotConfigured", ...}]}}
    Returns a dict {status, reason, message} or None. This is the PRIMARY
    classification path - text scraping is only a fallback."""
    try:
        j = resp.json()
    except Exception:
        return None
    if not isinstance(j, dict):
        return None
    err = j.get("error")
    if not isinstance(err, dict):
        return None

    status_field = err.get("status")
    message_field = err.get("message") or ""
    reason_field = None
    errors_list = err.get("errors")
    if isinstance(errors_list, list) and errors_list:
        e0 = errors_list[0]
        if isinstance(e0, dict):
            reason_field = e0.get("reason")

    return {"status": status_field, "reason": reason_field, "message": message_field}

def classify_structured(struct, http_status):
    """Classify using Google's structured error fields.
    Returns a STATUS_* constant, or None if the structured data doesn't
    clearly match a known category (caller should fall back to text)."""
    if struct is None:
        return None

    status = (struct.get("status") or "").upper()
    reason = (struct.get("reason") or "").lower()
    message = (struct.get("message") or "").lower()

    # Only trust Google's own structured status/reason for "not found" -
    # a bare HTTP 404 by itself doesn't prove the endpoint/model is gone
    # (could be a wrong path, wrong version, unsupported operation, etc.).
    # That bare-404 case is handled separately below, as STATUS_HTTP_ERROR.
    if status == "NOT_FOUND" or reason == "notfound":
        return STATUS_NOT_FOUND

    if "api key not valid" in message or "invalid api key" in message or reason == "keyinvalid":
        return STATUS_INVALID_KEY

    if status == "UNAUTHENTICATED":
        return STATUS_INVALID_KEY

    if reason in ("accessnotconfigured", "servicedisabled") or \
       "has not been used in project" in message or "it is disabled" in message or \
       "api has not been used" in message:
        return STATUS_API_NOT_ENABLED

    if reason in ("quotaexceeded", "ratelimitexceeded", "userratelimitexceeded", "dailylimitexceeded") \
       or status == "RESOURCE_EXHAUSTED" or "quota" in message:
        return STATUS_QUOTA_EXCEEDED

    if reason in ("iprefererblocked", "referernotallowed", "refererblocked") or \
       "referer not allowed" in message or "ip not allowed" in message or \
       "requests from this ip" in message or "not authorized to use this api" in message:
        return STATUS_RESTRICTED

    if status == "PERMISSION_DENIED":
        return STATUS_RESTRICTED

    # Signal that auth/service checks passed and Google rejected the
    # request body/params - i.e. our synthetic test payload, not the key.
    # Checked AFTER key/enablement/quota/restriction checks above so an
    # invalid-key response phrased as INVALID_ARGUMENT is still caught by
    # the message check first.
    if status == "INVALID_ARGUMENT":
        return STATUS_BAD_TEST_DATA

    # A bare HTTP 404 with no structured NOT_FOUND status/reason isn't
    # strong enough evidence on its own to call the endpoint/model
    # nonexistent - report it as an unclassified HTTP error instead of
    # asserting anything about the endpoint or the key.
    if http_status == 404:
        return STATUS_HTTP_ERROR

    return None

def classify_reason_text(resp):
    """Fallback substring classification for non-JSON/HTML error pages
    with no structured `error` object."""
    try:
        txt = (resp.text or "")[:1200]
    except Exception:
        txt = ""
    low = txt.lower()

    if "api key not valid" in low or "invalid api key" in low or "invalidapikey" in low:
        return STATUS_INVALID_KEY, "invalid_key_text_match"
    if "accessnotconfigured" in low or "has not been used in project" in low or "service_disabled" in low:
        return STATUS_API_NOT_ENABLED, "api_not_enabled_text_match"
    if "quotaexceeded" in low or "quota exceeded" in low:
        return STATUS_QUOTA_EXCEEDED, "quota_exceeded_text_match"
    if "referernotallowed" in low or "referer not allowed" in low or "ip not allowed" in low or "iprefererblocked" in low:
        return STATUS_RESTRICTED, "restricted_text_match"
    # NOTE: a bare "not found" text match was removed here too, for the
    # same reason as the HTTP-404 case above - it isn't strong enough
    # evidence to assert the endpoint/model doesn't exist.
    if "permissiondenied" in low or "permission denied" in low:
        return STATUS_RESTRICTED, "restricted_text_match_weak"
    # NOTE: a bare "blocked" match was removed here - it was too broad and
    # could misclassify unrelated HTML error pages as IP/referer restricted.
    return STATUS_HTTP_ERROR, "unclassified_text"

def is_image_response(resp):
    if resp is None:
        return False
    try:
        ctype = resp.headers.get("Content-Type", "").lower()
        if any(x in ctype for x in ["image", "png", "jpeg", "jpg"]):
            return True
    except Exception:
        pass
    try:
        b = resp.content[:4]
        if b.startswith(b"\x89PNG") or b.startswith(b"\xff\xd8"):
            return True
    except Exception:
        pass
    return False

def is_trusted_google_redirect(location):
    """Only treat a 302/303 as evidence of accessibility if it points at a
    Google-owned host. A redirect to a login/consent/error page elsewhere
    is not proof the requested API operation succeeded."""
    if not location:
        return False
    try:
        netloc = urlparse(location).netloc.lower()
    except Exception:
        return False
    return netloc.endswith("googleapis.com") or netloc.endswith("gstatic.com") or netloc.endswith("google.com")

# ----------------- URL helpers ----------------- #

def strip_key_param(url: str) -> str:
    try:
        p = urlparse(url)
        qs = parse_qsl(p.query, keep_blank_values=True)
        qs = [(k, v) for (k, v) in qs if k.lower() != "key"]
        new_q = urlencode(qs)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
    except Exception:
        return url

def mask_api_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return key[0:2] + "*" * max(0, len(key) - 4) + key[-2:]
    return key[:4] + "*" * (len(key) - 8) + key[-4:]

# ----------------- Endpoint Check Logic ----------------- #

def _do_request_with_retries(method, url, headers, json_body, data, force_raw_data, allow_redirects=True):
    """Fires the HTTP request, retrying only TIMEOUT/connection-type
    failures up to RETRY_COUNT extra times with linear backoff. Returns
    (resp, err, attempts_made)."""
    attempts_made = 0
    resp, err = None, None
    for attempt_num in range(RETRY_COUNT + 1):
        attempts_made += 1
        if REQUEST_DELAY_MS > 0:
            time.sleep(REQUEST_DELAY_MS / 1000.0)

        if method == "GET":
            resp, err = try_get(url, headers=headers, allow_redirects=allow_redirects)
        else:
            if force_raw_data and data is None and json_body is not None:
                resp, err = try_post(url, data=json.dumps(json_body), headers=headers)
            else:
                resp, err = try_post(url, data=data, json_body=json_body, headers=headers)

        if resp is not None:
            break
        if err["type"] not in ("timeout", "connection_error"):
            break  # not the kind of transient failure a retry can help with
        if attempt_num < RETRY_COUNT:
            time.sleep(RETRY_BACKOFF_BASE * (attempt_num + 1))

    return resp, err, attempts_made

def _perform_single_attempt(method, url, headers, json_body, data, auth_method,
                             expect_image, treat_200_non_json_as_vuln, force_raw_data):
    """Performs one HTTP attempt (with retry policy applied) and returns a
    fully-populated attempt/result dict. Every branch resolves to an
    explicit status - nothing falls through to an implicit None/False."""

    # Image/redirect tests (Static Maps, Streetview) need the raw 302/303
    # response to validate the redirect target themselves - if requests
    # followed it automatically, that check below would never see it.
    allow_redirects = not expect_image

    t0 = time.perf_counter()
    resp, err, attempts_made = _do_request_with_retries(
        method, url, headers, json_body, data, force_raw_data, allow_redirects=allow_redirects
    )
    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    base = {
        "auth_method": auth_method, "elapsed_ms": elapsed_ms, "http_status": None,
        "reason": None, "message": None, "vuln": False,
        "response_obj": None, "attempts_made": attempts_made,
    }

    if resp is None:
        base["status"] = STATUS_TIMEOUT if err["type"] == "timeout" else STATUS_REQUEST_FAILED
        base["reason"] = err["type"]
        base["message"] = f"{err['message']} (after {attempts_made} attempt(s))"
        return base

    base["http_status"] = resp.status_code

    # ---- Image / redirect based checks (Static Maps, Streetview) ---- #
    if expect_image:
        if resp.status_code == 200 and is_image_response(resp):
            base["status"] = STATUS_ACCESSIBLE
            base["vuln"] = True
            base["message"] = f"Returned image ({len(resp.content)} bytes)"
            return base
        if resp.status_code in (302, 303):
            location = resp.headers.get('Location')
            if is_trusted_google_redirect(location):
                base["status"] = STATUS_ACCESSIBLE
                base["vuln"] = True
                base["message"] = f"Redirected to Google-owned host: {location}"
                return base
            base["status"] = STATUS_HTTP_ERROR
            base["message"] = f"Redirected to non-Google host ({location})"
            return base
        struct = parse_structured_error(resp)
        cls = classify_structured(struct, resp.status_code)
        if cls:
            base["status"] = cls
            base["reason"] = struct.get("reason") or struct.get("status")
            base["message"] = struct.get("message")
            return base
        cls, reason_tag = classify_reason_text(resp)
        base["status"] = cls
        base["reason"] = reason_tag
        return base

    # ---- Normal JSON/text based checks ---- #
    if resp.status_code in (200, 201):
        try:
            j = resp.json()
        except ValueError:
            j = None

        if j is not None and isinstance(j, dict):
            if j.get("error"):
                error_obj = j["error"]
                error_msg = error_obj.get("message", "") if isinstance(error_obj, dict) else str(error_obj)
                if "EMAIL_EXISTS" in error_msg or "email already exists" in error_msg.lower():
                    base["status"] = STATUS_KEY_VALID_NO_FINDING
                    base["message"] = "Endpoint reachable, valid key, but EMAIL_EXISTS (test account already created)"
                    base["reason"] = "email_exists"
                    return base
                struct = {"status": None, "reason": None, "message": error_msg}
                if isinstance(error_obj, dict):
                    struct = parse_structured_error(resp) or struct
                cls = classify_structured(struct, resp.status_code) or STATUS_HTTP_ERROR
                base["status"] = cls
                base["reason"] = struct.get("reason") or struct.get("status")
                base["message"] = struct.get("message")
                return base

            if j.get("error_message") or j.get("errorMessage"):
                base["status"] = STATUS_HTTP_ERROR
                base["message"] = j.get("error_message") or j.get("errorMessage")
                return base

            if "responses" in j and isinstance(j["responses"], list):
                for response_item in j["responses"]:
                    if isinstance(response_item, dict) and response_item.get("error"):
                        base["status"] = STATUS_HTTP_ERROR
                        base["message"] = str(response_item.get("error"))
                        return base

            base["status"] = STATUS_ACCESSIBLE
            base["vuln"] = True
            base["response_obj"] = j
            base["message"] = f"Success: {str(j).replace(chr(10), ' ')}"
            return base

        if treat_200_non_json_as_vuln:
            base["status"] = STATUS_ACCESSIBLE
            base["vuln"] = True
            base["message"] = f"Raw response: {(resp.text or '').replace(chr(10), ' ')}"
            return base

        base["status"] = STATUS_HTTP_ERROR
        base["message"] = "200 OK but response body not recognized as JSON"
        return base

    # ---- Non-2xx: structured error first, text as fallback ---- #
    struct = parse_structured_error(resp)
    cls = classify_structured(struct, resp.status_code)
    if cls:
        base["status"] = cls
        base["reason"] = struct.get("reason") or struct.get("status")
        base["message"] = struct.get("message")
        return base

    cls, reason_tag = classify_reason_text(resp)
    base["status"] = cls
    base["reason"] = reason_tag
    base["message"] = (resp.text or "")[:300]
    return base


def check_endpoint(
    name, method, url, headers=None, json_body=None, data=None,
    expect_image=False, treat_200_non_json_as_vuln=False,
    header_fallback=False, apikey_for_header=None, use_key_header=False,
    force_raw_data=False, force_content_type=None, legacy_fcm=False,
    family=None, idx=None
):
    """Runs one endpoint check end-to-end and returns a result dict. Does
    NOT record it - the caller (scan_key's executor loop) does that once,
    guaranteeing exactly one recorded result per endpoint even if this
    function were ever called more than once for the same task."""

    method = method.upper()
    headers = headers.copy() if headers else {}
    req_url = url

    if use_key_header and apikey_for_header:
        headers["X-Goog-Api-Key"] = apikey_for_header
        req_url = strip_key_param(req_url)

    if force_content_type:
        headers["Content-Type"] = force_content_type

    if legacy_fcm:
        auth_method = "legacy_fcm_key"
    elif "X-Goog-Api-Key" in headers:
        auth_method = "header:X-Goog-Api-Key"
    else:
        auth_method = "query_parameter"

    attempts = []
    attempt = _perform_single_attempt(
        method, req_url, headers, json_body, data, auth_method,
        expect_image, treat_200_non_json_as_vuln, force_raw_data
    )
    attempts.append({"auth_method": auth_method, "status": attempt["status"], "http_status": attempt["http_status"]})

    # Header-fallback retry: only for query-param attempts that came back
    # invalid/not-enabled (i.e. plausibly an auth-transport issue). We
    # deliberately do NOT fall back on generic HTTP_ERROR - that means "we
    # don't understand the response," which retrying with a different auth
    # transport won't clarify and can muddy the primary result.
    if (header_fallback and not use_key_header and apikey_for_header and
            attempt["status"] in (STATUS_INVALID_KEY, STATUS_API_NOT_ENABLED)):
        fb_headers = headers.copy()
        fb_headers["X-Goog-Api-Key"] = apikey_for_header
        fb_url = strip_key_param(req_url)
        fb_attempt = _perform_single_attempt(
            method, fb_url, fb_headers, json_body, data, "header:X-Goog-Api-Key",
            expect_image, treat_200_non_json_as_vuln, force_raw_data
        )
        attempts.append({"auth_method": "header:X-Goog-Api-Key", "status": fb_attempt["status"], "http_status": fb_attempt["http_status"]})
        # The fallback attempt's outcome becomes the reported one, but both
        # attempts are preserved in `attempts` so it's traceable which auth
        # transport actually produced the final classification.
        attempt = fb_attempt
        req_url = fb_url
        headers = fb_headers

    result = {
        "idx": idx, "name": name, "url": req_url, "method": method, "family": family or "Other",
        "status": attempt["status"], "http_status": attempt["http_status"],
        "reason": attempt["reason"], "message": attempt["message"],
        "elapsed_ms": attempt["elapsed_ms"], "attempts": attempts,
    }

    # ---- Emit interactive output (status only - no confidence/severity judgment) ---- #
    if attempt["vuln"]:
        response_preview = None
        if POC_MODE:
            if attempt.get("response_obj") is not None:
                response_preview = json.dumps(attempt["response_obj"], indent=2)
            elif "Raw response:" in (attempt["message"] or ""):
                response_preview = attempt["message"][len("Raw response: "):]
        print_finding(name, req_url, attempt["message"], method=method, headers=headers, data=data,
                      json_body=json_body, response_preview=response_preview, apikey=apikey_for_header,
                      idx=idx, family=family)
    elif attempt["status"] == STATUS_API_NOT_ENABLED:
        print_info(f"{name}: {Colors.WARNING}Valid Key{Colors.ENDC}, API not enabled", Colors.GRAY)
    elif attempt["status"] == STATUS_QUOTA_EXCEEDED:
        print_info(f"{name}: {Colors.WARNING}Valid Key{Colors.ENDC}, Quota Exceeded", Colors.GRAY)
    elif attempt["status"] == STATUS_RESTRICTED:
        print_info(f"{name}: {Colors.WARNING}Valid Key{Colors.ENDC}, IP/Referer/Permission Restricted", Colors.GRAY)
    elif attempt["status"] == STATUS_INVALID_KEY:
        print_info(f"{name}: {Colors.FAIL}Invalid Key{Colors.ENDC}", Colors.GRAY)
    elif attempt["status"] == STATUS_KEY_VALID_NO_FINDING:
        print_info(f"{name}: {Colors.GRAY}Valid Key ({attempt['message']}){Colors.ENDC}")
    elif attempt["status"] == STATUS_BAD_TEST_DATA:
        print_info(f"{name}: {Colors.GRAY}Valid Key, INVALID_ARGUMENT ({attempt['message']}){Colors.ENDC}")
    elif attempt["status"] == STATUS_NOT_FOUND:
        print_info(f"{name}: {Colors.GRAY}NOT_FOUND ({attempt['message']}){Colors.ENDC}")
    elif attempt["status"] == STATUS_TIMEOUT:
        print_info(f"{name}: {Colors.WARNING}Timeout{Colors.ENDC}")
    elif attempt["status"] == STATUS_REQUEST_FAILED:
        print_info(f"{name}: {Colors.WARNING}Request failed ({attempt['reason']}){Colors.ENDC}")
    elif attempt["status"] == STATUS_HTTP_ERROR and (VERBOSE_MODE or DEBUG_MODE):
        print_info(f"{name}: {Colors.GRAY}HTTP {attempt['http_status']} - unclassified{Colors.ENDC}")

    return result

# ----------------- Main Scanner ----------------- #

def scan_key(apikey, run_ai=True, run_fcm=True, allow_state_change=True, experimental=True,
             project_id=None, threads=MAX_WORKERS, assume_yes=False, profile="custom"):
    global ACCESSIBLE_ENDPOINTS, ALL_RESULTS, CURRENT_APIKEY
    ACCESSIBLE_ENDPOINTS = []
    ALL_RESULTS = []
    CURRENT_APIKEY = apikey
    masked = mask_api_key(apikey)

    tasks = []  # (name, method, url, kwargs)

    # ============= STATE-CHANGING (default ON; disable with --no-state-change) ============= #
    if allow_state_change:
        key_digest = hashlib.sha256(apikey.encode("utf-8")).hexdigest()[:12]
        signup_body = {
            "email": f"test-slayer-scanner-{key_digest}@example.com",
            "password": "TestPassword123!",
            "returnSecureToken": True
        }
        tasks.append(("Firebase signUp", "POST",
                     f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={apikey}",
                     {"json_body": signup_body, "header_fallback": True, "apikey_for_header": apikey,
                      "family": "Identity/Firebase (state-changing)"}))

    # ============= HIGH VALUE ENDPOINTS ============= #
    cse_id = "017576662512468239146:omuauf_lfve"
    tasks.append(("Custom Search API", "GET",
                 f"https://www.googleapis.com/customsearch/v1?q=test&cx={cse_id}&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": "Search"}))

    tasks.append(("Translate v2", "GET",
                 f"https://translation.googleapis.com/language/translate/v2?target=en&q=Bonjour&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": "Translate"}))

    yt_base = "https://www.googleapis.com/youtube/v3"
    tasks.append(("YouTube (MostPopular)", "GET",
                 f"{yt_base}/videos?part=snippet&chart=mostPopular&maxResults=1&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": "YouTube"}))
    tasks.append(("YouTube (Search)", "GET",
                 f"{yt_base}/search?part=snippet&maxResults=1&q=test&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": "YouTube"}))

    # ============= MAPS API ENDPOINTS ============= #
    MAPS_FAMILY = "Maps Platform"
    tasks.append(("Maps - Static Maps", "GET",
                 f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={apikey}",
                 {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Streetview", "GET",
                 f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={apikey}",
                 {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Directions", "GET",
                 f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Geocode", "GET",
                 f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Distance Matrix", "GET",
                 f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615,-73.9976592&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Find Place", "GET",
                 f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art&inputtype=textquery&fields=photos,formatted_address,name&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Autocomplete", "GET",
                 f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Paris&types=(cities)&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Elevation", "GET",
                 f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Timezone", "GET",
                 f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Roads", "GET",
                 f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))
    tasks.append(("Maps - Geolocate", "POST",
                 f"https://www.googleapis.com/geolocation/v1/geolocate?key={apikey}",
                 {"json_body": {}, "header_fallback": True, "apikey_for_header": apikey, "family": MAPS_FAMILY}))

    # ============= AI/ML ENDPOINTS ============= #

    # Vision API: inline 1x1 base64 PNG instead of a third-party imageUri -
    # removes a dependency on Wikimedia's availability/reachability.
    tiny_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    vision_body = {
        "requests": [{
            "image": {"content": tiny_png_b64},
            "features": [{"type": "LABEL_DETECTION", "maxResults": 1}]
        }]
    }
    tasks.append(("Vision API", "POST",
                 f"https://vision.googleapis.com/v1/images:annotate?key={apikey}",
                 {"json_body": vision_body, "header_fallback": True, "apikey_for_header": apikey, "family": "Vision"}))

    if run_ai:
        tts_body = {
            "input": {"text": "Hello, from slayer !!!"},
            "voice": {"languageCode": "en-US", "name": "en-US-Wavenet-D"},
            "audioConfig": {"audioEncoding": "MP3"}
        }
        tasks.append(("Text-to-Speech", "POST",
                     f"https://texttospeech.googleapis.com/v1/text:synthesize?key={apikey}",
                     {"json_body": tts_body, "header_fallback": True, "apikey_for_header": apikey, "family": "Speech/Audio"}))

    GEMINI_FAMILY = "Generative Language (Gemini)"
    tasks.append(("Gemini - List Files", "GET",
                 f"https://generativelanguage.googleapis.com/v1beta/files?key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": GEMINI_FAMILY}))
    tasks.append(("Gemini - List Models", "GET",
                 f"https://generativelanguage.googleapis.com/v1beta/models?key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": GEMINI_FAMILY}))

    if run_ai:
        # NOTE: these test specific, currently-serving model IDs. Google
        # periodically retires older model names - if Google retires these,
        # the request resolves to ENDPOINT_NOT_FOUND (explicitly labeled
        # "not a key finding"), never to INVALID_KEY/RESTRICTED. Re-check
        # "Gemini - List Models" output above if these consistently 404.
        GEMINI_MODEL = "gemini-1.5-flash"
        EMBED_MODEL = "text-embedding-004"

        gemini_body = {"contents": [{"parts": [{"text": "Say hello from slayer scanner"}]}]}
        tasks.append(("Gemini - generateContent", "POST",
                     f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={apikey}",
                     {"json_body": gemini_body, "header_fallback": True, "apikey_for_header": apikey, "family": GEMINI_FAMILY}))

        gemini_vision_body = {
            "contents": [{"parts": [
                {"text": "Describe this image"},
                {"inline_data": {"mime_type": "image/png", "data": tiny_png_b64}},
            ]}]
        }
        tasks.append(("Gemini - generateContent (vision)", "POST",
                     f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={apikey}",
                     {"json_body": gemini_vision_body, "header_fallback": True, "apikey_for_header": apikey, "family": GEMINI_FAMILY}))

        embed_body = {"model": f"models/{EMBED_MODEL}", "content": {"parts": [{"text": "test embedding"}]}}
        tasks.append(("Gemini - embedContent", "POST",
                     f"https://generativelanguage.googleapis.com/v1beta/models/{EMBED_MODEL}:embedContent?key={apikey}",
                     {"json_body": embed_body, "header_fallback": True, "apikey_for_header": apikey, "family": GEMINI_FAMILY}))

        tokens_body = {"contents": [{"parts": [{"text": "test token count"}]}]}
        tasks.append(("Gemini - countTokens", "POST",
                     f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:countTokens?key={apikey}",
                     {"json_body": tokens_body, "header_fallback": True, "apikey_for_header": apikey, "family": GEMINI_FAMILY}))

        # PaLM 2 (text-bison-001) is a legacy/likely-retired model kept only
        # for completeness against older projects; a 404 here is expected
        # and is NOT evidence of anything about the key.
        palm_body = {"prompt": {"text": "Say hello from slayer scanner"}}
        tasks.append(("PaLM 2 - generateText (legacy)", "POST",
                     f"https://generativelanguage.googleapis.com/v1beta/models/text-bison-001:generateText?key={apikey}",
                     {"json_body": palm_body, "header_fallback": True, "apikey_for_header": apikey,
                      "family": "Generative Language (PaLM - legacy)"}))

        stt_body = {
            "config": {"encoding": "LINEAR16", "sampleRateHertz": 16000, "languageCode": "en-US"},
            "audio": {"content": "//uQx"},  # deliberately minimal - see BAD_TEST_DATA classification
        }
        tasks.append(("Speech-to-Text", "POST",
                     f"https://speech.googleapis.com/v1/speech:recognize?key={apikey}",
                     {"json_body": stt_body, "header_fallback": True, "apikey_for_header": apikey, "family": "Speech/Audio"}))

        nl_sentiment_body = {"document": {"type": "PLAIN_TEXT", "content": "I love this scanner!"}}
        NL_FAMILY = "Natural Language"
        tasks.append(("Natural Language - Sentiment", "POST",
                     f"https://language.googleapis.com/v1/documents:analyzeSentiment?key={apikey}",
                     {"json_body": nl_sentiment_body, "header_fallback": True, "apikey_for_header": apikey, "family": NL_FAMILY}))
        tasks.append(("Natural Language - Entities", "POST",
                     f"https://language.googleapis.com/v1/documents:analyzeEntities?key={apikey}",
                     {"json_body": nl_sentiment_body, "header_fallback": True, "apikey_for_header": apikey, "family": NL_FAMILY}))
        tasks.append(("Natural Language - Syntax", "POST",
                     f"https://language.googleapis.com/v1/documents:analyzeSyntax?key={apikey}",
                     {"json_body": nl_sentiment_body, "header_fallback": True, "apikey_for_header": apikey, "family": NL_FAMILY}))

    # ============= OTHER ENDPOINTS ============= #
    tasks.append(("Drive API (List)", "GET",
                 f"https://www.googleapis.com/drive/v3/files?pageSize=1&key={apikey}",
                 {"header_fallback": True, "apikey_for_header": apikey, "family": "Drive"}))

    # ============= EXPERIMENTAL (default ON; disable with --no-experimental) ============= #
    if experimental:
        tp_url = "https://translate-pa.googleapis.com/v1/translateHtml"
        tp_data = '[[["Hello, from slayer_apis_scanner !!!"],"en","hi"],"en"]'
        tasks.append(("Translate-PA (Internal, undocumented)", "POST", tp_url, {
            "data": tp_data, "force_raw_data": True, "force_content_type": "application/json+protobuf",
            "use_key_header": True, "apikey_for_header": apikey, "treat_200_non_json_as_vuln": True,
            "family": "Experimental/Internal",
        }))

    if project_id:
        tasks.append(("Cloud Storage List", "GET",
                     f"https://www.googleapis.com/storage/v1/b?project={project_id}&maxResults=1&key={apikey}",
                     {"header_fallback": True, "apikey_for_header": apikey, "family": "Cloud Storage"}))

    # ============= LEGACY FCM (default ON; disable with --no-legacy-fcm) ============= #
    if run_fcm:
        fcm_headers = {"Content-Type": "application/json", "Authorization": "key=" + apikey}
        fcm_body = {"registration_ids": ["ABC"]}
        tasks.append(("FCM (Legacy Server Key)", "POST", "https://fcm.googleapis.com/fcm/send",
                     {"json_body": fcm_body, "headers": fcm_headers, "legacy_fcm": True, "family": "Legacy FCM"}))

    total_tasks = len(tasks)

    # ---- Print the startup screen (target, live test inventory, risk notes) ---- #
    # and wait for the tester to confirm before any network traffic goes out.
    banner(masked_key=masked, threads=threads, total_tasks=total_tasks, run_ai=run_ai,
           run_fcm=run_fcm, allow_state_change=allow_state_change, experimental=experimental,
           project_id=project_id, assume_yes=assume_yes, profile=profile)

    print_info(f"\n{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
    print_info(f"{Colors.BOLD}Starting API endpoint scan ({total_tasks} endpoint(s))...{Colors.ENDC}\n")

    # Assign a stable index to every task up front so output/exports can be
    # sorted deterministically regardless of thread completion order.
    indexed_tasks = [(i, name, method, url, kwargs) for i, (name, method, url, kwargs) in enumerate(tasks, start=1)]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_task = {
            executor.submit(check_endpoint, name, method, url, idx=i, **kwargs): (i, name, method, url)
            for (i, name, method, url, kwargs) in indexed_tasks
        }
        for future in as_completed(future_to_task):
            i, name, method, url = future_to_task[future]
            try:
                result = future.result()
                record_result(result)  # single recording point - success path
            except Exception as e:
                tb = traceback.format_exc(limit=3)
                with PRINT_LOCK:
                    print(f"{Colors.FAIL}[ERROR] {name}: unhandled exception in worker thread: {_san(str(e))}{Colors.ENDC}")
                    if VERBOSE_MODE or DEBUG_MODE:
                        print(f"{Colors.GRAY}{_san(tb)}{Colors.ENDC}")
                record_result({  # single recording point - exception path
                    "idx": i, "name": name, "url": url, "method": method, "family": "Other",
                    "status": STATUS_UNKNOWN, "http_status": None,
                    "reason": "unhandled_exception", "message": _san(str(e)),
                    "elapsed_ms": None,
                    "attempts": [{"auth_method": "n/a", "status": STATUS_UNKNOWN, "http_status": None}],
                })

    print_summary(total_tasks)

def print_summary(total_tasks=None):
    with PRINT_LOCK:
        print(f"\n{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        print(f"{Colors.BOLD}  SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}\n")

        sorted_accessible = sorted(ACCESSIBLE_ENDPOINTS, key=lambda v: (v.get('idx') is None, v.get('idx')))

        if sorted_accessible:
            print(f"{Colors.FAIL}{Colors.BOLD}Accessible endpoints: {len(sorted_accessible)}{Colors.ENDC}\n")

            # Group by Google service family so e.g. 8 Maps endpoints don't
            # read as "8 separate vulnerabilities" when it's really "1 key
            # with the Maps Platform enabled."
            by_family = {}
            for v in sorted_accessible:
                by_family.setdefault(v["family"], []).append(v)

            print(f"{Colors.BOLD}Accessible services breakdown:{Colors.ENDC}")
            for fam, items in by_family.items():
                print(f"  {Colors.FAIL}{fam:<38}: {len(items)} endpoint(s){Colors.ENDC}")
            print()

            for v in sorted_accessible:
                idx_str = f"{v['idx']:>2}. " if v.get('idx') is not None else ""
                print(f"{Colors.FAIL}  ● {idx_str}{v['name']} {Colors.GRAY}({v['family']}){Colors.ENDC}")
                if POC_MODE and v.get('curl'):
                    print(f"{Colors.GRAY}    cURL: {v['curl']}{Colors.ENDC}")
                if POC_MODE and v.get('response'):
                    print(f"{Colors.GRAY}    Response:{Colors.ENDC}")
                    print(f"    {v['response']}")
                if v.get('note'):
                    print(f"{Colors.GRAY}    Note: {v['note']}{Colors.ENDC}")
                print()

        counts = {s: 0 for s in STATUS_ORDER}
        for r in ALL_RESULTS:
            counts[r["status"]] = counts.get(r["status"], 0) + 1

        tested = len(ALL_RESULTS)
        total = total_tasks if total_tasks is not None else tested

        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        print(f"{Colors.BOLD}Endpoint accounting (every test, not just findings){Colors.ENDC}\n")
        label_map = {
            STATUS_ACCESSIBLE: "Accessible",
            STATUS_API_NOT_ENABLED: "API not enabled",
            STATUS_RESTRICTED: "Restricted",
            STATUS_INVALID_KEY: "Invalid key",
            STATUS_QUOTA_EXCEEDED: "Quota exceeded",
            STATUS_NOT_FOUND: "Endpoint/model not found",
            STATUS_KEY_VALID_NO_FINDING: "Valid key, resource already exists",
            STATUS_BAD_TEST_DATA: "Valid key, INVALID_ARGUMENT",
            STATUS_REQUEST_FAILED: "Request failed",
            STATUS_TIMEOUT: "Timeout",
            STATUS_HTTP_ERROR: "Unclassified/HTTP error",
            STATUS_UNKNOWN: "Unknown (worker exception)",
        }
        for status in STATUS_ORDER:
            c = counts.get(status, 0)
            if c == 0:
                continue
            color = STATUS_COLOR.get(status, Colors.GRAY)
            print(f"  {color}{label_map[status]:<28}: {c}{Colors.ENDC}")

        print(f"\n  {Colors.BOLD}Execution coverage{Colors.ENDC} : {tested}/{total}")

        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        print(f"{Colors.BOLD}Total accessible endpoints: {len(sorted_accessible)}{Colors.ENDC}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        print(f"{Colors.GRAY}Scanner: {TOOL_NAME} {TOOL_VERSION} by Slayer{Colors.ENDC}")
        print(f"{Colors.GRAY}GitHub : https://github.com/dodal-omkar/slayer-apis-scanner{Colors.ENDC}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}\n")

def main():
    global VERBOSE_MODE, DEBUG_MODE, MAX_WORKERS, POC_MODE, RETRY_COUNT, REQUEST_DELAY_MS

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} {TOOL_VERSION} - Google API Key Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -a AIzaSyABC123... --profile standard   (recommended default)
  %(prog)s -a AIzaSyABC123... --profile quick
  %(prog)s -a AIzaSyABC123... --profile deep -t 16
  %(prog)s -a AIzaSyABC123... --profile custom --no-legacy-fcm --no-state-change
  %(prog)s -a AIzaSyABC123... -v --poc
  %(prog)s -a AIzaSyABC123... --debug -t 1 --retries 2
  %(prog)s -a AIzaSyABC123... -y   (skip the confirmation prompt, e.g. in CI)

Profiles (--profile):
  quick     Core APIs only (Search/Translate/YouTube/Maps/Vision/Drive) -
            no AI, no legacy FCM, no state-change, no experimental probes.
            Fastest, safest first pass.
  standard  Core + AI/Generative checks. No legacy FCM, state-change, or
            experimental probes. Recommended default for most assessments.
  deep      Everything: Core + AI + legacy FCM + Firebase signUp
            (state-changing) + experimental probes + Cloud Storage if
            --project-id is given. Most thorough, least conservative.
  custom    Every module ON by default, same as `deep`, but meant to be
            combined with the individual --no-* flags below to hand-pick
            exactly what runs.
  (default: custom - i.e. unchanged behavior if you don't pass --profile)

  Any individual --no-* flag always overrides the chosen profile, e.g.
  `--profile deep --no-state-change` runs everything deep runs except
  the Firebase signUp test.

Notes:
  * State Change (Firebase signUp) can create a real account.
  * Legacy FCM uses `Authorization: key=...`, a different credential
    mechanism than a Google API key.
  * The exact number of endpoints tested depends on the profile/flags
    above and is always printed on the startup screen.
        """
    )

    parser.add_argument("-a", "--api-key", help="Google API key to test")
    parser.add_argument("--profile", choices=["quick", "standard", "deep", "custom"], default="custom",
                       help="Preset test scope: quick (core only) / standard (core + AI, recommended) / "
                            "deep (everything) / custom (everything, fine-tune with --no-* flags). Default: custom.")
    parser.add_argument("-y", "--yes", action="store_true", dest="assume_yes",
                       help="Skip the startup confirmation prompt (for automation/CI)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Print verbose HTTP requests/responses (API key sanitized)")
    parser.add_argument("--debug", action="store_true",
                       help="Print a final status line for EVERY endpoint, including "
                            "timeouts/failures/unknowns")
    parser.add_argument("--poc", action="store_true",
                       help="Generate curl PoC commands for accessible endpoints")
    # NOTE: these default to None (not True) so we can tell "user didn't touch
    # this" apart from "user explicitly wants it off" - that's what lets an
    # individual --no-* flag override whatever the chosen --profile picked.
    parser.add_argument("--no-ai", action="store_false", dest="run_ai", default=None,
                       help="Skip AI/ML checks (TTS, Gemini generate/embed/countTokens, PaLM, STT, Natural Language). "
                            "Overrides --profile.")
    parser.add_argument("--no-legacy-fcm", action="store_false", dest="run_fcm", default=None,
                       help="Skip the legacy FCM server-key test (Authorization: key=...) - "
                            "a different credential mechanism than a Google API key. Overrides --profile.")
    parser.add_argument("--no-state-change", action="store_false", dest="allow_state_change", default=None,
                       help="Skip the Firebase accounts:signUp test - it can create a real account. Overrides --profile.")
    parser.add_argument("--no-experimental", action="store_false", dest="experimental", default=None,
                       help="Skip weak/undocumented probes (e.g. translate-pa). Overrides --profile.")
    parser.add_argument("--project-id", help="GCP Project ID for storage checks")
    parser.add_argument("-t", "--threads", type=int, default=MAX_WORKERS,
                       help=f"Number of concurrent threads (default: {MAX_WORKERS}). "
                            f"Use -t 1 for a sequential baseline to rule out concurrency-related timeouts.")
    parser.add_argument("--retries", type=int, default=0,
                       help="Extra attempts for TIMEOUT/connection failures only, with linear backoff (default: 0)")
    parser.add_argument("--delay-ms", type=int, default=0,
                       help="Delay in milliseconds before each request, to reduce concurrency-induced "
                            "rate limiting (default: 0)")

    args = parser.parse_args()

    VERBOSE_MODE = args.verbose
    DEBUG_MODE = args.debug
    POC_MODE = args.poc
    MAX_WORKERS = max(1, args.threads)
    RETRY_COUNT = max(0, args.retries)
    REQUEST_DELAY_MS = max(0, args.delay_ms)

    # Profile defaults, then any explicitly-passed --no-* flag wins.
    PROFILE_DEFAULTS = {
        "quick":    {"run_ai": False, "run_fcm": False, "allow_state_change": False, "experimental": False},
        "standard": {"run_ai": True,  "run_fcm": False, "allow_state_change": False, "experimental": False},
        "deep":     {"run_ai": True,  "run_fcm": True,  "allow_state_change": True,  "experimental": True},
        "custom":   {"run_ai": True,  "run_fcm": True,  "allow_state_change": True,  "experimental": True},
    }
    defaults = PROFILE_DEFAULTS[args.profile]
    run_ai = args.run_ai if args.run_ai is not None else defaults["run_ai"]
    run_fcm = args.run_fcm if args.run_fcm is not None else defaults["run_fcm"]
    allow_state_change = args.allow_state_change if args.allow_state_change is not None else defaults["allow_state_change"]
    experimental = args.experimental if args.experimental is not None else defaults["experimental"]

    key = args.api_key or input(f"{Colors.OKCYAN}Enter Google API Key: {Colors.ENDC}").strip()
    if not key:
        print(f"{Colors.FAIL}Error: No API key provided{Colors.ENDC}")
        sys.exit(1)

    scan_key(key, run_ai=run_ai, run_fcm=run_fcm,
            allow_state_change=allow_state_change, experimental=experimental,
            project_id=args.project_id, threads=MAX_WORKERS, assume_yes=args.assume_yes,
            profile=args.profile)

if __name__ == "__main__":
    main()
