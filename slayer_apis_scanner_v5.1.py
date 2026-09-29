#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  slayer_apis_scanner - Google API Key Misconfiguration Scanner
  Version : v5.1

  Author  : Slayer

═══════════════════════════════════════════════════════════════

Changelog v5.1 (Correctness & Hardening):

 - [Fix] Removed FCM Legacy API (fcm.googleapis.com/fcm/send) — shut
   down July 22, 2024; new FCM v1 requires OAuth2, out of scope for
   API key scanner. Removed --no-legacy-fcm flag and all related wiring.
 - [Fix] Removed PaLM 2 text-bison-001:generateText probe — PaLM API
   fully decommissioned by Google; test always returned an error.
 - [Fix] Updated Gemini models: gemini-1.5-flash → gemini-2.5-flash,
   text-embedding-004 (retired Jan 14 2026) → gemini-embedding-2.
 - [Fix] Translate v2: corrected HTTP method GET → POST with parameters
   in JSON body per current Google REST spec.
 - [Fix] Gemini List Files / List Models moved inside if run_ai: block
   so --no-ai and quick/standard profiles suppress all Gemini traffic.
 - [Fix] mask_api_key: keys ≤4 chars no longer expose full content.
 - [Fix] Routes v2 PoC: added apikey_for_header so key is sanitized in
   --poc curl output.
 - [Fix] Firebase RT DB treat_200_non_json_as_vuln=True: JSON null
   response (empty but accessible DB) now correctly scores ACCESSIBLE.
 - [Fix] Batch Vision response loop: only returns HTTP_ERROR when all
   items failed; partial success falls through to ACCESSIBLE.
 - [Fix] ACCESSIBLE_ENDPOINTS.append moved inside PRINT_LOCK to prevent
   concurrent list mutation.
 - [Fix] curl PoC shell injection: single quotes in data and double
   quotes in header values are now properly escaped.
 - [Fix] Output file uses write mode with overwrite warning instead of
   silently appending to existing files.
 - [Fix] GCP_PROJECT_HINT double-checked locking: "already set" check
   moved inside _GCP_LOCK to eliminate read/write race.
 - [Fix] Removed dead warnings.filterwarnings (verify=True everywhere).
 - [Fix] _TeeWriter.fileno() simplified to direct delegation.

Changelog v5.0 (Expansion & Automation):

 - [Feature] -K / --keys-file: batch scan from a file (one key per
   line); blank lines and lines starting with # are skipped. Each
   key runs a full independent scan with its own summary.
 - [Feature] -o / --output: save a clean (ANSI-stripped) copy of all
   terminal output to a file, like nmap -oN. Works for single-key
   and batch mode. A timestamped separator is written before each
   key's section when scanning multiple keys.
 - [Feature] GCP project attribution: Google's "has not been used in
   project ..." error messages embed the project ID/name. The tool
   now extracts and surfaces it automatically in the summary — free
   attribution intel with no extra request.
 - [Feature] Firebase Realtime Database world-read probe: pass
   --firebase-url https://<project>-default-rtdb.firebaseio.com to
   test whether the database allows unauthenticated reads (Firebase
   Rules control this, not the API key itself).
 - [Feature] Firebase Remote Config read: added automatically when
   --project-id is given. Can leak feature flags and config values
   embedded in the app's remote configuration.
 - [Feature] --no-maps: opt-out flag that skips all Maps Platform
   endpoints in one shot (14 endpoints including new ones), reducing
   accidental billing when Maps access isn't the scan focus.
 - [Feature] Maps - Routes API v2: tests
   routes.googleapis.com/directions/v2:computeRoutes — separate
   billing surface and distinct service enablement from classic
   Directions.
 - [Feature] Maps - Address Validation: tests
   addressvalidation.googleapis.com/v1:validateAddress — high per-
   call billing cost; good signal for unrestricted keys.
 - [Feature] Maps - Roads (snapToRoads): added alongside the existing
   nearestRoads check (same API family, separate quota bucket).
 - [Accuracy] Adaptive QUOTA_EXCEEDED retry: when an endpoint returns
   QUOTA_EXCEEDED the tool waits 3 s and retries once. Concurrent
   burst scanning commonly produces per-second quota errors that
   resolve on retry; this converts those false positives to their
   true outcome automatically.
 - [UX] Improved banner: Maps Platform status, GCP project hint (when
   known), output file path, and batch key index shown. Summary now
   includes a mini bar chart per status category and service family.

Changelog v4.2 (Reliability & Accuracy overhaul):

--- Round 1 ---
 - [CRITICAL FIX] Every endpoint produces a persistent result record.
 - [CRITICAL FIX] try_get/try_post distinguish error types.
 - [CRITICAL FIX] Worker exceptions → UNKNOWN, never dropped.
 - [CRITICAL FIX] Summary derived from ALL tested endpoints.
 - [Accuracy] Structured JSON error is the primary classification path.
 - [Determinism] Firebase signUp email derived from sha256(apikey).

--- Round 2 ---
 - [CRITICAL FIX] Endpoint count from live task list, not hard-coded.
 - [CRITICAL FIX] [VULN] → [ACCESSIBLE] everywhere.
 - [Accuracy] BAD_TEST_DATA for INVALID_ARGUMENT responses.
 - [Accuracy] Vision API uses inline base64 image.
 - [Accuracy] Static Maps/Street View redirect target validation.
 - [Accuracy] Removed overbroad text fallback matches.
 - [Accuracy] Updated Gemini model IDs to currently-serving names.
 - [Reliability] --retries N with linear backoff.
 - [Reliability] Thread-local requests.Session per worker.
 - [Correctness] One result recorded per endpoint.
 - [Correctness] Deterministic output ordering by task index.

--- Round 3 ---
 - [Behavior] All categories ON by default with opt-OUT flags.
 - [UX] Compact startup screen with live test inventory.
 - [Safety] ENTER confirmation before traffic (skippable with -y).
 - [UX] --profile quick|standard|deep|custom.

--- Round 4 ---
 - [CRITICAL FIX] Thread-local sessions (one per worker).
 - [CRITICAL FIX] allow_redirects=False for image/redirect checks.
 - [Accuracy] Bare HTTP 404 → HTTP_ERROR, not ENDPOINT_NOT_FOUND.
 - [Behavior] No confidence/severity/impact judgments in output.

Changelog v4.1:
 - [CRITICAL SECURITY] API key sanitization in PoC output.
 - [CRITICAL FIX] permission_denied removed from API-not-enabled path.
 - [Feature] Gemini AI, PaLM 2, STT, Natural Language API.
 - [Accuracy] permission_denied → restricted_key.

Changelog v4.0:
 - [CRITICAL FIX] Removed createAuthUri false positive.
 - [CRITICAL FIX] EMAIL_EXISTS detection for Firebase signUp.
 - [Feature] --poc flag, Generative Language API, 8 Maps endpoints.
"""

import requests
import warnings
import sys
import re
import json
import argparse
import threading
import time
import hashlib
import traceback
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

TOOL_NAME    = "slayer_apis_scanner"
TOOL_VERSION = "v5.1"
DEFAULT_TIMEOUT  = 12
MAX_WORKERS      = 8

# ── Global flags / locks ────────────────────────────────────────────────────
VERBOSE_MODE      = False
DEBUG_MODE        = False
POC_MODE          = False
RETRY_COUNT       = 0
RETRY_BACKOFF_BASE = 1.0
REQUEST_DELAY_MS  = 0
CURRENT_APIKEY    = None
OUTPUT_FILE       = None        # -o path; None = terminal only

PRINT_LOCK   = threading.Lock()
RESULTS_LOCK = threading.Lock()
ACCESSIBLE_ENDPOINTS = []
ALL_RESULTS          = []

# GCP project attribution ── extracted from Google error messages
GCP_PROJECT_HINT = None
_GCP_LOCK        = threading.Lock()

# ANSI stripper for clean file output
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHFABCDsuJfr]')

# Extracts GCP project ID/name from error message prose
_GCP_PROJECT_RE = re.compile(r'project[s]?\s+[\'"]?([a-zA-Z0-9_\-]+)[\'"]?', re.IGNORECASE)

_THREAD_LOCAL = threading.local()


# ── Output tee ──────────────────────────────────────────────────────────────

class _TeeWriter:
    """Wraps sys.stdout: passes all writes to the real stdout and also
    accumulates an ANSI-stripped copy in `buf` for the -o output file."""

    def __init__(self, real, buf, lock):
        self._real = real
        self._buf  = buf
        self._lock = lock

    def write(self, data):
        self._real.write(data)
        if data:
            clean = _ANSI_RE.sub('', data)
            with self._lock:
                self._buf.append(clean)

    def flush(self):   self._real.flush()
    def isatty(self):  return self._real.isatty()

    def fileno(self):
        return self._real.fileno()


# ── Thread-local session ────────────────────────────────────────────────────

def get_session():
    if not hasattr(_THREAD_LOCAL, "session"):
        _THREAD_LOCAL.session = requests.Session()
        _THREAD_LOCAL.session.headers.update({"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"})
    return _THREAD_LOCAL.session


# ── Status taxonomy ─────────────────────────────────────────────────────────

STATUS_ACCESSIBLE           = "ACCESSIBLE"
STATUS_API_NOT_ENABLED      = "API_NOT_ENABLED"
STATUS_RESTRICTED           = "RESTRICTED"
STATUS_INVALID_KEY          = "INVALID_KEY"
STATUS_QUOTA_EXCEEDED       = "QUOTA_EXCEEDED"
STATUS_NOT_FOUND            = "ENDPOINT_NOT_FOUND"
STATUS_KEY_VALID_NO_FINDING = "KEY_VALID_NO_FINDING"
STATUS_BAD_TEST_DATA        = "BAD_TEST_DATA"
STATUS_REQUEST_FAILED       = "REQUEST_FAILED"
STATUS_TIMEOUT              = "TIMEOUT"
STATUS_HTTP_ERROR           = "HTTP_ERROR"
STATUS_UNKNOWN              = "UNKNOWN"

STATUS_ORDER = [
    STATUS_ACCESSIBLE, STATUS_API_NOT_ENABLED, STATUS_RESTRICTED,
    STATUS_INVALID_KEY, STATUS_QUOTA_EXCEEDED, STATUS_NOT_FOUND,
    STATUS_KEY_VALID_NO_FINDING, STATUS_BAD_TEST_DATA,
    STATUS_REQUEST_FAILED, STATUS_TIMEOUT, STATUS_HTTP_ERROR, STATUS_UNKNOWN,
]


class Colors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKCYAN    = '\033[96m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY      = '\033[90m'


STATUS_COLOR = {
    STATUS_ACCESSIBLE:           Colors.FAIL,
    STATUS_API_NOT_ENABLED:      Colors.WARNING,
    STATUS_RESTRICTED:           Colors.WARNING,
    STATUS_INVALID_KEY:          Colors.GRAY,
    STATUS_QUOTA_EXCEEDED:       Colors.WARNING,
    STATUS_NOT_FOUND:            Colors.GRAY,
    STATUS_KEY_VALID_NO_FINDING: Colors.GRAY,
    STATUS_BAD_TEST_DATA:        Colors.GRAY,
    STATUS_REQUEST_FAILED:       Colors.WARNING,
    STATUS_TIMEOUT:              Colors.WARNING,
    STATUS_HTTP_ERROR:           Colors.WARNING,
    STATUS_UNKNOWN:              Colors.FAIL,
}


# ── Utilities ───────────────────────────────────────────────────────────────

def sanitize_key(text, key):
    if not text or not key:
        return text
    return text.replace(key, mask_api_key(key))


def _san(text):
    if text is None or not CURRENT_APIKEY:
        return text
    return sanitize_key(str(text), CURRENT_APIKEY)


def _try_extract_gcp_project(message: str):
    """Extract GCP project ID from a Google error message and cache it.
    Called whenever we parse a structured error that might reference a project."""
    global GCP_PROJECT_HINT
    if not message:
        return
    # Prefer the project= param embedded in the console URL Google includes
    url_m = re.search(r'project=([a-zA-Z0-9_\-]+)', message)
    if url_m:
        candidate = url_m.group(1)
    else:
        m = _GCP_PROJECT_RE.search(message)
        candidate = m.group(1) if m else None
    # Skip common prose words that can false-match the regex
    if candidate and candidate not in ("the", "a", "an", "this", "your", "our"):
        with _GCP_LOCK:
            if not GCP_PROJECT_HINT:      # check inside lock: no race between read and write
                GCP_PROJECT_HINT = candidate


def mask_api_key(key: str) -> str:
    if not key:
        return ""
    n = len(key)
    if n <= 4:
        return key[0] + "*" * (n - 1)     # show only first char; ≤4 chars fully exposed otherwise
    if n <= 8:
        return key[0:2] + "*" * (n - 2)   # show first 2 only
    return key[:4] + "*" * (n - 8) + key[-4:]


def strip_key_param(url: str) -> str:
    try:
        p  = urlparse(url)
        qs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k.lower() != "key"]
        return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(qs), p.fragment))
    except Exception:
        return url


# ── Banner / startup screen ─────────────────────────────────────────────────

def banner(masked_key=None, threads=None, total_tasks=None, run_ai=True,
           allow_state_change=True, experimental=True, project_id=None, assume_yes=False,
           profile="custom", run_maps=True, firebase_url=None, output_file=None,
           key_index=None, key_total=None):
    with PRINT_LOCK:
        W   = 66
        DIV = f"{Colors.GRAY}{'━' * 68}{Colors.ENDC}"
        batch = f"  [{key_index}/{key_total}]" if key_index and key_total and key_total > 1 else ""

        # ── Title box ─────────────────────────────────────────────────────
        print(f"\n{Colors.HEADER}{Colors.BOLD}╔{'═' * W}╗{Colors.ENDC}")
        title = f"  {TOOL_NAME.upper()}  {TOOL_VERSION}{batch}"
        print(f"{Colors.HEADER}{Colors.BOLD}║{title:<{W}}║{Colors.ENDC}")
        sub = "  Google API Key Security Assessment"
        print(f"{Colors.HEADER}{Colors.BOLD}║{sub:<{W}}║{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}╚{'═' * W}╝{Colors.ENDC}")
        print(f"{Colors.OKCYAN}  Author    : Slayer{Colors.ENDC}")
        print(DIV)

        # ── Scan target info ───────────────────────────────────────────────
        if masked_key:
            print(f"{Colors.OKBLUE}  API Key   : {masked_key}{Colors.ENDC}")
        if GCP_PROJECT_HINT:
            print(f"{Colors.OKBLUE}  GCP Proj  : {Colors.OKGREEN}{GCP_PROJECT_HINT}"
                  f"{Colors.OKBLUE}  (attributed){Colors.ENDC}")
        end_str = f"{total_tasks}" if total_tasks is not None else "?"
        mode_str = "Debug" if DEBUG_MODE else "Verbose" if VERBOSE_MODE else "Standard"
        poc_str  = "ON" if POC_MODE else "OFF"
        print(f"{Colors.OKBLUE}  Profile   : {profile}   Endpoints: {end_str}   Threads: {threads}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}  Mode      : {mode_str}   PoC: {poc_str}{Colors.ENDC}")
        if output_file:
            print(f"{Colors.OKBLUE}  Output    : {output_file}{Colors.ENDC}")
        print(DIV)

        # ── Module state ───────────────────────────────────────────────────
        ON  = f"{Colors.FAIL}ON {Colors.ENDC}"
        OFF = f"{Colors.GRAY}OFF{Colors.ENDC}"

        def _mline(label, enabled, flag, note=None):
            tick = ON if enabled else OFF
            row  = f"  {Colors.OKBLUE}{label:<18}{Colors.ENDC}{tick}  {Colors.GRAY}{flag}"
            if note and enabled:
                row += f"  ({note})"
            return row + Colors.ENDC

        print(_mline("Maps Platform",   run_maps,          "--no-maps"))
        print(_mline("AI / Gemini",     run_ai,            "--no-ai"))
        print(_mline("State Change",    allow_state_change,"--no-state-change", "Firebase signUp"))
        print(_mline("Experimental",    experimental,      "--no-experimental", "translate-pa"))
        if project_id:
            print(f"  {Colors.OKBLUE}{'Cloud/Firebase':<18}{Colors.ENDC}{ON}  "
                  f"{Colors.GRAY}--project-id  ({project_id}){Colors.ENDC}")
        else:
            print(f"  {Colors.OKBLUE}{'Cloud/Firebase':<18}{Colors.ENDC}{OFF}  "
                  f"{Colors.GRAY}--project-id{Colors.ENDC}")
        if firebase_url:
            short = firebase_url.replace("https://", "")[:36]
            print(f"  {Colors.OKBLUE}{'Firebase RT DB':<18}{Colors.ENDC}{ON}  "
                  f"{Colors.GRAY}--firebase-url  ({short}){Colors.ENDC}")
        else:
            print(f"  {Colors.OKBLUE}{'Firebase RT DB':<18}{Colors.ENDC}{OFF}  "
                  f"{Colors.GRAY}--firebase-url{Colors.ENDC}")
        print(DIV)

        if allow_state_change:
            print(f"{Colors.WARNING}⚠️  State-change ON — Firebase signUp can create a real account.{Colors.ENDC}")

        print(f"\n  {Colors.BOLD}Ready to scan.{Colors.ENDC}")

    if assume_yes or not sys.stdin.isatty():
        return
    try:
        input(f"\n  {Colors.OKCYAN}Press ENTER to start, Ctrl+C to cancel ...{Colors.ENDC} ")
    except (KeyboardInterrupt, EOFError):
        with PRINT_LOCK:
            print(f"\n  {Colors.GRAY}Cancelled — no requests sent.{Colors.ENDC}")
        sys.exit(130)


# ── Verbose / PoC helpers ───────────────────────────────────────────────────

def verbose_log(method, url, headers, data=None, resp=None):
    if not (VERBOSE_MODE or DEBUG_MODE):
        return
    with PRINT_LOCK:
        print(f"\n{Colors.GRAY}  [V] > {method} {_san(url)}")
        if headers:
            try:    print(f"  Headers: {_san(json.dumps(headers))}")
            except: print(f"  Headers: {_san(str(headers))}")
        if data:
            print(f"  Body: {_san(data)}")
        if resp is not None:
            try:
                print(f"  < {resp.status_code}  {_san(resp.text[:200].replace(chr(10),' '))}...{Colors.ENDC}")
            except:
                print(f"  < (binary/unprintable)...{Colors.ENDC}")


def generate_curl_command(method, url, headers=None, data=None, json_body=None):
    parts = ["curl", "-s"]
    if method.upper() == "POST":
        parts.append("-X POST")
    if headers:
        for k, v in headers.items():
            v_escaped = str(v).replace('"', '\\"')
            parts.append(f'-H "{k}: {v_escaped}"')
    if data:
        # single-quote shell quoting: end quote, escape the quote, reopen quote
        sq_escaped = str(data).replace("'", "'\"'\"'")
        parts.append(f"-d '{sq_escaped}'")
    elif json_body:
        sq_escaped = json.dumps(json_body).replace("'", "'\"'\"'")
        parts.append(f"-d '{sq_escaped}'")
    parts.append(f'"{url}"')
    return " ".join(parts)


def print_finding(name, url, note=None, method="GET", headers=None, data=None, json_body=None,
                  response_preview=None, apikey=None, idx=None, family=None):
    with PRINT_LOCK:
        idx_tag = f"{Colors.GRAY}#{idx} {Colors.ENDC}" if idx else ""
        fam_tag = f"  {Colors.GRAY}({family}){Colors.ENDC}" if family else ""
        print(f"\n{Colors.FAIL}[ACCESSIBLE]{Colors.ENDC} {idx_tag}{Colors.BOLD}{name}{Colors.ENDC}{fam_tag}")
        if POC_MODE:
            cmd = generate_curl_command(method, url, headers, data, json_body)
            if apikey:
                cmd = sanitize_key(cmd, apikey)
            print(f"{Colors.GRAY}       PoC cURL: {Colors.ENDC}{cmd}")
            if response_preview:
                if apikey:
                    response_preview = sanitize_key(response_preview, apikey)
                print(f"{Colors.GRAY}       Response: {Colors.ENDC}{response_preview[:300].replace(chr(10), ' ')}...")
        if note:
            if apikey:
                note = sanitize_key(note, apikey)
            print(f"{Colors.GRAY}       Note    : {Colors.ENDC}{note}")

        s_curl = s_resp = None
        if POC_MODE:
            s_curl = generate_curl_command(method, url, headers, data, json_body)
            if apikey:
                s_curl = sanitize_key(s_curl, apikey)
            if response_preview and apikey:
                s_resp = sanitize_key(response_preview, apikey)

        ACCESSIBLE_ENDPOINTS.append({
            "idx": idx, "name": name, "family": family or "Other",
            "url": url, "note": note, "curl": s_curl, "response": s_resp,
        })


def print_info(msg, color=None):
    with PRINT_LOCK:
        print(f"  {color}{msg}{Colors.ENDC}" if color else f"  {msg}")


def record_result(result):
    with RESULTS_LOCK:
        ALL_RESULTS.append(result)
    if DEBUG_MODE:
        color = STATUS_COLOR.get(result["status"], Colors.GRAY)
        with PRINT_LOCK:
            att = ""
            if len(result.get("attempts", [])) > 1:
                att = "  " + " → ".join(f"{a['auth_method']}={a['status']}" for a in result["attempts"])
            idx_s = f"{result.get('idx'):>2}." if result.get('idx') is not None else "  ."
            print(f"  {Colors.GRAY}[DBG]{idx_s} {color}{result['status']:<22}{Colors.ENDC}"
                  f"{Colors.GRAY} {result['name']:<36} http={result.get('http_status')}"
                  f" ms={result.get('elapsed_ms')}{att}{Colors.ENDC}")


# ── HTTP helpers ────────────────────────────────────────────────────────────

def _classify_exception(e):
    if isinstance(e, requests.exceptions.Timeout):        return "timeout"
    if isinstance(e, requests.exceptions.SSLError):       return "tls_error"
    if isinstance(e, requests.exceptions.ProxyError):     return "proxy_error"
    if isinstance(e, requests.exceptions.ConnectionError): return "connection_error"
    return "request_failed"


def try_get(url, headers=None, allow_redirects=True, timeout=DEFAULT_TIMEOUT):
    try:
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("GET", url, headers)
        resp = get_session().get(url, headers=headers, verify=True,
                                 allow_redirects=allow_redirects, timeout=timeout)
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("GET", url, headers, resp=resp)
        return resp, None
    except requests.exceptions.RequestException as e:
        err_type = _classify_exception(e)
        msg = _san(str(e))
        if VERBOSE_MODE or DEBUG_MODE:
            with PRINT_LOCK:
                print(f"  {Colors.GRAY}[V] failed ({err_type}): {msg}{Colors.ENDC}")
        return None, {"type": err_type, "message": msg}


def try_post(url, data=None, json_body=None, headers=None, timeout=DEFAULT_TIMEOUT):
    send_data = data
    try:
        if send_data is None and json_body is not None:
            send_data = json.dumps(json_body)
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("POST", url, headers, data=send_data)

        kw = {'headers': headers or {}, 'verify': True, 'timeout': timeout}
        if data is not None:
            kw['data'] = data
        elif json_body is not None:
            kw['json'] = json_body

        resp = get_session().post(url, **kw)
        if VERBOSE_MODE or DEBUG_MODE:
            verbose_log("POST", url, headers, data=send_data, resp=resp)
        return resp, None
    except requests.exceptions.RequestException as e:
        err_type = _classify_exception(e)
        msg = _san(str(e))
        if VERBOSE_MODE or DEBUG_MODE:
            with PRINT_LOCK:
                print(f"  {Colors.GRAY}[V] failed ({err_type}): {msg}{Colors.ENDC}")
        return None, {"type": err_type, "message": msg}


# ── Error parsing & classification ──────────────────────────────────────────

def parse_structured_error(resp):
    """Extract Google's structured JSON error object.
    Returns {status, reason, message} or None. Primary classification path."""
    try:
        j = resp.json()
    except Exception:
        return None
    if not isinstance(j, dict):
        return None
    err = j.get("error")
    if not isinstance(err, dict):
        return None

    status_field  = err.get("status")
    message_field = err.get("message") or ""
    reason_field  = None
    errors_list   = err.get("errors")
    if isinstance(errors_list, list) and errors_list:
        e0 = errors_list[0]
        if isinstance(e0, dict):
            reason_field = e0.get("reason")

    # Opportunistic GCP project extraction from any error message
    _try_extract_gcp_project(message_field)

    return {"status": status_field, "reason": reason_field, "message": message_field}


def classify_structured(struct, http_status):
    """Map Google's structured error fields to a STATUS_* constant.
    Returns None if no clear match (caller falls back to text)."""
    if struct is None:
        return None

    status  = (struct.get("status")  or "").upper()
    reason  = (struct.get("reason")  or "").lower()
    message = (struct.get("message") or "").lower()

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

    if status == "INVALID_ARGUMENT":
        return STATUS_BAD_TEST_DATA

    # Bare 404 without Google's structured NOT_FOUND → inconclusive
    if http_status == 404:
        return STATUS_HTTP_ERROR

    return None


def classify_reason_text(resp):
    """Fallback substring classification for non-JSON / HTML error pages."""
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
    if "permissiondenied" in low or "permission denied" in low:
        return STATUS_RESTRICTED, "restricted_text_match_weak"
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
    if not location:
        return False
    try:
        host = (urlparse(location).hostname or "").lower()
    except Exception:
        return False
    trusted = ("googleapis.com", "gstatic.com", "google.com")
    return any(host == d or host.endswith("." + d) for d in trusted)


# ── Request core ────────────────────────────────────────────────────────────

def _do_request_with_retries(method, url, headers, json_body, data, force_raw_data, allow_redirects=True):
    attempts_made = 0
    resp = err = None
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
            break
        if attempt_num < RETRY_COUNT:
            time.sleep(RETRY_BACKOFF_BASE * (attempt_num + 1))

    return resp, err, attempts_made


def _perform_single_attempt(method, url, headers, json_body, data, auth_method,
                             expect_image, treat_200_non_json_as_vuln, force_raw_data):
    """One HTTP attempt (with retry policy). Returns a fully-populated dict.
    Every branch resolves to an explicit status — nothing falls through."""
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
        base["status"]  = STATUS_TIMEOUT if err["type"] == "timeout" else STATUS_REQUEST_FAILED
        base["reason"]  = err["type"]
        base["message"] = f"{err['message']} (after {attempts_made} attempt(s))"
        return base

    base["http_status"] = resp.status_code

    # ── Image / redirect checks (Static Maps, Streetview) ──────────────────
    if expect_image:
        if resp.status_code == 200 and is_image_response(resp):
            base["status"]  = STATUS_ACCESSIBLE
            base["vuln"]    = True
            base["message"] = f"Returned image ({len(resp.content)} bytes)"
            return base
        if resp.status_code in (302, 303):
            location = resp.headers.get("Location")
            if is_trusted_google_redirect(location):
                base["status"]  = STATUS_ACCESSIBLE
                base["vuln"]    = True
                base["message"] = f"Redirected → {location}"
                return base
            base["status"]  = STATUS_HTTP_ERROR
            base["message"] = f"Redirected to non-Google host ({location})"
            return base
        struct = parse_structured_error(resp)
        cls    = classify_structured(struct, resp.status_code)
        if cls:
            base["status"]  = cls
            base["reason"]  = struct.get("reason") or struct.get("status")
            base["message"] = struct.get("message")
            return base
        cls, tag = classify_reason_text(resp)
        base["status"] = cls
        base["reason"] = tag
        return base

    # ── Normal JSON / text checks ───────────────────────────────────────────
    if resp.status_code in (200, 201):
        try:
            j = resp.json()
        except ValueError:
            j = None

        if j is not None and isinstance(j, dict):
            if j.get("error"):
                err_obj = j["error"]
                err_msg = err_obj.get("message", "") if isinstance(err_obj, dict) else str(err_obj)
                if "EMAIL_EXISTS" in err_msg or "email already exists" in err_msg.lower():
                    base["status"]  = STATUS_KEY_VALID_NO_FINDING
                    base["message"] = "Reachable, valid key — EMAIL_EXISTS (test account already exists)"
                    base["reason"]  = "email_exists"
                    return base
                struct = {"status": None, "reason": None, "message": err_msg}
                if isinstance(err_obj, dict):
                    struct = parse_structured_error(resp) or struct
                cls = classify_structured(struct, resp.status_code) or STATUS_HTTP_ERROR
                base["status"]  = cls
                base["reason"]  = struct.get("reason") or struct.get("status")
                base["message"] = struct.get("message")
                return base

            if j.get("error_message") or j.get("errorMessage"):
                base["status"]  = STATUS_HTTP_ERROR
                base["message"] = j.get("error_message") or j.get("errorMessage")
                return base

            if "responses" in j and isinstance(j["responses"], list):
                resp_items = j["responses"]
                item_errors = [item.get("error") for item in resp_items
                               if isinstance(item, dict) and item.get("error")]
                if item_errors and len(item_errors) == len(resp_items):
                    base["status"]  = STATUS_HTTP_ERROR
                    base["message"] = str(item_errors[0])
                    return base

            base["status"]       = STATUS_ACCESSIBLE
            base["vuln"]         = True
            base["response_obj"] = j
            base["message"]      = f"Success: {str(j).replace(chr(10), ' ')}"
            return base

        if treat_200_non_json_as_vuln:
            base["status"]  = STATUS_ACCESSIBLE
            base["vuln"]    = True
            base["message"] = f"Raw response: {(resp.text or '').replace(chr(10), ' ')}"
            return base

        base["status"]  = STATUS_HTTP_ERROR
        base["message"] = "200 OK — response not recognized as JSON"
        return base

    # ── Non-2xx ─────────────────────────────────────────────────────────────
    struct = parse_structured_error(resp)
    cls    = classify_structured(struct, resp.status_code)
    if cls:
        base["status"]  = cls
        base["reason"]  = struct.get("reason") or struct.get("status")
        base["message"] = struct.get("message")
        return base

    cls, tag = classify_reason_text(resp)
    base["status"]  = cls
    base["reason"]  = tag
    base["message"] = (resp.text or "")[:300]
    return base


def check_endpoint(
    name, method, url, headers=None, json_body=None, data=None,
    expect_image=False, treat_200_non_json_as_vuln=False,
    header_fallback=False, apikey_for_header=None, use_key_header=False,
    force_raw_data=False, force_content_type=None,
    family=None, idx=None
):
    """Runs one endpoint check end-to-end. Returns result dict.
    Does NOT record it — caller does that once (guarantees exactly one record)."""
    method  = method.upper()
    headers = headers.copy() if headers else {}
    req_url = url

    if use_key_header and apikey_for_header:
        headers["X-Goog-Api-Key"] = apikey_for_header
        req_url = strip_key_param(req_url)

    if force_content_type:
        headers["Content-Type"] = force_content_type

    if "X-Goog-Api-Key" in headers:
        auth_method = "header:X-Goog-Api-Key"
    else:
        auth_method = "query_parameter"

    attempts = []
    attempt  = _perform_single_attempt(
        method, req_url, headers, json_body, data, auth_method,
        expect_image, treat_200_non_json_as_vuln, force_raw_data
    )
    attempts.append({"auth_method": auth_method,
                     "status": attempt["status"], "http_status": attempt["http_status"]})

    # Header-fallback: only on auth-transport failures (INVALID_KEY / API_NOT_ENABLED)
    # Track the active auth method separately so quota-retry inherits the correct one.
    active_auth_method = auth_method
    if (header_fallback and not use_key_header and apikey_for_header and
            attempt["status"] in (STATUS_INVALID_KEY, STATUS_API_NOT_ENABLED)):
        fb_h = headers.copy()
        fb_h["X-Goog-Api-Key"] = apikey_for_header
        fb_u = strip_key_param(req_url)
        fb_a = _perform_single_attempt(
            method, fb_u, fb_h, json_body, data, "header:X-Goog-Api-Key",
            expect_image, treat_200_non_json_as_vuln, force_raw_data
        )
        attempts.append({"auth_method": "header:X-Goog-Api-Key",
                         "status": fb_a["status"], "http_status": fb_a["http_status"]})
        attempt = fb_a
        req_url = fb_u
        headers = fb_h
        active_auth_method = "header:X-Goog-Api-Key"  # update to the transport that won

    # Adaptive QUOTA_EXCEEDED retry: per-second burst limits are transient.
    # Uses active_auth_method so the retry reflects the actual transport in use.
    if attempt["status"] == STATUS_QUOTA_EXCEEDED:
        time.sleep(3.0)
        qa = _perform_single_attempt(
            method, req_url, headers, json_body, data, active_auth_method,
            expect_image, treat_200_non_json_as_vuln, force_raw_data
        )
        attempts.append({"auth_method": active_auth_method + "(quota_retry)",
                         "status": qa["status"], "http_status": qa["http_status"]})
        if qa["status"] != STATUS_QUOTA_EXCEEDED:
            attempt = qa  # resolved to the real outcome

    result = {
        "idx": idx, "name": name, "url": req_url, "method": method, "family": family or "Other",
        "status": attempt["status"], "http_status": attempt["http_status"],
        "reason": attempt["reason"], "message": attempt["message"],
        "elapsed_ms": attempt["elapsed_ms"], "attempts": attempts,
    }

    # ── Per-endpoint terminal output ────────────────────────────────────────
    if attempt["vuln"]:
        rpreview = None
        if POC_MODE:
            if attempt.get("response_obj") is not None:
                rpreview = json.dumps(attempt["response_obj"], indent=2)
            elif "Raw response:" in (attempt["message"] or ""):
                rpreview = attempt["message"][len("Raw response: "):]
        print_finding(name, req_url, attempt["message"], method=method, headers=headers,
                      data=data, json_body=json_body, response_preview=rpreview,
                      apikey=apikey_for_header, idx=idx, family=family)
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
        print_info(f"{name}: {Colors.GRAY}Valid Key, INVALID_ARGUMENT (key/service OK, payload rejected){Colors.ENDC}")
    elif attempt["status"] == STATUS_NOT_FOUND:
        print_info(f"{name}: {Colors.GRAY}NOT_FOUND (endpoint/model retired — not a key finding){Colors.ENDC}")
    elif attempt["status"] == STATUS_TIMEOUT:
        print_info(f"{name}: {Colors.WARNING}Timeout{Colors.ENDC}")
    elif attempt["status"] == STATUS_REQUEST_FAILED:
        print_info(f"{name}: {Colors.WARNING}Request failed ({attempt['reason']}){Colors.ENDC}")
    elif attempt["status"] == STATUS_HTTP_ERROR and (VERBOSE_MODE or DEBUG_MODE):
        print_info(f"{name}: {Colors.GRAY}HTTP {attempt['http_status']} — unclassified{Colors.ENDC}")

    return result


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan_key(apikey, run_ai=True, allow_state_change=True, experimental=True,
             project_id=None, threads=MAX_WORKERS, assume_yes=False, profile="custom",
             run_maps=True, firebase_url=None, key_index=None, key_total=None):
    global ACCESSIBLE_ENDPOINTS, ALL_RESULTS, CURRENT_APIKEY, GCP_PROJECT_HINT
    ACCESSIBLE_ENDPOINTS = []
    ALL_RESULTS          = []
    CURRENT_APIKEY       = apikey
    GCP_PROJECT_HINT     = None    # reset per-key in batch mode
    masked = mask_api_key(apikey)

    tasks = []   # list of (name, method, url, kwargs)

    # ══ STATE-CHANGING ══════════════════════════════════════════════════════
    if allow_state_change:
        kd = hashlib.sha256(apikey.encode()).hexdigest()[:12]
        tasks.append(("Firebase signUp", "POST",
                      f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={apikey}",
                      {"json_body": {"email": f"test-slayer-{kd}@example.com",
                                     "password": "TestPassword123!", "returnSecureToken": True},
                       "header_fallback": True, "apikey_for_header": apikey,
                       "family": "Identity/Firebase (state-changing)"}))

    # ══ CORE HIGH-VALUE ══════════════════════════════════════════════════════
    tasks.append(("Custom Search API", "GET",
                  f"https://www.googleapis.com/customsearch/v1?q=test&cx=017576662512468239146:omuauf_lfve&key={apikey}",
                  {"header_fallback": True, "apikey_for_header": apikey, "family": "Search"}))

    tasks.append(("Translate v2", "POST",
                  f"https://translation.googleapis.com/language/translate/v2?key={apikey}",
                  {"json_body": {"q": "Bonjour", "target": "en"},
                   "header_fallback": True, "apikey_for_header": apikey, "family": "Translate"}))

    yt = "https://www.googleapis.com/youtube/v3"
    tasks.append(("YouTube (MostPopular)", "GET",
                  f"{yt}/videos?part=snippet&chart=mostPopular&maxResults=1&key={apikey}",
                  {"header_fallback": True, "apikey_for_header": apikey, "family": "YouTube"}))
    tasks.append(("YouTube (Search)", "GET",
                  f"{yt}/search?part=snippet&maxResults=1&q=test&key={apikey}",
                  {"header_fallback": True, "apikey_for_header": apikey, "family": "YouTube"}))

    # ══ MAPS PLATFORM ════════════════════════════════════════════════════════
    if run_maps:
        MF = "Maps Platform"
        tasks.append(("Maps - Static Maps", "GET",
                      f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={apikey}",
                      {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Streetview", "GET",
                      f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={apikey}",
                      {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Directions", "GET",
                      f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Geocode", "GET",
                      f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Distance Matrix", "GET",
                      f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615,-73.9976592&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Find Place", "GET",
                      f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art&inputtype=textquery&fields=photos,formatted_address,name&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Autocomplete", "GET",
                      f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Paris&types=(cities)&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Elevation", "GET",
                      f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Timezone", "GET",
                      f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Roads (nearestRoads)", "GET",
                      f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Roads (snapToRoads)", "GET",
                      f"https://roads.googleapis.com/v1/snapToRoads?path=60.170880,24.942795|60.170879,24.942796&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        tasks.append(("Maps - Geolocate", "POST",
                      f"https://www.googleapis.com/geolocation/v1/geolocate?key={apikey}",
                      {"json_body": {}, "header_fallback": True, "apikey_for_header": apikey, "family": MF}))
        # Routes API v2 — separate billing surface from classic Directions
        tasks.append(("Maps - Routes v2", "POST",
                      "https://routes.googleapis.com/directions/v2:computeRoutes",
                      {"json_body": {"origin":      {"address": "1600 Amphitheatre Pkwy, Mountain View, CA"},
                                     "destination": {"address": "Googleplex, Mountain View, CA"},
                                     "travelMode":  "DRIVE"},
                       "headers": {"X-Goog-Api-Key": apikey,
                                   "X-Goog-FieldMask": "routes.duration",
                                   "Content-Type": "application/json"},
                       "apikey_for_header": apikey,
                       "family": MF}))
        # Address Validation — high per-call billing cost
        tasks.append(("Maps - Address Validation", "POST",
                      f"https://addressvalidation.googleapis.com/v1:validateAddress?key={apikey}",
                      {"json_body": {"address": {"addressLines":      ["1600 Amphitheatre Pkwy"],
                                                 "locality":          "Mountain View",
                                                 "administrativeArea":"CA",
                                                 "postalCode":        "94043",
                                                 "regionCode":        "US"}},
                       "header_fallback": True, "apikey_for_header": apikey, "family": MF}))

    # ══ VISION ═══════════════════════════════════════════════════════════════
    # Inline 1×1 PNG — no third-party dependency
    tiny_png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    tasks.append(("Vision API", "POST",
                  f"https://vision.googleapis.com/v1/images:annotate?key={apikey}",
                  {"json_body": {"requests": [{"image": {"content": tiny_png},
                                               "features": [{"type": "LABEL_DETECTION", "maxResults": 1}]}]},
                   "header_fallback": True, "apikey_for_header": apikey, "family": "Vision"}))

    # ══ AI / ML ══════════════════════════════════════════════════════════════
    if run_ai:
        tasks.append(("Text-to-Speech", "POST",
                      f"https://texttospeech.googleapis.com/v1/text:synthesize?key={apikey}",
                      {"json_body": {"input": {"text": "Hello from slayer scanner"},
                                     "voice": {"languageCode": "en-US", "name": "en-US-Wavenet-D"},
                                     "audioConfig": {"audioEncoding": "MP3"}},
                       "header_fallback": True, "apikey_for_header": apikey, "family": "Speech/Audio"}))

    if run_ai:
        GF = "Generative Language (Gemini)"
        tasks.append(("Gemini - List Files", "GET",
                      f"https://generativelanguage.googleapis.com/v1beta/files?key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": GF}))
        tasks.append(("Gemini - List Models", "GET",
                      f"https://generativelanguage.googleapis.com/v1beta/models?key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": GF}))
        GM = "gemini-2.5-flash"
        EM = "gemini-embedding-2"

        tasks.append(("Gemini - generateContent", "POST",
                      f"https://generativelanguage.googleapis.com/v1beta/models/{GM}:generateContent?key={apikey}",
                      {"json_body": {"contents": [{"parts": [{"text": "Say hello from slayer scanner"}]}]},
                       "header_fallback": True, "apikey_for_header": apikey, "family": GF}))

        tasks.append(("Gemini - generateContent (vision)", "POST",
                      f"https://generativelanguage.googleapis.com/v1beta/models/{GM}:generateContent?key={apikey}",
                      {"json_body": {"contents": [{"parts": [{"text": "Describe this image"},
                                                             {"inline_data": {"mime_type": "image/png",
                                                                              "data": tiny_png}}]}]},
                       "header_fallback": True, "apikey_for_header": apikey, "family": GF}))

        tasks.append(("Gemini - embedContent", "POST",
                      f"https://generativelanguage.googleapis.com/v1beta/models/{EM}:embedContent?key={apikey}",
                      {"json_body": {"model": f"models/{EM}",
                                     "content": {"parts": [{"text": "test embedding"}]}},
                       "header_fallback": True, "apikey_for_header": apikey, "family": GF}))

        tasks.append(("Gemini - countTokens", "POST",
                      f"https://generativelanguage.googleapis.com/v1beta/models/{GM}:countTokens?key={apikey}",
                      {"json_body": {"contents": [{"parts": [{"text": "test token count"}]}]},
                       "header_fallback": True, "apikey_for_header": apikey, "family": GF}))

        tasks.append(("Speech-to-Text", "POST",
                      f"https://speech.googleapis.com/v1/speech:recognize?key={apikey}",
                      {"json_body": {"config": {"encoding": "LINEAR16", "sampleRateHertz": 16000,
                                                "languageCode": "en-US"},
                                     "audio": {"content": "//uQx"}},
                       "header_fallback": True, "apikey_for_header": apikey, "family": "Speech/Audio"}))

        NL = "Natural Language"
        nl_doc = {"document": {"type": "PLAIN_TEXT", "content": "I love this scanner!"}}
        tasks.append(("Natural Language - Sentiment", "POST",
                      f"https://language.googleapis.com/v1/documents:analyzeSentiment?key={apikey}",
                      {"json_body": nl_doc, "header_fallback": True, "apikey_for_header": apikey, "family": NL}))
        tasks.append(("Natural Language - Entities", "POST",
                      f"https://language.googleapis.com/v1/documents:analyzeEntities?key={apikey}",
                      {"json_body": nl_doc, "header_fallback": True, "apikey_for_header": apikey, "family": NL}))
        tasks.append(("Natural Language - Syntax", "POST",
                      f"https://language.googleapis.com/v1/documents:analyzeSyntax?key={apikey}",
                      {"json_body": nl_doc, "header_fallback": True, "apikey_for_header": apikey, "family": NL}))

    # ══ DRIVE ════════════════════════════════════════════════════════════════
    tasks.append(("Drive API (List)", "GET",
                  f"https://www.googleapis.com/drive/v3/files?pageSize=1&key={apikey}",
                  {"header_fallback": True, "apikey_for_header": apikey, "family": "Drive"}))

    # ══ EXPERIMENTAL ══════════════════════════════════════════════════════════
    if experimental:
        tasks.append(("Translate-PA (Internal, undocumented)", "POST",
                      "https://translate-pa.googleapis.com/v1/translateHtml",
                      {"data": '[[["Hello from slayer_apis_scanner"],"en","hi"],"en"]',
                       "force_raw_data": True, "force_content_type": "application/json+protobuf",
                       "use_key_header": True, "apikey_for_header": apikey,
                       "treat_200_non_json_as_vuln": True, "family": "Experimental/Internal"}))

    # ══ PROJECT-SCOPED (needs --project-id) ══════════════════════════════════
    if project_id:
        tasks.append(("Cloud Storage List", "GET",
                      f"https://www.googleapis.com/storage/v1/b?project={project_id}&maxResults=1&key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": "Cloud Storage"}))
        # Firebase Remote Config — can leak feature flags and embedded config values
        tasks.append(("Firebase Remote Config (read)", "GET",
                      f"https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/remoteConfig?key={apikey}",
                      {"header_fallback": True, "apikey_for_header": apikey, "family": "Firebase Remote Config"}))

    # ══ FIREBASE REALTIME DB (needs --firebase-url) ═══════════════════════════
    if firebase_url:
        fb = firebase_url.rstrip("/")
        # No API key passed — world-read access is controlled by Firebase Rules, not key auth
        # treat_200_non_json_as_vuln=True so JSON null (empty-but-accessible DB) also scores ACCESSIBLE
        tasks.append(("Firebase RT DB (shallow read)", "GET", f"{fb}/.json?shallow=true",
                      {"treat_200_non_json_as_vuln": True, "family": "Firebase Realtime DB"}))
        tasks.append(("Firebase RT DB (root read)", "GET", f"{fb}/.json",
                      {"treat_200_non_json_as_vuln": True, "family": "Firebase Realtime DB"}))

    # ── Run ──────────────────────────────────────────────────────────────────
    total         = len(tasks)
    indexed_tasks = [(i, n, m, u, kw) for i, (n, m, u, kw) in enumerate(tasks, start=1)]

    banner(masked_key=masked, threads=threads, total_tasks=total, run_ai=run_ai,
           allow_state_change=allow_state_change, experimental=experimental,
           project_id=project_id, assume_yes=assume_yes, profile=profile,
           run_maps=run_maps, firebase_url=firebase_url, output_file=OUTPUT_FILE,
           key_index=key_index, key_total=key_total)

    print(f"\n  {Colors.GRAY}{'─' * 62}{Colors.ENDC}")
    print(f"  {Colors.BOLD}Scanning {total} endpoint(s) ...{Colors.ENDC}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(check_endpoint, n, m, u, idx=i, **kw): (i, n, m, u)
            for (i, n, m, u, kw) in indexed_tasks
        }
        for future in as_completed(future_map):
            i, n, m, u = future_map[future]
            try:
                record_result(future.result())
            except Exception as e:
                tb = traceback.format_exc(limit=3)
                with PRINT_LOCK:
                    print(f"  {Colors.FAIL}[ERROR] {n}: unhandled exception — {_san(str(e))}{Colors.ENDC}")
                    if VERBOSE_MODE or DEBUG_MODE:
                        print(f"  {Colors.GRAY}{_san(tb)}{Colors.ENDC}")
                record_result({
                    "idx": i, "name": n, "url": u, "method": m, "family": "Other",
                    "status": STATUS_UNKNOWN, "http_status": None,
                    "reason": "unhandled_exception", "message": _san(str(e)),
                    "elapsed_ms": None,
                    "attempts": [{"auth_method": "n/a", "status": STATUS_UNKNOWN, "http_status": None}],
                })

    print_summary(total)


# ── Summary ─────────────────────────────────────────────────────────────────

def print_summary(total_tasks=None):
    with PRINT_LOCK:
        DIV = f"{Colors.GRAY}{'━' * 68}{Colors.ENDC}"
        div = f"{Colors.GRAY}{'─' * 68}{Colors.ENDC}"

        print(f"\n{DIV}")
        print(f"  {Colors.BOLD}SCAN SUMMARY{Colors.ENDC}")
        print(DIV)

        if GCP_PROJECT_HINT:
            print(f"\n  {Colors.OKCYAN}{Colors.BOLD}GCP Project : {GCP_PROJECT_HINT}{Colors.ENDC}"
                  f"  {Colors.GRAY}(attributed from error response){Colors.ENDC}")

        sorted_acc = sorted(ACCESSIBLE_ENDPOINTS, key=lambda v: (v.get("idx") is None, v.get("idx")))

        if sorted_acc:
            print(f"\n  {Colors.FAIL}{Colors.BOLD}Findings: {len(sorted_acc)} endpoint(s) accessible{Colors.ENDC}\n")

            # Service family mini-chart
            by_fam = {}
            for v in sorted_acc:
                by_fam.setdefault(v["family"], []).append(v)

            print(f"  {Colors.BOLD}Services breakdown:{Colors.ENDC}")
            for fam, items in by_fam.items():
                bar = "█" * len(items)
                print(f"  {Colors.FAIL}  {fam:<42} {bar} {len(items)}{Colors.ENDC}")
            print()

            for v in sorted_acc:
                idx_s = f"{v['idx']:>2}. " if v.get("idx") is not None else "  . "
                print(f"  {Colors.FAIL}  ● {idx_s}{v['name']} {Colors.GRAY}({v['family']}){Colors.ENDC}")
                if POC_MODE and v.get("curl"):
                    print(f"  {Colors.GRAY}       cURL: {v['curl']}{Colors.ENDC}")
                if POC_MODE and v.get("response"):
                    print(f"  {Colors.GRAY}       Response:{Colors.ENDC}")
                    print(f"       {v['response']}")
                if v.get("note"):
                    print(f"  {Colors.GRAY}       Note: {v['note']}{Colors.ENDC}")
                print()
        else:
            print(f"\n  {Colors.OKGREEN}✓ No accessible endpoints found.{Colors.ENDC}")
            print(f"  {Colors.GRAY}  The API key appears to be properly restricted or invalid.{Colors.ENDC}\n")

        counts = {s: 0 for s in STATUS_ORDER}
        for r in ALL_RESULTS:
            counts[r["status"]] = counts.get(r["status"], 0) + 1

        tested = len(ALL_RESULTS)
        total  = total_tasks if total_tasks is not None else tested

        print(div)
        print(f"  {Colors.BOLD}Endpoint accounting{Colors.ENDC}\n")
        label_map = {
            STATUS_ACCESSIBLE:           "Accessible",
            STATUS_API_NOT_ENABLED:      "API not enabled",
            STATUS_RESTRICTED:           "Restricted",
            STATUS_INVALID_KEY:          "Invalid key",
            STATUS_QUOTA_EXCEEDED:       "Quota exceeded",
            STATUS_NOT_FOUND:            "Endpoint/model not found",
            STATUS_KEY_VALID_NO_FINDING: "Valid key, resource exists",
            STATUS_BAD_TEST_DATA:        "Valid key, INVALID_ARGUMENT",
            STATUS_REQUEST_FAILED:       "Request failed",
            STATUS_TIMEOUT:              "Timeout",
            STATUS_HTTP_ERROR:           "Unclassified HTTP error",
            STATUS_UNKNOWN:              "Worker exception",
        }
        for status in STATUS_ORDER:
            c = counts.get(status, 0)
            if c == 0:
                continue
            color = STATUS_COLOR.get(status, Colors.GRAY)
            bar   = "▪" * c
            print(f"  {color}  {label_map[status]:<32} {bar} {c}{Colors.ENDC}")

        print(f"\n  {Colors.OKBLUE}Coverage  : {tested}/{total} endpoints tested{Colors.ENDC}")

        print(f"\n{DIV}")
        print(f"  {Colors.BOLD}Total accessible: {len(sorted_acc)}{Colors.ENDC}")
        if sorted_acc:
            print(f"  {Colors.WARNING}⚠️  Review each finding in context to determine actual impact.{Colors.ENDC}")
        print(DIV)
        print(f"  {Colors.GRAY}Scanner : {TOOL_NAME} {TOOL_VERSION} by Slayer{Colors.ENDC}")
        print(f"  {Colors.GRAY}GitHub  : https://github.com/dodal-omkar/slayer-apis-scanner{Colors.ENDC}")
        print(f"{DIV}\n")


# ── CLI ──────────────────────────────────────────────────────────────────────

class _ColorHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Post-processes the argparse help string to inject ANSI colors."""

    def format_help(self):
        raw = super().format_help()

        # ── usage: line ────────────────────────────────────────────────────
        raw = re.sub(
            r'^(usage:)',
            f'{Colors.OKCYAN}{Colors.BOLD}\\1{Colors.ENDC}',
            raw, flags=re.MULTILINE
        )
        # ── description (first line after usage) ───────────────────────────
        raw = raw.replace(
            f"{TOOL_NAME} {TOOL_VERSION} - Google API Key Security Scanner",
            f"{Colors.HEADER}{Colors.BOLD}{TOOL_NAME} {TOOL_VERSION}"
            f" - Google API Key Security Scanner{Colors.ENDC}"
        )
        # ── section headers: "options:", "positional arguments:" ───────────
        raw = re.sub(
            r'^(options:|positional arguments:)',
            f'{Colors.BOLD}{Colors.OKGREEN}\\1{Colors.ENDC}',
            raw, flags=re.MULTILINE
        )
        # ── all flag names: -x and --xxx wherever they appear ──────────────
        raw = re.sub(
            r'(?<!\w)(--?[a-zA-Z][\w-]*)',
            f'{Colors.OKCYAN}\\1{Colors.ENDC}',
            raw
        )
        # ── epilog section headers (e.g. "Examples:", "Profiles (--profile):") ─
        raw = re.sub(
            r'^([A-Z][^\n]{0,60}:)$',
            f'{Colors.BOLD}{Colors.OKGREEN}\\1{Colors.ENDC}',
            raw, flags=re.MULTILINE
        )
        # ── profile names in the epilog ────────────────────────────────────
        raw = re.sub(
            r'\b(quick|standard|deep|custom)\b',
            f'{Colors.WARNING}\\1{Colors.ENDC}',
            raw
        )
        # ── * note lines ───────────────────────────────────────────────────
        raw = re.sub(
            r'^(  \* .+)$',
            f'{Colors.GRAY}\\1{Colors.ENDC}',
            raw, flags=re.MULTILINE
        )
        return raw


def main():
    global VERBOSE_MODE, DEBUG_MODE, MAX_WORKERS, POC_MODE, RETRY_COUNT, REQUEST_DELAY_MS, OUTPUT_FILE

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} {TOOL_VERSION} - Google API Key Security Scanner",
        formatter_class=_ColorHelpFormatter,
        epilog="""
Examples:
  %(prog)s -a AIzaSyABC123...                               single key, all modules
  %(prog)s -a AIzaSyABC123... --profile standard            recommended default
  %(prog)s -a AIzaSyABC123... --profile quick --no-maps     fastest, no billing risk
  %(prog)s -K keys.txt -y -o results.txt --profile deep     batch scan, save output
  %(prog)s -a AIzaSyABC123... --firebase-url https://myapp-default-rtdb.firebaseio.com
  %(prog)s -a AIzaSyABC123... --project-id my-gcp-project-123
  %(prog)s -a AIzaSyABC123... -v --poc -o scan.txt
  %(prog)s -a AIzaSyABC123... --debug -t 1 --retries 2

Profiles (--profile):
  quick     Core APIs only. No AI, FCM, state-change, experimental. Fastest.
  standard  Core + AI/Generative. Recommended default for most assessments.
  deep      Everything: Core + AI + FCM + Firebase signUp + experimental.
  custom    Same as deep; combine with --no-* flags to hand-pick modules.

Module flags (each overrides the chosen profile):
  --no-maps           Skip all 14 Maps Platform endpoints (billing protection)
  --no-ai             Skip AI/ML checks (Gemini, TTS, STT, NL)
  --no-state-change   Skip Firebase signUp (creates a real account if used)
  --no-experimental   Skip undocumented probes (translate-pa)

Output:
  -o FILE    Save clean (ANSI-stripped) copy of all output to FILE.
             In batch mode each key's section is timestamped.

Notes:
  * --firebase-url probes world-read without an API key (Firebase Rules control it).
  * --project-id unlocks Cloud Storage + Firebase Remote Config tests.
  * GCP project attribution is extracted automatically from Google error messages.
        """
    )

    parser.add_argument("-a", "--api-key",        help="Google API key to test")
    parser.add_argument("-K", "--keys-file",      help="File with one API key per line (batch mode)")
    parser.add_argument("-o", "--output",         help="Save clean output to file (like nmap -oN)")
    parser.add_argument("--profile",              choices=["quick","standard","deep","custom"],
                        default="custom",         help="Test scope preset (default: custom)")
    parser.add_argument("-y", "--yes",            action="store_true", dest="assume_yes",
                        help="Skip confirmation prompt (CI/automation)")
    parser.add_argument("-v", "--verbose",        action="store_true",
                        help="Verbose HTTP requests/responses (key sanitized)")
    parser.add_argument("--debug",               action="store_true",
                        help="Print status line for EVERY endpoint")
    parser.add_argument("--poc",                 action="store_true",
                        help="Generate curl PoC for accessible endpoints")
    # All --no-* default to None so explicit flags always override the profile
    parser.add_argument("--no-ai",               action="store_false", dest="run_ai",            default=None)
    parser.add_argument("--no-maps",             action="store_false", dest="run_maps",           default=None,
                        help="Skip all Maps Platform endpoints")
    parser.add_argument("--no-state-change",     action="store_false", dest="allow_state_change", default=None)
    parser.add_argument("--no-experimental",     action="store_false", dest="experimental",       default=None)
    parser.add_argument("--firebase-url",        help="Firebase Realtime DB URL to probe for world-read access")
    parser.add_argument("--project-id",          help="GCP Project ID (unlocks Cloud Storage + Firebase Remote Config)")
    parser.add_argument("-t", "--threads",       type=int, default=MAX_WORKERS,
                        help=f"Concurrent threads (default: {MAX_WORKERS})")
    parser.add_argument("--retries",             type=int, default=0,
                        help="Extra retries for TIMEOUT/connection failures (default: 0)")
    parser.add_argument("--delay-ms",            type=int, default=0,
                        help="Delay ms before each request (default: 0)")

    args = parser.parse_args()

    VERBOSE_MODE     = args.verbose
    DEBUG_MODE       = args.debug
    POC_MODE         = args.poc
    MAX_WORKERS      = max(1, args.threads)
    RETRY_COUNT      = max(0, args.retries)
    REQUEST_DELAY_MS = max(0, args.delay_ms)
    OUTPUT_FILE      = args.output

    PROFILE_DEFAULTS = {
        "quick":    {"run_ai": False, "allow_state_change": False, "experimental": False, "run_maps": True},
        "standard": {"run_ai": True,  "allow_state_change": False, "experimental": False, "run_maps": True},
        "deep":     {"run_ai": True,  "allow_state_change": True,  "experimental": True,  "run_maps": True},
        "custom":   {"run_ai": True,  "allow_state_change": True,  "experimental": True,  "run_maps": True},
    }
    d = PROFILE_DEFAULTS[args.profile]
    run_ai            = args.run_ai            if args.run_ai            is not None else d["run_ai"]
    allow_state_change= args.allow_state_change if args.allow_state_change is not None else d["allow_state_change"]
    experimental      = args.experimental      if args.experimental      is not None else d["experimental"]
    run_maps          = args.run_maps          if args.run_maps          is not None else d["run_maps"]

    # Build key list
    keys = []
    if args.keys_file:
        try:
            with open(args.keys_file, encoding="utf-8") as f:
                keys = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
        except OSError as e:
            print(f"{Colors.FAIL}Error reading keys file: {e}{Colors.ENDC}")
            sys.exit(1)
        if not keys:
            print(f"{Colors.FAIL}No valid keys found in {args.keys_file}{Colors.ENDC}")
            sys.exit(1)
    elif args.api_key:
        keys = [args.api_key]
    else:
        k = input(f"{Colors.OKCYAN}Enter Google API Key: {Colors.ENDC}").strip()
        if not k:
            print(f"{Colors.FAIL}Error: No API key provided{Colors.ENDC}")
            sys.exit(1)
        keys = [k]

    # Set up output tee BEFORE any printing (captures everything including banners)
    _out_buf      = []
    _out_buf_lock = threading.Lock()
    if OUTPUT_FILE:
        sys.stdout = _TeeWriter(sys.__stdout__, _out_buf, _out_buf_lock)

    key_total = len(keys)
    for key_index, key in enumerate(keys, start=1):
        if key_total > 1:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n{Colors.HEADER}{Colors.BOLD}{'═' * 66}{Colors.ENDC}")
            print(f"{Colors.HEADER}{Colors.BOLD}  Key {key_index}/{key_total} — {mask_api_key(key)}  [{ts}]{Colors.ENDC}")
            print(f"{Colors.HEADER}{Colors.BOLD}{'═' * 66}{Colors.ENDC}")

        scan_key(key, run_ai=run_ai,
                 allow_state_change=allow_state_change, experimental=experimental,
                 project_id=args.project_id, threads=MAX_WORKERS, assume_yes=args.assume_yes,
                 profile=args.profile, run_maps=run_maps, firebase_url=args.firebase_url,
                 key_index=key_index, key_total=key_total)

    # Flush tee buffer to file
    if OUTPUT_FILE:
        sys.stdout = sys.__stdout__
        try:
            import os as _os
            mode = "w"
            if _os.path.exists(OUTPUT_FILE):
                print(f"{Colors.WARNING}Warning: overwriting existing file {OUTPUT_FILE}{Colors.ENDC}")
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(OUTPUT_FILE, mode, encoding="utf-8") as f:
                f.write(f"# {TOOL_NAME} {TOOL_VERSION} — {ts}\n")
                f.write("".join(_out_buf))
            print(f"\n{Colors.OKGREEN}Output saved → {OUTPUT_FILE}{Colors.ENDC}")
        except OSError as e:
            print(f"{Colors.FAIL}Failed to write output file: {e}{Colors.ENDC}")


if __name__ == "__main__":
    main()
