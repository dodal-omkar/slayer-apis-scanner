#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  slayer_apis_scanner — Google API Key Misconfiguration Scanner
  Version : v3.1

  Author  : Slayer
  Role    : Security Research / Offensive Testing
  Scope   : Google API key exposure & misconfiguration detection

═══════════════════════════════════════════════════════════════

Changelog since v3.01: 
 - Show PoC URL in vulnerability output and summary
 - Restore more detailed error-token parsing (parity with v2.x)
 - Use print_info() for pre-scan prints to keep output locked/ordered
 - Minor cleanups and comments
Changelog since v3.00:
 - Safer removal of `key` query parameter when using header fallback (uses urllib.parse).
 - Cleaner `force_raw_data` handling (uses json.dumps instead of str()).
 - `is_image_response` no longer rejects small images based on length.
 - Improved error visibility for non-200 responses (prints HTTP status + parsed reason).
 - Added --threads / -t CLI flag to control concurrency.
 - Masked API key in banner output to avoid leaking it on-screen.
Changelog since v2.00: 
 - [Critical Fix] Reverted translate-pa payload to v2.01 version (fixes false negative).
 - [Fix] Removed aggressive 400 error suppression for translate-pa.
 - [Feature] Multi-threaded & Verbose modes retained.  
"""

import requests
import warnings
import sys
import json
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

warnings.filterwarnings("ignore")

TOOL_NAME = "slayer_apis_scanner"
TOOL_VERSION = "v3.1"
DEFAULT_TIMEOUT = 12
MAX_WORKERS = 8  # default number of concurrent threads

# Global Flags / Locks
VERBOSE_MODE = False
PRINT_LOCK = threading.Lock()
VULNERABLE_APIS = []

# ----------------- Utils ----------------- #

def banner(masked_key=None, threads=None):
    with PRINT_LOCK:
        print(f"\n\033[1;35m[{TOOL_NAME} {TOOL_VERSION}]\033[0m Google API key scanner")
        print("-------------------------------------------------------------")
        print("\033[1;36mAuthor    : Slayer\033[0m")
        print("-------------------------------------------------------------")
        if masked_key is not None:
            print(f"Key: \033[36m{masked_key}\033[0m")
        if threads is not None:
            print(f"Threads: {threads}")

def verbose_log(method, url, headers, data=None, resp=None):
    if not VERBOSE_MODE:
        return
    with PRINT_LOCK:
        print(f"\n\033[1;30m[VERBOSE] > {method} {url}")
        if headers:
            try:
                print(f"Headers: {json.dumps(headers)}")
            except:
                print(f"Headers: {headers}")
        if data:
            print(f"Body: {data}")
        if resp is not None:
            try:
                print(f"< Status: {resp.status_code}")
                snippet = resp.text[:200].replace('\n', ' ')
                print(f"< Resp Body: {snippet}...\033[0m")
            except Exception:
                print(f"< Resp Body: (binary/unprintable)...\033[0m")
        else:
            print(f"< No Response / Error\033[0m")

def print_vuln(name, url, note=None, status="success"):
    with PRINT_LOCK:
        print(f"\033[1;31m[VULN]\033[0m {name} \033[1;32m[{status}]\033[0m")
        print(f"       PoC : {url}")
        if note:
            print(f"       Note: {note}")
        VULNERABLE_APIS.append((name, url, note))

def print_info(msg):
    with PRINT_LOCK:
        print(msg)

def try_get(url, headers=None, allow_redirects=True, timeout=DEFAULT_TIMEOUT):
    try:
        if VERBOSE_MODE: verbose_log("GET", url, headers)
        resp = requests.get(url, headers=headers, verify=True, allow_redirects=allow_redirects, timeout=timeout)
        if VERBOSE_MODE: verbose_log("GET", url, headers, resp=resp)
        return resp
    except Exception:
        if VERBOSE_MODE: verbose_log("GET", url, headers, resp=None)
        return None

def try_post(url, data=None, json_body=None, headers=None, timeout=DEFAULT_TIMEOUT):
    send_data = data
    try:
        if send_data is None and json_body is not None:
            # Keep JSON body string for verbose preview; actual call may use json= to let requests set headers
            send_data = json.dumps(json_body)
        if VERBOSE_MODE: verbose_log("POST", url, headers, data=send_data)

        kwargs = {'headers': headers or {}, 'verify': True, 'timeout': timeout}
        # If caller explicitly provided `data`, prefer that raw body.
        if data is not None:
            kwargs['data'] = data
        elif json_body is not None:
            # pass it as JSON so requests sets Content-Type and serializes properly
            kwargs['json'] = json_body

        resp = requests.post(url, **kwargs)
        if VERBOSE_MODE: verbose_log("POST", url, headers, data=send_data, resp=resp)
        return resp
    except Exception:
        if VERBOSE_MODE: verbose_log("POST", url, headers, data=send_data, resp=None)
        return None

# ----------------- Error parsing & classification (improved) ----------------- #

def parse_error_reason(resp):
    """
    Try to parse common Google API error shapes to extract a short reason.
    Extended token set for better classification.
    """
    if resp is None:
        return "request_failed"

    # Try obvious header/text-based signals first
    try:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "text" in ctype or "html" in ctype:
            txt = (resp.text or "")[:1200]
            tokens = (
                "invalidApiKey",
                "invalid api key",
                "api key not valid",
                "accessNotConfigured",
                "has not been used in project",
                "quotaExceeded",
                "refererNotAllowed",
                "referer not allowed",
                "ip not allowed",
                "permissionDenied",
                "blocked",
                "not found",
            )
            for token in tokens:
                if token.lower() in txt.lower():
                    return token
    except Exception:
        pass

    # Try JSON parsing
    try:
        j = resp.json()
    except Exception:
        return f"non-json_status_{getattr(resp, 'status_code', 'no_status')}"

    if isinstance(j, dict):
        # Known Google error envelope
        if "error" in j:
            err = j["error"]
            if isinstance(err, dict):
                # errors list with reasons
                if "errors" in err and isinstance(err["errors"], list) and err["errors"]:
                    e0 = err["errors"][0]
                    return e0.get("reason") or e0.get("message") or "error_with_errors_list"
                if "message" in err:
                    return err["message"]
            # sometimes 'error' is a string
            return str(err)
        # Some APIs use other fields
        for key in ("error_message", "errorMessage", "reason", "message"):
            if key in j:
                return j.get(key)
    return "unknown_error_shape"

def classify_reason(reason, status_code):
    """
    Classify a parsed reason string into:
      - invalid_key
      - api_not_enabled_but_key_valid
      - quota_exceeded
      - success
      - restricted_key
      - other
    """
    if reason is None:
        return "other"
    r = str(reason).lower()
    if status_code in (200, 201):
        return "success"
    # invalid key patterns
    if (
        "invalidapikey" in r
        or "invalid api key" in r
        or "api key not valid" in r
        or "invalid key" in r
    ):
        return "invalid_key"
    # API not enabled but key exists
    if (
        "accessnotconfigured" in r
        or "has not been used in project" in r
        or "it is disabled" in r
        or "api has not been used" in r
        or "not enabled" in r
    ):
        return "api_not_enabled_but_key_valid"
    # quota
    if "quota" in r or "quotaexceeded" in r or "quota exceeded" in r:
        return "quota_exceeded"
    # referer/ip/permission restrictions
    if (
        "referernotallowed" in r
        or "referer not allowed" in r
        or "ip not allowed" in r
        or "permissiondenied" in r
        or "permission denied" in r
        or "restricted" in r
    ):
        return "restricted_key"
    return "other"

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

# ----------------- URL helpers ----------------- #

def strip_key_param(url: str) -> str:
    """Remove only the `key` query parameter from a URL; preserve other query params and ordering."""
    try:
        p = urlparse(url)
        qs = parse_qsl(p.query, keep_blank_values=True)
        qs = [(k, v) for (k, v) in qs if k.lower() != "key"]
        new_q = urlencode(qs)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
    except Exception:
        return url

def mask_api_key(key: str) -> str:
    """Show a masked version of the API key (first 4 and last 4 chars) to avoid leaking it on-screen."""
    if not key:
        return ""
    if len(key) <= 8:
        return key[0:2] + "*" * max(0, len(key)-4) + key[-2:]
    return key[:4] + "*" * (len(key)-8) + key[-4:]

# ----------------- Endpoint Logic ----------------- #

def check_endpoint(
    name, method, url, headers=None, json_body=None, data=None,
    expect_image=False, allow_redirects=True, treat_200_non_json_as_vuln=False,
    header_fallback=False, apikey_for_header=None, use_key_header=False,
    force_raw_data=False, force_content_type=None
):
    method = method.upper()
    headers = headers.copy() if headers else {}

    # If caller wants the API key as a header instead of query param, set header and strip only the key param
    if use_key_header and apikey_for_header:
        headers["X-Goog-Api-Key"] = apikey_for_header
        url = strip_key_param(url)

    if force_content_type:
        headers["Content-Type"] = force_content_type

    resp = None
    if method == "GET":
        resp = try_get(url, headers=headers, allow_redirects=allow_redirects)
    elif method == "POST":
        # If caller requested a raw body but passed json_body, serialize it with json.dumps (safer than str())
        if force_raw_data and data is None and json_body is not None:
            resp = try_post(url, data=json.dumps(json_body), headers=headers)
        else:
            resp = try_post(url, data=data, json_body=json_body, headers=headers)

    if resp is None:
        print_info(f"{name}: request failed.")
        return False

    # --- translate-pa Logic (note: payload shaping is caller's responsibility) ---
    reason = parse_error_reason(resp)
    cls = classify_reason(reason, getattr(resp, "status_code", None))

    # header fallback: if initial run looked like invalid/not enabled and caller wants a fallback, try header form once
    if header_fallback and cls in ("invalid_key", "api_not_enabled_but_key_valid", "other") and apikey_for_header:
        if "X-Goog-Api-Key" not in headers:
            # re-run with header form and without header_fallback to avoid recursion
            return check_endpoint(
                name, method, url, headers, json_body, data, expect_image,
                allow_redirects, treat_200_non_json_as_vuln,
                header_fallback=False, apikey_for_header=apikey_for_header, use_key_header=True,
                force_raw_data=force_raw_data, force_content_type=force_content_type
            )

    # Success Detection
    if expect_image:
        if resp.status_code == 200 and is_image_response(resp):
            print_vuln(name, url, f"Returned image ({len(resp.content)} bytes).")
            return True
        elif resp.status_code in (302, 303):
            print_vuln(name, url, f"Redirected to {resp.headers.get('Location')}")
            return True
        else:
            # not a vuln in the image sense
            return False

    if resp.status_code in (200, 201):
        try:
            j = resp.json()
            # if JSON object with explicit error fields, treat as error; otherwise success
            if isinstance(j, dict) and (j.get("error") or j.get("error_message") or j.get("errorMessage")):
                # Let downstream classification handle this
                pass
            else:
                snippet = str(j)[:200].replace('\n', '')
                print_vuln(name, url, f"JSON returned: {snippet}...")
                return True
        except ValueError:
            if treat_200_non_json_as_vuln:
                snippet = (resp.text or "")[:200].replace('\n', '')
                print_vuln(name, url, f"Raw body: {snippet}...")
                return True

    # Error Printing & Info (locked prints)
    if cls == "api_not_enabled_but_key_valid":
        print_info(f"{name}: \033[33mValid Key\033[0m but API not enabled.")
    elif cls == "quota_exceeded":
        print_info(f"{name}: \033[33mValid Key\033[0m but Quota Exceeded.")
    elif cls == "restricted_key":
        print_info(f"{name}: \033[33mValid Key\033[0m but IP/Referer Restricted.")
    elif cls == "invalid_key":
        print_info(f"{name}: \033[31mInvalid/Not usable key\033[0m (reason: {reason}).")
    else:
        # Provide visibility for other non-success cases
        try:
            status_code = resp.status_code
        except:
            status_code = 'no_status'
        print_info(f"{name}: HTTP {status_code}, reason: {reason}")

    return False

# ----------------- Main Scanner ----------------- #

def scan_key(apikey, run_ai=True, run_fcm=True, project_id=None, threads=MAX_WORKERS):
    global VULNERABLE_APIS
    VULNERABLE_APIS = []
    masked = mask_api_key(apikey)
    banner(masked_key=masked, threads=threads)
    if project_id:
        print_info(f"Project: {project_id}")
    print_info(f"Mode: {'Verbose' if VERBOSE_MODE else 'Standard'}")

    print_info("\nScanning endpoints...\n")

    tasks = []

    # 1. CSE
    cse_id = "017576662512468239146:omuauf_lfve"
    tasks.append(("Custom Search API", "GET", f"https://www.googleapis.com/customsearch/v1?q=test&cx={cse_id}&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))

    # 2. Calendar
    tasks.append(("Calendar API", "GET", f"https://www.googleapis.com/calendar/v3/users/me/calendarList?key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))

    # 3. Translate v2
    tasks.append(("Translate v2", "GET", f"https://translation.googleapis.com/language/translate/v2?target=en&q=Bonjour&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))

    # 4. YouTube
    yt_base = "https://www.googleapis.com/youtube/v3"
    tasks.append(("YouTube (MostPopular)", "GET", f"{yt_base}/videos?part=snippet&chart=mostPopular&maxResults=1&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))
    tasks.append(("YouTube (Search)", "GET", f"{yt_base}/search?part=snippet&maxResults=1&q=test&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))

    # 5-8. Maps
    tasks.append(("Static Maps", "GET", f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={apikey}", {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey}))
    tasks.append(("Streetview", "GET", f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.72,-73.98&key={apikey}", {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey}))
    tasks.append(("Maps Directions", "GET", f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))
    tasks.append(("Maps Geocode", "GET", f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))

    # 9. Vision
    vision_body = {"requests": [{"image": {"source": {"imageUri": "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Google_2015_logo.svg/368px-Google_2015_logo.svg.png"}}, "features": [{"type": "LABEL_DETECTION", "maxResults": 1}]}]}
    tasks.append(("Vision API", "POST", f"https://vision.googleapis.com/v1/images:annotate?key={apikey}", {"json_body": vision_body, "header_fallback": True, "apikey_for_header": apikey}))

    # 10. Drive
    tasks.append(("Drive API (List)", "GET", f"https://www.googleapis.com/drive/v3/files?pageSize=1&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))

    # 11. Translate-PA
    tp_url = "https://translate-pa.googleapis.com/v1/translateHtml"
    tp_data = '[[["Hello, from slayer_apis_scanner !!!"],"en","hi"],"en"]'
    tasks.append((
        "Translate-PA (Internal)", "POST",
        tp_url,
        {
            "data": tp_data,
            "force_raw_data": True,
            "force_content_type": "application/json+protobuf",
            "use_key_header": True,
            "apikey_for_header": apikey,
            "treat_200_non_json_as_vuln": True
        }
    ))

    # 12. Storage
    if project_id:
        tasks.append(("Cloud Storage List", "GET", f"https://www.googleapis.com/storage/v1/b?project={project_id}&maxResults=1&key={apikey}", {"header_fallback": True, "apikey_for_header": apikey}))

    # 13. FCM
    if run_fcm:
        fcm_headers = {"Content-Type": "application/json", "Authorization": "key=" + apikey}
        fcm_body = {"registration_ids": ["ABC"]}
        tasks.append(("FCM (Server Key)", "POST", "https://fcm.googleapis.com/fcm/send", {"json_body": fcm_body, "headers": fcm_headers}))

    # 14. TTS
    if run_ai:
        tts_body = {"input": {"text": "Hello, from slayer !!!"}, "voice": {"languageCode": "en-US", "name": "en-US-Wavenet-D"}, "audioConfig": {"audioEncoding": "MP3"}}
        tasks.append(("Text-to-Speech", "POST", f"https://texttospeech.googleapis.com/v1/text:synthesize?key={apikey}", {"json_body": tts_body, "header_fallback": True, "apikey_for_header": apikey}))

    # 15. Identity
    id_body = {"providerId": "google.com", "continueUri": "http://localhost"}
    tasks.append(("Identity Toolkit (Firebase)", "POST", f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={apikey}", {"json_body": id_body, "header_fallback": True, "apikey_for_header": apikey}))

    # Execute
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_check = {executor.submit(check_endpoint, name, method, url, **kwargs): name for (name, method, url, kwargs) in tasks}
        for future in as_completed(future_to_check):
            try:
                future.result()
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[ERROR] Thread failed: {e}")

    # Summary
    with PRINT_LOCK:
        print("\n-------------------------------------------------------------")
        print("  Summary of Vulnerabilities")
        print("-------------------------------------------------------------")
        if VULNERABLE_APIS:
            for name, url, note in VULNERABLE_APIS:
                print(f"\033[1;31m[VULN]\033[0m {name}")
                print(f"       PoC : {url}")
                if note: print(f"       Note: {note}")
        else:
            print("No vulnerabilities found.")
        print("-------------------------------------------------------------")
        # Signed footer for attribution in logs/reports
        print("\033[1;30mScanner executed, Thanks for using from Slayer | slayer_apis_scanner\033[0m")
        print("-------------------------------------------------------------")

def main():
    global VERBOSE_MODE, MAX_WORKERS
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("-a", "--api-key", help="Google API key to test")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose HTTP requests/responses")
    parser.add_argument("--no-ai", action="store_false", dest="run_ai", help="Skip AI checks")
    parser.add_argument("--no-fcm", action="store_false", dest="run_fcm", help="Skip FCM checks")
    parser.add_argument("--project-id", help="GCP Project ID for storage checks")
    parser.add_argument("-t", "--threads", type=int, default=MAX_WORKERS, help="Number of concurrent threads (default: 8)")
    args = parser.parse_args()
    
    VERBOSE_MODE = args.verbose
    MAX_WORKERS = max(1, args.threads)
    key = args.api_key or input("Enter Google API Key: ").strip()
    if not key:
        print("No key provided."); sys.exit(1)
    scan_key(key, run_ai=args.run_ai, run_fcm=args.run_fcm, project_id=args.project_id, threads=MAX_WORKERS)

if __name__ == "__main__":
    main()
