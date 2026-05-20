#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  slayer_apis_scanner — Google API Key Misconfiguration Scanner
  Version : v4.0

  Author  : Slayer
  Role    : Security Research / Offensive Testing
  Scope   : Google API key exposure & misconfiguration detection
═══════════════════════════════════════════════════════════════

Changelog v4.0 (Major Update):
 - [CRITICAL FIX] Removed createAuthUri false positive (OAuth discovery endpoint, not a vulnerability)
 - [CRITICAL FIX] Added EMAIL_EXISTS detection for Firebase signUp (prevents false positives)
 - [IMPROVEMENT] Removed automatic severity classification (P1/P2) - tester determines impact based on context
 - [Feature] Added --poc flag for curl command generation
 - [Feature] Added Generative Language API endpoint
 - [Feature] Added 8 new Maps API endpoints (Distance Matrix, Geolocate, Find Place, etc.)
 - [Improvement] Better output formatting 
 - [Fix] Improved error detection for API responses
 - [Fix] Proper JSON error field checking
 - [Improvement] Dynamic email generation for signUp tests to avoid EMAIL_EXISTS
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
TOOL_VERSION = "v4.0"
DEFAULT_TIMEOUT = 12
MAX_WORKERS = 8

# Global Flags / Locks
VERBOSE_MODE = False
POC_MODE = False
PRINT_LOCK = threading.Lock()
VULNERABLE_APIS = []

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

# ----------------- Utils ----------------- #

def banner(masked_key=None, threads=None):
    with PRINT_LOCK:
        print(f"\n{Colors.HEADER}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}║  {TOOL_NAME} {TOOL_VERSION} - Google API Key Scanner      ║{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Author    : Slayer{Colors.ENDC}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        if masked_key is not None:
            print(f"{Colors.OKBLUE}API Key   : {masked_key}{Colors.ENDC}")
        if threads is not None:
            print(f"{Colors.OKBLUE}Threads   : {threads}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Mode      : {'Verbose' if VERBOSE_MODE else 'Standard'} | PoC: {'Enabled' if POC_MODE else 'Disabled'}{Colors.ENDC}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        print(f"{Colors.WARNING}⚠️  Scanner reports accessible endpoints - tester determines actual impact{Colors.ENDC}")

def verbose_log(method, url, headers, data=None, resp=None):
    if not VERBOSE_MODE:
        return
    with PRINT_LOCK:
        print(f"\n{Colors.GRAY}[VERBOSE] > {method} {url}")
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
                print(f"< Resp Body: {snippet}...{Colors.ENDC}")
            except Exception:
                print(f"< Resp Body: (binary/unprintable)...{Colors.ENDC}")

def generate_curl_command(method, url, headers=None, data=None, json_body=None):
    """Generate curl command for PoC"""
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

def print_vuln(name, url, note=None, method="GET", headers=None, data=None, json_body=None, response_preview=None):
    with PRINT_LOCK:
        print(f"\n{Colors.FAIL}[VULN]{Colors.ENDC} {name}")
        print(f"{Colors.GRAY}       PoC URL : {Colors.ENDC}{url}")
        
        if POC_MODE:
            curl_cmd = generate_curl_command(method, url, headers, data, json_body)
            print(f"{Colors.GRAY}       PoC cURL: {Colors.ENDC}{curl_cmd}")
            if response_preview:
                preview = response_preview[:300].replace('\n', ' ')
                print(f"{Colors.GRAY}       Response: {Colors.ENDC}{preview}...")
        
        if note:
            print(f"{Colors.GRAY}       Note    : {Colors.ENDC}{note}")
        
        VULNERABLE_APIS.append({
            "name": name,
            "url": url,
            "note": note,
            "curl": generate_curl_command(method, url, headers, data, json_body) if POC_MODE else None
        })

def print_info(msg, color=None):
    with PRINT_LOCK:
        if color:
            print(f"{color}{msg}{Colors.ENDC}")
        else:
            print(msg)

def try_get(url, headers=None, allow_redirects=True, timeout=DEFAULT_TIMEOUT):
    try:
        if VERBOSE_MODE: verbose_log("GET", url, headers)
        resp = requests.get(url, headers=headers, verify=True, allow_redirects=allow_redirects, timeout=timeout)
        if VERBOSE_MODE: verbose_log("GET", url, headers, resp=resp)
        return resp
    except requests.exceptions.RequestException as e:
        if VERBOSE_MODE:
            with PRINT_LOCK:
                print(f"{Colors.GRAY}[VERBOSE] Request failed: {str(e)}{Colors.ENDC}")
        return None

def try_post(url, data=None, json_body=None, headers=None, timeout=DEFAULT_TIMEOUT):
    send_data = data
    try:
        if send_data is None and json_body is not None:
            send_data = json.dumps(json_body)
        if VERBOSE_MODE: verbose_log("POST", url, headers, data=send_data)

        kwargs = {'headers': headers or {}, 'verify': True, 'timeout': timeout}
        if data is not None:
            kwargs['data'] = data
        elif json_body is not None:
            kwargs['json'] = json_body

        resp = requests.post(url, **kwargs)
        if VERBOSE_MODE: verbose_log("POST", url, headers, data=send_data, resp=resp)
        return resp
    except requests.exceptions.RequestException as e:
        if VERBOSE_MODE:
            with PRINT_LOCK:
                print(f"{Colors.GRAY}[VERBOSE] Request failed: {str(e)}{Colors.ENDC}")
        return None

# ----------------- Error parsing & classification ----------------- #

def parse_error_reason(resp):
    """Extract error reason from Google API response"""
    if resp is None:
        return "request_failed"

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
                "ipRefererBlocked",
                "permissionDenied",
                "blocked",
                "not found",
                "SERVICE_DISABLED",
            )
            for token in tokens:
                if token.lower() in txt.lower():
                    return token
    except Exception:
        pass

    try:
        j = resp.json()
    except Exception:
        return f"non-json_status_{getattr(resp, 'status_code', 'no_status')}"

    if isinstance(j, dict):
        if "error" in j:
            err = j["error"]
            if isinstance(err, dict):
                if "errors" in err and isinstance(err["errors"], list) and err["errors"]:
                    e0 = err["errors"][0]
                    return e0.get("reason") or e0.get("message") or "error_with_errors_list"
                if "message" in err:
                    return err["message"]
                if "status" in err:
                    return err.get("status")
            return str(err)
        for key in ("error_message", "errorMessage", "reason", "message"):
            if key in j:
                return j.get(key)
    return "unknown_error_shape"

def classify_reason(reason, status_code):
    """Classify error reason into categories"""
    if reason is None:
        return "other"
    r = str(reason).lower()
    
    if status_code in (200, 201):
        return "success"
    
    # Invalid key
    if (
        "invalidapikey" in r
        or "invalid api key" in r
        or "api key not valid" in r
        or "invalid key" in r
    ):
        return "invalid_key"
    
    # API not enabled but key is valid
    if (
        "accessnotconfigured" in r
        or "has not been used in project" in r
        or "it is disabled" in r
        or "api has not been used" in r
        or "not enabled" in r
        or "service_disabled" in r
        or "permission_denied" in r  # Often means API not enabled
    ):
        return "api_not_enabled_but_key_valid"
    
    # Quota
    if "quota" in r or "quotaexceeded" in r or "quota exceeded" in r:
        return "quota_exceeded"
    
    # Restrictions
    if (
        "referernotallowed" in r
        or "referer not allowed" in r
        or "ip not allowed" in r
        or "iprefererblocked" in r
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
    """Remove only the `key` query parameter from a URL"""
    try:
        p = urlparse(url)
        qs = parse_qsl(p.query, keep_blank_values=True)
        qs = [(k, v) for (k, v) in qs if k.lower() != "key"]
        new_q = urlencode(qs)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
    except Exception:
        return url

def mask_api_key(key: str) -> str:
    """Mask API key for display"""
    if not key:
        return ""
    if len(key) <= 8:
        return key[0:2] + "*" * max(0, len(key)-4) + key[-2:]
    return key[:4] + "*" * (len(key)-8) + key[-4:]

# ----------------- Endpoint Check Logic ----------------- #

def check_endpoint(
    name, method, url, headers=None, json_body=None, data=None,
    expect_image=False, allow_redirects=True, treat_200_non_json_as_vuln=False,
    header_fallback=False, apikey_for_header=None, use_key_header=False,
    force_raw_data=False, force_content_type=None
):
    method = method.upper()
    headers = headers.copy() if headers else {}

    if use_key_header and apikey_for_header:
        headers["X-Goog-Api-Key"] = apikey_for_header
        url = strip_key_param(url)

    if force_content_type:
        headers["Content-Type"] = force_content_type

    resp = None
    if method == "GET":
        resp = try_get(url, headers=headers, allow_redirects=allow_redirects)
    elif method == "POST":
        if force_raw_data and data is None and json_body is not None:
            resp = try_post(url, data=json.dumps(json_body), headers=headers)
        else:
            resp = try_post(url, data=data, json_body=json_body, headers=headers)

    if resp is None:
        # Don't print "request failed" to avoid clutter
        return False

    reason = parse_error_reason(resp)
    cls = classify_reason(reason, getattr(resp, "status_code", None))

    # Header fallback
    if header_fallback and cls in ("invalid_key", "api_not_enabled_but_key_valid", "other") and apikey_for_header:
        if "X-Goog-Api-Key" not in headers:
            return check_endpoint(
                name, method, url, headers, json_body, data, expect_image,
                allow_redirects, treat_200_non_json_as_vuln,
                header_fallback=False, apikey_for_header=apikey_for_header, use_key_header=True,
                force_raw_data=force_raw_data, force_content_type=force_content_type
            )

    # Success Detection
    if expect_image:
        if resp.status_code == 200 and is_image_response(resp):
            print_vuln(name, url, f"Returned image ({len(resp.content)} bytes)", 
                      method=method, headers=headers)
            return True
        elif resp.status_code in (302, 303):
            print_vuln(name, url, f"Redirected to {resp.headers.get('Location')}", 
                      method=method, headers=headers)
            return True
        return False

    if resp.status_code in (200, 201):
        try:
            j = resp.json()
            # Check for error fields that indicate failure
            if isinstance(j, dict):
                # Check for explicit error object
                if j.get("error"):
                    error_obj = j["error"]
                    if isinstance(error_obj, dict):
                        error_msg = error_obj.get("message", "")
                        # EMAIL_EXISTS means signup failed - not a vulnerability
                        if "EMAIL_EXISTS" in error_msg or "email already exists" in error_msg.lower():
                            print_info(f"{name}: Endpoint exists but EMAIL_EXISTS (test account already created)", Colors.GRAY)
                            return False
                    # Other error objects indicate failure
                    return False
                
                # Check for other error indicators
                if j.get("error_message") or j.get("errorMessage"):
                    return False
                
                # For Firebase signUp specifically, verify account was actually created
                if "signUp" in name and "idToken" not in j:
                    # No idToken means account wasn't created
                    return False
                
                # Success - valid response without errors
                snippet = str(j)[:200].replace('\n', '')
                response_preview = json.dumps(j) if POC_MODE else None
                print_vuln(name, url, f"Success: {snippet}...", 
                          method=method, headers=headers, 
                          data=data, json_body=json_body, response_preview=response_preview)
                return True
        except ValueError:
            if treat_200_non_json_as_vuln:
                snippet = (resp.text or "")[:200].replace('\n', '')
                response_preview = resp.text if POC_MODE else None
                print_vuln(name, url, f"Raw response: {snippet}...", 
                          method=method, headers=headers, 
                          data=data, json_body=json_body, response_preview=response_preview)
                return True

    # Informational messages (not vulnerabilities but useful info)
    if cls == "api_not_enabled_but_key_valid":
        print_info(f"{name}: {Colors.WARNING}Valid Key{Colors.ENDC} but API not enabled", Colors.GRAY)
    elif cls == "quota_exceeded":
        print_info(f"{name}: {Colors.WARNING}Valid Key{Colors.ENDC} but Quota Exceeded", Colors.GRAY)
    elif cls == "restricted_key":
        print_info(f"{name}: {Colors.WARNING}Valid Key{Colors.ENDC} but IP/Referer Restricted", Colors.GRAY)
    elif cls == "invalid_key":
        print_info(f"{name}: {Colors.FAIL}Invalid Key{Colors.ENDC}", Colors.GRAY)

    return False

# ----------------- Main Scanner ----------------- #

def scan_key(apikey, run_ai=True, run_fcm=True, project_id=None, threads=MAX_WORKERS):
    global VULNERABLE_APIS
    VULNERABLE_APIS = []
    masked = mask_api_key(apikey)
    banner(masked_key=masked, threads=threads)
    
    if project_id:
        print_info(f"{Colors.OKBLUE}Project   : {project_id}{Colors.ENDC}")
    
    print_info(f"\n{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
    print_info(f"{Colors.BOLD}Starting API endpoint scan...{Colors.ENDC}\n")

    tasks = []

    # ============= CRITICAL ENDPOINTS ============= #
    
    # 1. Firebase Identity Toolkit - signUp
    # Note: Success means account was actually created (not EMAIL_EXISTS error)
    signup_body = {
        "email": "test-slayer-scanner-{}@example.com".format(hash(apikey) % 100000),
        "password": "TestPassword123!",
        "returnSecureToken": True
    }
    tasks.append(("Firebase signUp", "POST", 
                 f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={apikey}", 
                 {"json_body": signup_body, "header_fallback": True, "apikey_for_header": apikey}))

    # ============= HIGH VALUE ENDPOINTS ============= #
    
    # 3. Custom Search API
    cse_id = "017576662512468239146:omuauf_lfve"
    tasks.append(("Custom Search API", "GET", 
                 f"https://www.googleapis.com/customsearch/v1?q=test&cx={cse_id}&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))

    # 4. Calendar API
    tasks.append(("Calendar API", "GET", 
                 f"https://www.googleapis.com/calendar/v3/users/me/calendarList?key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))

    # 5. Translate v2
    tasks.append(("Translate v2", "GET", 
                 f"https://translation.googleapis.com/language/translate/v2?target=en&q=bonne%20journ%C3%A9e%20de%20Slayer&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))

    # 6-7. YouTube
    yt_base = "https://www.googleapis.com/youtube/v3"
    tasks.append(("YouTube (MostPopular)", "GET", 
                 f"{yt_base}/videos?part=snippet&chart=mostPopular&maxResults=1&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    tasks.append(("YouTube (Search)", "GET", 
                 f"{yt_base}/search?part=snippet&maxResults=1&q=test&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))

    # ============= MAPS API ENDPOINTS ============= #
    
    # 8. Static Maps
    tasks.append(("Maps - Static Maps", "GET", 
                 f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={apikey}", 
                 {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey}))
    
    # 9. Streetview
    tasks.append(("Maps - Streetview", "GET", 
                 f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={apikey}", 
                 {"expect_image": True, "header_fallback": True, "apikey_for_header": apikey}))
    
    # 10. Directions
    tasks.append(("Maps - Directions", "GET", 
                 f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 11. Geocoding
    tasks.append(("Maps - Geocode", "GET", 
                 f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 12. Distance Matrix
    tasks.append(("Maps - Distance Matrix", "GET", 
                 f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615,-73.9976592&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 13. Find Place from Text
    tasks.append(("Maps - Find Place", "GET", 
                 f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art&inputtype=textquery&fields=photos,formatted_address,name&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 14. Autocomplete
    tasks.append(("Maps - Autocomplete", "GET", 
                 f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Paris&types=(cities)&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 15. Elevation
    tasks.append(("Maps - Elevation", "GET", 
                 f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 16. Timezone
    tasks.append(("Maps - Timezone", "GET", 
                 f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 17. Roads
    tasks.append(("Maps - Roads", "GET", 
                 f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))
    
    # 18. Geolocate
    tasks.append(("Maps - Geolocate", "POST", 
                 f"https://www.googleapis.com/geolocation/v1/geolocate?key={apikey}", 
                 {"json_body": {}, "header_fallback": True, "apikey_for_header": apikey}))

    # ============= AI/ML ENDPOINTS ============= #
    
    # 19. Vision API
    vision_body = {
        "requests": [{
            "image": {"source": {"imageUri": "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Google_2015_logo.svg/368px-Google_2015_logo.svg.png"}}, 
            "features": [{"type": "LABEL_DETECTION", "maxResults": 1}]
        }]
    }
    tasks.append(("Vision API", "POST", 
                 f"https://vision.googleapis.com/v1/images:annotate?key={apikey}", 
                 {"json_body": vision_body, "header_fallback": True, "apikey_for_header": apikey}))

    # 20. Text-to-Speech
    if run_ai:
        tts_body = {
            "input": {"text": "Hello, from slayer !!!"}, 
            "voice": {"languageCode": "en-US", "name": "en-US-Wavenet-D"}, 
            "audioConfig": {"audioEncoding": "MP3"}
        }
        tasks.append(("Text-to-Speech", "POST", 
                     f"https://texttospeech.googleapis.com/v1/text:synthesize?key={apikey}", 
                     {"json_body": tts_body, "header_fallback": True, "apikey_for_header": apikey}))

    # 21. Generative Language API (Gemini)
    tasks.append(("Generative Language API", "GET", 
                 f"https://generativelanguage.googleapis.com/v1beta/files?key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))

    # ============= OTHER ENDPOINTS ============= #
    
    # 22. Drive API
    tasks.append(("Drive API (List)", "GET", 
                 f"https://www.googleapis.com/drive/v3/files?pageSize=1&key={apikey}", 
                 {"header_fallback": True, "apikey_for_header": apikey}))

    # 23. Translate-PA (Internal)
    tp_url = "https://translate-pa.googleapis.com/v1/translateHtml"
    tp_data = '[[["Hello, from slayer_apis_scanner !!!"],"en","hi"],"en"]'
    tasks.append(("Translate-PA (Internal)", "POST", tp_url, {
        "data": tp_data,
        "force_raw_data": True,
        "force_content_type": "application/json+protobuf",
        "use_key_header": True,
        "apikey_for_header": apikey,
        "treat_200_non_json_as_vuln": True
    }))

    # 24. Cloud Storage
    if project_id:
        tasks.append(("Cloud Storage List", "GET", 
                     f"https://www.googleapis.com/storage/v1/b?project={project_id}&maxResults=1&key={apikey}", 
                     {"header_fallback": True, "apikey_for_header": apikey}))

    # 25. FCM
    if run_fcm:
        fcm_headers = {"Content-Type": "application/json", "Authorization": "key=" + apikey}
        fcm_body = {"registration_ids": ["ABC"]}
        tasks.append(("FCM (Server Key)", "POST", "https://fcm.googleapis.com/fcm/send", 
                     {"json_body": fcm_body, "headers": fcm_headers}))

    # Execute all tasks
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_check = {
            executor.submit(check_endpoint, name, method, url, **kwargs): name 
            for (name, method, url, kwargs) in tasks
        }
        for future in as_completed(future_to_check):
            try:
                future.result()
            except Exception as e:
                if VERBOSE_MODE:
                    with PRINT_LOCK:
                        print(f"{Colors.FAIL}[ERROR] Thread failed: {e}{Colors.ENDC}")

    # Summary
    print_summary()

def print_summary():
    with PRINT_LOCK:
        print(f"\n{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        print(f"{Colors.BOLD}  SCAN SUMMARY{Colors.ENDC}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}\n")
        
        if VULNERABLE_APIS:
            print(f"{Colors.FAIL}{Colors.BOLD}Findings: {len(VULNERABLE_APIS)} endpoint(s) accessible{Colors.ENDC}\n")
            
            for v in VULNERABLE_APIS:
                print(f"{Colors.FAIL}  ● {v['name']}{Colors.ENDC}")
                print(f"{Colors.GRAY}    PoC: {v['url']}{Colors.ENDC}")
                if POC_MODE and v.get('curl'):
                    print(f"{Colors.GRAY}    {v['curl']}{Colors.ENDC}")
                if v.get('note'):
                    print(f"{Colors.GRAY}    {v['note']}{Colors.ENDC}")
                print()
            
            print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
            print(f"{Colors.FAIL}{Colors.BOLD}Total Accessible Endpoints: {len(VULNERABLE_APIS)}{Colors.ENDC}")
            print(f"{Colors.WARNING}⚠️  Review each finding in context to determine actual impact{Colors.ENDC}")
        else:
            print(f"{Colors.OKGREEN}✓ No accessible endpoints found.{Colors.ENDC}")
            print(f"{Colors.GRAY}  The API key appears to be properly restricted or invalid.{Colors.ENDC}")
        
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}")
        print(f"{Colors.GRAY}Scanner: {TOOL_NAME} {TOOL_VERSION} by Slayer{Colors.ENDC}")
        print(f"{Colors.GRAY}GitHub : https://github.com/dodal-omkar/slayer-apis-scanner{Colors.ENDC}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}\n")

def main():
    global VERBOSE_MODE, MAX_WORKERS, POC_MODE
    
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} {TOOL_VERSION} - Google API Key Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -a AIzaSyABC123...
  %(prog)s -a AIzaSyABC123... -v --poc
  %(prog)s -a AIzaSyABC123... --project-id my-project-123 -t 16
  %(prog)s -a AIzaSyABC123... --no-ai --no-fcm
        """
    )
    
    parser.add_argument("-a", "--api-key", help="Google API key to test")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Print verbose HTTP requests/responses")
    parser.add_argument("--poc", action="store_true", 
                       help="Generate curl PoC commands for vulnerabilities")
    parser.add_argument("--no-ai", action="store_false", dest="run_ai", 
                       help="Skip AI/ML checks (TTS, etc.)")
    parser.add_argument("--no-fcm", action="store_false", dest="run_fcm", 
                       help="Skip FCM checks")
    parser.add_argument("--project-id", help="GCP Project ID for storage checks")
    parser.add_argument("-t", "--threads", type=int, default=MAX_WORKERS, 
                       help=f"Number of concurrent threads (default: {MAX_WORKERS})")
    
    args = parser.parse_args()
    
    VERBOSE_MODE = args.verbose
    POC_MODE = args.poc
    MAX_WORKERS = max(1, args.threads)
    
    key = args.api_key or input(f"{Colors.OKCYAN}Enter Google API Key: {Colors.ENDC}").strip()
    if not key:
        print(f"{Colors.FAIL}Error: No API key provided{Colors.ENDC}")
        sys.exit(1)
    
    scan_key(key, run_ai=args.run_ai, run_fcm=args.run_fcm, 
            project_id=args.project_id, threads=MAX_WORKERS)

if __name__ == "__main__":
    main()
