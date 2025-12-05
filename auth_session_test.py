#!/usr/bin/env python3
"""
Auth & Session Testing Module for WebScanPro (Week 4)
Safe, local-lab oriented (DVWA by default).

Capabilities:
- default/weak credential check (limited list)
- controlled brute-force simulation (rate-limited)
- cookie flags inspection (Secure, HttpOnly, SameSite)
- session rotation check (session id before vs after login)
- logout invalidation check
- JSON report generation (auth_session_report.json)

Usage:
    python auth_session_tester.py

IMPORTANT:
- Run only against systems you own or have permission to test (DVWA local lab recommended).
- This script intentionally keeps brute-force attempts small and rate-limited.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import json
import datetime
import sys

# ------------- Configuration -------------
BASE = "http://localhost:8080/"           # DVWA default (change if needed)
LOGIN_PATH = "login.php"
LOGOUT_PATH = "logout.php"
PROTECTED_CHECK_PATH = "vulnerabilities/sqli/"  # page only visible/useful after login
CSRF_FIELD = "user_token"                 # DVWA CSRF token field name

# small, safe credential lists (lab/demo only)
COMMON_DEFAULTS = [
    ("admin", "password"),
    ("admin", "admin"),
    ("root", "root"),
    ("test", "test")
]

# limited brute-force password list (do NOT expand for production)
BRUTE_FOR_TOKENS = ["password", "admin", "123456", "qwerty", "letmein"]

# delay between attempts (seconds)
BRUTE_DELAY = 1.0

REPORT_FILE = "auth_session_report.json"

# ------------- Helpers -------------
def now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"

def get_csrf_token(session, login_url):
    """Fetch login page and return value of CSRF input (if present)."""
    r = session.get(login_url, timeout=10)
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": CSRF_FIELD})
    if token_input:
        return token_input.get("value")
    return None

def post_login(session, login_url, username, password, token=None):
    """Perform login POST. Returns response object."""
    data = {
        "username": username,
        "password": password,
        "Login": "Login"
    }
    if token:
        data[CSRF_FIELD] = token
    return session.post(login_url, data=data, timeout=10, allow_redirects=True)

def is_logged_in(response):
    """Heuristic: DVWA shows 'logout' link when logged in."""
    return "logout" in response.text.lower()

def inspect_cookie_flags(response):
    """
    Inspect Set-Cookie headers in requests.Response.
    Returns dict mapping cookie -> flags dict.
    """
    cookies_info = {}
    # requests.Response.headers may contain multiple Set-Cookie separated per header key
    set_cookie_headers = response.headers.getlist("Set-Cookie") if hasattr(response.headers, "getlist") else response.headers.get("Set-Cookie")
    # requests library typically folds multiple Set-Cookie into one readable str only on urllib3, so iterate session.cookies as alternative
    for cookie in response.cookies:
        c = cookie
        flags = {
            "secure": False,
            "httponly": False,
            "samesite": None,
            "domain": c.domain,
            "name": c.name,
            "value": "REDACTED"
        }
        # Some attributes are not exposed by CookieJar; parse raw header if available
        # Try to locate matching Set-Cookie header for this cookie name
        raw = None
        if isinstance(set_cookie_headers, list):
            for header in set_cookie_headers:
                if f"{c.name}=" in header:
                    raw = header
                    break
        elif isinstance(set_cookie_headers, str):
            if f"{c.name}=" in set_cookie_headers:
                raw = set_cookie_headers

        if raw:
            l = raw.lower()
            flags["secure"] = "secure" in l
            flags["httponly"] = "httponly" in l
            # find samesite token if present
            for token in ("samesite=lax", "samesite=strict", "samesite=none"):
                if token in l:
                    flags["samesite"] = token.split("=")[1]
                    break
        cookies_info[c.name] = flags
    return cookies_info

# ------------- Tests -------------
def check_default_credentials(target_base, session=None):
    """Try a short list of default credentials. Return findings list."""
    findings = []
    s = session or requests.Session()
    login_url = urljoin(target_base, LOGIN_PATH)
    for username, password in COMMON_DEFAULTS:
        token = get_csrf_token(s, login_url)
        r = post_login(s, login_url, username, password, token)
        success = is_logged_in(r)
        findings.append({
            "timestamp": now_iso(),
            "test": "default_credentials",
            "username": username,
            "password_tested": True,   # we don't store plaintext in report beyond this flag
            "success": bool(success),
            "evidence_excerpt": r.text[:200]
        })
        # If success, logout and stop trying further defaults to be polite
        if success:
            s.get(urljoin(target_base, LOGOUT_PATH))
            break
    return findings

def brute_force_username(target_base, username="admin", passwords=None, limit=5, delay=BRUTE_DELAY):
    """Controlled brute force simulation against a single username.
       passwords: list of candidates (small). limit: max attempts recorded.
    """
    findings = []
    attempts = 0
    s = requests.Session()
    login_url = urljoin(target_base, LOGIN_PATH)
    pwd_list = passwords or BRUTE_FOR_TOKENS
    for pwd in pwd_list:
        if attempts >= limit:
            break
        token = get_csrf_token(s, login_url)
        r = post_login(s, login_url, username, pwd, token)
        success = is_logged_in(r)
        findings.append({
            "timestamp": now_iso(),
            "test": "bruteforce_sim",
            "username": username,
            "password_tried": True,  # avoid storing plaintext password
            "success": bool(success),
            "response_len": len(r.text)
        })
        attempts += 1
        if success:
            # polite cleanup
            s.get(urljoin(target_base, LOGOUT_PATH))
            break
        time.sleep(delay)
    return findings

def check_cookie_policies(target_base, session=None):
    """Fetch a page and inspect cookie flags (Set-Cookie headers)."""
    s = session or requests.Session()
    r = s.get(target_base, timeout=10)
    # inspect cookies from response
    cookies = inspect_cookie_flags(r)
    return {
        "timestamp": now_iso(),
        "test": "cookie_flags",
        "cookies": cookies
    }

def test_session_rotation(target_base):
    """
    Check whether session id rotates on login.
    Steps:
      - Anonymous session A: GET base -> record session cookie (e.g., PHPSESSID)
      - Login with new session B or same session: perform login, get session cookie post-login
      - If cookie value changes, rotation implemented (good). If same, rotation missing (issue).
    """
    s = requests.Session()
    login_url = urljoin(target_base, LOGIN_PATH)
    # initial GET to collect pre-login cookies
    r1 = s.get(target_base, timeout=10)
    pre_cookies = {c.name: c.value for c in s.cookies}
    pre_session = None
    # common session cookie names
    for candidate in ("PHPSESSID", "session", "SessionID"):
        if candidate in pre_cookies:
            pre_session = {candidate: pre_cookies[candidate]}
            break

    token = get_csrf_token(s, login_url)
    r2 = post_login(s, login_url, "admin", "password", token)
    post_cookies = {c.name: c.value for c in s.cookies}
    post_session = None
    for candidate in ("PHPSESSID", "session", "SessionID"):
        if candidate in post_cookies:
            post_session = {candidate: post_cookies[candidate]}
            break

    result = {
        "timestamp": now_iso(),
        "test": "session_rotation",
        "pre_session_cookie": bool(pre_session),
        "post_session_cookie": bool(post_session),
        "pre_value_redacted": bool(pre_session),
        "post_value_redacted": bool(post_session),
        "rotated": None
    }
    # determine rotation if both present and different values
    if pre_session and post_session:
        # compare names and values in a redacted manner
        pre_name = list(pre_session.keys())[0]
        post_name = list(post_session.keys())[0]
        if pre_name != post_name:
            result["rotated"] = True
        else:
            result["rotated"] = (pre_session[pre_name] != post_session[post_name])
    else:
        # if one missing assume rotation behavior unknown/partial
        result["rotated"] = None

    # logout cleanup
    try:
        s.get(urljoin(target_base, LOGOUT_PATH), timeout=5)
    except Exception:
        pass

    return result

def test_logout_invalidation(target_base):
    """
    Check whether server invalidates session after logout:
      - login, capture session cookie + access protected page (should be accessible)
      - perform logout, then try to access same protected page using same session
      - if still accessible -> logout invalidation failure
    """
    s = requests.Session()
    login_url = urljoin(target_base, LOGIN_PATH)
    token = get_csrf_token(s, login_url)
    r_login = post_login(s, login_url, "admin", "password", token)
    logged = is_logged_in(r_login)
    # try to access protected page
    protected_url = urljoin(target_base, PROTECTED_CHECK_PATH)
    r_prot_before = s.get(protected_url, timeout=10)
    before_ok = ("logout" in r_prot_before.text.lower()) or (r_prot_before.status_code == 200 and len(r_prot_before.text) > 200)
    # perform logout
    s.get(urljoin(target_base, LOGOUT_PATH), timeout=10)
    # try access again with same session
    r_prot_after = s.get(protected_url, timeout=10)
    after_ok = ("logout" in r_prot_after.text.lower()) or (r_prot_after.status_code == 200 and len(r_prot_after.text) > 200)
    result = {
        "timestamp": now_iso(),
        "test": "logout_invalidation",
        "login_success": bool(logged),
        "protected_before_accessible": bool(before_ok),
        "protected_after_accessible": bool(after_ok),
        "logout_invalidation_ok": (before_ok and not after_ok)
    }
    return result

# ------------- Runner & Report -------------
def run_all_tests(target_base=BASE):
    report = {
        "target": target_base,
        "started_at": now_iso(),
        "tests": []
    }

    s = requests.Session()

    # 1. Cookie flags (initial page)
    try:
        ck = check_cookie_policies(target_base, session=s)
        report["tests"].append(ck)
    except Exception as e:
        report["tests"].append({"test": "cookie_flags", "error": str(e), "timestamp": now_iso()})

    # 2. Default credentials
    try:
        defaults = check_default_credentials(target_base, session=s)
        report["tests"].extend(defaults)
    except Exception as e:
        report["tests"].append({"test": "default_credentials", "error": str(e), "timestamp": now_iso()})

    # 3. Controlled brute-force (small)
    try:
        brute = brute_force_username(target_base, username="admin", passwords=BRUTE_FOR_TOKENS, limit=4, delay=BRUTE_DELAY)
        report["tests"].extend(brute)
    except Exception as e:
        report["tests"].append({"test": "bruteforce_sim", "error": str(e), "timestamp": now_iso()})

    # 4. Session rotation
    try:
        rot = test_session_rotation(target_base)
        report["tests"].append(rot)
    except Exception as e:
        report["tests"].append({"test": "session_rotation", "error": str(e), "timestamp": now_iso()})

    # 5. Logout invalidation
    try:
        lo = test_logout_invalidation(target_base)
        report["tests"].append(lo)
    except Exception as e:
        report["tests"].append({"test": "logout_invalidation", "error": str(e), "timestamp": now_iso()})

    report["finished_at"] = now_iso()
    return report

def save_report(report_obj, fname=REPORT_FILE):
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report_obj, f, indent=2)
    print(f"[+] Report written to {fname}")

# ------------- CLI -------------
if __name__ == "__main__":
    print("[*] Running Authentication & Session tests (safe defaults).")
    print("[!] Make sure DVWA is running and you have permission to test.")
    print()

    rep = run_all_tests(BASE)
    save_report(rep)
    print("\nSummary:")
    # quick summary prints
    for t in rep["tests"]:
        print("-", t.get("test", "unknown"), ":", "error" in t and t["error"] or t.get("success", t))
    print("\nDone.")
