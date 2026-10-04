#!/usr/bin/env python3
"""Interactive, robust HackerOne disclosed-reports crawler.

Run with no args for fully interactive mode:
    python3 crawler.py

Optional non-interactive overrides (all optional, for automation):
    python3 crawler.py --username USER --token TOKEN --query "disclosed:true ..." --output data

Uses only stdlib + `requests`.
Official HackerOne Hacker API v1: GET /v1/hackers/hacktivity
  Filters: severity_rating, asset_type, substate, cwe, cve_ids,
           reporter, team, total_awarded_amount, disclosed_at,
           has_collaboration, disclosed
  Sort: latest_disclosable_activity_at, disclosed_at,
        total_awarded_amount, votes (prefix '-' = descending)
"""

import csv
import json
import getpass
import os
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:  # pragma: no cover
    print("ERROR: the 'requests' package is required. Install with: pip install requests")
    sys.exit(1)

BASE_URL = "https://api.hackerone.com/v1/hackers/hacktivity"

# ---------------------------------------------------------------------------
# Official / documented option sets
# ---------------------------------------------------------------------------

SEVERITIES = ["none", "low", "medium", "high", "critical"]

# API-side values are lowercase / hyphenated (see H1 import docs + report JSON).
# Display labels are human-friendly; mapping below keeps the query correct.
SUBSTATES = [
    ("1", "Resolved", "resolved"),
    ("2", "Duplicate", "duplicate"),
    ("3", "Triaged", "triaged"),
    ("4", "New", "new"),
    ("5", "Informative", "informative"),
    ("6", "Not Applicable", "not-applicable"),
    ("7", "Needs More Info", "needs-more-info"),
    ("8", "Spam", "spam"),
]

ASSET_TYPES = [
    "URL", "DOMAIN", "WILDCARD", "CIDR", "IP_ADDRESS",
    "ANDROID_PLAY_STORE", "ANDROID_APK", "IOS_APP_STORE", "IOS_IPA",
    "SOURCE_CODE", "EXECUTABLE", "HARDWARE", "SMART_CONTRACT",
    "AI_MODEL", "OTHER",
]

SORT_OPTIONS = [
    ("1", "Recent activity (default: -latest_disclosable_activity_at)", "-latest_disclosable_activity_at"),
    ("2", "Oldest activity (latest_disclosable_activity_at)", "latest_disclosable_activity_at"),
    ("3", "Recently disclosed (-disclosed_at)", "-disclosed_at"),
    ("4", "Earliest disclosed (disclosed_at)", "disclosed_at"),
    ("5", "Highest bounty (-total_awarded_amount)", "-total_awarded_amount"),
    ("6", "Lowest bounty (total_awarded_amount)", "total_awarded_amount"),
    ("7", "Most upvoted (-votes)", "-votes"),
    ("8", "Least upvoted (votes)", "votes"),
]

FIELDNAMES = [
    "id", "title", "url", "program", "program_name", "reporter",
    "substate", "severity", "cvss_score", "weakness", "cwe",
    "cve_ids", "bounty", "upvotes", "disclosed_at", "submitted_at",
    "asset_type", "disclosed",
]

DEFAULT_PAGE_SIZE = 25
DEFAULT_START_PAGE = 1
DEFAULT_MAX_PAGES = 50
DEFAULT_DELAY = 0.6
REQUEST_TIMEOUT = 30
MAX_RETRIES = 5


# ---------------------------------------------------------------------------
# Small prompt helpers (all input validated, Ctrl+C / EOF handled)
# ---------------------------------------------------------------------------

def _input(prompt, default=None):
    try:
        raw = input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Cancelled by user during prompts. Exiting (nothing fetched).")
        sys.exit(130)
    raw = raw.strip()
    if not raw and default is not None:
        return default
    return raw


def ask_secret(prompt):
    try:
        val = getpass.getpass(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Cancelled. Exiting.")
        sys.exit(130)
    return val


def ask_yes_no(prompt, default="y"):
    suffix = " [Y/n]: " if default == "y" else " [y/N]: "
    while True:
        ans = _input(prompt + suffix).strip().lower()
        if not ans:
            return default == "y"
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("    Please answer y or n.")


def ask_int(prompt, default, min_val=None, max_val=None, allow_zero_unlimited=False):
    while True:
        raw = _input(f"{prompt} [{default}]: ", default=str(default)).strip()
        try:
            val = int(raw)
        except ValueError:
            print("    Please enter a whole number.")
            continue
        if allow_zero_unlimited and val == 0:
            return 0
        if min_val is not None and val < min_val:
            print(f"    Must be >= {min_val} (0 = unlimited)." if allow_zero_unlimited else f"    Must be >= {min_val}.")
            continue
        if max_val is not None and val > max_val:
            print(f"    Must be <= {max_val}.")
            continue
        return val


def ask_float(prompt, default):
    while True:
        raw = _input(f"{prompt} [{default}]: ", default=str(default)).strip()
        try:
            val = float(raw)
        except ValueError:
            print("    Please enter a number.")
            continue
        if val < 0:
            print("    Must be >= 0.")
            continue
        return val


def ask_single_choice(title, options, default_num=None):
    """options: list of (num, label, value). Returns value (or None if skipped)."""
    print(f"\n{title}")
    for num, label, _ in options:
        marker = "  <-- default" if default_num and num == default_num else ""
        print(f"  [{num}] {label}{marker}")
    while True:
        raw = _input("  Enter number (or press Enter to skip): ").strip()
        if not raw:
            if default_num:
                for num, _, val in options:
                    if num == default_num:
                        return val
            return None
        for num, _, val in options:
            if raw == num:
                return val
        print("    Invalid choice. Enter one of: " + ", ".join(n for n, _, _ in options))


def ask_multi_choice(title, options):
    """Returns list of values (empty = skip / no filter)."""
    print(f"\n{title}")
    for num, label, _ in options:
        print(f"  [{num}] {label}")
    print("  (comma-separated, e.g. 1,2  - or press Enter to skip)")
    while True:
        raw = _input("  Your choice: ").strip()
        if not raw:
            return []
        picks = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
        valid = {num: val for num, _, val in options}
        if all(p in valid for p in picks):
            # de-duplicate, preserve order
            seen, out = set(), []
            for p in picks:
                if valid[p] not in seen:
                    seen.add(valid[p])
                    out.append(valid[p])
            return out
        print("    Invalid choice. Use numbers like 1,3.")


def ask_optional_text(prompt, example=""):
    hint = f"  (e.g. {example})" if example else ""
    print(f"{prompt}{hint}")
    return _input("  > ").strip()


def ask_optional_list(prompt, example=""):
    print(f"{prompt}")
    if example:
        print(f"  (comma-separated, e.g. {example} - or Enter to skip)")
    else:
        print("  (comma-separated - or Enter to skip)")
    raw = _input("  > ").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]


def ask_date_yyyy_mm_dd(prompt):
    while True:
        raw = _input(prompt + " [skip]: ").strip()
        if not raw:
            return None
        try:
            datetime.strptime(raw, "%Y-%m-%d")
            return raw
        except ValueError:
            print("    Use YYYY-MM-DD format (e.g. 2023-01-31), or press Enter to skip.")


# ---------------------------------------------------------------------------
# Query building (Lucene)
# ---------------------------------------------------------------------------

def _quote(value):
    """Quote a Lucene term only when needed (spaces / reserved chars)."""
    import re
    if re.fullmatch(r"[A-Za-z0-9_.\-]+", value):
        return value
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'


def _or_group(field, values):
    if not values:
        return None
    if len(values) == 1:
        return f"{field}:{_quote(values[0])}"
    inner = " OR ".join(_quote(v) for v in values)
    return f"{field}:({inner})"


def to_h1_date(yyyy_mm_dd):
    """H1 docs use MM-DD-YYYY in queryString examples ('disclosed_at:>=01-01-1970')."""
    dt = datetime.strptime(yyyy_mm_dd, "%Y-%m-%d")
    return dt.strftime("%m-%d-%Y")


def build_query_from_answers(a):
    parts = []
    if a.get("disclosed") in ("true", "false"):
        parts.append(f"disclosed:{a['disclosed']}")
    if a.get("substates"):
        parts.append(_or_group("substate", a["substates"]))
    if a.get("severities"):
        parts.append(_or_group("severity_rating", a["severities"]))
    if a.get("teams"):
        parts.append(_or_group("team", a["teams"]))
    if a.get("reporters"):
        parts.append(_or_group("reporter", a["reporters"]))
    if a.get("asset_types"):
        parts.append(_or_group("asset_type", a["asset_types"]))
    if a.get("cwes"):
        parts.append(_or_group("cwe", a["cwes"]))
    if a.get("cves"):
        parts.append(_or_group("cve_ids", a["cves"]))
    if a.get("has_collaboration") in ("true", "false"):
        parts.append(f"has_collaboration:{a['has_collaboration']}")
    if a.get("min_bounty") is not None:
        parts.append(f"total_awarded_amount:>={int(a['min_bounty'])}")
    if a.get("max_bounty") is not None:
        parts.append(f"total_awarded_amount:<={int(a['max_bounty'])}")
    if a.get("disclosed_from"):
        parts.append(f"disclosed_at:>={to_h1_date(a['disclosed_from'])}")
    if a.get("disclosed_to"):
        parts.append(f"disclosed_at:<={to_h1_date(a['disclosed_to'])}")
    return " AND ".join(parts)


# ---------------------------------------------------------------------------
# Interactive wizard - covers every documented filter + pagination + output
# ---------------------------------------------------------------------------

def interactive_wizard(cli_overrides):
    print("=" * 64)
    print(" HackerOne Hacktivity crawler - interactive setup")
    print("=" * 64)
    print(" Every filter below maps to the official /hackers/hacktivity API.")
    print(" Press Enter to accept [defaults] or skip optional filters.\n")

    # ---- credentials ----
    username = cli_overrides.get("username") or os.environ.get("H1_USERNAME", "")
    token = cli_overrides.get("token") or os.environ.get("H1_TOKEN", "")
    if not username:
        username = _input("HackerOne API username: ")
        while not username:
            print("    Username cannot be empty.")
            username = _input("HackerOne API username: ")
    else:
        print(f"[*] Using username from {'CLI' if cli_overrides.get('username') else 'env'}: {username}")
    if not token:
        token = ask_secret("HackerOne API token (hidden): ")
        while not token:
            print("    Token cannot be empty.")
            token = ask_secret("HackerOne API token (hidden): ")
    else:
        print("[*] Using API token from CLI/env (hidden).")

    # ---- 1. disclosed ----
    print("\n[1/11] Disclosure state")
    print("  [1] Only disclosed (recommended)")
    print("  [2] Only undisclosed")
    print("  [3] Both (no disclosed filter)")
    while True:
        raw = _input("  Enter number [1]: ", default="1").strip()
        if raw in ("1", "2", "3"):
            break
        print("    Enter 1, 2 or 3.")
    disclosed = {"1": "true", "2": "false", "3": None}[raw]

    # ---- 2. substate ----
    substates = ask_multi_choice(
        "[2/11] Report state (substate) - pick any, Enter = no filter",
        SUBSTATES,
    )

    # ---- 3. severity ----
    sev_opts = [(str(i + 1), s.capitalize(), s) for i, s in enumerate(SEVERITIES)]
    severities = ask_multi_choice("[3/11] Severity rating - pick any, Enter = all", sev_opts)

    # ---- 4. program + reporter ----
    teams = ask_optional_list("[4/11] Program handle(s) (H1 'team' filter)",
                              example="gitlab, curl")
    reporters = ask_optional_list("Reporter username(s)", example="jobert")

    # ---- 5. asset type ----
    asset_opts = [(str(i + 1), t, t) for i, t in enumerate(ASSET_TYPES)]
    asset_types = ask_multi_choice("[5/11] Asset type - pick any, Enter = all", asset_opts)

    # ---- 6. CWE / CVE ----
    cwes = ask_optional_list("[6/11] Weakness / CWE name (free text, matched as phrase)",
                             example="Cross-Site Scripting (XSS)")
    cves = ask_optional_list("CVE ID(s)", example="CVE-2021-44228")
    # validate CVE shape loosely
    for c in list(cves):
        if not c.upper().startswith("CVE-"):
            print(f"    [!] '{c}' doesn't look like a CVE ID (expected CVE-YYYY-NNNN). Keeping it anyway.")

    # ---- 7. collaboration ----
    print("\n[7/11] Collaboration reports (has_collaboration)")
    print("  [1] No filter (default)")
    print("  [2] Only collaboration reports")
    print("  [3] Only non-collaboration reports")
    while True:
        raw = _input("  Enter number [1]: ", default="1").strip()
        if raw in ("1", "2", "3"):
            break
        print("    Enter 1, 2 or 3.")
    has_collaboration = {"1": None, "2": "true", "3": "false"}[raw]

    # ---- 8. bounty range ----
    print("\n[8/11] Bounty range in USD (total_awarded_amount) - Enter to skip")
    min_bounty = max_bounty = None
    if ask_yes_no("  Filter by bounty amount?", default="n"):
        while True:
            lo = _input("  Min bounty (number) [skip]: ").strip()
            hi = _input("  Max bounty (number) [skip]: ").strip()
            try:
                if lo:
                    min_bounty = float(lo)
                    if min_bounty < 0:
                        raise ValueError
                if hi:
                    max_bounty = float(hi)
                    if max_bounty < 0:
                        raise ValueError
                if min_bounty is not None and max_bounty is not None and min_bounty > max_bounty:
                    print("    Min cannot be greater than max. Try again.")
                    min_bounty = max_bounty = None
                    continue
                break
            except ValueError:
                print("    Enter non-negative numbers (or Enter to skip).")
                min_bounty = max_bounty = None

    # ---- 9. disclosed date range ----
    print("\n[9/11] Disclosed-date range (YYYY-MM-DD) - Enter to skip")
    disclosed_from = disclosed_to = None
    if ask_yes_no("  Filter by disclosed date?", default="n"):
        disclosed_from = ask_date_yyyy_mm_dd("  From date")
        disclosed_to = ask_date_yyyy_mm_dd("  To date")
        if disclosed_from and disclosed_to and disclosed_from > disclosed_to:
            print("    [!] From is after To - swapping them.")
            disclosed_from, disclosed_to = disclosed_to, disclosed_from

    # ---- 10. sort + pagination ----
    sort = ask_single_choice("[10/11] Sort order", SORT_OPTIONS, default_num="1")
    if not sort:
        sort = "-latest_disclosable_activity_at"
    page_size = ask_int("  Results per page (1-100)", DEFAULT_PAGE_SIZE, 1, 100)
    start_page = ask_int("  Start page (>=1)", DEFAULT_START_PAGE, 1)
    max_pages = ask_int("  Max pages to fetch (0 = unlimited)", DEFAULT_MAX_PAGES, 0, allow_zero_unlimited=True)
    max_reports = ask_int("  Max reports to save (0 = unlimited)", 0, 0, allow_zero_unlimited=True)

    # ---- 11. output ----
    print("\n[11/11] Output")
    output = cli_overrides.get("output") or _input("  Output base name (no extension) [data]: ", default="data").strip() or "data"
    print("  Formats: [1] both JSONL+CSV (default)  [2] JSONL only  [3] CSV only")
    while True:
        raw = _input("  Enter number [1]: ", default="1").strip()
        if raw in ("1", "2", "3"):
            break
        print("    Enter 1, 2 or 3.")
    fmt = {"1": "both", "2": "jsonl", "3": "csv"}[raw]
    delay = ask_float("  Delay between pages in seconds (rate-limit courtesy)", DEFAULT_DELAY)

    # ---- raw query override (advanced) ----
    custom = cli_overrides.get("query")
    if custom:
        query = custom
        print(f"\n[*] Using custom --query override:\n    {query}")
    else:
        answers = {
            "disclosed": disclosed, "substates": substates, "severities": severities,
            "teams": teams, "reporters": reporters, "asset_types": asset_types,
            "cwes": cwes, "cves": cves, "has_collaboration": has_collaboration,
            "min_bounty": min_bounty, "max_bounty": max_bounty,
            "disclosed_from": disclosed_from, "disclosed_to": disclosed_to,
        }
        query = build_query_from_answers(answers)
        if not query and not ask_yes_no("\n[!] No filters selected - this fetches ALL hacktivity (huge). Continue?", default="n"):
            print("[*] Aborted. Re-run and pick at least one filter.")
            sys.exit(0)
        if ask_yes_no("\nAdvanced: type a raw Lucene query instead of the built one?", default="n"):
            print(f"  Built query: {query or '(empty = all reports)'}")
            raw_q = ask_optional_text("  Raw query (Enter to keep built query)")
            if raw_q:
                query = raw_q

    print("\n" + "-" * 64)
    print(" Final queryString:")
    print(f"   {query or '(empty = all reports)'}")
    print(f" Sort: {sort} | page size: {page_size} | start: {start_page}")
    print(f" Caps: {'unlimited' if not max_pages else str(max_pages) + ' pages'} / "
          f"{'unlimited' if not max_reports else str(max_reports) + ' reports'}")
    print(f" Output: {output}.{{{ 'jsonl+csv' if fmt == 'both' else fmt }}} | delay: {delay}s")
    print("-" * 64)
    if not ask_yes_no("Start fetching?", default="y"):
        print("[*] Aborted by user.")
        sys.exit(0)

    return {
        "username": username, "token": token, "query": query, "sort": sort,
        "page_size": page_size, "start_page": start_page,
        "max_pages": max_pages, "max_reports": max_reports,
        "output": output, "fmt": fmt, "delay": delay,
    }


# ---------------------------------------------------------------------------
# HTTP layer with retries / backoff / clear auth errors
# ---------------------------------------------------------------------------

class AuthError(Exception):
    pass


class QueryError(Exception):
    pass


def make_session(username, token):
    s = requests.Session()
    s.auth = (username, token)
    s.headers.update({
        "Accept": "application/json",
        "User-Agent": "h1-hacktivity-crawler/2.0 (+interactive)",
    })
    return s


def fetch_page(session, query, sort, page_num, page_size):
    params = {
        "page[number]": page_num,
        "page[size]": page_size,
        "sort": sort,
    }
    if query:
        params["queryString"] = query

    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = session.get(BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
        except (requests.ConnectionError, requests.Timeout) as e:
            last_err = e
            wait = min(2 ** attempt, 30)
            print(f"    [!] Network error (attempt {attempt}/{MAX_RETRIES}): {e}. Retrying in {wait}s...")
            time.sleep(wait)
            continue

        if resp.status_code in (401, 403):
            raise AuthError(
                "Authentication failed (HTTP %s). Check username/token - "
                "H1 API needs an API username + token from hackerone.com/settings/api_token." % resp.status_code
            )
        if resp.status_code == 422:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text[:500]
            raise QueryError(f"Invalid query rejected by HackerOne (HTTP 422): {detail}")
        if resp.status_code == 429:
            try:
                retry_after = int(resp.headers.get("Retry-After", "60"))
            except ValueError:
                retry_after = 60
            retry_after = min(retry_after, 300)
            print(f"    [!] Rate limited (429). Sleeping {retry_after}s...")
            time.sleep(retry_after)
            continue
        if 500 <= resp.status_code < 600:
            wait = min(2 ** attempt, 30)
            print(f"    [!] Server error {resp.status_code} (attempt {attempt}/{MAX_RETRIES}). Retrying in {wait}s...")
            time.sleep(wait)
            last_err = requests.HTTPError(f"HTTP {resp.status_code}")
            continue
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            raise QueryError(f"HTTP {resp.status_code}: {resp.text[:500]}") from e
        try:
            return resp.json()
        except ValueError as e:
            last_err = e
            wait = min(2 ** attempt, 10)
            print(f"    [!] Bad JSON (attempt {attempt}/{MAX_RETRIES}). Retrying in {wait}s...")
            time.sleep(wait)

    raise QueryError(f"Gave up on page {page_num} after {MAX_RETRIES} retries. Last error: {last_err}")


def test_auth(session, query, sort):
    """Fail fast with a friendly message instead of crawling 1000s of pages."""
    try:
        fetch_page(session, query, sort, page_num=1, page_size=1)
        print("[+] Auth OK + query accepted by HackerOne.")
    except AuthError as e:
        print(f"\n[✗] {e}")
        sys.exit(1)
    except QueryError as e:
        print(f"\n[✗] {e}")
        print("    Tip: re-run and simplify the query (e.g. drop CWE/CVE free text first).")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Parsing - defensive against both attribute shapes H1 has returned
# ---------------------------------------------------------------------------

def _safe_get(d, *keys, default=""):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur if cur != "" else default


def parse_report(item):
    attrs = item.get("attributes", {}) or {}
    rels = item.get("relationships", {}) or {}

    def rel_attr(rel, field, default=""):
        return _safe_get(rels, rel, "data", "attributes", field, default=default)

    report_id = str(item.get("id", "") or "")
    url = attrs.get("url") or (f"https://hackerone.com/reports/{report_id}" if report_id else "")

    # severity: flat `severity_rating` (current docs) OR relationships.severity.rating (older shape)
    severity = attrs.get("severity_rating") or rel_attr("severity", "rating")
    cvss = rel_attr("severity", "score", default="") or attrs.get("cvss_score", "") or ""
    # weakness: flat `cwe` string OR relationships.weakness.name
    weakness = rel_attr("weakness", "name", default="") or ""
    cwe = attrs.get("cwe", "") or weakness

    cve_raw = attrs.get("cve_ids", []) or []
    if isinstance(cve_raw, str):
        cve_list = [c.strip() for c in cve_raw.split("|") if c.strip()]
    elif isinstance(cve_raw, list):
        cve_list = [str(c).strip() for c in cve_raw if str(c).strip()]
    else:
        cve_list = []

    try:
        bounty = attrs.get("total_awarded_amount", 0) or 0
        bounty = float(bounty)
        bounty = int(bounty) if bounty.is_integer() else bounty
    except (TypeError, ValueError):
        bounty = 0
    try:
        upvotes = int(attrs.get("votes", 0) or 0)
    except (TypeError, ValueError):
        upvotes = 0

    program = rel_attr("program", "handle") or attrs.get("program_handle", "")
    program_name = rel_attr("program", "name") or ""
    reporter = rel_attr("reporter", "username") or attrs.get("reporter", "")
    asset_type = _safe_get(rels, "structured_scope", "data", "attributes", "asset_type", default="") or attrs.get("asset_type", "")

    return {
        "id": report_id,
        "title": attrs.get("title", "") or "",
        "url": url,
        "program": program,
        "program_name": program_name,
        "reporter": reporter,
        "substate": attrs.get("substate", "") or "",
        "severity": (severity or "").lower() if isinstance(severity, str) else severity,
        "cvss_score": cvss,
        "weakness": weakness,
        "cwe": cwe,
        "cve_ids": cve_list,
        "bounty": bounty,
        "upvotes": upvotes,
        "disclosed_at": attrs.get("disclosed_at", "") or "",
        "submitted_at": attrs.get("submitted_at", "") or "",
        "asset_type": asset_type,
        "disclosed": attrs.get("disclosed", ""),
    }


# ---------------------------------------------------------------------------
# Output - resume-safe, de-duplicated, stable CSV header
# ---------------------------------------------------------------------------

def load_seen_ids(jsonl_path):
    seen = set()
    if os.path.exists(jsonl_path):
        try:
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        seen.add(str(json.loads(line).get("id", "")))
                    except ValueError:
                        continue
            if seen:
                print(f"[*] Resume: {len(seen)} existing IDs loaded from {jsonl_path} (duplicates skipped).")
        except OSError as e:
            print(f"[!] Could not read existing {jsonl_path}: {e} (starting fresh dedup set).")
    return seen


def ensure_parent_dir(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def save_batch(reports, jsonl_path, csv_path, fmt):
    if fmt in ("jsonl", "both"):
        ensure_parent_dir(jsonl_path)
        with open(jsonl_path, "a", encoding="utf-8") as f:
            for r in reports:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    if fmt in ("csv", "both"):
        ensure_parent_dir(csv_path)
        write_header = not (os.path.exists(csv_path) and os.path.getsize(csv_path) > 0)
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
            if write_header:
                writer.writeheader()
            for r in reports:
                row = dict(r)
                cve = row.get("cve_ids", [])
                row["cve_ids"] = "|".join(cve) if isinstance(cve, list) else str(cve or "")
                writer.writerow(row)


# ---------------------------------------------------------------------------
# Main crawl loop
# ---------------------------------------------------------------------------

def fetch_all(cfg):
    session = make_session(cfg["username"], cfg["token"])
    test_auth(session, cfg["query"], cfg["sort"])

    fmt = cfg["fmt"]
    jsonl_path = f"{cfg['output']}.jsonl" if fmt in ("jsonl", "both") else None
    csv_path = f"{cfg['output']}.csv" if fmt in ("csv", "both") else None
    seen = load_seen_ids(jsonl_path) if jsonl_path else set()

    start = datetime.now()
    print(f"[*] Started at {start:%Y-%m-%d %H:%M:%S}")
    print(f"[*] Fetching from page {cfg['start_page']} "
          f"({'unlimited pages' if not cfg['max_pages'] else 'max %d pages' % cfg['max_pages']})... "
          "(Ctrl+C to stop gracefully)\n")

    total_items = saved = skipped_dup = skipped_empty = errors = 0
    page = cfg["start_page"]
    pages_done = 0

    try:
        while True:
            if cfg["max_pages"] and pages_done >= cfg["max_pages"]:
                print("[*] Max pages reached. Stopping.")
                break
            if cfg["max_reports"] and saved >= cfg["max_reports"]:
                print("[*] Max reports reached. Stopping.")
                break

            print(f"[*] Page {page} (saved: {saved}, dups skipped: {skipped_dup})...")
            try:
                data = fetch_page(session, cfg["query"], cfg["sort"], page, cfg["page_size"])
            except (AuthError, QueryError) as e:
                print(f"[!] Fatal on page {page}: {e}")
                errors += 1
                break
            except Exception as e:  # defensive: never crash the whole run on one page
                print(f"[!] Unexpected error on page {page}: {type(e).__name__}: {e}")
                errors += 1
                if errors > 10:
                    print("[!] Too many consecutive errors (>10). Stopping.")
                    break
                time.sleep(2)
                page += 1
                pages_done += 1
                continue

            items = data.get("data", []) if isinstance(data, dict) else []
            if not items:
                print("[*] Empty page = end of results. Stopping.")
                break

            total_items += len(items)
            fresh = []
            for item in items:
                try:
                    r = parse_report(item)
                except Exception as e:
                    print(f"    [!] Skipping unparseable item: {e}")
                    skipped_empty += 1
                    continue
                if not r.get("id"):
                    skipped_empty += 1
                    continue
                if r["id"] in seen:
                    skipped_dup += 1
                    continue
                seen.add(r["id"])
                fresh.append(r)
                if cfg["max_reports"] and (saved + len(fresh)) >= cfg["max_reports"]:
                    fresh = fresh[: cfg["max_reports"] - saved]
                    break

            if fresh:
                try:
                    save_batch(fresh, jsonl_path, csv_path, fmt)
                except OSError as e:
                    print(f"[!] Write failed: {e}. Stopping (progress kept in memory).")
                    errors += 1
                    break
                saved += len(fresh)
                print(f"    [+] Saved {len(fresh)} reports.")
            else:
                print("    [-] No new reports on this page (all duplicates/unparseable).")

            # Natural end: server returned fewer items than requested
            if len(items) < cfg["page_size"]:
                print("[*] Last page (fewer items than page size). Stopping.")
                break

            page += 1
            pages_done += 1
            time.sleep(cfg["delay"])

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Saving progress so far...")

    elapsed = (datetime.now() - start).total_seconds()
    print("\n" + "=" * 64)
    print(" Done.")
    print(f"  Pages fetched : {pages_done}")
    print(f"  Items seen    : {total_items}")
    print(f"  Reports saved : {saved}")
    print(f"  Dups skipped  : {skipped_dup}")
    print(f"  Unparseable   : {skipped_empty}")
    print(f"  Page errors   : {errors}")
    if jsonl_path:
        print(f"  JSONL         : {jsonl_path}")
    if csv_path:
        print(f"  CSV           : {csv_path}")
    print(f"  Elapsed       : {elapsed:.1f}s")
    print("=" * 64)


def parse_cli_overrides(argv):
    """All optional. Missing values are asked interactively."""
    import argparse
    p = argparse.ArgumentParser(
        description="Interactive HackerOne hacktivity crawler (all flags optional).",
        epilog="Run with no flags for the interactive wizard.",
    )
    p.add_argument("--username", default=None, help="H1 API username (or H1_USERNAME env)")
    p.add_argument("--token", default=None, help="H1 API token (or H1_TOKEN env)")
    p.add_argument("--query", default=None, help="Raw Lucene queryString (skips filter wizard)")
    p.add_argument("--output", default=None, help="Output basename without extension (default: data)")
    return vars(p.parse_args(argv))


def main(argv=None):
    overrides = parse_cli_overrides(argv or sys.argv[1:])
    cfg = interactive_wizard(overrides)
    fetch_all(cfg)


if __name__ == "__main__":
    main()
