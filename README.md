# h1-hacktivity-crawler

Interactive HackerOne Hacktivity crawler. Run one command, pick every official API filter from simple numbered menus, and save disclosed reports to JSONL and CSV. No CLI args required.

Built on the official HackerOne Hacker API v1 (`GET /v1/hackers/hacktivity`), using your own API token. Handles auth errors, rate limits, retries, resume, and de-duplication out of the box.

## Features

- Fully interactive setup. Just run `python3 crawler.py` and answer the prompts.
- Covers every documented `queryString` filter: disclosed state, substate, severity, program (team), reporter, asset type, CWE, CVE, collaboration flag, bounty range, disclosed-date range.
- All 8 official sort orders: recent activity, disclosed date, bounty, votes (ascending and descending).
- Raw Lucene query override for advanced users.
- Saves to JSONL and CSV (or either one), with a stable CSV header.
- Resume-safe. Existing IDs in the JSONL file are loaded and skipped, so re-runs never create duplicates.
- Robust networking. Clear message on bad credentials (401/403), readable error on invalid query (422), `Retry-After` respected on 429, exponential backoff on 5xx and timeouts.
- Graceful stop. Press Ctrl+C any time and your progress is kept with a final summary.
- Optional non-interactive flags and `H1_USERNAME` / `H1_TOKEN` env vars for automation.

## Requirements

- Python 3.8+
- `requests` package (`pip install requests`)
- A HackerOne account with an API token (any valid hacker account works, it only reads Hacktivity data your account can already see)

## Get your HackerOne API token

1. Log in to HackerOne.
2. Go to Profile Settings, then API Token (or open `hackerone.com/settings/api_token`).
3. Generate a token and copy the API username and token.
4. Keep the token private. Never commit it, paste it in issues, or share screenshots containing it.

## Install

```bash
git clone https://github.com/Raunaksplanet/h1-hacktivity-crawler.git
cd h1-hacktivity-crawler
pip install requests
```

## Usage

### Interactive mode (recommended)

```bash
python3 crawler.py
```

The wizard walks you through 11 short steps: credentials, disclosure state, substate, severity, programs, reporters, asset type, CWE/CVE, collaboration, bounty range, disclosed-date range, sort order, pagination caps, and output settings. It then shows the final Lucene `queryString` and asks for confirmation before fetching.

### Automation mode (optional)

All flags are optional. Anything you pass is used directly, the rest is still asked interactively. Credentials can also come from env vars.

```bash
# everything prompted except the token source
export H1_USERNAME="<your-h1-username>"
export H1_TOKEN="<your-h1-token>"
python3 crawler.py

# fully scripted run with a raw query
python3 crawler.py \
  --username "<your-h1-username>" \
  --token "<your-h1-token>" \
  --query "disclosed:true AND substate:resolved AND severity_rating:critical" \
  --output data
```

## Filter reference

Every prompt maps to a documented HackerOne `queryString` filter. Pressing Enter skips a filter.

| Prompt | API filter | Example query fragment |
|---|---|---|
| Disclosure state | `disclosed` | `disclosed:true` |
| Report state | `substate` | `substate:(resolved OR duplicate)` |
| Severity rating | `severity_rating` | `severity_rating:(critical OR high)` |
| Program handle | `team` | `team:(gitlab OR curl)` |
| Reporter | `reporter` | `reporter:<username>` |
| Asset type | `asset_type` | `asset_type:URL` |
| Weakness | `cwe` | `cwe:"Cross-Site Scripting (XSS)"` |
| CVE | `cve_ids` | `cve_ids:CVE-2021-44228` |
| Collaboration | `has_collaboration` | `has_collaboration:true` |
| Bounty range (USD) | `total_awarded_amount` | `total_awarded_amount:>=100 AND total_awarded_amount:<=5000` |
| Disclosed-date range | `disclosed_at` | `disclosed_at:>=01-01-2023 AND disclosed_at:<=12-31-2023` |

Substate values: resolved, duplicate, triaged, new, informative, not-applicable, needs-more-info, spam.
Severity values: none, low, medium, high, critical.
Sort values: `-latest_disclosable_activity_at` (default), `latest_disclosable_activity_at`, `-disclosed_at`, `disclosed_at`, `-total_awarded_amount`, `total_awarded_amount`, `-votes`, `votes`.
Page size allowed by the API is 1 to 100 (default 25).

## Output

Two files are written next to the script (basename is configurable, default `data`):

- `data.jsonl` - one JSON object per line, ideal for `jq` and data pipelines.
- `data.csv` - flat table with the same fields, CVE IDs joined with `|`.

Columns: `id, title, url, program, program_name, reporter, substate, severity, cvss_score, weakness, cwe, cve_ids, bounty, upvotes, disclosed_at, submitted_at, asset_type, disclosed`.

Example with `jq`:

```bash
# top 5 bounties in this fetch
jq -s 'sort_by(.bounty) | reverse | .[0:5] | .[] | "\(.bounty) - \(.title) (\(.url))"' data.jsonl

# count by severity
jq -r '.severity' data.jsonl | sort | uniq -c | sort -rn
```

## Working demo

Real run below, trimmed for readability. Personal details redacted, repetitive per-page lines snipped.

```text
$ python3 crawler.py
================================================================
 HackerOne Hacktivity crawler - interactive setup
================================================================
 Every filter below maps to the official /hackers/hacktivity API.
 Press Enter to accept [defaults] or skip optional filters.

HackerOne API username: <your-h1-username>
HackerOne API token (hidden):

[1/11] Disclosure state
  [1] Only disclosed (recommended)
  [2] Only undisclosed
  [3] Both (no disclosed filter)
  Enter number [1]: 1

[2/11] Report state (substate) - pick any, Enter = no filter
  [1] Resolved
  [2] Duplicate
  [3] Triaged
  [4] New
  [5] Informative
  [6] Not Applicable
  [7] Needs More Info
  [8] Spam
  (comma-separated, e.g. 1,2  - or press Enter to skip)
  Your choice: 1

[3/11] Severity rating - pick any, Enter = all
  [1] None
  [2] Low
  [3] Medium
  [4] High
  [5] Critical
  (comma-separated, e.g. 1,2  - or press Enter to skip)
  Your choice: 5

[4/11] Program handle(s) (H1 'team' filter)
  (comma-separated, e.g. gitlab, curl - or Enter to skip)
  >
Reporter username(s)
  (comma-separated, e.g. <username> - or Enter to skip)
  >

[5/11] Asset type - pick any, Enter = all
  [1] URL
  [2] DOMAIN
  [3] WILDCARD
  [4] CIDR
  [5] IP_ADDRESS
  ... (full list shown in the tool)
  (comma-separated, e.g. 1,2  - or press Enter to skip)
  Your choice:

[6/11] Weakness / CWE name (free text, matched as phrase)
  (comma-separated, e.g. Cross-Site Scripting (XSS) - or Enter to skip)
  >
CVE ID(s)
  (comma-separated, e.g. CVE-2021-44228 - or Enter to skip)
  >

[7/11] Collaboration reports (has_collaboration)
  [1] No filter (default)
  [2] Only collaboration reports
  [3] Only non-collaboration reports
  Enter number [1]:

[8/11] Bounty range in USD (total_awarded_amount) - Enter to skip
  Filter by bounty amount? [y/N]:

[9/11] Disclosed-date range (YYYY-MM-DD) - Enter to skip
  Filter by disclosed date? [y/N]:

[10/11] Sort order
  [1] Recent activity (default: -latest_disclosable_activity_at)  <-- default
  [2] Oldest activity (latest_disclosable_activity_at)
  [3] Recently disclosed (-disclosed_at)
  [4] Earliest disclosed (disclosed_at)
  [5] Highest bounty (-total_awarded_amount)
  [6] Lowest bounty (total_awarded_amount)
  [7] Most upvoted (-votes)
  [8] Least upvoted (votes)
  Enter number (or press Enter to skip):
  Results per page (1-100) [25]:
  Start page (>=1) [1]:
  Max pages to fetch (0 = unlimited) [50]:
  Max reports to save (0 = unlimited) [0]:

[11/11] Output
  Output base name (no extension) [data]:
  Formats: [1] both JSONL+CSV (default)  [2] JSONL only  [3] CSV only
  Enter number [1]:
  Delay between pages in seconds (rate-limit courtesy) [0.6]:

Advanced: type a raw Lucene query instead of the built one? [y/N]:

----------------------------------------------------------------
 Final queryString:
   disclosed:true AND substate:resolved AND severity_rating:critical
 Sort: -latest_disclosable_activity_at | page size: 25 | start: 1
 Caps: 50 pages / unlimited
 Output: data.jsonl + data.csv | delay: 0.6s
----------------------------------------------------------------
Start fetching? [Y/n]:

[+] Auth OK + query accepted by HackerOne.
[*] Started at 2026-10-05 03:36:20
[*] Fetching from page 1 (max 50 pages)... (Ctrl+C to stop gracefully)

[*] Page 1 (saved: 0, dups skipped: 0)...
    [+] Saved 25 reports.
... (pages 2 to 26, 25 reports each, snipped for brevity) ...
[*] Page 27 (saved: 650, dups skipped: 0)...
    [+] Saved 25 reports.
^C
[!] Interrupted by user. Saving progress so far...

================================================================
 Done.
  Pages fetched : 27
  Items seen    : 675
  Reports saved : 675
  Dups skipped  : 0
  Unparseable   : 0
  Page errors   : 0
  JSONL         : data.jsonl
  CSV           : data.csv
  Elapsed       : 44.1s
================================================================
```

What this demo shows: filter `disclosed:true AND substate:resolved AND severity_rating:critical` returned a full page of 25 reports per request, 675 reports saved in about 44 seconds, and Ctrl+C stopped the run cleanly with all progress kept.

## Robustness notes

- Credentials are validated with a 1-item probe request before the crawl starts, so typos fail fast instead of after hundreds of pages.
- `disclosed:true` is pre-selected because undisclosed items have no public title or URL.
- Date input is validated as YYYY-MM-DD and converted to the MM-DD-YYYY form the API expects.
- Bounty min/max is validated so min can never exceed max.
- A run with zero filters warns you first, since that fetches all of Hacktivity.
- Short pages (fewer items than page size) and empty pages both end the crawl naturally.
- Set max pages or max reports to bound large crawls. Defaults are 50 pages and unlimited reports.

## Project structure

```text
h1-hacktivity-crawler/
  crawler.py    # the interactive crawler (stdlib + requests only)
  README.md     # this file
  .gitignore    # keeps fetched data, tokens, and caches out of git
```

Fetched files (`data.jsonl`, `data.csv`) are intentionally git-ignored. They can grow large and may contain data you do not want to publish.

## Disclaimer

This tool only reads Hacktivity data through the official HackerOne API with your own credentials. It cannot access private program data. Use it for research and learning, respect the HackerOne terms of service and each program's disclosure policy, and never publish your API token.
