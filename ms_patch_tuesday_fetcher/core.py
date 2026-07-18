"""Shared logic for fetching and parsing Microsoft Patch Tuesday updates.

Imported by both the CLI (`ms_patch_tuesday_fetcher.py`) and the AWS Lambda
example (`lambda_example/ms_patch_tuesday_fetcher_lambda.py`) so the fetch,
parse, filter, and extract logic lives in one place. This module is pure
data/IO logic with no presentation — callers decide how to render the result.
"""

import re
import json
import requests
from bs4 import BeautifulSoup  # For parsing HTML
from datetime import datetime, timedelta, timezone

# Constants
BASE_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/releaseNote"

# Per-month CVRF ("Common Vulnerability Reporting Framework") documents carry
# the full per-CVE detail (severity, CVSS, affected products/KBs) that the
# release-note summary omits. Only fetched when full CVE data is requested.
CVRF_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"

# CVE identifier pattern, e.g. "CVE-2026-56155".
CVE_ID_RE = re.compile(r'CVE-\d{4}-\d+')

# MSRC severity ordering, used to pick the most severe rating a CVE carries
# across the various products it affects.
_SEVERITY_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}

# Headers for the API (no API key needed)
HEADERS = {
    'Accept': 'application/json'
}

# Default seconds to wait for the API before giving up, so a hung server
# can't block indefinitely. Callers may pass a smaller value (e.g. the
# Lambda keeps it under the function timeout).
DEFAULT_TIMEOUT = 30


# Fetch all updates (no OData filter)
def get_all_updates(show_raw=False, timeout=DEFAULT_TIMEOUT):
    try:
        response = requests.get(BASE_URL, headers=HEADERS, timeout=timeout)
        response.raise_for_status()  # Raise error if the request fails
        updates = response.json()

        if show_raw:  # Show raw response if requested
            print("Raw Updates Response:")
            print(json.dumps(updates, indent=4))

        return updates.get('value', [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching updates from Microsoft API: {e}")
        return []


# Parse an MSRC releaseDate into a UTC-aware datetime, or None if the
# value is missing or in an unexpected format. Tolerates fractional
# seconds and explicit offsets in addition to the usual trailing "Z".
def parse_release_date(release_date_str):
    if not release_date_str:
        return None

    # datetime.fromisoformat() didn't accept a trailing "Z" until Python
    # 3.11, so normalize it to an explicit UTC offset first.
    normalized = release_date_str.strip()
    if normalized.endswith('Z'):
        normalized = normalized[:-1] + '+00:00'

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    # Treat a naive timestamp as UTC (the API reports UTC).
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# Filter updates to those released within the last `days_back` days
def filter_updates_by_date(updates, days_back):
    # The API's releaseDate values are UTC, so compare against a UTC "now"
    # to keep the day window independent of the host's local timezone.
    time_threshold = datetime.now(timezone.utc) - timedelta(days=days_back)
    filtered_updates = []

    for update in updates:
        release_date = parse_release_date(update.get('releaseDate'))
        if release_date is None:
            # Skip records with a missing/unrecognized date rather than
            # letting one bad value abort the whole run.
            continue
        if release_date >= time_threshold:
            filtered_updates.append(update)

    return filtered_updates


# Extract (KB number, product) pairs from a release-note description table
def extract_kb_from_description(description):
    soup = BeautifulSoup(description, "html.parser")  # Parse the HTML content
    kb_table_rows = soup.find_all('tr')  # Find all table rows

    kb_list = []
    for row in kb_table_rows:
        columns = row.find_all('td')  # Find all columns in the row
        if len(columns) >= 2:  # Header rows (only <th>) have no <td> and are skipped
            kb_link = columns[0].find('a')  # Find the KB link
            if kb_link:
                kb_number = kb_link.text  # Extract the KB number
                product = columns[1].text  # Extract the product it applies to
                kb_list.append((kb_number, product))
    return kb_list


# Extract the "notable" CVEs from a release-note description. The release note
# only tabulates the highlighted CVEs (publicly disclosed / actively exploited)
# in a table whose first column header is "CVE ID"; the full per-CVE list lives
# in the CVRF document (see extract_cves_from_cvrf). Parsing only that table
# avoids the summary table and the blog table, which mention unrelated CVEs.
def extract_notable_cves_from_description(description):
    soup = BeautifulSoup(description, "html.parser")

    cves = []
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if not rows:
            continue
        header = [cell.get_text(strip=True).lower() for cell in rows[0].find_all(['th', 'td'])]
        if not header or header[0] != 'cve id':
            continue

        for row in rows[1:]:
            columns = row.find_all(['td', 'th'])
            if len(columns) < 2:
                continue
            match = CVE_ID_RE.search(columns[0].get_text())
            if not match:
                continue
            # The third column ("Notable Item") explains why it is highlighted,
            # e.g. "Publicly Known" or "Exploitation Detected".
            exploitation = columns[2].get_text(strip=True) if len(columns) > 2 else None
            cves.append({
                "id": match.group(0),
                "title": columns[1].get_text(strip=True),
                "notable": True,
                "exploitation": exploitation or None,
            })
    return cves


# Derive the CVRF document id (e.g. "2026-Jul") for an update from its release
# date, so we can fetch that month's full CVE detail. Returns None when the
# date is missing/unparseable.
def release_to_cvrf_id(update):
    parsed = parse_release_date(update.get('releaseDate'))
    if parsed is None:
        return None
    return parsed.strftime('%Y-%b')


# Fetch a monthly CVRF document. Returns the parsed JSON, or None on any
# network/HTTP error so callers can fall back to the notable-CVE subset.
def fetch_cvrf_document(doc_id, timeout=DEFAULT_TIMEOUT):
    url = f"{CVRF_BASE_URL}/{doc_id}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVRF document {doc_id}: {e}")
        return None


# Pull the text value out of a CVRF Threat/Title node, which is either a
# {"Value": ...} dict or a bare value.
def _node_value(node):
    if isinstance(node, dict):
        return node.get('Value')
    return node


# Pick the most severe rating from a list of MSRC severity strings.
def _most_severe(values):
    best, best_rank = None, 0
    for value in values:
        rank = _SEVERITY_ORDER.get(value, 0)
        if rank > best_rank:
            best, best_rank = value, rank
    return best


# Parse the Type-1 "exploit status" threats into (exploited, publicly_disclosed)
# flags. The Description is a string like "Publicly Disclosed:No;Exploited:Yes".
def _exploit_flags(threats):
    exploited = publicly_disclosed = False
    for threat in threats:
        if threat.get('Type') == 1:
            status = _node_value(threat.get('Description')) or ''
            exploited = exploited or 'Exploited:Yes' in status
            publicly_disclosed = publicly_disclosed or 'Publicly Disclosed:Yes' in status
    return exploited, publicly_disclosed


# Build the list of affected {product, kb} pairs from a vulnerability's
# Remediations (those whose Description is a KB number), resolving product IDs
# to names via the supplied map.
def _affected_products(vuln, product_names):
    products, seen = [], set()
    for remediation in vuln.get('Remediations', []):
        kb = _node_value(remediation.get('Description'))
        if not kb or not str(kb).strip().isdigit():
            continue
        for pid in remediation.get('ProductID', []):
            key = (str(pid), str(kb))
            if key not in seen:
                seen.add(key)
                products.append({"product": product_names.get(str(pid), str(pid)), "kb": str(kb)})
    return products


# Turn one CVRF Vulnerability entry into our structured CVE dict.
def _cve_from_vuln(vuln, product_names):
    threats = vuln.get('Threats', [])
    # Threat Type 3 = severity, Type 0 = impact, Type 1 = exploit status.
    severity = _most_severe([_node_value(t.get('Description')) for t in threats if t.get('Type') == 3])
    impact = next((_node_value(t.get('Description')) for t in threats if t.get('Type') == 0), None)
    exploited, publicly_disclosed = _exploit_flags(threats)

    scores = [s.get('BaseScore') for s in vuln.get('CVSSScoreSets', []) if s.get('BaseScore')]
    cvss = max(scores) if scores else None

    if exploited:
        exploitation = "Exploitation Detected"
    elif publicly_disclosed:
        exploitation = "Publicly Disclosed"
    else:
        exploitation = None

    return {
        "id": vuln.get('CVE'),
        "title": _node_value(vuln.get('Title')),
        "severity": severity,
        "impact": impact,
        "cvss": cvss,
        "exploited": exploited,
        "publicly_disclosed": publicly_disclosed,
        "exploitation": exploitation,
        "notable": exploited or publicly_disclosed,
        "products": _affected_products(vuln, product_names),
    }


# Extract the full per-CVE detail from a CVRF document: severity, impact, CVSS
# base score, exploitation flags, and the affected products with their KBs.
def extract_cves_from_cvrf(cvrf_doc):
    # Map numeric ProductID -> human-readable product name.
    product_names = {}
    for product in cvrf_doc.get('ProductTree', {}).get('FullProductName', []):
        pid = product.get('ProductID')
        if pid is not None:
            product_names[str(pid)] = product.get('Value', str(pid))

    return [
        _cve_from_vuln(vuln, product_names)
        for vuln in cvrf_doc.get('Vulnerability', [])
        if vuln.get('CVE')
    ]


# Resolve the CVE list for one update. Tier 1 (default) returns the notable
# CVEs already present in the release note. Tier 2 (include_full_cves) fetches
# the month's CVRF document for the complete list, carrying over the release
# note's "Notable Item" wording, and falls back to Tier 1 if the fetch fails.
def _cves_for_update(update, notable, include_full_cves, cvrf_cache, timeout):
    if not include_full_cves:
        return notable

    doc_id = release_to_cvrf_id(update)
    if doc_id is None:
        return notable
    if doc_id not in cvrf_cache:
        cvrf_cache[doc_id] = fetch_cvrf_document(doc_id, timeout=timeout)
    document = cvrf_cache[doc_id]
    if not document:
        return notable

    full = extract_cves_from_cvrf(document)
    notable_labels = {cve['id']: cve.get('exploitation') for cve in notable}
    for cve in full:
        if cve['id'] in notable_labels:
            cve['notable'] = True
            if notable_labels[cve['id']]:
                cve['exploitation'] = notable_labels[cve['id']]
    return full


# Build a structured report for each update: title, release date, the formatted
# KB-article strings, and the CVEs. Returned as plain dicts so callers can print
# them (CLI) or serialize them to JSON (Lambda). With include_full_cves the CVE
# list is the complete CVRF detail; otherwise it is the notable-CVE subset.
def collect_updates(updates, include_full_cves=False, timeout=DEFAULT_TIMEOUT):
    results = []
    cvrf_cache = {}
    for update in updates:
        title = update.get('title', 'No title available')
        release_date = update.get('releaseDate', 'Unknown release date')
        description = update.get('description', 'No description available')

        kb_articles = [
            f"KB{kb} (Applies to: {product})"
            for kb, product in extract_kb_from_description(description)
        ]

        notable = extract_notable_cves_from_description(description)
        cves = _cves_for_update(update, notable, include_full_cves, cvrf_cache, timeout)

        results.append({
            "title": title,
            "release_date": release_date,
            "kb_articles": kb_articles,
            "cves": cves,
        })
    return results


# Filter collected reports to a case-insensitive product-name substring. KB
# articles and (in full-CVE mode) each CVE's products are narrowed to matches;
# notable-only CVEs, which carry no product data, match on their title instead.
# Updates left with no matching KBs or CVEs are dropped.
def filter_reports_by_product(reports, pattern):
    needle = pattern.lower()
    filtered = []
    for report in reports:
        kb_articles = [kb for kb in report['kb_articles'] if needle in kb.lower()]

        cves = []
        for cve in report.get('cves', []):
            products = cve.get('products')
            if products is None:
                if needle in (cve.get('title') or '').lower():
                    cves.append(cve)
            else:
                matched = [p for p in products if needle in p['product'].lower()]
                if matched:
                    cves.append({**cve, 'products': matched})

        if kb_articles or cves:
            filtered.append({**report, 'kb_articles': kb_articles, 'cves': cves})
    return filtered
