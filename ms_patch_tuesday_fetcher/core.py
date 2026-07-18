"""Shared logic for fetching and parsing Microsoft Patch Tuesday updates.

Imported by both the CLI (`ms_patch_tuesday_fetcher.py`) and the AWS Lambda
example (`lambda_example/ms_patch_tuesday_fetcher_lambda.py`) so the fetch,
parse, filter, and extract logic lives in one place. This module is pure
data/IO logic with no presentation — callers decide how to render the result.
"""

import json
import requests
from bs4 import BeautifulSoup  # For parsing HTML
from datetime import datetime, timedelta, timezone

# Constants
BASE_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/releaseNote"

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


# Build a structured report for each update: title, release date, and the
# formatted KB-article strings. Returned as plain dicts so callers can print
# them (CLI) or serialize them to JSON (Lambda).
def collect_updates(updates):
    results = []
    for update in updates:
        title = update.get('title', 'No title available')
        release_date = update.get('releaseDate', 'Unknown release date')
        description = update.get('description', 'No description available')

        kb_articles = [
            f"KB{kb} (Applies to: {product})"
            for kb, product in extract_kb_from_description(description)
        ]
        results.append({
            "title": title,
            "release_date": release_date,
            "kb_articles": kb_articles,
        })
    return results
