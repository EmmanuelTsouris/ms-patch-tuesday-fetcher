import requests
import json
import re
import argparse
from bs4 import BeautifulSoup  # For parsing HTML
from datetime import datetime, timedelta, timezone

# Constants
BASE_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/releaseNote"

# Headers for the API (no API key needed)
HEADERS = {
    'Accept': 'application/json'
}

# Seconds to wait for the API before giving up, so a hung server can't
# block the CLI (or tie up a Lambda) indefinitely.
REQUEST_TIMEOUT = 30

# Function to fetch all updates (no OData filter)
def get_all_updates(show_raw=False):
    try:
        response = requests.get(BASE_URL, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()  # Raise error if the request fails
        updates = response.json()

        if show_raw:  # Show raw response if --raw switch is passed
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

# Function to filter updates by release date in Python
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

# Function to extract KB numbers from the description
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

# Function to extract CVEs, KB numbers, and other relevant information
def extract_cve_kb_info(updates):
    for update in updates:
        title = update.get('title', 'No title available')
        release_date = update.get('releaseDate', 'Unknown release date')
        description = update.get('description', 'No description available')  # Extract description

        print(f"- Title: {title}, Released on: {release_date}")

        # Extract KB Articles from the description
        kb_articles = extract_kb_from_description(description)

        # Display KB Articles
        if kb_articles:
            print("  KB Articles:")
            for kb, product in kb_articles:
                print(f"  - KB{kb} (Applies to: {product})")
        else:
            print("  No KB Articles found.")

# Main function to execute the script logic
def main():
    parser = argparse.ArgumentParser(description="Fetch and display Microsoft Patch Tuesday updates.")

    # Adding the --raw flag
    parser.add_argument('--raw', action='store_true', help="Show raw API response for debugging.")

    # Adding the --days argument to specify the number of days back
    parser.add_argument('--days', type=int, default=7, help="Number of days back to fetch updates for (default: 7 days).")

    args = parser.parse_args()

    print(f"Fetching updates from the last {args.days} days...")

    # Fetch all updates from Microsoft's API, passing the raw flag
    updates = get_all_updates(show_raw=args.raw)

    if updates:
        # Filter updates by release date
        recent_updates = filter_updates_by_date(updates, args.days)
        print(f"Found {len(recent_updates)} updates from the last {args.days} days.")
        extract_cve_kb_info(recent_updates)
    else:
        print(f"No updates found.")

if __name__ == "__main__":
    main()
