import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone

# Constants
BASE_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/releaseNote"

# Headers for the API (no API key needed)
HEADERS = {
    'Accept': 'application/json'
}

# Seconds to wait for the API before giving up, so a hung server can't
# tie up the Lambda for its full timeout.
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
    results = []
    for update in updates:
        title = update.get('title', 'No title available')
        release_date = update.get('releaseDate', 'Unknown release date')
        description = update.get('description', 'No description available')  # Extract description

        result = {"title": title, "release_date": release_date, "kb_articles": []}

        # Extract KB Articles from the description
        kb_articles = extract_kb_from_description(description)

        if kb_articles:
            for kb, product in kb_articles:
                result["kb_articles"].append(f"KB{kb} (Applies to: {product})")

        results.append(result)

    return results

# Lambda handler function
def lambda_handler(event, context):
    # Get the 'days' and 'raw' values from the event (default: 7 days, no raw output)
    days_back = event.get('days', 7)
    show_raw = event.get('raw', False)

    # Fetch updates
    updates = get_all_updates(show_raw=show_raw)

    if updates:
        # Filter updates by date
        recent_updates = filter_updates_by_date(updates, days_back)
        print(f"Found {len(recent_updates)} updates from the last {days_back} days.")

        # Extract KB articles and CVEs
        results = extract_cve_kb_info(recent_updates)
        return {
            'statusCode': 200,
            'body': json.dumps(results, indent=4)
        }
    else:
        return {
            'statusCode': 200,
            'body': json.dumps({"message": "No updates found."})
        }
