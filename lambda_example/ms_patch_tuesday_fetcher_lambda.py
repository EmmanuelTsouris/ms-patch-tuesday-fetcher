import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta

# Constants
BASE_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/releaseNote"

# Headers for the API (no API key needed)
HEADERS = {
    'Accept': 'application/json'
}

# Function to fetch all updates (no OData filter)
def get_all_updates(show_raw=False):
    try:
        response = requests.get(BASE_URL, headers=HEADERS)
        response.raise_for_status()  # Raise error if the request fails
        updates = response.json()

        if show_raw:  # Show raw response if --raw switch is passed
            print("Raw Updates Response:")
            print(json.dumps(updates, indent=4))

        return updates.get('value', [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching updates from Microsoft API: {e}")
        return []

# Function to filter updates by release date in Python
def filter_updates_by_date(updates, days_back):
    time_threshold = datetime.now() - timedelta(days=days_back)
    filtered_updates = []

    for update in updates:
        release_date_str = update.get('releaseDate', None)
        if release_date_str:
            release_date = datetime.strptime(release_date_str, '%Y-%m-%dT%H:%M:%SZ')
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
        if len(columns) == 2:
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
