import json

from ms_patch_tuesday_fetcher.core import (
    get_all_updates,
    filter_updates_by_date,
    collect_updates,
)

# Seconds to wait for the API before giving up. Kept below the Lambda
# function timeout (30s in lambda-cfn.yml) so a hung connection is caught
# with headroom to log the error and return the intended response instead
# of the function being killed mid-request.
REQUEST_TIMEOUT = 25


# Lambda handler function
def lambda_handler(event, context):
    # Get the 'days' and 'raw' values from the event (default: 7 days, no raw output)
    days_back = event.get('days', 7)
    show_raw = event.get('raw', False)

    # Fetch updates
    updates = get_all_updates(show_raw=show_raw, timeout=REQUEST_TIMEOUT)

    if updates:
        # Filter updates by date
        recent_updates = filter_updates_by_date(updates, days_back)
        print(f"Found {len(recent_updates)} updates from the last {days_back} days.")

        # Build the structured report
        results = collect_updates(recent_updates)
        return {
            'statusCode': 200,
            'body': json.dumps(results, indent=4)
        }
    else:
        return {
            'statusCode': 200,
            'body': json.dumps({"message": "No updates found."})
        }
