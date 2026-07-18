import argparse

# Support both `python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py`
# (run as a script, so the package root isn't on sys.path) and importing this
# module as part of the package (tests).
try:
    from ms_patch_tuesday_fetcher.core import (
        get_all_updates,
        filter_updates_by_date,
        collect_updates,
    )
except ImportError:  # pragma: no cover - exercised when run directly as a script
    from core import (
        get_all_updates,
        filter_updates_by_date,
        collect_updates,
    )


# Print each update's title, release date, and KB articles to the console
def print_report(updates):
    for report in collect_updates(updates):
        print(f"- Title: {report['title']}, Released on: {report['release_date']}")
        if report['kb_articles']:
            print("  KB Articles:")
            for kb in report['kb_articles']:
                print(f"  - {kb}")
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
        print_report(recent_updates)
    else:
        print("No updates found.")


if __name__ == "__main__":
    main()
