import sys
import json
import argparse

# Support both `python ms_patch_tuesday_fetcher/ms_patch_tuesday_fetcher.py`
# (run as a script, so the package root isn't on sys.path) and importing this
# module as part of the package (tests).
try:
    from ms_patch_tuesday_fetcher.core import (
        get_all_updates,
        filter_updates_by_date,
        collect_updates,
        filter_reports_by_product,
    )
except ImportError:  # pragma: no cover - exercised when run directly as a script
    from core import (
        get_all_updates,
        filter_updates_by_date,
        collect_updates,
        filter_reports_by_product,
    )


# Render a single CVE dict as a one-line string. Works for both the notable
# subset (id/title/exploitation) and the full CVRF detail (adds severity, CVSS,
# and affected-product count).
def format_cve(cve):
    parts = [cve['id']]
    if cve.get('severity'):
        parts.append(f"[{cve['severity']}]")
    if cve.get('cvss') is not None:
        parts.append(f"CVSS {cve['cvss']}")
    if cve.get('title'):
        parts.append(f"- {cve['title']}")

    tags = []
    if cve.get('exploited'):
        tags.append("EXPLOITED")
    elif cve.get('exploitation'):
        tags.append(cve['exploitation'])
    elif cve.get('publicly_disclosed'):
        tags.append("Publicly Disclosed")
    if tags:
        parts.append(f"({', '.join(tags)})")

    products = cve.get('products')
    if products:
        # Some affected products have no KB fix (kb=None); only list real KBs.
        kbs = sorted({p['kb'] for p in products if p.get('kb')})
        if kbs:
            parts.append(f"[KB{', KB'.join(kbs)}]")
    return " ".join(parts)


# Print each collected report's title, release date, KB articles, and CVEs.
# Takes the output of core.collect_updates(), not raw API updates.
def print_report(reports):
    for report in reports:
        print(f"- Title: {report['title']}, Released on: {report['release_date']}")
        if report['kb_articles']:
            print("  KB Articles:")
            for kb in report['kb_articles']:
                print(f"  - {kb}")
        else:
            print("  No KB Articles found.")

        cves = report.get('cves', [])
        if cves:
            print(f"  CVEs ({len(cves)}):")
            for cve in cves:
                print(f"  - {format_cve(cve)}")


# Main function to execute the script logic
def main():
    parser = argparse.ArgumentParser(description="Fetch and display Microsoft Patch Tuesday updates.")

    # Adding the --raw flag
    parser.add_argument('--raw', action='store_true', help="Show raw API response for debugging.")

    # Adding the --days argument to specify the number of days back
    parser.add_argument('--days', type=int, default=7, help="Number of days back to fetch updates for (default: 7 days).")

    # CVE options
    parser.add_argument('--full-cves', action='store_true', dest='full_cves',
                        help="Fetch the complete CVE list (severity, CVSS, affected products/KBs) from the "
                             "MSRC CVRF API. Default: only the notable CVEs listed in the release note.")
    parser.add_argument('--product',
                        help="Filter results to a product-name substring (case-insensitive), "
                             "e.g. --product 'Windows Server 2025'.")
    parser.add_argument('--json', action='store_true', dest='as_json',
                        help="Emit the structured report as JSON (for scripting / feeding to another tool).")

    args = parser.parse_args()

    # Keep JSON output clean (parseable) by suppressing the progress lines.
    if not args.as_json:
        print(f"Fetching updates from the last {args.days} days...")

    # Fetch all updates from Microsoft's API, passing the raw flag
    updates = get_all_updates(show_raw=args.raw)

    if not updates:
        if args.as_json:
            print(json.dumps([]))
        else:
            print("No updates found.")
        return

    # Filter updates by release date, then build the structured report
    recent_updates = filter_updates_by_date(updates, args.days)
    reports = collect_updates(recent_updates, include_full_cves=args.full_cves)
    if args.product:
        # Notable-only CVEs carry no product data, so product filtering can only
        # narrow CVEs (beyond KB articles) when the full CVE list is fetched.
        if not args.full_cves:
            print("Note: --product filters CVEs by affected product only with --full-cves; "
                  "without it, only KB articles are filtered.", file=sys.stderr)
        reports = filter_reports_by_product(reports, args.product)

    if args.as_json:
        print(json.dumps(reports, indent=2))
    else:
        print(f"Found {len(reports)} updates from the last {args.days} days.")
        print_report(reports)


if __name__ == "__main__":
    main()
