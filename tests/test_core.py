import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from ms_patch_tuesday_fetcher.core import (
    get_all_updates,
    filter_updates_by_date,
    extract_kb_from_description,
    extract_notable_cves_from_description,
    extract_cves_from_cvrf,
    release_to_cvrf_id,
    filter_reports_by_product,
    parse_release_date,
    collect_updates,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# A release-note description with all four real tables: summary, the notable
# "CVE ID" table, a blog table that mentions an unrelated CVE, and the KB table.
DESCRIPTION_WITH_CVES = """
<table><tr><th>Product Family</th><th>Vulnerabilities Addressed</th></tr>
<tr><td>Windows</td><td>50</td></tr></table>
<table>
  <tr><th>CVE ID</th><th>Title</th><th>Notable Item</th></tr>
  <tr><td>CVE-2026-56155</td><td>ADFS Elevation of Privilege Vulnerability</td><td>Exploitation Detected</td></tr>
  <tr><td>CVE-2026-50661</td><td>BitLocker Security Feature Bypass</td><td>Publicly Known</td></tr>
</table>
<table>
  <tr><th>Date</th><th>Blog Post</th></tr>
  <tr><td>October 28, 2025</td><td>Understanding CVE-2025-55315: deep dive</td></tr>
</table>
<table>
  <tr><th>KB Article</th><th>Applies To</th></tr>
  <tr><td><a href="https://support.microsoft.com/help/5099536">5099536</a></td><td>Windows Server 2025</td></tr>
</table>
"""

# Release date relative to "now" so the date-window tests stay valid no
# matter when they run. 5 days ago is inside a 30/7-day window and outside
# a 1-day window.
RECENT_RELEASE_DATE = (datetime.now(timezone.utc) - timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%SZ')

# Sample API response for testing
sample_response = {
    "value": [
        {
            "title": "September 2024 Security Updates",
            "releaseDate": RECENT_RELEASE_DATE,
            "description": """<table>
            <tr><td><a href="https://support.microsoft.com/help/5002624">5002624</a></td><td>SharePoint Enterprise Server 2016</td></tr>
            <tr><td><a href="https://support.microsoft.com/help/5002639">5002639</a></td><td>SharePoint Server 2019</td></tr>
            </table>"""
        }
    ]
}


@patch('ms_patch_tuesday_fetcher.core.requests.get')
def test_get_all_updates(mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = sample_response

    updates = get_all_updates(show_raw=False)

    assert len(updates) == 1
    assert updates[0]['title'] == "September 2024 Security Updates"


# The API request must specify a timeout so a hung server can't block forever
@patch('ms_patch_tuesday_fetcher.core.requests.get')
def test_get_all_updates_uses_timeout(mock_get):
    mock_get.return_value.json.return_value = sample_response

    get_all_updates(show_raw=False)

    assert mock_get.call_args.kwargs.get('timeout') is not None


# Diagnostics (raw dump and errors) must go to stderr, never stdout, so they
# can't corrupt a machine-readable stdout payload (e.g. CLI --json).
@patch('ms_patch_tuesday_fetcher.core.requests.get')
def test_get_all_updates_diagnostics_go_to_stderr(mock_get, capsys):
    import requests as _requests
    mock_get.return_value.json.return_value = sample_response

    # Raw dump goes to stderr, not stdout.
    get_all_updates(show_raw=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Raw Updates Response:" in captured.err

    # Request errors go to stderr, not stdout.
    mock_get.side_effect = _requests.exceptions.RequestException("boom")
    assert get_all_updates() == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Error fetching updates" in captured.err


def test_filter_updates_by_date():
    updates = sample_response['value']

    # 30 days back keeps the 5-day-old update
    assert len(filter_updates_by_date(updates, 30)) == 1

    # 1 day back filters it out
    assert len(filter_updates_by_date(updates, 1)) == 0


# parse_release_date tolerates format variants and returns UTC-aware values
def test_parse_release_date_accepts_variants():
    for value in ("2024-09-10T07:00:00Z",
                  "2024-09-10T07:00:00.123Z",
                  "2024-09-10T07:00:00+00:00"):
        parsed = parse_release_date(value)
        assert parsed is not None
        assert parsed.tzinfo is not None
        assert parsed.utctimetuple()[:5] == (2024, 9, 10, 7, 0)


# Unparseable or missing dates return None instead of raising
def test_parse_release_date_rejects_bad_values():
    assert parse_release_date("not-a-date") is None
    assert parse_release_date(None) is None
    assert parse_release_date("") is None


# A single malformed date must not abort filtering of the good records
def test_filter_updates_skips_unparseable_dates():
    updates = [
        {"title": "bad", "releaseDate": "garbage"},
        {"title": "good", "releaseDate": RECENT_RELEASE_DATE},
    ]
    filtered = filter_updates_by_date(updates, 30)
    assert [u["title"] for u in filtered] == ["good"]


def test_extract_kb_from_description():
    kb_articles = extract_kb_from_description(sample_response['value'][0]['description'])

    assert kb_articles == [
        ('5002624', 'SharePoint Enterprise Server 2016'),
        ('5002639', 'SharePoint Server 2019'),
    ]


# Rows with more than two columns should still yield their KB + product
def test_extract_kb_handles_extra_columns():
    description = """<table>
    <tr><th>KB</th><th>Product</th><th>Severity</th></tr>
    <tr><td><a href="https://support.microsoft.com/help/5002624">5002624</a></td><td>SharePoint Enterprise Server 2016</td><td>Important</td></tr>
    </table>"""
    assert extract_kb_from_description(description) == [('5002624', 'SharePoint Enterprise Server 2016')]


# collect_updates returns structured dicts with formatted KB strings
def test_collect_updates_structures_output():
    results = collect_updates(sample_response['value'])

    assert results[0]['title'] == "September 2024 Security Updates"
    assert results[0]['kb_articles'] == [
        "KB5002624 (Applies to: SharePoint Enterprise Server 2016)",
        "KB5002639 (Applies to: SharePoint Server 2019)",
    ]
    # No notable-CVE table in this sample -> empty list, not missing key.
    assert results[0]['cves'] == []


# The notable-CVE table is parsed; the summary and blog tables are ignored so
# the blog's unrelated CVE mention (CVE-2025-55315) is not picked up.
def test_extract_notable_cves_parses_only_cve_table():
    cves = extract_notable_cves_from_description(DESCRIPTION_WITH_CVES)

    assert [c['id'] for c in cves] == ["CVE-2026-56155", "CVE-2026-50661"]
    assert cves[0] == {
        "id": "CVE-2026-56155",
        "title": "ADFS Elevation of Privilege Vulnerability",
        "notable": True,
        "exploitation": "Exploitation Detected",
    }
    assert all(c['notable'] for c in cves)
    assert "CVE-2025-55315" not in [c['id'] for c in cves]


# A description with no CVE table yields an empty list (graceful, no crash).
def test_extract_notable_cves_handles_no_table():
    assert extract_notable_cves_from_description("<p>nothing here</p>") == []


# collect_updates surfaces the notable CVEs (tier 1) without any network call.
def test_collect_updates_includes_notable_cves():
    update = {"title": "July 2026", "releaseDate": RECENT_RELEASE_DATE, "description": DESCRIPTION_WITH_CVES}
    results = collect_updates([update])

    assert [c['id'] for c in results[0]['cves']] == ["CVE-2026-56155", "CVE-2026-50661"]


# release_to_cvrf_id derives the MSRC document id from an update's release date.
def test_release_to_cvrf_id():
    assert release_to_cvrf_id({"releaseDate": "2026-07-14T07:00:00Z"}) == "2026-Jul"
    assert release_to_cvrf_id({"releaseDate": "garbage"}) is None
    assert release_to_cvrf_id({}) is None


# extract_cves_from_cvrf pulls severity, CVSS, impact, exploitation, and the
# affected products/KBs out of a real (trimmed) CVRF document.
def test_extract_cves_from_cvrf():
    with open(os.path.join(FIXTURES, "cvrf_sample.json")) as f:
        doc = json.load(f)
    cves = {c['id']: c for c in extract_cves_from_cvrf(doc)}

    exploited = cves["CVE-2026-56155"]
    assert exploited['severity'] == "Important"
    assert exploited['cvss'] == 7.8
    assert exploited['impact'] == "Elevation of Privilege"
    assert exploited['exploited'] is True
    assert exploited['notable'] is True
    # Product IDs are resolved to human-readable names paired with their KB.
    assert exploited['products']
    assert all(p['product'] and p['kb'].isdigit() for p in exploited['products'])

    critical = cves["CVE-2026-48561"]
    assert critical['severity'] == "Critical"
    assert critical['cvss'] == 9.6
    assert critical['exploited'] is False
    assert critical['notable'] is False


# Products fixed without a KB article (auto-updating apps like Edge/Copilot)
# are still reported from ProductStatuses, with kb=None, so product filtering
# and rendering don't silently drop them.
def test_extract_cves_reports_non_kb_products():
    with open(os.path.join(FIXTURES, "cvrf_sample.json")) as f:
        doc = json.load(f)
    cves = {c['id']: c for c in extract_cves_from_cvrf(doc)}

    # CVE-2026-45488 affects Microsoft Edge, which has no KB fix.
    edge = cves["CVE-2026-45488"]
    assert edge['products'], "expected affected products even without a KB"
    assert any("Edge" in p['product'] for p in edge['products'])
    assert all(p['kb'] is None for p in edge['products'])

    # Copilot (CVE-2026-48561) likewise: affected products, no KB.
    copilot = cves["CVE-2026-48561"]
    assert copilot['products']
    assert all(p['kb'] is None for p in copilot['products'])

    # Such CVEs are now reachable by a product filter.
    reports = [{"title": "t", "release_date": "d", "kb_articles": [], "cves": [edge]}]
    assert filter_reports_by_product(reports, "Microsoft Edge")


# In full-CVE mode, collect_updates fetches the CVRF document (mocked) and
# carries the release-note's notable wording onto the matching CVE.
@patch('ms_patch_tuesday_fetcher.core.fetch_cvrf_document')
def test_collect_updates_full_cves_merges_notable(mock_fetch):
    with open(os.path.join(FIXTURES, "cvrf_sample.json")) as f:
        mock_fetch.return_value = json.load(f)

    update = {"title": "July 2026", "releaseDate": "2026-07-14T07:00:00Z", "description": DESCRIPTION_WITH_CVES}
    results = collect_updates([update], include_full_cves=True)

    mock_fetch.assert_called_once_with("2026-Jul", timeout=30)
    cves = {c['id']: c for c in results[0]['cves']}
    # The 3 fixture CVEs plus the one notable CVE absent from the CVRF doc.
    assert len(cves) == 4
    # CVE-2026-56155 appears in both the notable table and the CVRF doc; the
    # notable flag/wording is preserved.
    assert cves["CVE-2026-56155"]['notable'] is True
    assert cves["CVE-2026-56155"]['exploitation'] == "Exploitation Detected"
    # CVE-2026-50661 is notable but not in the CVRF fixture; it must survive so
    # full mode never shows fewer highlighted CVEs than the default.
    assert "CVE-2026-50661" in cves
    assert cves["CVE-2026-50661"]['notable'] is True


# The parsed CVRF list is cached and never mutated: two updates in the same
# month trigger a single fetch, and one update's notable wording must not leak
# onto another's copy. CVE-2026-48561 is non-notable in the CVRF fixture, so
# it's a clean discriminator.
@patch('ms_patch_tuesday_fetcher.core.fetch_cvrf_document')
def test_collect_updates_full_cves_caches_and_isolates(mock_fetch):
    with open(os.path.join(FIXTURES, "cvrf_sample.json")) as f:
        mock_fetch.return_value = json.load(f)

    # Only update A's release note flags CVE-2026-48561 as notable.
    description_a = """<table>
      <tr><th>CVE ID</th><th>Title</th><th>Notable Item</th></tr>
      <tr><td>CVE-2026-48561</td><td>Copilot RCE</td><td>Publicly Known</td></tr>
    </table>"""
    updates = [
        {"title": "A", "releaseDate": "2026-07-14T07:00:00Z", "description": description_a},
        {"title": "B", "releaseDate": "2026-07-20T07:00:00Z", "description": "<p>none</p>"},
    ]
    results = collect_updates(updates, include_full_cves=True)

    # One fetch for the shared month (parsed list is cached).
    mock_fetch.assert_called_once()
    a = {c['id']: c for c in results[0]['cves']}
    b = {c['id']: c for c in results[1]['cves']}
    # A's notable wording applies to A only; B's copy is untouched — proof the
    # cached dicts were copied, not mutated in place.
    assert a["CVE-2026-48561"]['notable'] is True
    assert a["CVE-2026-48561"]['exploitation'] == "Publicly Known"
    assert b["CVE-2026-48561"]['notable'] is False
    assert b["CVE-2026-48561"]['exploitation'] is None


# If the CVRF fetch fails, full mode falls back to the notable subset.
@patch('ms_patch_tuesday_fetcher.core.fetch_cvrf_document', return_value=None)
def test_collect_updates_full_cves_falls_back(mock_fetch):
    update = {"title": "July 2026", "releaseDate": "2026-07-14T07:00:00Z", "description": DESCRIPTION_WITH_CVES}
    results = collect_updates([update], include_full_cves=True)

    assert [c['id'] for c in results[0]['cves']] == ["CVE-2026-56155", "CVE-2026-50661"]


# filter_reports_by_product narrows KBs and (full-mode) CVE products by name.
def test_filter_reports_by_product():
    reports = [{
        "title": "July 2026",
        "release_date": "2026-07-14",
        "kb_articles": [
            "KB5099536 (Applies to: Windows Server 2025)",
            "KB5002882 (Applies to: SharePoint Server Subscription Edition)",
        ],
        "cves": [
            {"id": "CVE-A", "title": "x", "products": [
                {"product": "Windows Server 2025", "kb": "5099536"},
                {"product": "SharePoint Server", "kb": "5002882"},
            ]},
            {"id": "CVE-B", "title": "y", "products": [{"product": "SharePoint Server", "kb": "5002882"}]},
        ],
    }]

    filtered = filter_reports_by_product(reports, "windows server 2025")

    assert len(filtered) == 1
    assert filtered[0]['kb_articles'] == ["KB5099536 (Applies to: Windows Server 2025)"]
    # Only the CVE touching the product survives, narrowed to matching products.
    assert [c['id'] for c in filtered[0]['cves']] == ["CVE-A"]
    assert filtered[0]['cves'][0]['products'] == [{"product": "Windows Server 2025", "kb": "5099536"}]


# A product with no matches drops the update entirely.
def test_filter_reports_by_product_drops_empty():
    reports = [{"title": "t", "release_date": "d", "kb_articles": ["KB1 (Applies to: Azure)"], "cves": []}]
    assert filter_reports_by_product(reports, "nonexistent") == []
