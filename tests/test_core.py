from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from ms_patch_tuesday_fetcher.core import (
    get_all_updates,
    filter_updates_by_date,
    extract_kb_from_description,
    parse_release_date,
    collect_updates,
)

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
