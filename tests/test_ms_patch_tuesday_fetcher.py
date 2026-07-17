import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from ms_patch_tuesday_fetcher.ms_patch_tuesday_fetcher import get_all_updates, filter_updates_by_date, extract_kb_from_description, extract_cve_kb_info, parse_release_date

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

# Mock the requests.get method to return the sample_response
@patch('ms_patch_tuesday_fetcher.ms_patch_tuesday_fetcher.requests.get')
def test_get_all_updates(mock_get):
    # Mocking requests.get to return a successful response
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = sample_response

    updates = get_all_updates(show_raw=False)

    assert len(updates) == 1
    assert updates[0]['title'] == "September 2024 Security Updates"

# Test filtering updates by date
def test_filter_updates_by_date():
    updates = sample_response['value']

    # Test with 30 days back
    filtered_updates = filter_updates_by_date(updates, 30)
    assert len(filtered_updates) == 1

    # Test with 1 day back (should filter out all updates)
    filtered_updates = filter_updates_by_date(updates, 1)
    assert len(filtered_updates) == 0

# Test extracting KB articles from description
def test_extract_kb_from_description():
    description = sample_response['value'][0]['description']
    kb_articles = extract_kb_from_description(description)

    assert len(kb_articles) == 2
    assert kb_articles[0][0] == '5002624'
    assert kb_articles[0][1] == 'SharePoint Enterprise Server 2016'
    assert kb_articles[1][0] == '5002639'
    assert kb_articles[1][1] == 'SharePoint Server 2019'

# Test extracting CVE and KB information
def test_extract_cve_kb_info(capsys):
    updates = sample_response['value']
    extract_cve_kb_info(updates)

    captured = capsys.readouterr()
    assert "September 2024 Security Updates" in captured.out
    assert "KB5002624 (Applies to: SharePoint Enterprise Server 2016)" in captured.out
    assert "KB5002639 (Applies to: SharePoint Server 2019)" in captured.out

# The API request must specify a timeout so a hung server can't block forever
@patch('ms_patch_tuesday_fetcher.ms_patch_tuesday_fetcher.requests.get')
def test_get_all_updates_uses_timeout(mock_get):
    mock_get.return_value.json.return_value = sample_response

    get_all_updates(show_raw=False)

    assert mock_get.call_args.kwargs.get('timeout') is not None

# parse_release_date tolerates format variants and returns UTC-aware values
def test_parse_release_date_accepts_variants():
    # Trailing "Z", fractional seconds, and an explicit offset all parse to UTC
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

# Rows with more than two columns should still yield their KB + product
def test_extract_kb_handles_extra_columns():
    description = """<table>
    <tr><th>KB</th><th>Product</th><th>Severity</th></tr>
    <tr><td><a href="https://support.microsoft.com/help/5002624">5002624</a></td><td>SharePoint Enterprise Server 2016</td><td>Important</td></tr>
    </table>"""
    kb_articles = extract_kb_from_description(description)

    assert kb_articles == [('5002624', 'SharePoint Enterprise Server 2016')]
