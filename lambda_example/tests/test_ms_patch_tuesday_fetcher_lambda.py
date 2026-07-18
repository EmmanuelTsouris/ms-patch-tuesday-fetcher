import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from lambda_example.ms_patch_tuesday_fetcher_lambda import lambda_handler

# Release date relative to "now" so the handler's date filter keeps it.
RECENT_RELEASE_DATE = (datetime.now(timezone.utc) - timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%SZ')

sample_value = [
    {
        "title": "September 2024 Security Updates",
        "releaseDate": RECENT_RELEASE_DATE,
        "description": """<table>
        <tr><td><a href="https://support.microsoft.com/help/5002624">5002624</a></td><td>SharePoint Enterprise Server 2016</td></tr>
        <tr><td><a href="https://support.microsoft.com/help/5002639">5002639</a></td><td>SharePoint Server 2019</td></tr>
        </table>"""
    }
]


# The handler fetches, filters, and returns a JSON body of structured updates.
# Shared fetch/parse/extract logic is covered in tests/test_core.py.
@patch('lambda_example.ms_patch_tuesday_fetcher_lambda.get_all_updates')
def test_lambda_handler(mock_get_all_updates):
    mock_get_all_updates.return_value = sample_value

    result = lambda_handler({"days": 7}, {})

    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert len(body) == 1
    assert body[0]['title'] == "September 2024 Security Updates"
    assert len(body[0]['kb_articles']) == 2
    assert "KB5002624 (Applies to: SharePoint Enterprise Server 2016)" in body[0]['kb_articles']


# With no updates, the handler returns the "No updates found." message
@patch('lambda_example.ms_patch_tuesday_fetcher_lambda.get_all_updates')
def test_lambda_handler_no_updates(mock_get_all_updates):
    mock_get_all_updates.return_value = []

    result = lambda_handler({"days": 7}, {})

    assert result['statusCode'] == 200
    assert json.loads(result['body']) == {"message": "No updates found."}
