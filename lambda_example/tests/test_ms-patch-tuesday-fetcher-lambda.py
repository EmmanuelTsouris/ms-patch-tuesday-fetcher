import pytest
import json
from unittest.mock import patch
from lambda_example.ms_patch_tuesday_fetcher_lambda import lambda_handler, get_all_updates, filter_updates_by_date, extract_kb_from_description

# Sample API response for testing
sample_response = {
    "value": [
        {
            "title": "September 2024 Security Updates",
            "releaseDate": "2024-09-10T07:00:00Z",
            "description": """<table>
            <tr><td><a href="https://support.microsoft.com/help/5002624">5002624</a></td><td>SharePoint Enterprise Server 2016</td></tr>
            <tr><td><a href="https://support.microsoft.com/help/5002639">5002639</a></td><td>SharePoint Server 2019</td></tr>
            </table>"""
        }
    ]
}

# Mock the requests.get method to return the sample_response
@patch('lambda_example.ms_patch_tuesday_fetcher_lambda.requests.get')
def test_get_all_updates(mock_get):
    # Mocking requests.get to return a successful response
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = sample_response

    updates = get_all_updates()

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

# Test the Lambda handler function
@patch('lambda_example.ms_patch_tuesday_fetcher_lambda.get_all_updates')
def test_lambda_handler(mock_get_all_updates):
    # Mocking the get_all_updates function to return sample_response['value']
    mock_get_all_updates.return_value = sample_response['value']

    event = {"days": 7}
    context = {}

    result = lambda_handler(event, context)

    assert result['statusCode'] == 200
    body = json.loads(result['body'])
    assert len(body) == 1
    assert body[0]['title'] == "September 2024 Security Updates"
    assert len(body[0]['kb_articles']) == 2
    assert "KB5002624 (Applies to: SharePoint Enterprise Server 2016)" in body[0]['kb_articles']
