from ms_patch_tuesday_fetcher.ms_patch_tuesday_fetcher import print_report

# Sample updates for testing the CLI report formatting
sample_updates = [
    {
        "title": "September 2024 Security Updates",
        "releaseDate": "2024-09-10T07:00:00Z",
        "description": """<table>
        <tr><td><a href="https://support.microsoft.com/help/5002624">5002624</a></td><td>SharePoint Enterprise Server 2016</td></tr>
        <tr><td><a href="https://support.microsoft.com/help/5002639">5002639</a></td><td>SharePoint Server 2019</td></tr>
        </table>"""
    }
]


# The CLI printer renders the title and each KB article
def test_print_report_outputs_title_and_kbs(capsys):
    print_report(sample_updates)

    captured = capsys.readouterr()
    assert "September 2024 Security Updates" in captured.out
    assert "KB5002624 (Applies to: SharePoint Enterprise Server 2016)" in captured.out
    assert "KB5002639 (Applies to: SharePoint Server 2019)" in captured.out


# Updates with no KB table produce the "No KB Articles found." line
def test_print_report_handles_no_kbs(capsys):
    print_report([{"title": "Empty", "releaseDate": "2024-09-10T07:00:00Z", "description": "<p>none</p>"}])

    captured = capsys.readouterr()
    assert "No KB Articles found." in captured.out
