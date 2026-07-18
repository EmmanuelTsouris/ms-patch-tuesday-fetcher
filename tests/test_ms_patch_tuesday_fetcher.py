from ms_patch_tuesday_fetcher.ms_patch_tuesday_fetcher import print_report, format_cve
from ms_patch_tuesday_fetcher.core import collect_updates

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


# The CLI printer renders the title and each KB article. It takes the collected
# reports from core.collect_updates(), so build those first.
def test_print_report_outputs_title_and_kbs(capsys):
    print_report(collect_updates(sample_updates))

    captured = capsys.readouterr()
    assert "September 2024 Security Updates" in captured.out
    assert "KB5002624 (Applies to: SharePoint Enterprise Server 2016)" in captured.out
    assert "KB5002639 (Applies to: SharePoint Server 2019)" in captured.out


# Updates with no KB table produce the "No KB Articles found." line
def test_print_report_handles_no_kbs(capsys):
    reports = collect_updates([{"title": "Empty", "releaseDate": "2024-09-10T07:00:00Z", "description": "<p>none</p>"}])
    print_report(reports)

    captured = capsys.readouterr()
    assert "No KB Articles found." in captured.out


# The printer lists CVEs when the report carries them.
def test_print_report_outputs_cves(capsys):
    reports = [{
        "title": "July 2026",
        "release_date": "2026-07-14",
        "kb_articles": [],
        "cves": [{"id": "CVE-2026-56155", "title": "ADFS EoP", "exploitation": "Exploitation Detected"}],
    }]
    print_report(reports)

    captured = capsys.readouterr()
    assert "CVEs (1):" in captured.out
    assert "CVE-2026-56155" in captured.out
    assert "Exploitation Detected" in captured.out


# format_cve renders the notable subset (id + title + exploitation)...
def test_format_cve_notable():
    line = format_cve({"id": "CVE-2026-50661", "title": "BitLocker Bypass", "exploitation": "Publicly Known"})
    assert line == "CVE-2026-50661 - BitLocker Bypass (Publicly Known)"


# ...and the full CVRF detail (severity, CVSS, EXPLOITED tag, affected KBs).
def test_format_cve_full():
    line = format_cve({
        "id": "CVE-2026-56155", "title": "ADFS EoP", "severity": "Important", "cvss": 7.8,
        "exploited": True, "products": [{"product": "Windows Server 2025", "kb": "5099536"}],
    })
    assert "CVE-2026-56155" in line
    assert "[Important]" in line
    assert "CVSS 7.8" in line
    assert "EXPLOITED" in line
    assert "KB5099536" in line
