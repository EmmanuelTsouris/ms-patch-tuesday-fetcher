"""Live integration tests against the real MSRC API.

Excluded from the default run (see pytest.ini). Run explicitly with:

    pytest -m integration

These assert on the *shape* of the data (fields present, types, at least one
CVE match), never on monthly-changing values, so a fresh Patch Tuesday does
not turn the suite red. They require outbound access to api.msrc.microsoft.com.
"""

import pytest

from ms_patch_tuesday_fetcher.core import (
    get_all_updates,
    filter_updates_by_date,
    collect_updates,
    release_to_cvrf_id,
    fetch_cvrf_document,
    extract_cves_from_cvrf,
)

pytestmark = pytest.mark.integration


def _recent_updates(days=45):
    updates = get_all_updates()
    assert updates, "expected at least one update from the live API"
    return filter_updates_by_date(updates, days)


# The release-note endpoint returns updates with the expected fields, and
# collect_updates yields the notable-CVE structure for at least one of them.
def test_live_notable_cves_shape():
    reports = collect_updates(_recent_updates())
    assert reports, "expected recent updates in the last 45 days"

    for report in reports:
        assert set(report) >= {"title", "release_date", "kb_articles", "cves"}
        for cve in report['cves']:
            assert cve['id'].startswith("CVE-")
            assert cve['notable'] is True

    assert any(report['cves'] for report in reports), "expected at least one notable CVE"


# The CVRF document for a recent month parses into full per-CVE detail with the
# expected field types.
def test_live_cvrf_full_detail_shape():
    recent = _recent_updates()
    doc_id = next((release_to_cvrf_id(u) for u in recent if release_to_cvrf_id(u)), None)
    assert doc_id, "expected a resolvable CVRF document id"

    document = fetch_cvrf_document(doc_id)
    assert document, f"expected to fetch CVRF document {doc_id}"

    cves = extract_cves_from_cvrf(document)
    assert cves, "expected at least one CVE in the CVRF document"

    sample = cves[0]
    assert sample['id'].startswith("CVE-")
    assert isinstance(sample['products'], list)
    assert isinstance(sample['exploited'], bool)
    # Somewhere in the month at least one CVE should carry a CVSS score and a KB.
    assert any(c['cvss'] is not None for c in cves)
    assert any(c['products'] for c in cves)
