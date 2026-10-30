"""Findings page behavior tests.

The fixture seeds three findings: one critical (nikto), one medium (nmap),
one low (nmap). These tests assert that the page renders those numbers,
that the table is populated, that clicking a row opens the slide-over with
real data, that the slide-over closes, and that sorting works.
"""
from __future__ import annotations


def _open_findings(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="findings"]')
    # Wait for the table to populate.
    page.wait_for_function(
        "() => document.querySelectorAll('#findings-tbody tr').length > 0",
        timeout=5000,
    )


def test_kpi_cards_show_real_counts(page, live_server):
    _open_findings(page, live_server)
    assert page.locator("#kpi-critical").text_content().strip() == "1"
    assert page.locator("#kpi-medium").text_content().strip() == "1"
    # The low card aggregates low + info; seed has 1 low, 0 info.
    assert page.locator("#kpi-low").text_content().strip() == "1"


def test_summary_line_reports_jobs_and_findings(page, live_server):
    _open_findings(page, live_server)
    summary = page.locator("#findings-summary").text_content()
    assert "3 findings" in summary
    assert "2 jobs" in summary


def test_donut_legend_matches_kpis(page, live_server):
    _open_findings(page, live_server)
    assert page.locator("#legend-critical").text_content().strip() == "1"
    assert page.locator("#legend-medium").text_content().strip() == "1"
    assert page.locator("#legend-low").text_content().strip() == "1"


def test_donut_segments_have_nonzero_dasharray(page, live_server):
    _open_findings(page, live_server)
    # The critical segment should have a non-zero first value in stroke-dasharray.
    dash = page.locator("#donut-critical").get_attribute("stroke-dasharray")
    assert dash is not None
    first = dash.split()[0]
    assert float(first) > 0


def test_table_has_seeded_rows(page, live_server):
    _open_findings(page, live_server)
    rows = page.locator("#findings-tbody tr")
    assert rows.count() == 3


def test_rows_sorted_by_severity_by_default(page, live_server):
    _open_findings(page, live_server)
    first_row_sev = page.locator("#findings-tbody tr").first.get_attribute("data-severity")
    assert first_row_sev == "critical"


def test_row_click_opens_slideover(page, live_server):
    _open_findings(page, live_server)
    first_row = page.locator("#findings-tbody tr").first
    expected_title = first_row.get_attribute("data-title")
    first_row.click()
    page.wait_for_selector("#slideover.open", timeout=3000)
    assert page.locator("#so-title").text_content() == expected_title


def test_slideover_shows_real_target_and_source(page, live_server):
    _open_findings(page, live_server)
    first_row = page.locator("#findings-tbody tr").first
    expected_target = first_row.get_attribute("data-target")
    expected_source = first_row.get_attribute("data-source")
    first_row.click()
    page.wait_for_selector("#slideover.open", timeout=3000)
    meta = page.locator("#so-meta").text_content()
    assert expected_target in meta
    assert expected_source in meta


def test_slideover_closes_on_escape(page, live_server):
    _open_findings(page, live_server)
    page.locator("#findings-tbody tr").first.click()
    page.wait_for_selector("#slideover.open", timeout=3000)
    page.keyboard.press("Escape")
    page.wait_for_timeout(300)
    assert not page.locator("#slideover").evaluate("el => el.classList.contains('open')")


def test_sort_by_title_changes_order(page, live_server):
    _open_findings(page, live_server)
    titles_before = page.locator("#findings-tbody tr").evaluate_all(
        "rows => rows.map(r => r.dataset.title)"
    )
    page.locator('th[data-sort="title"]').click()
    page.wait_for_timeout(400)
    titles_after = page.locator("#findings-tbody tr").evaluate_all(
        "rows => rows.map(r => r.dataset.title)"
    )
    assert titles_before != titles_after


def test_sort_by_severity_toggles_direction(page, live_server):
    _open_findings(page, live_server)
    first_before = page.locator("#findings-tbody tr").first.get_attribute("data-severity")
    page.locator('th[data-sort="severity"]').click()
    page.wait_for_timeout(400)
    first_after = page.locator("#findings-tbody tr").first.get_attribute("data-severity")
    assert first_before != first_after


def test_filter_chips_filter_real_findings(page, live_server):
    _open_findings(page, live_server)
    page.click('#findings-filters [data-filter="critical"]')
    assert page.locator("#findings-tbody tr").count() == 1
    assert page.locator("#findings-tbody tr").first.get_attribute("data-severity") == "critical"
    page.click('#findings-filters [data-filter="all"]')
    assert page.locator("#findings-tbody tr").count() == 3


def test_findings_export_downloads_csv(page, live_server):
    _open_findings(page, live_server)
    with page.expect_download() as download_info:
        page.click("#findings-export")
    assert download_info.value.suggested_filename == "whaxon-findings.csv"


def test_slideover_exposes_validate_and_retest_actions_for_real_finding(page, live_server):
    _open_findings(page, live_server)
    page.locator("#findings-tbody tr").first.click()
    page.wait_for_selector("#slideover.open", timeout=3000)
    assert page.locator("#so-validate").is_visible()
    assert page.locator("#so-validate").is_enabled()
    assert page.locator("#so-retest").is_visible()
    assert page.locator("#so-retest").is_disabled()


def test_target_summary_uses_real_findings(page, live_server):
    _open_findings(page, live_server)
    summary = page.locator("#findings-target-summary").text_content()
    assert "2 distinct target(s)" in summary
    assert page.locator("#findings-target-list .kv").count() == 2


def test_table_labels_each_verification_state_accurately(page, live_server):
    import json

    statuses = ["candidate", "verified", "refuted", "fixed", "still_vulnerable", "inconclusive"]
    findings = [
        {
            "seq": index + 1,
            "kind": "test_finding",
            "title": status,
            "severity": "medium",
            "source": "test",
            "verification_status": status,
            "data": {},
        }
        for index, status in enumerate(statuses)
    ]
    report = {
        "job_count": 1,
        "finding_count": len(findings),
        "severity_counts": {"medium": len(findings)},
        "jobs": [{"job": {"id": "status-job", "target": "lab.example"}, "findings": findings}],
    }
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(report),
        ),
    )
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="findings"]')
    page.wait_for_function(
        "() => document.querySelectorAll('#findings-tbody tr').length === 6"
    )
    labels = page.locator("#findings-tbody tr td:nth-child(6)").all_text_contents()
    assert labels == [
        "Candidate",
        "Verified",
        "Refuted",
        "Fixed",
        "Still Vulnerable",
        "Inconclusive",
    ]
