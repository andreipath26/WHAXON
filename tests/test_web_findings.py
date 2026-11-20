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
    # The server-rendered table contains reference rows before the live report
    # arrives. Wait for the summary and live rows, not merely any table row.
    page.wait_for_function(
        "() => { const summary = document.querySelector('#findings-summary')?.textContent || ''; "
        "return /^\\d+ findings across \\d+ jobs$/.test(summary) "
        "&& document.querySelectorAll('#findings-tbody tr[data-severity]').length > 0; }",
        timeout=10000,
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

def test_slideover_exposes_validate_and_retest_controls(page, live_server):
    _open_findings(page, live_server)
    row = page.locator("#findings-tbody tr").first
    assert row.get_attribute("data-job-id")
    assert row.get_attribute("data-seq") is not None
    row.click()
    page.wait_for_function(
        "() => getComputedStyle(document.getElementById('so-validate')).display !== 'none'",
        timeout=3000,
    )
    assert page.locator("#so-validate").is_visible()
    assert page.locator("#so-retest").is_visible()


def test_finding_filter_chips_use_live_counts_and_filter_rows(page, live_server):
    _open_findings(page, live_server)
    assert page.locator("#filter-count-all").text_content().strip() == "3"
    assert page.locator("#filter-count-critical").text_content().strip() == "1"
    page.locator('#page-findings .chip[data-filter="critical"]').click()
    assert page.locator("#findings-tbody tr:visible").count() == 1
    page.locator('#page-findings .chip[data-filter="all"]').click()
    assert page.locator("#findings-tbody tr:visible").count() == 3


def test_bulk_clear_unselects_dynamic_finding_rows(page, live_server):
    _open_findings(page, live_server)
    checkbox = page.locator("#findings-tbody .row-cb").first
    checkbox.check()
    assert checkbox.is_checked()
    page.locator("#bulk-clear-btn").click()
    assert not checkbox.is_checked()
    assert not page.locator("#bulk-bar").evaluate("el => el.classList.contains('on')")

def test_command_palette_search_navigates_to_catalog(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click("#palette-trigger")
    page.fill("#palette-input", "catalog")
    result = page.locator(".palette-item[role='button']").first
    assert result.count() == 1
    result.click()
    page.wait_for_function(
        "() => document.getElementById('page-catalog').classList.contains('active')",
        timeout=3000,
    )
