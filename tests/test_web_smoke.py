"""Smoke test for the Playwright fixtures.

Proves: the live_server fixture starts, the browser fixture launches,
the page fixture opens a browser context, and the app is reachable.
"""
from __future__ import annotations


def test_server_is_reachable(page, live_server):
    page.goto(f"{live_server}/api/health/simple")
    body = page.text_content("body")
    assert body is not None
    assert "ok" in body.lower() or "healthy" in body.lower() or len(body) > 0


def test_ui_renders(page, live_server):
    page.goto(f"{live_server}/ui")
    # The sidebar brand is present on every page.
    assert page.locator(".sb-brand .label-text").text_content() == "WHAXON"


def test_scope_page_loads(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="scope"]')
    # The scope rules container should be populated (or at least exist).
    page.wait_for_selector("#scope-rules", timeout=5000)
    assert page.locator("#scope-rules").count() == 1


def test_findings_page_loads(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="findings"]')
    page.wait_for_selector("#findings-tbody", timeout=5000)
    # The seeded store has 3 findings, so the tbody should have rows.
    page.wait_for_function(
        "() => document.querySelectorAll('#findings-tbody tr').length > 0",
        timeout=5000,
    )
    rows = page.locator("#findings-tbody tr")
    assert rows.count() >= 3


def test_surface_ui_loads_real_data_and_navigation_works(page, live_server):
    """The alternate UI loads API data and its primary navigation/filter controls work."""
    page_errors = []
    page.on("pageerror", lambda error: page_errors.append(str(error)))

    page.goto(f"{live_server}/ui/new")
    page.wait_for_function(
        "() => document.querySelector('#metric-jobs')?.textContent.trim() !== '—'",
        timeout=10000,
    )
    assert int(page.locator("#metric-jobs").text_content().strip()) >= 2
    assert page.locator("#recent-runs tr").count() >= 2

    page.click('.nav-item[data-view="findings"]')
    page.wait_for_function(
        "() => document.querySelectorAll('#findings-table tr').length > 0",
        timeout=10000,
    )
    assert page.locator("#findings-table tr").count() >= 3

    page.click('[data-severity="critical"]')
    critical_rows = page.locator("#findings-table tr")
    assert critical_rows.count() == 1
    # Assert the visible row is critical without assuming a particular seeded title.
    assert "critical" in critical_rows.first.text_content().lower()
    assert critical_rows.first.locator("td").nth(1).text_content().strip()

    page.click('.nav-item[data-view="scope"]')
    assert page.locator("#scope-target").is_visible()
    assert page_errors == []



def test_surface_job_details_search_and_scope_check(page, live_server):
    """Visible data actions work without launching a scan."""
    page.goto(f"{live_server}/ui/new")
    page.wait_for_function(
        "() => document.querySelector('#metric-jobs')?.textContent.trim() !== '—'",
        timeout=10000,
    )

    # Job Details must open the actual stored job record, not just a toast.
    page.locator("#recent-runs [data-job]").first.click()
    page.wait_for_selector("#job-detail:not(.hidden)", timeout=5000)
    assert page.locator("#job-detail-body").text_content().strip()
    page.locator("#close-job-detail").click()
    assert "hidden" in (page.locator("#job-detail").get_attribute("class") or "")

    # Target and finding search controls update the visible rows.
    page.click('.nav-item[data-view="assets"]')
    page.fill("#asset-search", "no-such-target-for-test")
    assert "No matching target" in page.locator("#asset-table").text_content()

    page.click('.nav-item[data-view="findings"]')
    page.fill("#finding-search", "no-such-finding-for-test")
    assert "No findings match" in page.locator("#findings-table").text_content()

    # Scan tools and reports sections are navigable and populated.
    page.click('.nav-item[data-view="scans"]')
    assert page.locator("#run-form").is_visible()
    page.fill("#tool-search", "no-such-tool-for-test")
    assert "No tools match" in page.locator("#tool-catalog").text_content()
    page.click('.nav-item[data-view="reports"]')
    assert page.locator(".report-card").count() == 5

    # A scope check is read-only and must not create a job.
    before = page.locator("#metric-jobs").text_content().strip()
    page.click('.nav-item[data-view="scope"]')
    page.fill("#scope-target", "127.0.0.1")
    page.click('#scope-form button[type="submit"]')
    page.wait_for_function(
        "() => document.querySelector('#scope-result')?.textContent.includes('scope')",
        timeout=5000,
    )
    page.click("#refresh-btn")
    page.wait_for_function(
        "() => document.querySelector('#system-state')?.textContent.includes('refreshed')",
        timeout=10000,
    )
    assert page.locator("#metric-jobs").text_content().strip() == before


def test_surface_report_exports_are_supported(page, live_server):
    """Every advertised report card points to a functioning API export."""
    page.goto(f"{live_server}/ui/new")
    formats = {
        "html": "text/html",
        "md": "text/markdown",
        "json": "application/json",
        "whaxon": "application/json",
        "pdf": "application/pdf",
    }
    for fmt, expected_type in formats.items():
        response = page.request.get(f"{live_server}/api/report?format={fmt}")
        assert response.status == 200, f"{fmt} export returned HTTP {response.status}"
        assert expected_type in response.headers.get("content-type", ""), (
            f"{fmt} export returned {response.headers.get('content-type')}"
        )
