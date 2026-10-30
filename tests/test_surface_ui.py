"""End-to-end acceptance tests for the additive Surface web interface."""
from __future__ import annotations

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


def test_surface_mobile_keyboard_and_api_failure_feedback(page, live_server):
    """Mobile layout remains usable and failed API actions show honest feedback."""
    page.set_viewport_size({"width": 390, "height": 844})
    page.route(
        "**/api/tools",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='[{"id":"test-tool","name":"Test tool","available":true}]',
        ),
    )
    page.route(
        "**/api/run",
        lambda route: route.fulfill(
            status=403,
            content_type="application/json",
            body='{"error":"target out of scope; scan not started"}',
        ),
    )
    page.route(
        "**/api/scope/check",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"scope service unavailable"}',
        ),
    )

    page.goto(f"{live_server}/ui/new")
    page.wait_for_function(
        "() => document.querySelector('#metric-jobs')?.textContent.trim() !== '—'",
        timeout=10000,
    )
    assert page.evaluate(
        "document.documentElement.scrollWidth <= window.innerWidth"
    ), "Surface should not introduce page-wide horizontal scrolling on mobile"

    # Navigation controls are native buttons and work from the keyboard.
    findings_nav = page.locator('.nav-item[data-view="findings"]')
    findings_nav.focus()
    page.keyboard.press("Enter")
    assert "active" in (findings_nav.get_attribute("class") or "")

    scans_nav = page.locator('.nav-item[data-view="scans"]')
    scans_nav.focus()
    page.keyboard.press("Enter")
    page.select_option("#run-tool", "test-tool")
    page.fill("#run-target", "example.invalid")
    page.locator('#run-form button[type="submit"]').click()
    page.wait_for_function(
        "() => document.querySelector('#run-message')?.textContent.includes('Run not started')",
        timeout=5000,
    )
    assert "out of scope" in page.locator("#run-message").text_content().lower()

    scope_nav = page.locator('.nav-item[data-view="scope"]')
    scope_nav.focus()
    page.keyboard.press("Enter")
    page.fill("#scope-target", "example.invalid")
    page.locator('#scope-form button[type="submit"]').click()
    page.wait_for_function(
        "() => document.querySelector('#scope-result')?.textContent.includes('Scope check failed')",
        timeout=5000,
    )
    assert "unavailable" in page.locator("#scope-result").text_content().lower()


def test_surface_scan_submission_success_feedback_without_real_scan(page, live_server):
    """The submit flow handles an accepted job response without launching a real tool."""
    page.route(
        "**/api/tools",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='[{"id":"test-tool","name":"Test tool","available":true}]',
        ),
    )
    page.route(
        "**/api/run",
        lambda route: route.fulfill(
            status=202,
            content_type="application/json",
            body='{"job_id":"mock-job-123"}',
        ),
    )

    page.goto(f"{live_server}/ui/new")
    page.wait_for_function(
        "() => document.querySelector('#metric-jobs')?.textContent.trim() !== '—'",
        timeout=10000,
    )
    page.locator('.nav-item[data-view="scans"]').click()
    page.select_option("#run-tool", "test-tool")
    page.fill("#run-target", "example.invalid")
    page.locator('#run-form button[type="submit"]').click()
    page.wait_for_function(
        "() => document.querySelector('#run-message')?.textContent.includes('mock-job-123')",
        timeout=5000,
    )
    assert "Run accepted" in page.locator("#run-message").text_content()



def test_surface_live_run_output_is_displayed(page, live_server):
    """Accepted runs expose their server-sent output and terminal status."""
    page.route("**/api/tools", lambda route: route.fulfill(status=200, content_type="application/json", body='[{"id":"test-tool","name":"Test tool","available":true}]'))
    page.route("**/api/run", lambda route: route.fulfill(status=202, content_type="application/json", body='{"job_id":"mock-stream-job"}'))
    stream = 'data: {"type":"status","status":"running"}\n\ndata: {"type":"line","text":"simulated tool output"}\n\ndata: {"type":"finished","exit_code":0}\n\n'
    page.route("**/api/jobs/mock-stream-job/stream", lambda route: route.fulfill(status=200, content_type="text/event-stream", body=stream))
    page.goto(f"{live_server}/ui/new")
    page.wait_for_function("() => document.querySelector('#metric-jobs')?.textContent.trim() !== '—'", timeout=10000)
    page.click('.nav-item[data-view="scans"]')
    page.select_option("#run-tool", "test-tool")
    page.fill("#run-target", "127.0.0.1")
    page.click('#run-form button[type="submit"]')
    page.wait_for_function("() => document.querySelector('#run-output')?.textContent.includes('simulated tool output')", timeout=5000)
    page.wait_for_function("() => document.querySelector('#run-live-status')?.textContent.includes('Finished')", timeout=5000)
    assert "exit code 0" in page.locator("#run-live-status").text_content()
    assert page.locator("#cancel-run-btn").is_disabled()
