"""Browser coverage for the canonical live job-history page."""
from __future__ import annotations


def test_job_history_renders_only_records_from_live_history_api(page, live_server):
    api_response = page.request.get(f"{live_server}/api/history")
    assert api_response.status == 200
    jobs = api_response.json()
    assert isinstance(jobs, list)

    response = page.goto(f"{live_server}/ui-v2/history")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => !document.querySelector('#history-live-summary')?.textContent.includes('Loading')",
        timeout=5000,
    )
    assert page.locator("#history-live-summary").is_visible()
    assert page.locator("table tbody tr").count() == len(jobs)
    visible = page.locator("body").inner_text()
    assert "Page 1 of 3" not in visible
    assert "Total 42 records" not in visible
    for marker in (
        "staging-api.corp.net",
        "api.internal.corp",
        "ENG-2026-X892",
        "JOB-8841",
        "JOB-8840",
        "7f99b1",
        "CVE-2023-38606",
    ):
        assert marker not in visible, f"Sample history data must not be shown as live: {marker}"


def test_job_history_exports_live_records_as_json(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/history")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => !document.querySelector('#history-live-summary')?.textContent.includes('Loading')",
        timeout=5000,
    )
    with page.expect_download() as download:
        page.get_by_role("button", name="Export Ledger", exact=False).click()
    assert download.value.suggested_filename == "whaxon-job-history.json"


def test_dashboard_navigation_reaches_job_history(page, live_server):
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    link = page.locator('a[data-path="job-execution-history"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/history"
    history_response = page.request.get(f"{live_server}/ui-v2/history")
    assert history_response.status == 200



def test_history_search_and_tool_filter_operate_on_live_records(page, live_server):
    def history(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body='['
                 '{"id":"job-alpha","tool":"nmap","status":"finished","target":"192.0.2.10","exit_code":0,"duration_s":1.2},'
                 '{"id":"job-beta","tool":"nikto","status":"failed","target":"192.0.2.20","exit_code":2,"duration_s":2.4}'
                 ']',
        )

    page.route("**/api/history", history)
    page.goto(f"{live_server}/ui-v2/history")
    page.wait_for_function(
        "() => document.querySelector('#history-live-summary')?.textContent.includes('2 recorded jobs')",
        timeout=8000,
    )
    rows = page.locator("table tbody tr")
    assert rows.count() == 2
    tool_filter = page.locator("#history-tool-filter")
    assert [tool_filter.locator("option").nth(i).get_attribute("value") for i in range(tool_filter.locator("option").count())] == ["all", "nikto", "nmap"]

    page.locator("#history-search").fill("job-beta")
    assert rows.count() == 1
    assert "job-beta" in rows.first.inner_text()
    page.locator("#history-search").fill("")
    tool_filter.select_option("nmap")
    assert rows.count() == 1
    assert "job-alpha" in rows.first.inner_text()

    tool_filter.select_option("all")
    page.get_by_role("button", name="Failed (1)", exact=True).click()
    assert rows.count() == 1
    assert "job-beta" in rows.first.inner_text()


def test_history_disables_filters_that_need_unrecorded_metadata(page, live_server):
    page.goto(f"{live_server}/ui-v2/history")
    page.wait_for_function(
        "() => !document.querySelector('#history-live-summary')?.textContent.includes('Loading')",
        timeout=8000,
    )
    assert page.locator("#history-date-filter").is_disabled()
    assert "timestamps" in page.locator("#history-date-filter").get_attribute("title")
    assert page.locator("#history-runner-filter").is_disabled()
    assert "runner mode" in page.locator("#history-runner-filter").get_attribute("title")
    assert "Date filter unavailable" in page.locator("#history-date-filter").inner_text()
    assert "Runner mode unavailable" in page.locator("#history-runner-filter").inner_text()
