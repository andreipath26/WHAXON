"""Browser tests for truthful Bug Bounty page behavior."""
from __future__ import annotations


def test_bug_bounty_workspace_uses_recorded_jobs_and_real_navigation(page, live_server):
    page.goto(f"{live_server}/ui-v2/bug-bounty")
    page.wait_for_function(
        "() => document.querySelector('#bounty-status')?.textContent.includes('report job(s)')"
        " || document.querySelector('#bounty-status')?.textContent.includes('Live data unavailable')",
        timeout=8000,
    )
    assert page.locator("#bounty-workspace-search").is_visible()
    assert page.locator("#bounty-workspace-refresh").is_enabled()
    assert "Browser automation is not connected" in page.locator("#bounty-status").inner_text()

    page.locator("header button").filter(has_text="LOGS").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")


def test_bug_bounty_halt_uses_active_workflow_apis_and_disables_simulations(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.route(
        "**/api/history",
        lambda route: route.fulfill(status=200, content_type="application/json", body="[]"),
    )
    page.goto(f"{live_server}/ui-v2/bug-bounty")
    page.wait_for_function(
        "() => document.querySelector('#bounty-status')?.textContent.includes('report job(s)')"
        " || document.querySelector('#bounty-status')?.textContent.includes('Live data unavailable')",
        timeout=8000,
    )
    page.locator("header button").filter(has_text="HALT SCAN").click()
    page.wait_for_function(
        "() => document.querySelector('#bounty-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )
    for button in page.locator("main button:visible").all():
        if button.evaluate("(el) => el.closest('#whaxon-live-bug-bounty') !== null"):
            continue
        assert button.is_disabled(), f"Disconnected browser action remains enabled: {button.inner_text()}"
    visible = page.locator("main").inner_text()
    assert "24 Ev/s" not in visible
    assert "CDP SENSORS ACTIVE" not in visible
    assert "COMMITTED_SETTLED" not in visible
    assert "not connected" in page.locator("#whaxon-live-bug-bounty").inner_text().lower()
