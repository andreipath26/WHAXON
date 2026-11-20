"""Browser tests for truthful PTaaS client portal actions."""
from __future__ import annotations


def test_ptaas_live_report_portal_and_navigation(page, live_server):
    page.goto(f"{live_server}/ui-v2/ptaas")
    page.wait_for_function(
        "() => document.querySelector('#ptaas-status')?.textContent.includes('recorded job(s)')"
        " || document.querySelector('#ptaas-status')?.textContent.includes('Report data could not be loaded')",
        timeout=8000,
    )
    assert page.locator("#ptaas-status").is_visible()
    assert page.locator("#whaxon-live-ptaas input[type=search]").is_visible()
    assert page.locator("#whaxon-live-ptaas button").filter(has_text="Refresh reports").is_enabled()

    page.locator("header button").filter(has_text="LOGS").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")

    page.goto(f"{live_server}/ui-v2/ptaas")
    page.locator("main button").filter(has_text="EXPAND SCOPE").click()
    page.wait_for_url("**/ui-v2/scope")
    assert page.url.endswith("/ui-v2/scope")

    page.goto(f"{live_server}/ui-v2/ptaas")
    page.locator("main button").filter(has_text="SCHEDULE RETEST").click()
    page.wait_for_url("**/ui-v2/retest")
    assert page.url.endswith("/ui-v2/retest")


def test_ptaas_halt_and_unwired_client_actions_are_safe(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.route(
        "**/api/history",
        lambda route: route.fulfill(status=200, content_type="application/json", body="[]"),
    )
    page.goto(f"{live_server}/ui-v2/ptaas")
    page.wait_for_function(
        "() => document.querySelector('#ptaas-status')?.textContent.includes('recorded job(s)')"
        " || document.querySelector('#ptaas-status')?.textContent.includes('Report data could not be loaded')",
        timeout=8000,
    )
    page.locator("header button").filter(has_text="HALT SCAN").click()
    page.wait_for_function(
        "() => document.querySelector('#ptaas-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )
    for button in page.locator("main button:visible").all():
        if button.evaluate("(el) => el.closest('#whaxon-live-ptaas') !== null"):
            continue
        if "EXPAND SCOPE" in button.inner_text() or "SCHEDULE RETEST" in button.inner_text():
            assert button.is_enabled()
        else:
            assert button.is_disabled(), f"Unsupported PTaaS action remains enabled: {button.inner_text()}"
    assert "not connected to live backend workflows" in page.locator("#whaxon-live-ptaas").inner_text()
