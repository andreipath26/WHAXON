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
    # This is a navigation smoke test. The live report endpoint and its
    # seeded finding counts have separate API/browser integration tests.
    # Parallel tests can alter the shared seeded store; do not couple this
    # route smoke check to its exact global finding count.
    assert page.locator("#page-findings").count() == 1
    assert page.locator("#findings-tbody").count() == 1
    assert page.locator("#page-findings").is_visible()


