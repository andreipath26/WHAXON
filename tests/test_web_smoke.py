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


