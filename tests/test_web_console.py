"""Console-error tour of the web UI.

Visits every page in the sidebar, waits for it to settle, and asserts that
no JavaScript errors reached the browser console. This is the single most
valuable test in the suite: it catches the class of bug that looks fine
from outside (page loads) but is broken inside (a fetch 500'd, a missing
element threw, a promise rejected silently).
"""
from __future__ import annotations

PAGES = [
    "scope",
    "target",
    "run",
    "findings",
    "report",
    "retest",
    "sessions",
    "graph",
    "monitoring",
    "audit",
    "catalog",
    "intel",
    "compliance",
    "settings",
]


def _attach_listeners(page):
    errors: list[str] = []
    page.on("console", lambda msg: errors.append(f"console.{msg.type}: {msg.text}") if msg.type == "error" else None)
    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on("response", lambda r: errors.append(f"HTTP {r.status}: {r.url}") if r.status >= 400 else None)
    return errors


def test_every_page_loads_without_console_errors(page, live_server):
    errors = _attach_listeners(page)
    page.goto(f"{live_server}/ui")
    page.wait_for_load_state("networkidle")

    visited = []
    for slug in PAGES:
        item = page.locator(f'.sb-item[data-page="{slug}"]')
        if item.count() == 0:
            continue
        item.click()
        page.wait_for_timeout(400)
        visited.append(slug)

    assert errors == [], "JavaScript errors found on: " + ", ".join(visited) + "\n" + "\n".join(errors)
    assert len(visited) >= 10, f"expected to visit most pages, only visited {visited}"


def test_initial_load_is_clean(page, live_server):
    errors = _attach_listeners(page)
    page.goto(f"{live_server}/ui")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)
    assert errors == [], "errors on initial load:\n" + "\n".join(errors)


def test_scope_page_is_clean(page, live_server):
    errors = _attach_listeners(page)
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="scope"]')
    page.wait_for_timeout(800)
    assert errors == [], "errors on scope page:\n" + "\n".join(errors)


def test_findings_page_is_clean(page, live_server):
    errors = _attach_listeners(page)
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="findings"]')
    page.wait_for_timeout(800)
    assert errors == [], "errors on findings page:\n" + "\n".join(errors)
