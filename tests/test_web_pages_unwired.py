"""Navigation smoke tests for the visible web pages.

These tests assert page activation only. Live-data and interaction behavior
belongs in the dedicated page tests; the legacy filename is retained to
avoid churn in downstream test references.
"""
from __future__ import annotations

import pytest

# Visible pages and the DOM id of each top-level section.
NAVIGABLE = [
    ("run", "page-run"),
    ("report", "page-report"),
    ("sessions", "page-sessions"),
    ("graph", "page-graph"),
    ("catalog", "page-catalog"),
]


@pytest.mark.parametrize("slug,section_id", NAVIGABLE)
def test_page_navigation_activates_section(page, live_server, slug, section_id):
    page.goto(f"{live_server}/ui")
    item = page.locator(f'.sb-item[data-page="{slug}"]')
    assert item.count() == 1, f"sidebar item for {slug} not found"
    item.click()
    page.wait_for_timeout(300)
    section = page.locator(f"#{section_id}")
    assert section.count() == 1, f"section #{section_id} not found"
    assert section.evaluate("el => el.classList.contains('active')"), f"{section_id} not active after click"


HIDDEN = ["audit", "intel", "compliance", "settings"]


@pytest.mark.parametrize("slug", HIDDEN)
def test_hidden_page_not_in_sidebar(page, live_server, slug):
    page.goto(f"{live_server}/ui")
    item = page.locator(f'.sb-item[data-page="{slug}"]')
    assert item.count() == 1, f"sidebar item for {slug} not in DOM"
    assert not item.is_visible(), f"sidebar item for {slug} is still visible"
