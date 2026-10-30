"""Stub tests for pages that still render ui-v4 mockup content.

These do NOT assert on mockup data -- that would be testing lies. They
assert only that the page loads, the section is present, and clicking the
sidebar item activates it. When a page gets wired to real data, its test
graduates to a real behavioral test in its own file.
"""
from __future__ import annotations

import pytest

# Pages that currently render static mockup content, with the DOM id of
# their top-level section.
UNWIRED = [
    ("run", "page-run"),
    ("report", "page-report"),
    ("sessions", "page-sessions"),
    ("catalog", "page-catalog"),
]


@pytest.mark.parametrize("slug,section_id", UNWIRED)
def test_unwired_page_loads(page, live_server, slug, section_id):
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
