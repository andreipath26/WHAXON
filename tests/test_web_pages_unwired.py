"""Regression checks for UI sections intentionally hidden until wired."""
from __future__ import annotations

import pytest

HIDDEN = ["audit", "intel", "compliance", "settings"]


@pytest.mark.parametrize("slug", HIDDEN)
def test_unimplemented_page_is_not_exposed_in_sidebar(page, live_server, slug):
    page.goto(f"{live_server}/ui")
    item = page.locator(f'.sb-item[data-page="{slug}"]')
    assert item.count() == 1, f"sidebar item for {slug} not in DOM"
    assert not item.is_visible(), f"unimplemented page {slug} is still visible"
