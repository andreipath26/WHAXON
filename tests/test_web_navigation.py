"""Cross-cutting navigation and keyboard tests."""
from __future__ import annotations

import pytest

ALL_PAGES = [
    ("scope", "page-scope"),
    ("run", "page-run"),
    ("findings", "page-findings"),
    ("report", "page-report"),
    ("retest", "page-retest"),
    ("sessions", "page-sessions"),
    ("graph", "page-graph"),
    ("monitoring", "page-monitoring"),
    ("audit", "page-audit"),
    ("catalog", "page-catalog"),
    ("intel", "page-intel"),
    ("compliance", "page-compliance"),
    ("settings", "page-settings"),
]


@pytest.mark.parametrize("slug,section_id", ALL_PAGES)
def test_sidebar_activates_correct_section(page, live_server, slug, section_id):
    page.goto(f"{live_server}/ui")
    page.click(f'.sb-item[data-page="{slug}"]')
    page.wait_for_timeout(200)
    assert page.locator(f"#{section_id}").evaluate("el => el.classList.contains('active')")
    # All other pages are inactive
    active_count = page.locator("section.page.active").count()
    assert active_count == 1, f"expected exactly 1 active page, got {active_count}"


def test_breadcrumb_updates_on_navigation(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="scope"]')
    page.wait_for_timeout(200)
    assert page.locator("#crumb-here").text_content().strip().lower() == "scope"
    page.click('.sb-item[data-page="catalog"]')
    page.wait_for_timeout(200)
    assert page.locator("#crumb-here").text_content().strip().lower() == "catalog"


def test_ctrl_k_opens_command_palette(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("Control+k")
    page.wait_for_timeout(200)
    assert page.locator("#palette").evaluate("el => el.classList.contains('open')")


def test_escape_closes_palette(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("Control+k")
    page.wait_for_timeout(200)
    page.keyboard.press("Escape")
    page.wait_for_timeout(200)
    assert not page.locator("#palette").evaluate("el => el.classList.contains('open')")


def test_question_mark_opens_shortcut_legend(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("?")
    page.wait_for_timeout(200)
    assert page.locator("#kbd-legend").evaluate("el => el.classList.contains('open')")


def test_sidebar_collapse_toggle(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click("#collapse-btn")
    page.wait_for_timeout(200)
    assert page.locator("#app").evaluate("el => el.classList.contains('collapsed')")
    page.click("#collapse-btn")
    page.wait_for_timeout(200)
    assert not page.locator("#app").evaluate("el => el.classList.contains('collapsed')")
