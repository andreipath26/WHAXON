"""Scope page behavior tests.

The fixture starts with a fresh data dir, so the server generates its
default scope: engagement 'default', 7 in-scope rules, no exclusions.
These tests assert the page renders that data and that the check panel
works for both in-scope and out-of-scope targets.
"""
from __future__ import annotations


def _open_scope(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="scope"]')
    page.wait_for_selector("#scope-rules .kv", timeout=5000)


def test_engagement_name_renders(page, live_server):
    _open_scope(page, live_server)
    text = page.locator("#scope-rules").text_content()
    assert "default" in text


def test_badge_shows_rule_count(page, live_server):
    _open_scope(page, live_server)
    assert page.locator("#scope-count").text_content().strip() == "7"


def test_rules_list_renders(page, live_server):
    _open_scope(page, live_server)
    rules = page.locator("#scope-rules .kv")
    # 1 engagement row + 7 in-scope rules
    assert rules.count() == 8


def test_rule_classification(page, live_server):
    _open_scope(page, live_server)
    text = page.locator("#scope-rules").text_content()
    assert "Network" in text       # CIDR rules
    assert "Address" in text       # ::1


def test_check_in_scope_target_green(page, live_server):
    _open_scope(page, live_server)
    page.fill("#scope-check-input", "127.0.0.1")
    page.click("#scope-check-btn")
    page.wait_for_selector("#scope-check-result div", timeout=3000)
    result = page.locator("#scope-check-result").text_content()
    assert "127.0.0.1" in result
    assert "\u2713" in result  # the checkmark
    # Green background
    style = page.locator("#scope-check-result div").get_attribute("style")
    assert "low-dim" in style or "low" in style


def test_check_out_of_scope_target_red(page, live_server):
    _open_scope(page, live_server)
    page.fill("#scope-check-input", "google.com")
    page.click("#scope-check-btn")
    page.wait_for_selector("#scope-check-result div", timeout=3000)
    result = page.locator("#scope-check-result").text_content()
    assert "google.com" in result
    assert "\u2717" in result  # the cross
    style = page.locator("#scope-check-result div").get_attribute("style")
    assert "critical" in style


def test_check_empty_input_shows_warning(page, live_server):
    _open_scope(page, live_server)
    page.fill("#scope-check-input", "")
    page.click("#scope-check-btn")
    page.wait_for_selector("#scope-check-result div", timeout=3000)
    result = page.locator("#scope-check-result").text_content()
    assert "Enter a target" in result


def test_check_enter_key_works(page, live_server):
    _open_scope(page, live_server)
    page.fill("#scope-check-input", "127.0.0.1")
    page.press("#scope-check-input", "Enter")
    page.wait_for_selector("#scope-check-result div", timeout=3000)
    result = page.locator("#scope-check-result").text_content()
    assert "127.0.0.1" in result
