"""Approvals page behavior (§4.4).

The fixture seeds two isolated AI runs in the 'waiting' state. These tests assert
that the legacy page renders its own run, that the owner filter works, and that
answering removes that run without hiding other pending decisions.
"""
from __future__ import annotations


def _open_approvals(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="approvals"]')
    page.wait_for_function(
        "() => document.querySelectorAll('#approvals-list .card[data-run]').length > 0",
        timeout=5000,
    )


def test_approvals_page_renders_pending_run(page, live_server):
    _open_approvals(page, live_server)
    card = page.locator('#approvals-list .card[data-run="seed-ai-run"]')
    assert card.count() == 1
    assert "enumeration" in card.text_content()


def test_approvals_summary_reports_count(page, live_server):
    _open_approvals(page, live_server)
    pending = page.evaluate("() => fetch('/api/ai/pending').then(response => response.json())")
    count = len(pending)
    summary = page.locator("#approvals-summary").text_content()
    assert summary.startswith(str(count))


def test_approvals_badge_shows_count(page, live_server):
    _open_approvals(page, live_server)
    pending = page.evaluate("() => fetch('/api/ai/pending').then(response => response.json())")
    badge = page.locator("#approvals-badge")
    assert badge.text_content().strip() == str(len(pending))


def test_owner_filter_narrows_results(page, live_server):
    _open_approvals(page, live_server)
    # Filter to a non-matching owner: list should become empty.
    page.fill("#approvals-owner", "nobody")
    page.click("#approvals-refresh")
    page.wait_for_function(
        "() => document.querySelectorAll('#approvals-list .card[data-run]').length === 0",
        timeout=5000,
    )


def test_legacy_answer_is_blocked_and_keeps_run_visible(page, live_server):
    _open_approvals(page, live_server)
    card = page.locator('#approvals-list .card[data-run="seed-ai-run"]')
    card.locator('[data-answer-input]').fill("y")
    card.locator('[data-answer-btn]').click()
    notice = card.locator('[role="status"]')
    notice.wait_for(timeout=5000)
    assert "Legacy AI execution is disabled" in notice.text_content()
    assert card.is_visible()
    assert card.locator('[data-answer-btn]').is_disabled()

