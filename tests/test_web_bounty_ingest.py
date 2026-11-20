"""Web API tests for safe bounty program import."""
from __future__ import annotations

_PROGRAM_TEXT = """Public programs
Example Program
Last update on 2026-10-29
https://app.example.org
Web application
High
Do not use automated scanners.
No vulnerability disclosure is allowed.
"""


def test_pasted_program_import_returns_reviewable_draft(page, live_server):
    response = page.request.post(
        f"{live_server}/api/bounty/import",
        data={"text": _PROGRAM_TEXT},
    )
    assert response.status == 200
    result = response.json()
    assert result["status"] == "draft_requires_review"
    assert result["policy_draft"]["program_url"] == ""
    assert result["policy_draft"]["scope"]["in_scope"]
    assert result["source"]["content_sha256"]
    assert result["evidence"]
    assert result["policy_draft"]["tools"]["allowlist"] == []
    ai = result["policy_draft"]["ai_policy"]
    assert ai["mode"] == "bounded_autonomous_after_approval"
    assert ai["require_human_confirm"] is False
    assert ai["allow_live_requests"] is False
    assert result["policy_draft"]["ai_policy"]["execution_enabled"] is False
    assert result["policy_draft"]["ai_policy"]["activation"] == "disabled_until_program_approval"
    assert result["policy_draft"]["hunting_requirements"]["disclosure_allowed"] is False
    assert result["review"]["scope.out_of_scope"] == "manual_review_required_not_extracted"
    assert any("not proof of authorization" in warning for warning in result["warnings"])


def test_program_import_rejects_unsafe_url_without_fetching(page, live_server):
    response = page.request.post(
        f"{live_server}/api/bounty/import",
        data={"url": "http://127.0.0.1/programs/attack"},
    )
    assert response.status == 400
    assert "HTTPS" in response.json()["error"]


def test_program_import_requires_exactly_one_source(page, live_server):
    response = page.request.post(
        f"{live_server}/api/bounty/import",
        data={"url": "https://yeswehack.com/programs/example", "text": _PROGRAM_TEXT},
    )
    assert response.status == 400
    assert "either url or text" in response.json()["error"]

def test_bug_bounty_page_can_import_and_review_pasted_program(page, live_server):
    page.goto(f"{live_server}/ui-v2/bug-bounty")
    page.wait_for_selector("#bounty-import-url", timeout=5000)
    page.locator("#bounty-import-text").fill(_PROGRAM_TEXT)
    page.locator("#bounty-import-submit").click()
    page.wait_for_function(
        "() => document.querySelector('#bounty-import-status')?.textContent.includes('NOT saved')",
        timeout=5000,
    )
    result = page.locator("#bounty-import-result").inner_text()
    assert "Example Program" in result
    assert "Extracted scope" in result
    assert "Source evidence" in result
    assert "NOT saved" in page.locator("#bounty-import-status").inner_text()
