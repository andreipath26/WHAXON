"""Browser tests for live and stored Metasploit session workflows."""
from __future__ import annotations

import json


def test_sessions_render_live_and_stored_and_execute_explicit_command(page, live_server):
    page.route(
        "**/api/msf/sessions",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "live": {
                    "9": {
                        "target_host": "10.0.0.9",
                        "type": "meterpreter",
                        "info": "operator@lab-host",
                    }
                },
                "stored": [
                    {
                        "id": "4",
                        "target_host": "10.0.0.4",
                        "type": "shell",
                        "status": "closed",
                    }
                ],
                "live_count": 1,
            }),
        ),
    )
    page.route(
        "**/api/msf/sessions/9/exec",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "session_id": "9",
                "command": "id",
                "output": "uid=1000(operator) gid=1000(operator)",
            }),
        ),
    )
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="sessions"]')
    page.wait_for_function(
        "() => document.querySelectorAll('#sessions-tbody tr').length === 2"
    )

    rows = page.locator("#sessions-tbody tr")
    assert "10.0.0.9" in rows.nth(0).text_content()
    assert "live" in rows.nth(0).text_content()
    assert "10.0.0.4" in rows.nth(1).text_content()
    assert "closed" in rows.nth(1).text_content()
    assert rows.nth(0).get_by_role("button", name="Interact").count() == 1
    assert rows.nth(1).get_by_role("button", name="Interact").count() == 0

    rows.nth(0).get_by_role("button", name="Interact").click()
    page.fill(".session-console-form input", "id")
    with page.expect_response("**/api/msf/sessions/9/exec") as response:
        page.click(".session-console-form button[type=submit]")
    assert response.value.status == 200
    assert "uid=1000(operator)" in page.locator(".session-console-output").text_content()


def test_sessions_show_empty_state(page, live_server):
    page.route(
        "**/api/msf/sessions",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"live": {}, "stored": [], "live_count": 0}),
        ),
    )
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="sessions"]')
    page.wait_for_function(
        "() => document.querySelector('#sessions-tbody').textContent.includes('No live or stored sessions')"
    )
    assert "0 live" in page.locator("#sessions-summary").text_content()


def test_sessions_report_service_error(page, live_server):
    page.route(
        "**/api/msf/sessions",
        lambda route: route.fulfill(status=503, body="unavailable"),
    )
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="sessions"]')
    page.wait_for_function(
        "() => document.querySelector('#sessions-tbody').textContent.includes('Could not load sessions')"
    )
    assert "HTTP 503" in page.locator("#sessions-tbody").text_content()
