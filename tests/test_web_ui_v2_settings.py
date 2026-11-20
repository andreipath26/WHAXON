"""Browser coverage for the read-only settings/API explorer."""
from __future__ import annotations

from whaxon.core import Core
from whaxon.interfaces.web.server import (
    AsyncRunner,
    JobRegistry,
    _redact_sensitive_settings,
    create_app,
)


def test_settings_explorer_loads_and_redacts_settings(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/settings")
    assert response is not None and response.status == 200
    page.wait_for_function("() => !document.querySelector('#settings-status')?.textContent.includes('Loading settings')")
    assert page.locator("#whaxon-live-settings").is_visible()
    assert page.locator("#settings-json").is_visible()
    refresh = page.get_by_role("button", name="Refresh settings")
    assert refresh.is_visible()
    refresh.click()
    page.wait_for_function("() => !document.querySelector('#settings-status')?.textContent.includes('Loading settings')")
    assert page.locator("#settings-status").get_attribute("aria-live") == "polite"
    visible = page.locator("body").inner_text()
    assert "svc_whaxon_probe" not in visible


def test_dashboard_links_to_settings_explorer(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    link = page.locator('a[data-path="settings-and-api-explorer"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/settings"


def test_settings_redaction_recurses_through_nested_values():
    raw = {
        "api_key": "never-return-this",
        "service": {
            "client_secret": "also-private",
            "passphrase": "private-passphrase",
            "timeout_seconds": 10,
            "headers": [{"Authorization": "Bearer very-private", "Cookie": "session=private", "Accept": "application/json"}],
        },
        "items": [{"password": "hidden"}],
    }
    assert _redact_sensitive_settings(raw) == {
        "api_key": "[REDACTED]",
        "service": {
            "client_secret": "[REDACTED]",
            "passphrase": "[REDACTED]",
            "timeout_seconds": 10,
            "headers": [{"Authorization": "[REDACTED]", "Cookie": "[REDACTED]", "Accept": "application/json"}],
        },
        "items": [{"password": "[REDACTED]"}],
    }


def test_settings_api_redacts_values_for_get_and_post(tmp_path, monkeypatch):
    core = Core(data_dir=tmp_path)
    registry = JobRegistry(core)
    runner = AsyncRunner(core)
    raw = {
        "api_key": "do-not-disclose",
        "service": {"password": "also-private", "timeout_seconds": 10},
    }
    monkeypatch.setattr(core.settings, "get", lambda: raw)
    monkeypatch.setattr(core.settings, "save", lambda _data: raw)
    app = create_app(core, registry, runner)
    app.config["TESTING"] = True
    client = app.test_client()

    get_response = client.get("/api/settings")
    post_response = client.post("/api/settings", json={"service": {"timeout_seconds": 10}}, headers={"Origin": "http://localhost"})
    assert get_response.status_code == 200
    assert post_response.status_code == 200
    expected = {
        "api_key": "[REDACTED]",
        "service": {"password": "[REDACTED]", "timeout_seconds": 10},
    }
    assert get_response.get_json() == expected
    assert post_response.get_json() == expected

def test_settings_reference_controls_are_not_mistaken_for_live_writes(page, live_server):
    page.goto(f"{live_server}/ui-v2/settings")
    page.wait_for_function("() => document.querySelector('#settings-status') && !document.querySelector('#settings-status').textContent.includes('Loading settings')")
    # Static design-reference controls remain visible for layout continuity but cannot submit writes.
    assert page.locator("main input, main select, main textarea").count() > 0
    assert page.locator("main input:disabled, main select:disabled, main textarea:disabled").count() == page.locator("main input, main select, main textarea").count()
    assert page.locator("main button:disabled").count() > 0
    assert "configuration writes are not connected" in page.locator("main").inner_text()


def test_settings_header_logs_button_opens_the_run_workspace(page, live_server):
    page.goto(f"{live_server}/ui-v2/settings")
    page.get_by_role("button", name="LOGS").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")


def test_settings_header_halt_uses_active_workflow_apis(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.goto(f"{live_server}/ui-v2/settings")
    page.wait_for_function(
        "() => document.querySelector('#settings-status')?.textContent.includes('Settings loaded read-only')"
        " || document.querySelector('#settings-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    page.get_by_role("button", name="HALT SCAN").click()
    page.wait_for_function(
        "() => document.querySelector('#settings-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )


def test_settings_emergency_halt_includes_durable_v2_run_requests(page, live_server, workflow_halt_sources):
    calls = []
    workflow_halt_sources(active_requests=[{
        "id": "settings-v2-request", "plan_id": "settings-plan",
        "status": "uncertain", "submitted_at": 1,
    }])
    def cancel_run(route):
        calls.append(route.request.method)
        route.fulfill(
            status=200, content_type="application/json",
            body='{"cancellation_requested":true,"external_effects_stopped":false}',
        )
    page.route("**/api/v2/workflow-runs/settings-v2-request/cancel", cancel_run)
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{live_server}/ui-v2/settings")
    page.wait_for_function(
        "() => document.querySelector('#settings-status')?.textContent.includes('Settings loaded read-only')",
        timeout=8000,
    )
    page.get_by_role("button", name="HALT SCAN").click()
    page.wait_for_function(
        "() => document.querySelector('#settings-status')?.textContent.includes('0 of 0 legacy job(s) and 1 of 1 durable workflow run(s)')",
        timeout=8000,
    )
    assert "not confirmed stopped" in page.locator("#settings-status").inner_text()
    assert calls == ["POST"]


def test_settings_reference_controls_are_disabled_except_live_refresh(page, live_server):
    page.goto(f"{live_server}/ui-v2/settings")
    page.wait_for_function(
        "() => document.querySelector('#settings-status')?.textContent.includes('Settings loaded read-only')"
        " || document.querySelector('#settings-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    for button in page.locator("main button:visible").all():
        if button.get_attribute("id") != "settings-refresh":
            assert button.is_disabled(), f"Unwired settings control is enabled: {button.inner_text()}"


def test_settings_header_reflects_live_engagement_and_scope(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"engagement":"settings-scope-test","enabled":true,"in_scope":["192.0.2.50"],"out_of_scope":[],"notes":""}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/settings")
    page.wait_for_function(
        "() => document.querySelector('#settings-scope-status')?.textContent.includes('192.0.2.50')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "settings-scope-test" in header
    assert "Target: 192.0.2.50" in header
    assert "RULE CONFIGURED" in header
    assert "ENG-2026-X892" not in header


def test_settings_header_reports_scope_unavailable_truthfully(page, live_server):
    page.route("**/api/scope", lambda route: route.abort())
    page.goto(f"{live_server}/ui-v2/settings")
    page.wait_for_function(
        "() => document.querySelector('#settings-scope-status')?.textContent.includes('Scope status unavailable')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "Scope status unavailable" in header
    assert "ENG-2026-X892" not in header
