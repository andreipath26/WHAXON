"""Browser coverage for the live adapter manager."""
from __future__ import annotations

import re


def test_adapter_manager_uses_live_tool_catalog(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/adapters")
    assert response is not None and response.status == 200
    page.wait_for_function("() => !document.querySelector('#adapter-status')?.textContent.includes('Loading live')")
    assert page.locator("#whaxon-live-adapters").is_visible()
    assert page.locator("#adapter-filter").is_visible()
    refresh = page.get_by_role("button", name="Refresh catalog")
    assert refresh.is_visible()
    refresh.click()
    page.wait_for_function("() => !document.querySelector('#adapter-status')?.textContent.includes('Loading live')")
    assert page.locator("#adapter-status").get_attribute("aria-live") == "polite"


def test_adapter_reference_controls_are_disabled_in_initial_markup(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/adapters")
    assert response is not None and response.status == 200
    html = response.text()
    for control_id in (
        "btn-sync", "btn-reload", "btn-register", "adapter-search",
        "status-select", "close-drawer", "add-flag-input", "btn-mock-test",
        "btn-resign", "btn-save-conf",
    ):
        match = re.search(
            rf"<(?:button|input|select|textarea)\b[^>]*\bid=\"{re.escape(control_id)}\"[^>]*>",
            html,
        )
        assert match is not None, f"Missing adapter reference control {control_id}"
        assert re.search(r"\sdisabled(?:\s|=|>)", match.group(0)), (
            f"Adapter reference control {control_id} is enabled in server HTML"
        )
        assert 'aria-disabled="true"' in match.group(0)
    assert "Mock execution successful" not in html
    assert "Signature re-computed and signed" not in html
    assert "Configuration saved to /etc/whaxon/adapters.d" not in html


def test_dashboard_links_to_adapter_manager(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    link = page.locator('a[data-path="adapter-and-plugin-manager"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/adapters"

def test_adapter_reference_actions_are_not_misrepresented_as_live(page, live_server):
    page.goto(f"{live_server}/ui-v2/adapters")
    mock_execution = page.locator("button").filter(has_text="Test Adapter Execution with Mock Output")
    if mock_execution.count():
        assert mock_execution.is_disabled()
    resign = page.locator("button").filter(has_text="Re-sign Manifest")
    if resign.count():
        assert resign.is_disabled()

def test_adapter_header_uses_live_scope_and_global_navigation(page, live_server):
    page.goto(f"{live_server}/ui-v2/adapters")
    page.wait_for_function(
        "() => document.querySelector('#adapter-status')?.textContent.includes('catalog tools')"
        " || document.querySelector('#adapter-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    page.wait_for_function(
        "() => !document.querySelector('header')?.innerText.includes('api.internal.corp')",
        timeout=8000,
    )
    scope = page.evaluate("() => fetch('/api/scope').then(response => response.json())")
    target = scope["in_scope"][0] if scope.get("in_scope") else "No target configured"
    header = page.locator("header").inner_text()
    assert target in header
    assert "SCOPE CONFIGURATION LOADED" in header or "SCOPE ENFORCEMENT DISABLED" in header

    page.locator("header button").filter(has_text="New").click()
    page.wait_for_url("**/ui-v2/scope")
    assert page.url.endswith("/ui-v2/scope")

    page.goto(f"{live_server}/ui-v2/adapters")
    page.locator("header button").filter(has_text="Terminal Log").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")


def test_adapter_halt_uses_active_workflow_apis_and_static_mutations_are_disabled(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.route(
        "**/api/history",
        lambda route: route.fulfill(status=200, content_type="application/json", body="[]"),
    )
    page.goto(f"{live_server}/ui-v2/adapters")
    page.wait_for_function(
        "() => document.querySelector('#adapter-status')?.textContent.includes('catalog tools')"
        " || document.querySelector('#adapter-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    page.locator("header button").filter(has_text="Emergency Halt Scan").click()
    page.wait_for_function(
        "() => document.querySelector('#adapter-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )
    for control_id in ("btn-sync", "btn-reload", "btn-register", "btn-mock-test", "btn-resign", "btn-save-conf"):
        assert page.locator(f"#{control_id}").is_disabled(), f"Disconnected adapter control remains enabled: {control_id}"
    configure_controls = page.locator(".select-adapter-btn")
    assert configure_controls.count() == 8
    assert configure_controls.evaluate_all(
        "nodes => nodes.every(node => node.disabled && node.getAttribute('aria-disabled') === 'true')"
    ), "Disconnected adapter configuration controls must stay disabled"
    assert page.locator("#adapter-refresh").is_enabled()
    assert page.locator("#adapter-filter").is_enabled()
    assert "read-only visual references" in page.locator("#whaxon-live-adapters").inner_text()



def test_adapter_catalog_filter_refresh_and_truthful_reference_status(page, live_server):
    calls = {"count": 0}

    def tools(route):
        calls["count"] += 1
        route.fulfill(
            status=200,
            content_type="application/json",
            body='[{"id":"nmap","name":"Nmap","category":"recon","transport":"cli",'
                 '"adapter_available":true,"binary_available":true},'
                 '{"id":"nikto","name":"Nikto","category":"vuln","transport":"cli",'
                 '"adapter_available":false,"binary_available":false}]',
        )

    page.route("**/api/tools", tools)
    page.goto(f"{live_server}/ui-v2/adapters")
    page.wait_for_function(
        "() => document.querySelector('#adapter-status')?.textContent.includes('2 of 2 catalog tools')",
        timeout=8000,
    )
    assert page.locator("#adapter-list article").count() == 2
    page.get_by_label("Filter tools").fill("nmap")
    assert page.locator("#adapter-list article:visible").count() == 1
    assert "Nmap" in page.locator("#adapter-list article:visible").inner_text()
    assert "Nikto" not in page.locator("#adapter-list article:visible").inner_text()
    page.get_by_label("Filter tools").fill("")

    with page.expect_response("**/api/tools"):
        page.get_by_role("button", name="Refresh catalog").click()
    page.wait_for_function(
        "() => document.querySelector('#adapter-status')?.textContent.includes('2 of 2 catalog tools')",
        timeout=8000,
    )
    assert calls["count"] >= 2

    visible = page.locator("body").inner_text()
    assert "100%" not in visible
    assert "SEC-RUNNER-V3.4 [KERNEL-ISOLATION: ACTIVE]" not in visible
    assert "HASH DETERMINISTIC CHECK: PASSED" not in visible
    assert "STRICT BOUNDARY ENFORCED" not in page.locator("header").inner_text()
    assert "read-only visual reference" in page.locator("#whaxon-live-adapters").inner_text().lower()


def test_adapter_catalog_failure_is_truthful_and_recoverable(page, live_server):
    calls = {"count": 0}

    def unavailable(route):
        calls["count"] += 1
        route.fulfill(status=503, content_type="application/json", body='{"error":"catalog offline"}')

    page.route("**/api/tools", unavailable)
    page.goto(f"{live_server}/ui-v2/adapters")
    page.wait_for_function(
        "() => document.querySelector('#adapter-status')?.textContent.includes('HTTP 503')",
        timeout=8000,
    )
    assert page.locator("#adapter-list article").count() == 0
    refresh = page.get_by_role("button", name="Refresh catalog")
    assert refresh.is_enabled()
    with page.expect_response("**/api/tools"):
        refresh.click()
    page.wait_for_function(
        "() => document.querySelector('#adapter-status')?.textContent.includes('HTTP 503')",
        timeout=8000,
    )
    assert calls["count"] >= 2
    assert refresh.is_enabled()
