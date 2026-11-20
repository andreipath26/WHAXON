"""Browser coverage for the canonical live diagnostics page."""
from __future__ import annotations

import json


def test_diagnostics_page_uses_live_health_and_tool_apis(page, live_server):
    health = page.request.get(f"{live_server}/api/health")
    tools = page.request.get(f"{live_server}/api/tools")
    assert health.status in (200, 503)
    assert tools.status == 200
    assert isinstance(health.json(), dict)
    assert isinstance(tools.json(), list)

    response = page.goto(f"{live_server}/ui-v2/diagnostics")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => !document.querySelector('#diagnostics-status')?.textContent.includes('Loading current')",
        timeout=5000,
    )
    assert page.locator("#whaxon-live-diagnostics").is_visible()
    assert page.locator("#diagnostics-checks > div").count() >= 3
    assert page.locator("#diagnostics-refresh").is_visible()


def test_dashboard_links_to_live_diagnostics(page, live_server):
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    link = page.locator('a[data-path="system-diagnostics-and-health"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/diagnostics"

def test_diagnostics_page_does_not_report_simulated_checks_as_live(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/diagnostics")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('Live values loaded') "
        "|| document.querySelector('#diagnostics-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    visible = page.locator("body").inner_text()
    for marker in (
        "All Tests Passed",
        "ACK RECEIVED (0.9ms)",
        "PID 8891 killed",
        "out_of_scope_drops",
        "msf_version",
        "ALL SUBSYSTEMS HEALTHY",
        "whaxon_health_diagnostics_",
    ):
        assert marker not in visible, f"Simulated diagnostic output must not be shown: {marker}"
    assert page.locator("#whaxon-live-diagnostics").is_visible()

def test_diagnostics_layout_remains_available_and_mock_actions_are_disabled(page, live_server):
    page.goto(f"{live_server}/ui-v2/diagnostics")
    assert page.get_by_role("heading", name="System Diagnostics & Health Monitor").is_visible()
    assert page.locator("#diagnostics-refresh").is_visible()
    restart = page.get_by_role("button", name="Restart Engine Daemons")
    if restart.count():
        assert restart.is_disabled()


def test_diagnostics_reference_buttons_cannot_run_simulated_operations(page, live_server):
    page.goto(f"{live_server}/ui-v2/diagnostics")
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('Live values loaded') "
        "|| document.querySelector('#diagnostics-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    for label in (
        "Restart Engine Daemons",
        "Test MSF RPC Handshake",
        "Benchmark SQLite Write Speed",
        "Probe Ollama LLM Socket",
        "Check eBPF Filter Integrity",
    ):
        button = page.get_by_role("button", name=label)
        if button.count():
            assert button.is_disabled(), f"{label} must not run a simulated operation"
    assert page.locator("#btn-run-diag").is_enabled(), "Run Full Diagnostic must refresh live diagnostics"
    assert page.locator("#btn-export-json").is_enabled(), "Export Health Report must export live API data"
    for button in page.locator("main button:visible").all():
        label = button.inner_text().strip()
        if label == "Review fix":
            assert button.is_enabled(), "Review fix must open the guided remediation plan"
        elif button.get_attribute("id") in (
            "diagnostics-refresh", "btn-run-diag", "btn-export-json",
            "dep-check", "dep-verify", "dep-snapshot", "dep-history", "dep-plan-close",
            "dep-profile-plan",
        ):
            assert button.is_enabled()
        else:
            assert button.is_disabled(), f"Unwired diagnostic control is enabled: {label}"

    review = page.get_by_role("button", name="Review fix").first
    if review.count():
        review.click()
        page.wait_for_function(
            "() => document.querySelector('#dep-plan') && !document.querySelector('#dep-plan').hidden",
            timeout=5000,
        )

def test_diagnostics_terminal_log_button_navigates_to_run_workspace(page, live_server):
    page.goto(f"{live_server}/ui-v2/diagnostics")
    page.get_by_role("button", name="Terminal Log").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")


def test_diagnostics_emergency_halt_reports_when_no_jobs_are_active(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.goto(f"{live_server}/ui-v2/diagnostics")
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('Live values loaded')"
        " || document.querySelector('#diagnostics-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    page.get_by_role("button", name="Emergency Halt Scan").click()
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )

def test_diagnostics_header_uses_live_scope_and_navigation(page, live_server):
    page.goto(f"{live_server}/ui-v2/diagnostics")
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('Live values loaded')"
        " || document.querySelector('#diagnostics-status')?.textContent.includes('Diagnostics could not be loaded')",
        timeout=10000,
    )
    scope = page.evaluate("() => fetch('/api/scope').then(response => response.json())")
    targets = scope.get("in_scope") or []
    target = targets[0] if targets else "No target configured"
    header = page.locator("header").inner_text()
    assert target in header
    assert "SCOPE CONFIGURATION LOADED" in header or "SCOPE ENFORCEMENT DISABLED" in header

    page.locator("header button").filter(has_text="New").click()
    page.wait_for_url("**/ui-v2/scope")
    assert page.url.endswith("/ui-v2/scope")


def test_diagnostics_run_and_export_use_live_api_data(page, live_server):
    page.goto(f"{live_server}/ui-v2/diagnostics")
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('Live values loaded')"
        " || document.querySelector('#diagnostics-status')?.textContent.includes('Diagnostics could not be loaded')",
        timeout=10000,
    )
    run_button = page.locator("#btn-run-diag")
    assert run_button.is_enabled()
    run_button.click()
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('Live values loaded')"
        " || document.querySelector('#diagnostics-status')?.textContent.includes('Diagnostics could not be loaded')",
        timeout=10000,
    )

    assert page.locator("#btn-export-json").get_attribute("onclick") is None
    with page.expect_download() as download_info:
        page.locator("#btn-export-json").click()
    download = download_info.value
    assert download.suggested_filename == "whaxon-health-report.json"
    page.wait_for_function(
        "() => document.querySelector('#diagnostics-status')?.textContent.includes('Exported a JSON report')"
        " || document.querySelector('#diagnostics-status')?.textContent.includes('Health report export failed')",
        timeout=5000,
    )
    assert "reference/demo control" in page.locator("#btn-restart-daemons").get_attribute("title").lower()
    assert page.locator("#btn-restart-daemons").is_disabled()
    assert page.locator("#btn-run-diag").is_enabled()
    assert page.locator("#btn-export-json").is_enabled()



def test_dependency_readiness_panel_uses_live_backend_and_existing_diagnostics_shell(
    page, live_server
):
    response = page.goto(f"{live_server}/ui-v2/diagnostics")
    assert response is not None and response.status == 200
    panel = page.locator("#whaxon-dependency-readiness")
    assert panel.is_visible()
    assert page.get_by_role("heading", name="Dependency Readiness").is_visible()
    page.wait_for_function(
        "() => document.querySelector('#dep-status')?.textContent.includes('Environment report loaded')"
        " || document.querySelector('#dep-status')?.textContent.includes('Dependency check failed')",
        timeout=10000,
    )
    assert page.locator("#dep-summary > div").count() == 6
    assert page.locator("#dep-rows tr").count() > 0
    assert page.locator("#dep-check").is_enabled()
    assert page.locator("#dep-verify").is_enabled()
    assert page.locator("#dep-install").is_disabled()


def test_dependency_readiness_plan_requires_explicit_ui_approval(page, live_server):
    page.goto(f"{live_server}/ui-v2/diagnostics")
    page.wait_for_function(
        "() => document.querySelector('#dep-rows button') !== null",
        timeout=10000,
    )
    page.locator("#dep-rows button").first.click()
    page.wait_for_function(
        "() => !document.querySelector('#dep-plan').hidden"
        " && !document.querySelector('#dep-plan-description').textContent.includes('Preparing')",
        timeout=10000,
    )
    assert page.locator("#dep-plan-id").inner_text().startswith("PLAN ID:")
    assert page.locator("#dep-install").is_disabled()
    assert page.locator("#dep-approve-check").is_visible()
    assert page.locator("#dep-operation").is_hidden()



def test_first_run_profile_wizard_builds_read_only_capability_plan(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/diagnostics")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#dep-status')?.textContent.includes('Environment report loaded')",
        timeout=10000,
    )

    submitted = []
    page.route(
        "**/api/dependencies/plan",
        lambda route: (
            submitted.append(route.request.post_data_json),
            route.continue_(),
        )[1],
    )
    page.locator("#dep-profile").select_option("standard")
    page.locator("#dep-profile-plan").click()
    page.wait_for_function(
        "() => document.querySelector('#dep-profile-status')?.textContent.includes('Plan generated')",
        timeout=10000,
    )
    assert submitted
    assert "python" in submitted[0]["dependency_ids"]
    assert page.locator("#dep-profile-actions").inner_text()
    assert page.locator("#dep-profile-plan").is_enabled()

    page.locator("#dep-profile").select_option("custom")
    assert page.locator("#dep-custom-capabilities").is_visible()
    page.locator("#dep-custom-capabilities input[value='web']").check()
    page.locator("#dep-profile-plan").click()
    page.wait_for_function(
        "() => document.querySelector('#dep-profile-status')?.textContent.includes('Plan generated')",
        timeout=10000,
    )
    assert submitted[-1]["dependency_ids"]
    # Profile planning is read-only; the installer endpoint must never be called.
    assert page.locator("#dep-operation").is_hidden()



def test_profile_batch_install_requires_explicit_approval_and_tracks_operation(page, live_server):
    invalid = page.request.post(
        f"{live_server}/api/dependencies/install-batch",
        data={},
    )
    assert invalid.status == 400
    page.goto(f"{live_server}/ui-v2/diagnostics")
    page.wait_for_function(
        "() => document.querySelector('#dep-status')?.textContent.includes('Environment report loaded')",
        timeout=10000,
    )
    page.route(
        "**/api/dependencies/plan",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "plan_id": "plan-0123456789abcdef",
                "actions": [{
                    "dependency_id": route.request.post_data_json["dependency_ids"][0],
                    "options": [{
                        "title": "Install approved package",
                        "kind": "python-package",
                        "automated_execution_supported": True,
                    }],
                }],
            }),
        ),
    )
    page.locator("#dep-profile").select_option("standard")
    page.locator("#dep-profile-plan").click()
    page.wait_for_function(
        "() => document.querySelector('#dep-profile-status')?.textContent.includes('Plan generated')",
        timeout=10000,
    )
    assert page.locator("#dep-profile-approval").is_visible()
    assert page.locator("#dep-profile-install").is_disabled()
    page.locator("#dep-profile-approve-check").check()
    assert page.locator("#dep-profile-install").is_enabled()
    # Changing the profile invalidates the previously reviewed approval.
    page.locator("#dep-profile").select_option("custom")
    assert page.locator("#dep-profile-approval").is_hidden()
    assert page.locator("#dep-profile-install").is_disabled()
    page.locator("#dep-custom-capabilities input[value='web']").check()
    page.locator("#dep-profile-plan").click()
    page.wait_for_function(
        "() => document.querySelector('#dep-profile-status')?.textContent.includes('Plan generated')",
        timeout=10000,
    )
    assert page.locator("#dep-profile-approval").is_visible()
    assert page.locator("#dep-profile-install").is_disabled()
    submitted = []
    page.route(
        "**/api/dependencies/install-batch",
        lambda route: (
            submitted.append(route.request.post_data_json),
            route.fulfill(
                status=202,
                content_type="application/json",
                body=json.dumps({
                    "operation_id": "0123456789abcdef0123456789abcdef",
                    "status": "QUEUED",
                    "progress": 0,
                }),
            ),
        )[1],
    )
    page.route(
        "**/api/dependencies/install/0123456789abcdef0123456789abcdef",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "operation_id": "0123456789abcdef0123456789abcdef",
                "status": "VERIFIED",
                "progress": 100,
                "message": "Profile batch verified.",
                "result": {"status": "VERIFIED"},
            }),
        ),
    )
    page.locator("#dep-profile-approve-check").check()
    assert page.locator("#dep-profile-install").is_enabled()
    page.locator("#dep-profile-install").click()
    page.wait_for_function(
        "() => document.querySelector('#dep-operation-status')?.textContent.includes('VERIFIED')",
        timeout=10000,
    )
    assert len(submitted) == 1
    assert submitted[0]["approved_plan_id"].startswith("plan-")
    assert submitted[0]["dependency_ids"]
