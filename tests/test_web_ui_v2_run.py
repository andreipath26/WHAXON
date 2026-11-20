"""Browser coverage for the canonical Run & Orchestration page (UI v2)."""
from __future__ import annotations

import json
import re


def _stub_v2_plan_authoring(page, *, in_scope=True):
    calls = {"scope": [], "missions": [], "plans": [], "runs": []}
    missions = []
    saved = {}

    def scope(route):
        calls["scope"].append(route.request.method)
        route.fulfill(
            status=200, content_type="application/json",
            body='{"allowed":' + ("true" if in_scope else "false") + '}',
        )

    def capabilities(route):
        route.fulfill(status=200, content_type="application/json", body=(
            '[{"capability_id":"network.services.discover","provider_id":"test.nmap",'
            '"provider_version":"1","impact":"moderate","timeout_s":60,'
            '"permissions":[],"input_schema":{"type":"object","properties":{},'
            '"required":[],"additionalProperties":false}}]'
        ))

    def providers(route):
        route.fulfill(status=200, content_type="application/json", body=(
            '[{"capability_id":"network.services.discover","provider_id":"test.nmap",'
            '"provider_version":"1","manifest_fingerprint":"test-fingerprint",'
            '"installed":true,"selected_for_execution":true}]'
        ))

    def missions_api(route):
        path = route.request.url.split("?", 1)[0]
        if path.endswith("/plans"):
            route.fulfill(status=200, content_type="application/json", body=json.dumps([
                {"id": plan_id, "digest": "test-digest", "status": "proposed"}
                for plan_id in saved
            ]))
        elif route.request.method == "GET":
            route.fulfill(status=200, content_type="application/json", body=json.dumps(missions))
        else:
            payload = route.request.post_data_json
            calls["missions"].append(payload)
            missions.append({"id": payload["id"], "objective": payload["objective"], "status": "active"})
            route.fulfill(status=201, content_type="application/json", body='{"created":true}')

    def workflows_api(route):
        url = route.request.url.rstrip("/")
        if route.request.method == "POST":
            payload = route.request.post_data_json
            calls["plans"].append(payload)
            saved[payload["id"]] = payload["plan"]
            route.fulfill(status=201, content_type="application/json", body='{"created":true}')
        elif url.endswith("/approvals"):
            route.fulfill(status=200, content_type="application/json", body="[]")
        elif url.endswith("/run"):
            calls["runs"].append(url)
            route.fulfill(status=202, content_type="application/json", body='{"run_request_id":"unexpected"}')
        else:
            plan_id = url.rsplit("/", 1)[-1]
            plan = saved[plan_id]
            tasks = [dict(task, task_key=task["id"], status="proposed") for task in plan["tasks"]]
            route.fulfill(status=200, content_type="application/json", body=json.dumps({"plan": plan, "tasks": tasks}))

    page.route("**/api/v2/scope/check", scope)
    page.route("**/api/v2/capabilities", capabilities)
    page.route("**/api/v2/providers", providers)
    page.route("**/api/v2/missions**", missions_api)
    page.route("**/api/v2/workflows**", workflows_api)
    return calls


def test_run_page_loads_live_tool_catalog(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/run")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => [...document.querySelector('#run-tool-select').options].some(o => o.value === 'echo')",
        timeout=8000,
    )
    assert page.locator("#run-target-input").count() == 1
    assert page.locator("#run-target-input").is_visible()
    assert page.locator("#run-active-btn").is_visible()
    assert page.get_by_role("button", name="Spawn Sub-tool").is_hidden()
    assert page.get_by_role("button", name="Inject Payload").is_hidden()
    assert page.get_by_role("button", name="Emergency Abort").is_hidden()
    assert page.get_by_role("button", name="Execute").is_hidden()
    visible_text = page.locator("main").inner_text()
    assert "CVE-2023-38606" not in visible_text
    assert "184,209" not in visible_text
    assert "Recon: 100%" not in visible_text
    assert page.locator("#run-job-id").text_content() == "No V2 request submitted"
    assert page.locator("#btn-pause").is_hidden()
    assert "staging-api.corp.net" not in response.text()
    assert "api.internal.corp" not in response.text()
    assert page.locator('a[data-path="run-and-orchestration"]').is_visible()
    assert page.locator('a[data-path="scope-and-targets"]').is_visible()
    assert page.locator('a[data-path="scope-and-targets"]').get_attribute("href") == "/ui-v2/scope"
    assert page.locator('a[data-path="trust-layer-and-findings"]').is_visible()
    assert page.locator('a[data-path="trust-layer-and-findings"]').get_attribute("href") == "/ui-v2/findings"


def test_run_page_serves_assets_without_external_requests(page, live_server):
    external_requests = []
    page.on(
        "request",
        lambda request: external_requests.append(request.url)
        if request.url.startswith("https://")
        else None,
    )
    page.route("https://**/*", lambda route: route.abort())
    response = page.goto(f"{live_server}/ui-v2/run")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => [...document.querySelector('#run-tool-select').options].some(o => o.value === 'echo')",
        timeout=8000,
    )
    assert page.title() == "WHAXON — Run & Orchestration"
    assert external_requests == []
    for path in (
        "run-v2.css",
        "dashboard-fonts.css",
        "dashboard-logo.jpg",
        "dashboard-profile.jpg",
    ):
        asset = page.request.get(f"{live_server}/static/{path}")
        assert asset.ok, (path, asset.status)
        assert asset.body(), path


def test_run_page_primary_action_saves_reviewable_v2_plan_only(page, live_server):
    calls = _stub_v2_plan_authoring(page)
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => [...document.querySelector('#v2-capability-select').options].some(o => o.value === 'network.services.discover')",
        timeout=8000,
    )
    page.locator("#run-target-input").fill("127.0.0.1")
    page.locator("#v2-mission-objective").fill("Review an authorized local service scan")
    page.locator("#v2-capability-select").select_option("network.services.discover")
    page.locator("#run-active-btn").click()
    page.wait_for_function(
        "() => document.querySelector('#v2-run-message')?.textContent.includes('reviewed')",
        timeout=8000,
    )
    assert len(calls["scope"]) == len(calls["missions"]) == len(calls["plans"]) == 1
    assert calls["runs"] == []
    assert page.get_by_role("button", name="Grant 1-hour approval").count() == 1
    assert "separate exact-plan approval" in page.locator("#v2-run-message").inner_text()
    assert page.locator("#v2-submit-run").is_disabled() is False


def test_run_page_blocks_plan_creation_for_out_of_scope_target(page, live_server):
    calls = _stub_v2_plan_authoring(page, in_scope=False)
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => [...document.querySelector('#v2-capability-select').options].some(o => o.value === 'network.services.discover')",
        timeout=8000,
    )
    page.locator("#run-target-input").fill("https://example.com")
    page.locator("#v2-mission-objective").fill("Review an authorized target")
    page.locator("#v2-capability-select").select_option("network.services.discover")
    page.locator("#run-active-btn").click()
    page.wait_for_function(
        "() => document.querySelector('#v2-authoring-message')?.textContent.includes('outside the configured scope')",
        timeout=8000,
    )
    assert calls["scope"] == ["POST"]
    assert calls["missions"] == []
    assert calls["plans"] == []
    assert page.locator("#run-job-id").text_content() == "No V2 request submitted"


def test_arbitrary_shell_input_is_disabled_and_execute_is_hidden(page, live_server):
    page.goto(f"{live_server}/ui-v2/run")
    command_input = page.locator("#cli-input")
    assert command_input.is_disabled()
    assert "Engine V2 workflow controls" in command_input.get_attribute("placeholder")
    assert page.get_by_role("button", name="Execute").is_hidden()


def test_run_page_reference_controls_are_inert_in_server_rendered_html(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/run")
    assert response is not None and response.status == 200
    html = response.text()

    checkboxes = re.findall(r"<input\b(?=[^>]*type=\"checkbox\")[^>]*>", html)
    assert checkboxes
    assert all(re.search(r"\sdisabled(?:\s|>)", tag) for tag in checkboxes)
    assert re.search(r'<input\b(?=[^>]*id="cli-input")(?=[^>]*\sdisabled)[^>]*>', html)

    for label in ("View stdout", "Re-run", "Engage Replay", "WhatWeb", "Gobuster",
                  "WPScan", "Execute", "Inject Payload", "Spawn Sub-tool", "Emergency Abort"):
        button = re.search(
            rf"(<button\b[^>]*>)(?:(?!</button>)[\s\S])*?{re.escape(label)}(?:(?!</button>)[\s\S])*?</button>",
            html,
        )
        assert button is not None and re.search(r"\sdisabled(?:\s|>)", button.group(1)), label

    assert 'onclick="clearLog()"' in html
    clear_button = re.search(r'<button\b(?=[^>]*onclick="clearLog\(\)")[^>]*>', html)
    assert clear_button is not None and not re.search(r"\sdisabled(?:\s|>)", clear_button.group(0))
    for handler in ("showNmapStdout", "sendManualCommand", "togglePipelinePause",
                    "injectPayloadPrompt", "spawnSubtoolModal", "emergencyAbort"):
        assert f"onclick=\"{handler}()\"" not in html


def test_run_page_start_is_single_flight(page, live_server):
    calls = _stub_v2_plan_authoring(page)
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => [...document.querySelector('#v2-capability-select').options].some(o => o.value === 'network.services.discover')",
        timeout=8000,
    )
    page.locator("#run-target-input").fill("127.0.0.1")
    page.locator("#v2-mission-objective").fill("Review an authorized local scan")
    page.locator("#v2-capability-select").select_option("network.services.discover")
    page.evaluate(
        """() => {
          const button = document.querySelector('#run-active-btn');
          button.click();
          button.click();
        }"""
    )
    page.wait_for_function(
        "() => document.querySelector('#v2-authoring-message')?.textContent.includes('Created mission')",
        timeout=8000,
    )
    assert calls["scope"] == ["POST"]
    assert len(calls["missions"]) == 1
    assert len(calls["plans"]) == 1
    assert calls["runs"] == []


def test_run_page_hides_legacy_cancel_control(page, live_server):
    page.goto(f"{live_server}/ui-v2/run")
    assert page.locator("#btn-pause").is_hidden()
    assert page.locator("#v2-cancel-run").is_disabled()


def test_run_page_clear_buffer_clears_terminal_output(page, live_server):
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => document.querySelector('#terminal-stdout')?.textContent.includes('No run request has been submitted')",
        timeout=8000,
    )
    page.locator("button[title='Clear buffer']").click()
    assert page.locator("#terminal-stdout").inner_text().strip() == ""



def test_run_page_disables_ai_planner_toggle_without_scope_enforcement(page, live_server):
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => [...document.querySelector('#run-tool-select').options].some(o => o.value === 'echo')",
        timeout=8000,
    )
    toggle = page.locator("#ai-planner-toggle")
    assert toggle.is_disabled()
    assert not toggle.is_checked()
    assert "approved engine v2 workflow plans" in toggle.get_attribute("title").lower()
    planner_card = toggle.locator("xpath=ancestor::div[contains(@class, 'bg-surface-container-low')][1]")
    assert "AI planner execution is disabled" in planner_card.inner_text()
    assert "GATE: NOT VERIFIED" in planner_card.inner_text()
    assert "GATE: ENFORCED" not in planner_card.inner_text()
    assert page.locator("#toggle-planner-gate").is_hidden()

def test_run_page_header_reflects_live_scope_without_claiming_strict_boundary(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"engagement":"run-scope-test","enabled":true,"in_scope":["192.0.2.44"],"out_of_scope":[],"notes":""}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('192.0.2.44')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "target: 192.0.2.44" in header.lower()
    assert "(rule configured)" in header.lower()
    assert "scope configuration loaded" in header.lower()
    assert "strict boundary enforced" not in header.lower()



def test_run_page_never_presents_reference_sample_telemetry_as_live_state(page, live_server):
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => [...document.querySelector('#run-tool-select').options].some(o => o.value === 'echo')",
        timeout=8000,
    )
    main = page.locator("main").inner_text()
    for sample in (
        "#WX-8492", "04 Active Replayers", "Nmap 7.94", "Nuclei v3.2.0",
        "Nikto 2.5.0", "sqlmap 1.8.3", "14 Candidates", "1,489 / 2,050",
        "142 req/s", "10/10 Enabled", "12 services found", "PID: 28491",
        "Awaiting Nuclei completion boundary", "whaxon://cli-pipeline",
        "VULN_CANDIDATE", "184,209", "31 Validated", "Recon: 100% | Enum: 72%",
        "CVE-2023-38606", "production endpoint candidate",
    ):
        assert sample not in main
    for name in ("View stdout", "Re-run", "Pause", "Abort"):
        assert page.get_by_role("button", name=name, exact=True).count() == 0


def test_run_page_exposes_one_truthful_dispatch_action(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/run")
    assert response is not None and response.status == 200
    assert page.locator("#run-passive-btn").count() == 0
    run_button = page.locator("#run-active-btn")
    assert run_button.is_visible()
    assert "Create V2 Plan" in run_button.inner_text()
    assert page.locator("#v2-cancel-run").is_disabled()
    assert 'fetch("/api/run"' not in response.text()


def test_v2_run_page_evidence_report_and_followups_are_preview_only(page, live_server):
    """UI uses the shared V2 endpoints and never saves or executes proposals."""
    page.goto(f"{live_server}/ui-v2/run")
    report_button = page.locator("#v2-inspect-report")
    followup_button = page.locator("#v2-propose-followups")
    assert report_button.is_disabled()
    assert followup_button.is_disabled()

    requests = []
    def details(route):
        route.fulfill(status=200, content_type="application/json", body=(
            '{"plan":{"mission_id":"m","tasks":[]},"tasks":[]}'
        ))

    def approvals(route):
        route.fulfill(status=200, content_type="application/json", body="[]")

    def report(route):
        requests.append(("report", route.request.method))
        route.fulfill(status=200, content_type="application/json", body=(
            '{"status":"partial","findings":[],"evidence":{'
            '"attempts":[],"all_evidence_integrity_verified":false}}'
        ))

    def followups(route):
        requests.append(("followups", route.request.post_data_json))
        route.fulfill(status=200, content_type="application/json", body=(
            '{"plan":null,"plan_id":null,"blocked":[],"created":false,'
            '"execution_started":false,"approval_granted":false}'
        ))

    page.route("**/api/v2/workflows/ui-test-plan/approvals", approvals)
    page.route("**/api/v2/workflows/ui-test-plan/report?limit=100", report)
    page.route("**/api/v2/workflows/ui-test-plan/followups", followups)
    page.route("**/api/v2/workflows/ui-test-plan", details)
    page.locator("#v2-plan-id").fill("ui-test-plan")
    page.locator("#v2-load-plan").click()
    page.wait_for_function(
        "() => !document.querySelector('#v2-inspect-report').disabled",
        timeout=8000,
    )
    report_button.click()
    page.wait_for_function(
        "() => document.querySelector('#v2-evidence-preview')?.textContent.includes('report status: partial')",
        timeout=8000,
    )
    assert "not established" in page.locator("#v2-evidence-preview").inner_text()
    followup_button.click()
    page.wait_for_function(
        "() => document.querySelector('#v2-evidence-preview')?.textContent.includes('Preview only')",
        timeout=8000,
    )
    assert requests == [
        ("report", "GET"),
        ("followups", {"max_tasks": 16, "save": False}),
    ]
    assert "nothing was saved, approved or submitted" in page.locator(
        "#v2-evidence-preview"
    ).inner_text()
