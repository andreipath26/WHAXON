"""Browser coverage for the canonical live remediation retest page."""
from __future__ import annotations

import json
import re


def test_retest_page_loads_current_findings(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/retest")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => !document.querySelector('#retest-status')?.textContent.includes('Loading recorded')",
        timeout=5000,
    )
    assert page.locator("#whaxon-live-retest").is_visible()
    assert page.locator("#retest-list").is_visible()


def test_dashboard_links_to_retest_page(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    link = page.locator('a[data-path="remediation-retest-studio"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/retest"

def test_retest_page_never_displays_static_fixture_evidence_or_commands(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/retest")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#retest-status')?.textContent.includes('finding record(s)') "
        "|| document.querySelector('#retest-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    visible = page.locator("body").inner_text()
    for marker in (
        "staging-api.corp.net",
        "pg_sleep(5)",
        "K9#xL9!pQ_corp_secret",
        "AKIAIOSFODNN7EXAMPLE",
        "5,009ms",
        "COMMIT 3-WAY VERDICT TO AUDIT LEDGER",
        "RE-EXECUTE IMMEDIATE PROBE",
    ):
        assert marker not in visible, f"Fictional retest fixture must not be shown: {marker}"
    assert page.locator("#whaxon-live-retest").is_visible()


def test_retest_page_only_offers_v2_plan_for_verified_findings(page, live_server):
    legacy_calls = []
    report_calls = {"count": 0}

    def report(route):
        report_calls["count"] += 1
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"jobs":[{"job_id":"job-live-1","findings":['
                 '{"seq":7,"kind":"verified finding","severity":"low","verification_status":"verified"},'
                 '{"seq":8,"kind":"sqli","severity":"high","verification_status":"pending"},'
                 '{"seq":null,"kind":"missing sequence","verification_status":"verified"}]}]}',
        )

    page.route("**/api/report?format=json", report)
    page.route("**/api/retest/**", lambda route: legacy_calls.append(route.request.url))
    page.goto(f"{live_server}/ui-v2/retest")
    page.wait_for_function(
        "() => document.querySelector('#retest-status')?.textContent.includes('2 finding record(s)')",
        timeout=8000,
    )

    retest = page.get_by_role("button", name="Propose V2 retest plan")
    verify = page.get_by_role("button", name="Propose V2 verification plan")
    assert retest.count() == 1 and retest.is_enabled()
    assert verify.count() == 1 and verify.is_enabled()
    assert report_calls["count"] == 1
    assert page.get_by_role("button", name="Retest verified finding").count() == 0
    assert legacy_calls == []


def test_v2_retest_proposal_is_saved_but_not_approved_or_submitted(page, live_server):
    proposals = []
    legacy_retests = []
    missions = []

    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"jobs":[{"job":{"id":"v2-source-job"},"job_id":"v2-source-job",'
                 '"findings":[{"seq":7,"kind":"sqli","severity":"medium",'
                 '"verification_status":"verified"}]}]}',
        ),
    )

    def mission_api(route):
        if route.request.method == "GET":
            route.fulfill(status=200, content_type="application/json", body=json.dumps(missions))
            return
        payload = route.request.post_data_json
        missions.append({"id": payload["id"], "objective": payload["objective"], "status": "active"})
        route.fulfill(
            status=201, content_type="application/json",
            body=json.dumps({"mission_id": payload["id"], "created": True}),
        )

    def proposal_api(route):
        payload = route.request.post_data_json
        proposals.append(payload)
        route.fulfill(
            status=200, content_type="application/json",
            body=json.dumps({
                "status": "proposed", "created": True, "plan_id": payload["id"],
                "capability_id": "tool.retest_sqli", "approval_granted": False,
                "execution_submitted": False,
            }),
        )

    page.route("**/api/v2/missions**", mission_api)
    page.route("**/api/v2/workflow-proposals", proposal_api)
    def legacy_retest(route):
        legacy_retests.append(route.request.url)
        route.fulfill(status=409, content_type="application/json", body='{"error":"legacy path must not be used"}')

    page.route("**/api/retest/**", legacy_retest)
    page.goto(f"{live_server}/ui-v2/retest")
    page.get_by_label("New mission objective").fill("Retest verified lab evidence")
    page.get_by_role("button", name="Create V2 mission").click()
    page.wait_for_function("() => document.querySelector('#v2-retest-mission')?.value.startsWith('ui-retest-mission-')")

    page.get_by_role("button", name="Propose V2 retest plan").click()
    page.wait_for_function("() => document.querySelector('#v2-retest-authoring-status')?.textContent.includes('has not been approved or submitted')")
    assert len(proposals) == 1
    assert proposals[0]["kind"] == "verification"
    assert proposals[0]["mission_id"] == missions[0]["id"]
    assert proposals[0]["source_job_id"] == "v2-source-job"
    assert proposals[0]["finding_seq"] == 7
    assert proposals[0]["mode"] == "retest"
    assert proposals[0]["save"] is True
    assert page.get_by_role("link", name=re.compile("Review V2 retest plan")).get_attribute("href").startswith("/ui-v2/run?plan_id=")
    assert legacy_retests == []


def test_v2_retest_proposal_surfaces_unsealed_source_block(page, live_server):
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"jobs":[{"job":{"id":"legacy-job"},"job_id":"legacy-job",'
                 '"findings":[{"seq":2,"kind":"sqli","verification_status":"verified"}]}]}',
        ),
    )
    page.route("**/api/v2/missions**", lambda route: route.fulfill(
        status=200, content_type="application/json",
        body='[{"id":"mission-1","objective":"authorized lab"}]',
    ))
    page.route("**/api/v2/workflow-proposals", lambda route: route.fulfill(
        status=200, content_type="application/json",
        body='{"status":"blocked","reason":"source evidence must be a sealed Engine V2 job",'
             '"created":false,"approval_granted":false,"execution_submitted":false}',
    ))
    page.goto(f"{live_server}/ui-v2/retest")
    page.get_by_label("Engine V2 mission").select_option("mission-1")
    page.get_by_role("button", name="Propose V2 retest plan").click()
    page.wait_for_function(
        "() => document.querySelector('#v2-retest-authoring-status')?.textContent.includes('sealed Engine V2 job')",
    )
    assert page.get_by_role("link", name=re.compile("Review V2 retest plan")).count() == 0


def test_run_page_loads_plan_id_from_retest_review_link(page, live_server):
    plan_id = "plan-from-retest"
    page.route(
        f"**/api/v2/workflows/{plan_id}",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"plan":{"mission_id":"mission-1","metadata":{},"tasks":[]},"tasks":[]}',
        ),
    )
    page.route(
        f"**/api/v2/workflows/{plan_id}/approvals",
        lambda route: route.fulfill(status=200, content_type="application/json", body="[]"),
    )
    page.route("**/api/v2/missions?limit=100", lambda route: route.fulfill(
        status=200, content_type="application/json", body="[]",
    ))
    page.route("**/api/v2/capabilities", lambda route: route.fulfill(
        status=200, content_type="application/json", body="[]",
    ))
    page.route("**/api/v2/providers", lambda route: route.fulfill(
        status=200, content_type="application/json", body="[]",
    ))
    page.goto(f"{live_server}/ui-v2/run?plan_id={plan_id}")
    assert page.locator("#v2-plan-id").input_value() == plan_id

def test_retest_header_reflects_live_scope_and_routes_to_scope_and_run(page, live_server):
    page.goto(f"{live_server}/ui-v2/retest")
    page.wait_for_function(
        "() => document.querySelector('#retest-status')?.textContent.includes('finding record(s)')"
        " || document.querySelector('#retest-status')?.textContent.includes('Findings could not be loaded')",
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

    page.goto(f"{live_server}/ui-v2/retest")
    page.locator("header button").filter(has_text="Terminal Log").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")


def test_retest_halt_uses_active_workflow_apis_and_disables_fixture_controls(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.route(
        "**/api/history",
        lambda route: route.fulfill(status=200, content_type="application/json", body="[]"),
    )
    page.goto(f"{live_server}/ui-v2/retest")
    page.wait_for_function(
        "() => document.querySelector('#retest-status')?.textContent.includes('finding record(s)')"
        " || document.querySelector('#retest-status')?.textContent.includes('Findings could not be loaded')",
        timeout=8000,
    )
    page.locator("header button").filter(has_text="Emergency Halt Scan").click()
    page.wait_for_function(
        "() => document.querySelector('#retest-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )
    for button in page.locator("main button:visible").all():
        if button.evaluate("(el) => el.closest('#whaxon-live-retest') !== null"):
            continue
        assert button.is_disabled(), f"Disconnected retest control remains enabled: {button.inner_text()}"
    assert "server confirms sealed Engine V2 evidence" in page.locator("#whaxon-live-retest").inner_text()


def test_v2_owned_retest_evidence_has_no_legacy_replay_control(page, live_server):
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"jobs":[{"job":{"id":"0123456789ab"},"job_id":"0123456789ab",'
                 '"findings":[{"seq":0,"kind":"sqli","verification_status":"verified"}]}]}',
        ),
    )

    legacy_calls = []
    page.route("**/api/retest/**", lambda route: legacy_calls.append(route.request.url))
    page.goto(f"{live_server}/ui-v2/retest")
    page.wait_for_function(
        "() => document.querySelector('#retest-status')?.textContent.includes('1 finding record(s)')",
        timeout=8000,
    )
    assert page.get_by_role("button", name="Retest verified finding").count() == 0
    assert page.get_by_role("button", name="Propose V2 retest plan").is_enabled()
    assert legacy_calls == []

