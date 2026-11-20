"""Browser coverage for the canonical scope-gated AI strategy gate."""
from __future__ import annotations


def test_ai_strategy_gate_loads_live_run_state(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/ai")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => !document.querySelector('#ai-run-status')?.textContent.includes('Loading live')",
        timeout=5000,
    )
    assert page.locator("#whaxon-ai-gate").is_visible()
    assert page.locator("#ai-target").is_visible()
    assert page.locator("#ai-goal").is_visible()


def test_ai_strategy_gate_hides_unverified_demo_state_until_live_data_is_loaded(page, live_server):
    context = page.context.browser.new_context(java_script_enabled=False)
    no_script_page = context.new_page()
    response = no_script_page.goto(f"{live_server}/ui-v2/ai")
    assert response is not None and response.status == 200
    assert no_script_page.locator("main").evaluate(
        "element => getComputedStyle(element).visibility"
    ) == "hidden"
    assert no_script_page.locator("header").first.evaluate(
        "element => getComputedStyle(element).visibility"
    ) == "hidden"
    assert no_script_page.locator("aside nav").is_visible()
    assert no_script_page.locator("#ai-runtime-status").inner_text() == "AI STATE PENDING"
    context.close()


def test_ai_strategy_gate_blocks_target_when_scope_check_denies(page, live_server):
    calls = []
    page.route("**/api/scope/check", lambda route: route.fulfill(status=200, content_type="application/json", body='{"allowed":false,"reason":"blocked by test"}'))
    page.route("**/api/ai/run", lambda route: calls.append(route.request.url) or route.fulfill(status=202, content_type="application/json", body='{"run_id":"should-not-run"}'))
    page.goto(f"{live_server}/ui-v2/ai")
    page.locator("#ai-target").fill("https://out-of-scope.invalid")
    page.locator("#ai-goal").fill("Test target scope guard")
    page.locator("#ai-run-form button[type=submit]").click()
    page.wait_for_function("() => document.querySelector('#ai-run-status')?.textContent.includes('blocked by test')")
    assert not calls


def test_dashboard_links_to_ai_strategy_gate(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    link = page.locator('a[data-path="ai-strategy-gate"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/ai"

def test_ai_strategy_gate_submits_to_server_even_if_client_scope_check_is_spoofed(page, live_server):
    page.route(
        "**/api/scope/check",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"allowed":true,"reason":"client says allowed"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.documentElement.dataset.aiGateReady === 'true'",
        timeout=8000,
    )
    page.locator("#ai-target").fill("https://example.com")
    page.locator("#ai-goal").fill("Assess this explicitly out-of-scope target")
    with page.expect_response(
        lambda response: response.request.method == "POST"
        and response.url.endswith("/api/v2/ai/proposals")
    ) as response_info:
        page.locator("#ai-run-form button[type=submit]").click()
    assert response_info.value.status == 200
    assert response_info.value.json()["status"] == "blocked"
    page.wait_for_function(
        "() => document.querySelector('#ai-run-status')?.textContent.toLowerCase().includes('outside current scope')",
        timeout=8000,
    )


def test_ai_strategy_gate_does_not_resume_legacy_pending_runs(page, live_server):
    calls = []
    pending_state = {"active": True}

    def pending(route):
        body = '[{"id":"ai-pending-ui-test","goal":"test authorized phase transition","phase":"recon","pending_question":{"rationale":"Confirm the next phase","target":"127.0.0.1","confidence":0.9,"proposed_phase":"enum"}}]' if pending_state["active"] else "[]"
        route.fulfill(status=200, content_type="application/json", body=body)

    def runs(route):
        route.fulfill(status=200, content_type="application/json", body="[]")

    page.route("**/api/ai/pending", pending)
    page.route("**/api/ai/runs", runs)
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.querySelector('#ai-pending-list')?.textContent.includes('Confirm the next phase')",
        timeout=8000,
    )
    assert page.locator("#btn-authorize").is_disabled()
    assert "read-only" in page.locator("#ai-pending-list").inner_text().lower()
    assert page.locator("#btn-authorize").is_disabled()
    assert calls == []
    assert pending_state["active"] is True


def test_ai_strategy_gate_emergency_halt_cancels_active_job(page, live_server, workflow_halt_sources):
    calls = []

    workflow_halt_sources(jobs=[{
        "id": "job-to-cancel", "status": "running", "engine_v2_owned": False,
    }])

    def cancel(route):
        calls.append(route.request.method)
        route.fulfill(status=200, content_type="application/json", body='{"ok":true}')

    page.route("**/api/jobs/job-to-cancel/cancel", cancel)
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.documentElement.dataset.aiGateReady === 'true'",
        timeout=8000,
    )
    page.get_by_role("button", name="Emergency Halt Scan").click()
    page.wait_for_function(
        "() => document.querySelector('#ai-run-status')?.textContent.includes('1 of 1 legacy job(s)')",
        timeout=8000,
    )
    assert calls == ["POST"]


def test_ai_strategy_gate_disables_legacy_reject_action(page, live_server):
    calls = []
    pending_state = {"active": True}

    def pending(route):
        body = '[{"id":"ai-reject-ui-test","goal":"test rejected phase transition","phase":"recon","pending_question":{"rationale":"Confirm the next phase","target":"127.0.0.1","confidence":0.9,"proposed_phase":"enum"}}]' if pending_state["active"] else "[]"
        route.fulfill(status=200, content_type="application/json", body=body)

    def runs(route):
        route.fulfill(status=200, content_type="application/json", body="[]")

    page.route("**/api/ai/pending", pending)
    page.route("**/api/ai/runs", runs)
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.querySelector('#ai-pending-list')?.textContent.includes('Confirm the next phase')",
        timeout=8000,
    )
    assert page.locator("#btn-reject").is_disabled()
    assert page.locator("#btn-reject").is_disabled()
    assert calls == []
    assert pending_state["active"] is True


def test_ai_strategy_gate_engagement_button_opens_scope_page(page, live_server):
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.documentElement.dataset.aiGateReady === 'true'",
        timeout=8000,
    )
    page.locator("header button").first.click()
    page.wait_for_url("**/ui-v2/scope", timeout=8000)


def test_ai_strategy_gate_keeps_successful_submission_confirmation(page, live_server):
    submitted = {"mission": [], "proposal": []}
    legacy_calls = []

    def scope_check(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"allowed":true,"reason":"matched local loopback rule"}',
        )

    def create_mission(route):
        submitted["mission"].append(route.request.post_data_json)
        route.fulfill(
            status=201,
            content_type="application/json",
            body='{"mission_id":"mission-ui-submit-test","created":true}',
        )

    def propose(route):
        submitted["proposal"].append(route.request.post_data_json)
        payload = route.request.post_data_json
        route.fulfill(
            status=200,
            content_type="application/json",
            body=(
                '{"status":"proposed","created":true,"plan_id":"' + payload["id"] + '",'
                '"digest":"test-digest","reason":null,"approval_granted":false,'
                '"execution_submitted":false}'
            ),
        )

    page.route("**/api/scope/check", scope_check)
    page.route("**/api/v2/missions", create_mission)
    page.route("**/api/v2/ai/proposals", propose)
    page.route("**/api/ai/run", lambda route: legacy_calls.append(route.request.url) or route.fulfill(status=500))
    page.route("**/api/ai/runs", lambda route: route.fulfill(status=200, content_type="application/json", body="[]"))
    page.route("**/api/ai/pending", lambda route: route.fulfill(status=200, content_type="application/json", body="[]"))
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.documentElement.dataset.aiGateReady === 'true'",
        timeout=8000,
    )
    page.locator("#ai-target").fill("127.0.0.1")
    page.locator("#ai-goal").fill("Review the authorized local target")
    page.locator("#ai-run-form button[type=submit]").click()
    page.wait_for_function(
        "() => document.querySelector('#ai-run-status')?.textContent.includes('V2 AI plan saved')",
        timeout=8000,
    )
    assert submitted["mission"] and submitted["mission"][0]["objective"] == "Review the authorized local target"
    assert submitted["proposal"] and submitted["proposal"][0]["target"] == "127.0.0.1"
    assert submitted["proposal"][0]["save"] is True
    assert page.locator("#ai-v2-plan-result a").get_attribute("href").startswith("/ui-v2/run?plan_id=ai-plan-")
    assert legacy_calls == []


def test_ai_strategy_gate_hides_fake_wire_preview_and_disables_actions_without_pending_run(page, live_server):
    page.route("**/api/ai/pending", lambda route: route.fulfill(status=200, content_type="application/json", body="[]"))
    page.route("**/api/ai/runs", lambda route: route.fulfill(status=200, content_type="application/json", body="[]"))
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.documentElement.dataset.aiGateReady === 'true'",
        timeout=8000,
    )
    assert page.locator("#btn-authorize").is_disabled()
    assert page.locator("#btn-reject").is_disabled()
    assert page.get_by_text("HTTP Request Wire Preview").is_hidden()
    assert page.locator("#ai-pending-list").inner_text().find("No legacy AI runs are waiting") >= 0
    visible_text = page.locator("body").inner_text()
    assert "CVE-2023-38606" not in visible_text
    assert "staging-api.corp.net" not in visible_text
    assert "Nmap 7.94 detected" not in visible_text
    assert "+204ms" not in visible_text
    assert "buffer boundary stress" not in visible_text
    assert "89.4%" not in visible_text
    assert "89% probability" not in visible_text
    assert "Kiln/Ollama (Mistral-Offensive-7B)" not in visible_text
    assert "LOW RISK" not in visible_text
    assert "Nuclei basic tech-detect" not in visible_text
    assert "PTES 4: Vulnerability Analysis" not in visible_text
    assert "Synaptic-Planner v2.4" not in visible_text
    assert "OP//7749-ALPHA" not in visible_text
    assert "4 / 12 REMAINING" not in visible_text
    assert "DETERMINISTIC OK" not in visible_text
    assert "WX-8492-491" not in visible_text
    assert "94.2%" not in visible_text
    assert "78.1%" not in visible_text
    assert "98.0%" not in visible_text
    assert "50 req/sec" not in visible_text
    assert "Chain-of-Thought" not in visible_text
    assert "Engine V2 AI plan proposal" in visible_text
    assert "No live proposal is awaiting operator input." in visible_text
    assert "AI Planner proposes spawning Nuclei" not in visible_text
    assert "LIVE PROPOSAL DETAILS" in visible_text
    assert "LIVE PROPOSAL DETAILS" in visible_text
    assert "RECORDED PROPOSAL DETAILS" not in visible_text
    assert "Recorded Proposal Details" not in visible_text
    assert "Target: No target selected" in page.locator("header span").filter(has_text="Target:").first.text_content()



def test_ai_strategy_gate_refreshes_engagement_label_after_live_scope_changes(page, live_server):
    scope_calls = {"count": 0}

    def scope(route):
        scope_calls["count"] += 1
        engagement = "scope-one" if scope_calls["count"] == 1 else "scope-two"
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"engagement":"' + engagement + '","in_scope":["127.0.0.1"],"enabled":true}',
        )

    page.route("**/api/ai/runs", lambda route: route.fulfill(status=200, content_type="application/json", body="[]"))
    page.route("**/api/ai/pending", lambda route: route.fulfill(status=200, content_type="application/json", body="[]"))
    page.route("**/api/scope", scope)
    page.route(
        "**/api/scope/check",
        lambda route: route.fulfill(status=200, content_type="application/json", body='{"allowed":true,"reason":"matched test scope"}'),
    )
    page.route(
        "**/api/v2/missions",
        lambda route: route.fulfill(status=201, content_type="application/json", body='{"mission_id":"scope-refresh-test","created":true}'),
    )
    page.route(
        "**/api/v2/ai/proposals",
        lambda route: route.fulfill(status=200, content_type="application/json", body='{"status":"proposed","created":true,"plan_id":"scope-refresh-plan","digest":"scope-refresh-digest","approval_granted":false,"execution_submitted":false}'),
    )

    page.add_init_script("const _setInterval = window.setInterval.bind(window); window.setInterval = (fn, delay, ...args) => _setInterval(fn, Math.max(delay, 60000), ...args);")
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.documentElement.dataset.aiGateReady === 'true'",
        timeout=8000,
    )
    # The engagement selector text changes after each live scope read.
    engagement = page.locator("header button").filter(has_text="scope-one")
    assert engagement.is_visible()
    page.locator("#ai-target").fill("127.0.0.1")
    page.locator("#ai-goal").fill("Check scope refresh behavior")
    page.locator("#ai-run-form button[type=submit]").click()
    page.wait_for_function(
        "() => document.querySelector('#ai-run-status')?.textContent.includes('V2 AI plan saved')",
        timeout=8000,
    )
    page.wait_for_function(
        "() => [...document.querySelectorAll('header button')].some(b => b.textContent.includes('scope-two'))",
        timeout=8000,
    )
    assert scope_calls["count"] >= 2



def test_ai_pending_target_is_not_labelled_scope_checked_before_server_verdict(page, live_server):
    page.route(
        "**/api/ai/runs",
        lambda route: route.fulfill(status=200, content_type="application/json", body="[]"),
    )
    page.route(
        "**/api/ai/pending",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='[{"id":"pending-scope-test","pending_question":{"target":"203.0.113.10","rationale":"Pending proposal for browser test","proposed_phase":"validation","tool_id":"nmap"}}]',
        ),
    )
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"enabled":true,"in_scope":["192.0.2.0/24"],"out_of_scope":[]}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/ai")
    page.wait_for_function(
        "() => document.documentElement.dataset.aiGateReady === 'true' && document.querySelector('#ai-pending-list')?.innerText.includes('pending-scope-test')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "(TARGET REQUIRES SERVER CHECK)" in header
    assert "(SCOPE CHECKED)" not in header
    assert "SCOPE RULE CONFIGURED" in header
    assert "SERVER-SIDE SCOPE CHECK ENABLED" not in header
