"""Browser coverage for the truthful execution ledger page."""
from __future__ import annotations


def test_audit_page_loads_recorded_execution_metadata(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/audit")
    assert response is not None and response.status == 200
    page.wait_for_function("() => !document.querySelector('#audit-status')?.textContent.includes('Loading recorded')")
    assert page.locator("#whaxon-live-audit").is_visible()
    assert "does not claim cryptographic signing" in page.locator("#whaxon-live-audit").inner_text()


def test_dashboard_links_to_audit_page(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    link = page.locator('a[data-path="cryptographic-audit-log"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/audit"

def test_audit_page_never_claims_fixture_signatures_or_merkle_attestation(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/audit")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#audit-status')?.textContent.includes('execution record(s)') "
        "|| document.querySelector('#audit-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    visible = page.locator("body").inner_text()
    for marker in (
        "EVT-9941",
        "EVT-9940",
        "DUAL_SIGNED_BRAV",
        "Merkle Root 100% Attested",
        "BEGIN ED25519 ATTESTATION SIGNATURE",
        "Court-Ready Forensic Bundle",
        "SHA-256 CHECKSUM MATCHED",
        "Cryptographic QR Verification Slip",
    ):
        assert marker not in visible, f"Fabricated audit claim must not be shown: {marker}"
    assert page.locator("#whaxon-live-audit").is_visible()
    assert "does not claim cryptographic signing" in page.locator("#whaxon-live-audit").inner_text()

def test_audit_ledger_filters_live_records_and_refreshes(page, live_server):
    calls = {"count": 0}

    def history(route):
        calls["count"] += 1
        route.fulfill(
            status=200,
            content_type="application/json",
            body='['
                 '{"id":"job-alpha","tool":"nmap","status":"finished","target":"192.0.2.10","exit_code":0,"duration_s":1.2},'
                 '{"id":"job-beta","tool":"nikto","status":"failed","target":"192.0.2.20","exit_code":2,"duration_s":2.4}'
                 ']',
        )

    page.route("**/api/history", history)
    page.goto(f"{live_server}/ui-v2/audit")
    page.wait_for_function(
        "() => document.querySelector('#audit-status')?.textContent.includes('2 execution record(s)')",
        timeout=8000,
    )
    assert page.locator(".audit-card").count() == 2
    page.get_by_label("Filter recorded jobs").fill("job-beta")
    assert page.locator(".audit-card:visible").count() == 1
    assert "job-beta" in page.locator(".audit-card:visible").inner_text()
    assert "job-alpha" not in page.locator(".audit-card:visible").inner_text()
    with page.expect_response("**/api/history"):
        page.get_by_role("button", name="Refresh ledger").click()
    page.wait_for_function("() => document.querySelector('#audit-status')?.textContent.includes('1 of 2 execution record(s)')")
    assert calls["count"] >= 2



def test_audit_reference_controls_are_disabled_except_live_ledger_actions(page, live_server):
    page.goto(f"{live_server}/ui-v2/audit")
    page.wait_for_function(
        "() => document.querySelector('#audit-status')?.textContent.includes('execution record(s)')"
        " || document.querySelector('#audit-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    for button in page.locator("main button:visible").all():
        if button.get_attribute("id") not in {"audit-refresh", "audit-export"}:
            assert button.is_disabled(), f"Unwired audit reference control is enabled: {button.inner_text()}"


def test_audit_header_new_and_logs_buttons_open_real_workspaces(page, live_server):
    page.goto(f"{live_server}/ui-v2/audit")
    page.locator("header button").filter(has_text="New").click()
    page.wait_for_url("**/ui-v2/scope")
    assert page.url.endswith("/ui-v2/scope")

    page.goto(f"{live_server}/ui-v2/audit")
    page.locator("header button").filter(has_text="Terminal Log").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")


def test_audit_header_halt_uses_active_workflow_apis(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.goto(f"{live_server}/ui-v2/audit")
    page.wait_for_function(
        "() => document.querySelector('#audit-status')?.textContent.includes('execution record(s)')"
        " || document.querySelector('#audit-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    page.locator("header button").filter(has_text="Emergency Halt Scan").click()
    page.wait_for_function(
        "() => document.querySelector('#audit-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )



def test_audit_header_reflects_live_engagement_and_scope(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"engagement":"audit-scope-test","enabled":true,"in_scope":["192.0.2.61"],"out_of_scope":[],"notes":""}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/audit")
    page.wait_for_function(
        "() => document.querySelector('#audit-live-scope-status')?.textContent.includes('192.0.2.61')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "audit-scope-test" in header
    assert "Target: 192.0.2.61" in header
    assert "RULE CONFIGURED" in header
    assert "ENG-2026-X892" not in header
    assert "STRICT BOUNDARY ENFORCED" not in header


def test_audit_header_reports_scope_unavailable_truthfully(page, live_server):
    page.route("**/api/scope", lambda route: route.abort())
    page.goto(f"{live_server}/ui-v2/audit")
    page.wait_for_function(
        "() => document.querySelector('#audit-live-scope-status')?.textContent.includes('Scope status unavailable')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "Scope status unavailable" in header
    assert "ENG-2026-X892" not in header
    assert "STRICT BOUNDARY ENFORCED" not in header
