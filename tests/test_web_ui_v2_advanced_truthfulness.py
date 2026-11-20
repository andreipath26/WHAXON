"""Acceptance tests for advanced workspaces with intentionally limited integrations."""
from __future__ import annotations


def test_bas_workspace_uses_persisted_findings_and_disables_provider_actions(page, live_server):
    page.goto(f"{live_server}/ui-v2/bas")
    panel = page.locator("#whaxon-live-bas")
    assert panel.is_visible()
    page.wait_for_function(
        "() => document.querySelector('#bas-status')?.textContent.includes('persisted finding')"
        " || document.querySelector('#bas-status')?.textContent.includes('Live data unavailable')",
        timeout=8000,
    )
    assert page.get_by_role("button", name="Detonate Sequence").is_disabled()
    assert page.get_by_role("button", name="Deploy to Sentinel").is_disabled()
    assert page.get_by_role("button", name="Deploy to Splunk").is_disabled()
    for button in page.locator("main button:visible").all():
        if not button.evaluate("(el) => el.closest('#whaxon-live-bas') !== null"):
            assert button.is_disabled(), f"Unconnected BAS control remains enabled: {button.inner_text()}"


def test_compliance_workspace_filters_and_exports_only_recorded_findings(page, live_server):
    page.goto(f"{live_server}/ui-v2/compliance")
    panel = page.locator("#whaxon-live-compliance")
    assert panel.is_visible()
    page.wait_for_function(
        "() => document.querySelector('#compliance-status')?.textContent.includes('recorded finding')"
        " || document.querySelector('#compliance-status')?.textContent.includes('Live data unavailable')",
        timeout=8000,
    )
    search = panel.get_by_role("searchbox", name="Filter framework crosswalk")
    assert search.is_visible()
    search.fill("no-such-record-should-match")
    assert any(message in panel.inner_text() for message in ("No findings match this filter", "No recorded findings are available"))
    export = panel.get_by_role("button", name="Export crosswalk JSON")
    assert export.is_enabled()
    with page.expect_download() as download_info:
        export.click()
    assert download_info.value.suggested_filename == "whaxon-framework-crosswalk.json"
    assert page.get_by_role("button", name="Auditor Crosswalk PDF").count() == 0


def test_threat_intel_workspace_is_local_catalog_not_a_fake_live_feed(page, live_server):
    page.goto(f"{live_server}/ui-v2/threat-intel")
    panel = page.locator("#whaxon-live-threat-intel")
    assert panel.is_visible()
    page.wait_for_function(
        "() => document.querySelector('#whaxon-live-threat-intel [role=status]')?.textContent.includes('No connected external threat-intelligence feed')"
        " || document.querySelector('#whaxon-live-threat-intel [role=status]')?.textContent.includes('Live catalog unavailable')",
        timeout=10000,
    )
    assert panel.get_by_role("searchbox", name="Filter threat intelligence references").is_visible()
    refresh = panel.get_by_role("button", name="Refresh catalog")
    assert refresh.is_enabled()
    refresh.click()
    page.wait_for_function(
        "() => document.querySelector('#whaxon-live-threat-intel [role=status]')?.textContent.includes('locally recorded')"
        " || document.querySelector('#whaxon-live-threat-intel [role=status]')?.textContent.includes('Live catalog unavailable')",
        timeout=10000,
    )
    assert page.get_by_role("button", name="Sync Upstream Feeds").is_disabled()
    assert page.get_by_role("button", name="Inspect Exploit Code").count() == 0


def test_approvals_workspace_loads_real_queue_and_disables_demo_decisions(page, live_server):
    page.goto(f"{live_server}/ui-v2/approvals")
    panel = page.locator("#whaxon-live-approvals")
    assert panel.is_visible()
    page.wait_for_function(
        "() => document.querySelector('#whaxon-live-approvals p')?.textContent.includes('pending or previously blocked V2 task(s)')"
        " || document.querySelector('#whaxon-live-approvals p')?.textContent.includes('Live V2 approvals unavailable')",
        timeout=10000,
    )
    refresh = panel.get_by_role("button", name="Refresh queue")
    assert refresh.is_enabled()
    refresh.click()
    page.wait_for_function(
        "() => document.querySelector('#whaxon-live-approvals p')?.textContent.includes('pending or previously blocked V2 task(s)')"
        " || document.querySelector('#whaxon-live-approvals p')?.textContent.includes('Live V2 approvals unavailable')",
        timeout=10000,
    )
    # Check a single DOM snapshot: refreshing the live queue may insert a
    # functional Submit answer button between separate nth-locator operations.
    unwired = page.locator("main button").evaluate_all("""buttons => buttons
      .filter(button => !button.closest('#whaxon-live-approvals'))
      .filter(button => {
        const style = getComputedStyle(button);
        return button.getClientRects().length > 0 && style.visibility !== 'hidden'
          && style.display !== 'none' && !button.closest('[hidden]');
      })
      .filter(button => !button.disabled)
      .map(button => button.textContent.trim())
    """)
    assert not unwired, f"Unwired approval controls remain enabled: {unwired}"


def test_approvals_workspace_keeps_legacy_waiting_runs_read_only(page, live_server):
    legacy_writes = []
    def guard_legacy_writes(route):
        if route.request.method.upper() in {"GET", "HEAD"}:
            route.continue_()
        else:
            legacy_writes.append(route.request.url)
            route.abort()

    page.route("**/api/ai/runs/**", guard_legacy_writes)
    page.goto(f"{live_server}/ui-v2/approvals")
    panel = page.locator("#whaxon-live-approvals")
    page.wait_for_function(
        "() => { const panel = document.querySelector('#whaxon-live-approvals'); "
        "return panel?.innerText.includes('Legacy AI runs (read-only)') "
        "&& panel.innerText.includes('seed-ai-approval-ui'); }",
        timeout=15000,
    )
    assert "seed-ai-approval-ui" in panel.inner_text()
    assert "cannot grant a V2 task approval or resume its legacy executor" in panel.inner_text()
    assert panel.get_by_role("textbox").count() == 0
    assert panel.get_by_role("button", name="Submit answer").count() == 0
    assert page.evaluate(
        "() => performance.getEntriesByType('resource').map(entry => entry.name).filter(url => url.includes('/api/ai/runs/'))"
    ) == []
    assert legacy_writes == []
    pending = page.evaluate("() => fetch('/api/ai/pending').then(response => response.json())")
    pending_items = pending if isinstance(pending, list) else pending.get("items", pending.get("pending", []))
    assert any(
        str(item.get("run_id") or item.get("id")) == "seed-ai-approval-ui"
        for item in pending_items
    )
    approvals = page.evaluate(
        "() => fetch('/api/ai/runs/seed-ai-approval-ui').then(response => response.json())"
    )
    assert approvals["status"] == "waiting"
