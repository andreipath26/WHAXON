"""Browser interaction tests for the canonical Scope & Targets page."""
from __future__ import annotations

import json


def _read_scope(page):
    return page.evaluate("() => fetch('/api/scope').then(response => response.json())")


def _save_scope(page, scope):
    return page.evaluate(
        """async (value) => {
          const response = await fetch('/api/scope', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(value)
          });
          return {status: response.status, body: await response.json()};
        }""",
        scope,
    )


def _restore_scope(page, scope):
    payload = dict(scope)
    if payload.get("enabled") is False:
        payload["confirm_disable"] = True
    return _save_scope(page, payload)


def _wait_loaded(page):
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=8000,
    )


def test_scope_modal_requires_authorization_and_persists_target(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    target = "scope-modal-test.example.invalid"
    try:
        page.locator("#openTargetModalBtn").click()
        page.locator("#modalTargetInput").fill(target)
        page.locator("#saveTargetBtn").click()
        assert "Confirm that written authorization exists" in page.locator("#scope-ui-notice").inner_text()
        assert target not in _read_scope(page)["in_scope"]

        page.locator("#authConfirmCheckbox").check()
        page.locator("#saveTargetBtn").click()
        page.wait_for_function(
            "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
            timeout=5000,
        )
        assert target in _read_scope(page)["in_scope"]
        assert page.locator("#targetModal").is_hidden()
    finally:
        _save_scope(page, before)


def test_scope_target_filter_filters_live_rows(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    rows = page.locator("#targetTableBody tr")
    assert rows.count() >= 1
    target = rows.first.locator("td").first.inner_text().strip()
    filter_input = page.locator("#targetFilterInput")
    filter_input.fill(target)
    assert page.locator("#targetTableBody tr:visible").count() >= 1
    filter_input.fill("no-such-scope-rule-987654")
    assert page.locator("#targetTableBody tr:visible").count() == 1
    assert "No scope rules match this filter" in page.locator("#scope-empty-state").inner_text()


def test_scope_import_drawer_imports_scope_json_and_closes(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    imported = {
        **before,
        "engagement": "Scope import browser test",
        "in_scope": ["scope-import.example.invalid"],
        "out_of_scope": ["scope-excluded.example.invalid"],
        "notes": "browser test import",
    }
    try:
        page.locator("#openImportDrawerBtn").click()
        assert page.locator("#importDrawer").is_visible()
        assert page.locator("#importDrawer button", has_text="scope.json").is_disabled()
        assert page.locator("#importDrawer button", has_text="Burp XML/JSON").is_hidden()
        assert page.locator("#importDrawer button", has_text="CIDR List").is_hidden()
        page.locator("#importDrawer textarea").fill(json.dumps(imported))
        page.locator("#executeImportBtn").click()
        page.wait_for_function(
            "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
            timeout=5000,
        )
        after = _read_scope(page)
        assert after["in_scope"] == imported["in_scope"]
        assert after["out_of_scope"] == imported["out_of_scope"]
        assert page.locator("#importDrawer").is_hidden()
    finally:
        _save_scope(page, before)


def test_scope_add_boundary_exclusion_persists_and_can_be_restored(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    rule = "scope-deny-test.example.invalid"
    try:
        page.once("dialog", lambda dialog: dialog.accept(rule))
        page.locator("#addDenyRuleBtn").click()
        page.wait_for_function(
            "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
            timeout=5000,
        )
        assert rule in _read_scope(page)["out_of_scope"]
    finally:
        _save_scope(page, before)


def test_scope_remove_rule_requires_confirmation_and_persists(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    field = "in_scope" if before.get("in_scope") else "out_of_scope"
    assert before.get(field), "test fixture needs at least one scope rule"
    target = before[field][0]
    try:
        page.once("dialog", lambda dialog: dialog.accept())
        row = page.locator("#targetTableBody tr").filter(has_text=target).first
        row.get_by_role("button", name="Remove").click()
        page.wait_for_function(
            "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
            timeout=5000,
        )
        assert target not in _read_scope(page)[field]
    finally:
        _save_scope(page, before)


def test_scope_header_reflects_disabled_enforcement(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    try:
        disabled = {**before, "enabled": False, "confirm_disable": True}
        result = _save_scope(page, disabled)
        assert result["status"] == 200
        page.reload()
        _wait_loaded(page)
        assert "SCOPE ENFORCEMENT DISABLED" in page.locator("header").inner_text()
    finally:
        _save_scope(page, before)

def test_scope_header_shows_the_actual_configured_target(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    scope = _read_scope(page)
    target = scope["in_scope"][0] if scope.get("in_scope") else "No target configured"
    assert target in page.locator("header").inner_text()


def test_scope_dialogs_support_escape_and_restore_focus(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    target_trigger = page.locator("#openTargetModalBtn")
    target_trigger.click()
    assert page.locator("#targetModal").get_attribute("role") == "dialog"
    assert page.locator("#targetModal").get_attribute("aria-modal") == "true"
    assert page.locator("#modalTargetInput").evaluate("(el) => el === document.activeElement")
    page.keyboard.press("Escape")
    assert page.locator("#targetModal").is_hidden()
    assert target_trigger.evaluate("(el) => el === document.activeElement")
    page.keyboard.press("Enter")
    page.keyboard.press("Shift+Tab")
    assert page.locator("#closeTargetModalBtn").evaluate("(el) => el === document.activeElement")
    page.keyboard.press("Shift+Tab")
    assert page.locator("#saveTargetBtn").evaluate("(el) => el === document.activeElement")
    page.keyboard.press("Escape")

    import_trigger = page.locator("#openImportDrawerBtn")
    import_trigger.click()
    assert page.locator("#importDrawer").get_attribute("aria-hidden") == "false"
    assert page.locator("#importDrawer textarea").evaluate("(el) => el === document.activeElement")
    page.keyboard.press("Escape")
    assert page.locator("#importDrawer").is_hidden()
    assert import_trigger.evaluate("(el) => el === document.activeElement")


def test_scope_text_inputs_have_accessible_names(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    assert page.get_by_role("textbox", name="Filter configured scope rules").is_visible()
    assert page.get_by_role("textbox", name="Check a target against the active scope").is_visible()
    page.locator("#openTargetModalBtn").click()
    assert page.get_by_role(
        "textbox", name="Authorized target hostname, IP address, or CIDR"
    ).is_visible()
    page.keyboard.press("Escape")
    page.locator("#openImportDrawerBtn").click()
    assert page.get_by_role("textbox", name="Paste scope JSON definition").is_visible()


def test_scope_import_rejects_json_null_without_mutating_configuration(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    page.locator("#openImportDrawerBtn").click()
    page.locator("#importDrawer textarea").fill("null")
    page.locator("#executeImportBtn").click()
    assert "Import must be a JSON object." in page.locator("#scope-ui-notice").inner_text()
    assert _read_scope(page) == before


def test_scope_import_without_enabled_field_preserves_disabled_enforcement(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    disabled = _save_scope(page, {**before, "enabled": False, "confirm_disable": True})
    assert disabled["status"] == 200
    try:
        page.reload()
        _wait_loaded(page)
        page.locator("#openImportDrawerBtn").click()
        page.locator("#importDrawer textarea").fill(json.dumps({
            "engagement": "Preserve disabled enforcement",
            "in_scope": ["127.0.0.1"],
            "out_of_scope": [],
            "notes": "import must not silently re-enable enforcement",
        }))
        page.locator("#executeImportBtn").click()
        page.wait_for_function(
            "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
            timeout=5000,
        )
        after = _read_scope(page)
        assert after["enabled"] is False
        assert after["engagement"] == "Preserve disabled enforcement"
    finally:
        _save_scope(page, before)


def test_scope_preflight_status_distinguishes_blocked_target(page, live_server):
    page.route(
        "**/api/scope/check",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"allowed":false,"reason":"explicit exclusion","matched_rule":"blocked.example.invalid"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    assert page.locator("#scopePreflightStatus").inner_text() == "NO CHECK RUN"
    page.locator("#scopeCheckTarget").fill("blocked.example.invalid")
    page.locator("#runScopeCheckBtn").click()
    page.wait_for_function(
        "() => document.querySelector('#scopePreflightStatus')?.textContent === 'LAST CHECK: BLOCKED'",
        timeout=5000,
    )
    assert "BLOCKED" in page.locator("#scopeCheckResult").inner_text()
    assert "bg-error" in page.locator("#scopePreflightIndicator").get_attribute("class")


def test_scope_preflight_status_reports_api_error(page, live_server):
    page.route(
        "**/api/scope/check",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"scope evaluation unavailable"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    page.locator("#scopeCheckTarget").fill("target.example.invalid")
    page.locator("#runScopeCheckBtn").click()
    page.wait_for_function(
        "() => document.querySelector('#scopePreflightStatus')?.textContent === 'CHECK ERROR'",
        timeout=5000,
    )
    assert "scope evaluation unavailable" in page.locator("#scopeCheckResult").inner_text()
    assert "bg-error" in page.locator("#scopePreflightIndicator").get_attribute("class")


def test_scope_edit_invalidates_previous_preflight_result(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    try:
        page.locator("#scopeCheckTarget").fill("127.0.0.1")
        page.locator("#runScopeCheckBtn").click()
        page.wait_for_function(
            "() => document.querySelector('#scopePreflightStatus')?.textContent === 'LAST CHECK: ALLOWED'",
            timeout=5000,
        )
        page.locator("#openTargetModalBtn").click()
        page.locator("#modalTargetInput").fill("scope-preflight-reset.example.invalid")
        page.locator("#authConfirmCheckbox").check()
        page.locator("#saveTargetBtn").click()
        page.wait_for_function(
            "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
            timeout=5000,
        )
        assert page.locator("#scopePreflightStatus").inner_text() == "NO CHECK RUN"
        assert "bg-outline" in page.locator("#scopePreflightIndicator").get_attribute("class")
        assert "No scope check has been run" in page.locator("#scopeCheckResult").inner_text()
    finally:
        _save_scope(page, before)


def test_scope_import_requires_confirmation_before_disabling_enforcement(page, live_server):
    # Stub the initial scope read so parallel browser workers cannot race this
    # confirmation test by mutating the shared live-server configuration.
    initial_scope = {
        "engagement": "Authorized assessment",
        "enabled": True,
        "in_scope": ["127.0.0.1"],
        "out_of_scope": [],
        "notes": "",
    }
    writes = []
    page.route(
        "**/api/scope",
        lambda route: (
            route.fulfill(status=200, content_type="application/json", body=json.dumps(initial_scope))
            if route.request.method == "GET"
            else (
                writes.append(route.request.method),
                route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=route.request.post_data or json.dumps(initial_scope),
                ),
            )[1]
        ),
    )
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    imported = {
        **initial_scope,
        "enabled": False,
        "engagement": "Confirmed enforcement disable",
    }
    page.locator("#openImportDrawerBtn").click()
    page.locator("#importDrawer textarea").fill(json.dumps(imported))

    page.once("dialog", lambda dialog: dialog.dismiss())
    page.locator("#executeImportBtn").click()
    page.wait_for_timeout(100)
    assert "POST" not in writes
    assert page.locator("#importDrawer").is_visible()

    page.once("dialog", lambda dialog: dialog.accept())
    page.locator("#executeImportBtn").click()
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
        timeout=5000,
    )
    assert "POST" in writes



def test_scope_preflight_verdict_is_cleared_when_checked_target_changes(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    target = page.locator("#scopeCheckTarget")
    target.fill("127.0.0.1")
    page.locator("#runScopeCheckBtn").click()
    page.wait_for_function(
        "() => document.querySelector('#scopePreflightStatus')?.textContent === 'LAST CHECK: ALLOWED'",
        timeout=5000,
    )
    assert "127.0.0.1" in page.locator("#scopeCheckResult").inner_text()
    target.fill("127.0.0.2")
    assert page.locator("#scopePreflightStatus").inner_text() == "NO CHECK RUN"
    assert "bg-outline" in page.locator("#scopePreflightIndicator").get_attribute("class")
    assert "No scope check has been run" in page.locator("#scopeCheckResult").inner_text()


def test_scope_preflight_ignores_response_after_target_changes(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    page.evaluate("""() => {
      const originalFetch = window.fetch.bind(window);
      window.fetch = (url, options) => {
        if (url === "/api/scope/check") {
          return new Promise(resolve => {
            window.__resolvePendingScopeCheck = () => resolve(new Response(
              JSON.stringify({allowed: true, reason: "matched configured rule"}),
              {status: 200, headers: {"Content-Type": "application/json"}}
            ));
          });
        }
        return originalFetch(url, options);
      };
    }""")
    target = page.locator("#scopeCheckTarget")
    target.fill("127.0.0.1")
    page.locator("#runScopeCheckBtn").click()
    page.wait_for_function(
        "() => document.querySelector('#scopePreflightStatus')?.textContent === 'CHECKING…'",
        timeout=5000,
    )
    target.fill("127.0.0.2")
    assert page.locator("#scopePreflightStatus").inner_text() == "NO CHECK RUN"
    page.evaluate("() => window.__resolvePendingScopeCheck()")
    page.wait_for_timeout(50)
    assert page.locator("#scopePreflightStatus").inner_text() == "NO CHECK RUN"
    assert "No scope check has been run" in page.locator("#scopeCheckResult").inner_text()

def test_scope_save_locks_mutation_controls_until_api_response(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    page.evaluate("""() => {
      const originalFetch = window.fetch.bind(window);
      window.fetch = (url, options = {}) => {
        if (url === "/api/scope" && options.method === "POST") {
          const payload = JSON.parse(options.body);
          return new Promise(resolve => {
            window.__resolveScopeSave = () => resolve(new Response(JSON.stringify(payload), {
              status: 200,
              headers: {"Content-Type": "application/json"}
            }));
          });
        }
        return originalFetch(url, options);
      };
    }""")
    page.locator("#openTargetModalBtn").click()
    page.locator("#modalTargetInput").fill("scope-save-lock.example.invalid")
    page.locator("#authConfirmCheckbox").check()
    page.locator("#saveTargetBtn").click()
    page.wait_for_function("() => typeof window.__resolveScopeSave === 'function'", timeout=5000)

    assert page.locator("#saveTargetBtn").is_disabled()
    assert page.locator("#openImportDrawerBtn").is_disabled()
    assert page.locator("#runScopeCheckBtn").is_disabled()
    assert page.locator("#openTargetModalBtn").is_disabled()
    assert page.locator("#targetTableBody button[data-scope-mutation]").count() >= 1
    assert page.locator("#targetTableBody button[data-scope-mutation]").first.is_disabled()

    page.evaluate("() => window.__resolveScopeSave()")
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Scope saved')",
        timeout=5000,
    )
    assert page.locator("#saveTargetBtn").is_enabled()
    assert page.locator("#openImportDrawerBtn").is_enabled()
    assert page.locator("#runScopeCheckBtn").is_enabled()


def test_scope_failed_save_restores_mutation_controls_and_keeps_live_config(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"scope persistence unavailable"}',
        ) if route.request.method == "POST" else route.continue_(),
    )
    page.locator("#openTargetModalBtn").click()
    page.locator("#modalTargetInput").fill("scope-save-failure.example.invalid")
    page.locator("#authConfirmCheckbox").check()
    page.locator("#saveTargetBtn").click()
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('scope persistence unavailable')",
        timeout=5000,
    )
    assert page.locator("#saveTargetBtn").is_enabled()
    assert page.locator("#openImportDrawerBtn").is_enabled()
    assert page.locator("#runScopeCheckBtn").is_enabled()
    assert _read_scope(page) == before
    assert "scope-save-failure.example.invalid" not in _read_scope(page)["in_scope"]


def test_scope_import_rejects_incomplete_scope_json_without_clearing_exclusions(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    page.locator("#openImportDrawerBtn").click()
    page.locator("#importDrawer textarea").fill(json.dumps({
        "engagement": "incomplete import",
        "in_scope": ["scope-import-incomplete.example.invalid"],
    }))
    page.locator("#executeImportBtn").click()
    assert "both in_scope and out_of_scope lists" in page.locator("#scope-ui-notice").inner_text()
    assert _read_scope(page) == before


def test_scope_enforcement_toggle_requires_confirmation_to_disable_and_can_reenable(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    # Earlier browser tests share this worker's live server. Re-establish the
    # enabled precondition explicitly, then restore the original state below.
    if before["enabled"] is not True:
        result = _save_scope(page, {**before, "enabled": True})
        assert result["status"] == 200
        page.reload()
        _wait_loaded(page)
    assert _read_scope(page)["enabled"] is True
    toggle = page.locator("#toggleScopeEnforcementBtn")
    assert toggle.is_enabled()
    assert toggle.inner_text() == "Disable enforcement"
    assert toggle.get_attribute("aria-pressed") == "true"

    try:
        page.once("dialog", lambda dialog: dialog.dismiss())
        toggle.click()
        assert _read_scope(page)["enabled"] is True
        assert toggle.inner_text() == "Disable enforcement"

        page.once("dialog", lambda dialog: dialog.accept())
        toggle.click()
        page.wait_for_function(
            "() => document.querySelector('#scopeStatusLabel')?.textContent === 'Enforcement disabled'",
            timeout=5000,
        )
        assert _read_scope(page)["enabled"] is False
        assert toggle.inner_text() == "Enable enforcement"
        assert toggle.get_attribute("aria-pressed") == "false"

        toggle.click()
        page.wait_for_function(
            "() => document.querySelector('#scopeStatusLabel')?.textContent === 'Enforcement enabled'",
            timeout=5000,
        )
        assert _read_scope(page)["enabled"] is True
        assert toggle.inner_text() == "Disable enforcement"
    finally:
        _restore_scope(page, before)


def test_scope_enforcement_toggle_is_locked_during_save(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    _wait_loaded(page)
    before = _read_scope(page)
    # The live server is shared within a worker; do not assume another test
    # left enforcement enabled.
    if before["enabled"] is not True:
        result = _save_scope(page, {**before, "enabled": True})
        assert result["status"] == 200
        page.reload()
        _wait_loaded(page)

    try:
        page.evaluate("""() => {
          const originalFetch = window.fetch.bind(window);
          window.__restoreScopeFetch = () => { window.fetch = originalFetch; };
          window.fetch = (url, options = {}) => {
            if (url === "/api/scope" && options.method === "POST") {
              const payload = JSON.parse(options.body);
              return new Promise(resolve => {
                window.__resolveScopeToggle = () => resolve(new Response(JSON.stringify(payload), {
                  status: 200,
                  headers: {"Content-Type": "application/json"}
                }));
              });
            }
            return originalFetch(url, options);
          };
        }""")
        page.once("dialog", lambda dialog: dialog.accept())
        page.locator("#toggleScopeEnforcementBtn").click()
        page.wait_for_function("() => typeof window.__resolveScopeToggle === 'function'", timeout=5000)
        assert page.locator("#toggleScopeEnforcementBtn").is_disabled()
        page.evaluate("() => window.__resolveScopeToggle()")
        page.wait_for_function(
            "() => document.querySelector('#scopeStatusLabel')?.textContent === 'Enforcement disabled'",
            timeout=5000,
        )
        assert page.locator("#toggleScopeEnforcementBtn").is_enabled()
    finally:
        page.evaluate("() => window.__restoreScopeFetch?.()")
        _restore_scope(page, before)
