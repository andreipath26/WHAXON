"""Browser tests for live dashboard controls and operational actions."""
from __future__ import annotations

import json
import re

import pytest


def test_dashboard_new_engagement_control_opens_scope(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    page.locator("#dashboard-engagement-selector").click()
    assert page.url.endswith("/ui-v2/scope")


def test_dashboard_filter_narrows_live_job_history(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => [...document.querySelectorAll('table tbody tr')].some(row => row.textContent.includes('seed-job-1'))",
        timeout=8000,
    )
    filter_input = page.get_by_role("textbox", name="Filter recent job history by ID, target, or tool")
    filter_input.fill("seed-job-1")
    visible_rows = page.locator("table tbody tr:visible")
    assert visible_rows.count() == 1
    assert "seed-job-1" in visible_rows.first.inner_text()
    filter_input.fill("nikto")
    assert visible_rows.count() == 1
    assert "seed-job-2" in visible_rows.first.inner_text()
    filter_input.fill("")
    assert visible_rows.count() >= 2
    assert "seed-job-1" in visible_rows.all_inner_texts()[0] or any("seed-job-1" in row for row in visible_rows.all_inner_texts())
    assert any("seed-job-2" in row for row in visible_rows.all_inner_texts())


def test_dashboard_exports_live_history_as_json(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    with page.expect_download() as download_info:
        page.get_by_role("button", name=re.compile(r"Export Archive")).click()
    download = download_info.value
    assert download.suggested_filename.startswith("whaxon-history-")
    assert download.suggested_filename.endswith(".json")
    path = download.path()
    assert path is not None
    with open(path, encoding="utf-8") as file:
        payload = json.load(file)
    assert isinstance(payload.get("jobs"), list)
    exported_ids = {job.get("id") or job.get("job_id") for job in payload["jobs"]}
    assert {"seed-job-1", "seed-job-2"}.issubset(exported_ids)



def test_dashboard_emergency_halt_uses_live_active_jobs_endpoint(page, live_server, workflow_halt_sources):
    calls = []

    workflow_halt_sources(jobs=[{
        "id": "running-job-1", "tool": "nmap", "target": "127.0.0.1",
        "status": "running", "engine_v2_owned": False,
    }])

    def cancel_job(route):
        calls.append({"method": route.request.method, "url": route.request.url})
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"ok":true,"job_id":"running-job-1"}',
        )

    page.route("**/api/jobs/running-job-1/cancel", cancel_job)
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    page.get_by_role("button", name=re.compile(r"Emergency Halt Scan")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('Cancellation requested for 1 of 1')",
        timeout=5000,
    )
    assert len(calls) == 1
    assert calls[0]["method"] == "POST"


def test_dashboard_emergency_halt_is_honest_when_no_jobs_are_active(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    page.get_by_role("button", name=re.compile(r"Emergency Halt Scan")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('No running jobs or durable workflow requests were found')",
        timeout=5000,
    )


def test_dashboard_emergency_halt_cancels_durable_v2_run_requests(page, live_server, workflow_halt_sources):
    calls = []
    workflow_halt_sources(active_requests=[{
        "id": "v2-request-1", "plan_id": "v2-plan", "status": "running", "submitted_at": 1,
    }])
    def cancel_run(route):
        calls.append({"method": route.request.method, "url": route.request.url})
        route.fulfill(
            status=200, content_type="application/json",
            body='{"cancellation_requested":true,"external_effects_stopped":false}',
        )
    page.route("**/api/v2/workflow-runs/v2-request-1/cancel", cancel_run)
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    page.get_by_role("button", name=re.compile(r"Emergency Halt Scan")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('0 of 0 legacy job(s) and 1 of 1 durable workflow run(s)')",
        timeout=8000,
    )
    status = page.locator("#dashboard-action-status").inner_text()
    assert "not confirmed stopped" in status
    assert len(calls) == 1 and calls[0]["method"] == "POST"


def test_dashboard_cli_help_and_credentials_controls_explain_real_setup(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    page.get_by_role("button", name=re.compile(r"CLI Help")).click()
    assert "whaxon --help" in page.locator("#dashboard-action-status").inner_text()
    page.get_by_role("button", name=re.compile(r"Update Credentials Now")).click()
    assert "WHAXON_AUTH_USER" in page.locator("#dashboard-action-status").inner_text()


def test_dashboard_does_not_claim_default_credentials_are_detected_without_checking(page, live_server):
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    html = response.text()
    assert "Default Local Engine Credentials Detected" not in html
    assert "whaxon:whaxon" not in html
    assert "Credential Configuration Before Network Exposure" in html
    assert "0.0%" not in html
    assert "STAGE 0/7" not in html
    assert "PLUGINS READY" not in html
    assert "0 FALSE POSITIVES" not in html

def test_dashboard_credential_notice_reflects_live_status_api(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    status = page.evaluate("() => fetch('/api/status').then(response => response.json())")
    page.wait_for_function(
        """(defaultCreds) => {
          const labels = [...document.querySelectorAll('span')].map(node => node.textContent.trim());
          return defaultCreds
            ? labels.includes('Default Credentials Detected')
            : labels.includes('Credential Configuration Status');
        }""",
        arg=status["default_creds"],
        timeout=8000,
    )

def test_dashboard_artifact_card_supports_drop_and_rejects_unwired_formats(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    assert page.locator("h2").filter(has_text="Import Existing Assessment Profile").is_visible()
    page.evaluate(
        """() => {
          const heading = [...document.querySelectorAll('h2')].find(node =>
            node.textContent.trim() === 'Import Existing Assessment Profile'
          );
          const card = heading.closest('.group.relative.flex.flex-col');
          const transfer = new DataTransfer();
          transfer.items.add(new File(['not an importable artifact'], 'unsupported.txt', {type: 'text/plain'}));
          card.dispatchEvent(new DragEvent('drop', {bubbles: true, cancelable: true, dataTransfer: transfer}));
        }"""
    )
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('Nmap and scope-profile imports are not wired yet')",
        timeout=5000,
    )


def test_dashboard_upload_artifact_button_opens_file_picker_and_imports_xml(page, live_server):
    calls = []

    def fulfill_import(route):
        calls.append(route.request.method)
        route.fulfill(status=200, content_type="application/json", body='{"count": 2}')

    page.route("**/api/import/burp", fulfill_import)
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached", timeout=8000)
    with page.expect_file_chooser() as chooser_info:
        page.get_by_role("button", name=re.compile(r"Upload Artifact")).click()
    chooser_info.value.set_files({
        "name": "dashboard-upload.xml",
        "mimeType": "application/xml",
        "buffer": b'<?xml version="1.0"?><issues></issues>',
    })
    page.wait_for_url("**/ui-v2/findings", timeout=10000)
    assert calls == ["POST"]


def test_dashboard_posts_burp_xml_and_opens_findings(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    calls = []

    def fulfill_import(route):
        calls.append({
            "method": route.request.method,
            "content_type": route.request.headers.get("content-type", ""),
        })
        route.fulfill(status=200, content_type="application/json", body='{"count": 1}')

    page.route("**/api/import/burp", fulfill_import)
    page.evaluate(
        """() => {
          const heading = [...document.querySelectorAll('h2')].find(node =>
            node.textContent.trim() === 'Import Existing Assessment Profile'
          );
          const card = heading.closest('.group.relative.flex.flex-col');
          const xml = '<?xml version="1.0"?><issues><issue><name>Dashboard import test</name><host>http://127.0.0.1</host><path>/dashboard-test</path><severity>High</severity><confidence>Certain</confidence></issue></issues>';
          const transfer = new DataTransfer();
          transfer.items.add(new File([xml], 'dashboard-import.xml', {type: 'application/xml'}));
          card.dispatchEvent(new DragEvent('drop', {bubbles: true, cancelable: true, dataTransfer: transfer}));
        }"""
    )
    page.wait_for_url("**/ui-v2/findings", timeout=10000)
    assert len(calls) == 1
    assert calls[0]["method"] == "POST"
    assert "multipart/form-data" in calls[0]["content_type"]



def test_dashboard_does_not_claim_scope_rule_when_target_list_is_empty(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"enabled":true,"in_scope":[],"engagement":"empty-scope-test"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('NO TARGET RULE CONFIGURED')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "(NO TARGET RULE)" in header
    assert "target: no target configured" in header.lower()
    assert "(CONFIGURED RULE)" not in header
    assert "SCOPE ENFORCEMENT ENABLED" not in header




def test_dashboard_shows_api_failures_as_unavailable_not_zero_or_empty(page, live_server):
    for endpoint in ("/api/history", "/api/jobs/active", "/api/report?format=json", "/api/tools"):
        page.route(
            f"**{endpoint}",
            lambda route: route.fulfill(
                status=503,
                content_type="application/json",
                body='{"error":"service unavailable"}',
            ),
        )

    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        """() => document.querySelector('table tbody')?.innerText.includes('Live job history is unavailable')""",
        timeout=8000,
    )

    cards = page.locator(".rounded-lg.bg-surface-container-low.p-space-md")
    assert "—" in cards.filter(has_text="Active Scans").inner_text()
    assert "—" in cards.filter(has_text="Verified Findings").inner_text()
    assert "—" in cards.filter(has_text="Active Adapters").inner_text()
    assert page.locator("table tbody").get_by_text("No job history has been recorded yet.").count() == 0


 
def test_dashboard_recent_job_rows_use_real_api_fields(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.innerText.includes('seed-job-1')",
        timeout=8000,
    )
    rows = page.locator("table tbody tr")
    assert "nmap" in rows.filter(has_text="seed-job-1").inner_text().lower()
    timeline = rows.filter(has_text="seed-job-1").locator("td").nth(3).inner_text()
    assert timeline not in {"Not recorded", "—"}
    assert rows.filter(has_text="seed-job-1").get_by_role("link", name="View History").get_attribute("href") == "/ui-v2/history"
    assert page.locator("#dashboard-runtime-state").inner_text() == "No active jobs"
    assert int(page.locator("#dashboard-history-count").inner_text()) == rows.count()
    assert rows.count() >= 2


def test_dashboard_add_new_engagement_control_is_wired(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    page.get_by_role("button", name=re.compile(r"add New")).click()
    assert page.url.endswith("/ui-v2/scope")


def test_dashboard_session_strip_uses_live_scope_and_avoids_fake_runtime_claims(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"enabled":true,"in_scope":["https://example.test"],"engagement":"Example engagement"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-session-engagement')?.textContent === 'Example engagement'",
        timeout=8000,
    )
    assert page.locator("#dashboard-session-target").inner_text() == "https://example.test"
    assert page.get_by_text("Live job status").is_visible()
    assert page.get_by_text("Version not reported").is_visible()
    assert page.get_by_text("Pre-Flight Boundary Checklist").is_hidden()
    assert page.get_by_text("Explore Lab Environments").is_hidden()


def test_dashboard_reports_scope_unavailable_instead_of_claiming_no_rules(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"scope backend unavailable"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('SCOPE STATUS UNAVAILABLE')",
        timeout=8000,
    )
    header = page.locator("header").inner_text()
    assert "(STATUS UNAVAILABLE)" in header
    assert "target: unavailable" in header.lower()
    assert "(NO TARGET RULE)" not in header
    assert "NO TARGET RULE CONFIGURED" not in header
    assert "SCOPE ENFORCEMENT ENABLED" not in header


@pytest.mark.parametrize(
    ("button_name", "expected_path"),
    [
        (re.compile(r"Open Scope Setup"), "/ui-v2/scope"),
        (re.compile(r"Start New Engagement"), "/ui-v2/scope"),
        (re.compile(r"Switch Target Session"), "/ui-v2/scope"),
        (re.compile(r"Terminal Log"), "/ui-v2/run"),
    ],
)
def test_dashboard_quick_actions_navigate_to_their_real_workspaces(page, live_server, button_name, expected_path):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    page.get_by_role("button", name=button_name).click()
    assert page.url.endswith(expected_path)



def test_dashboard_mobile_navigation_opens_closes_and_restores_focus(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2")

    menu = page.locator(".dashboard-mobile-menu")
    assert menu.is_visible()
    assert menu.get_attribute("aria-label") == "Open navigation"
    assert menu.get_attribute("aria-expanded") == "false"
    menu.click()

    assert page.locator(".dashboard-mobile-nav-backdrop").is_visible()
    assert menu.get_attribute("aria-label") == "Close navigation"
    assert menu.get_attribute("aria-expanded") == "true"
    assert page.locator("body").evaluate(
        "element => element.classList.contains('dashboard-mobile-nav-open')"
    )
    assert page.locator('aside a[data-path="dashboard-zero-state"]').evaluate(
        "element => document.activeElement === element"
    )

    page.keyboard.press("Escape")
    assert menu.get_attribute("aria-label") == "Open navigation"
    assert menu.get_attribute("aria-expanded") == "false"
    assert not page.locator("body").evaluate(
        "element => element.classList.contains('dashboard-mobile-nav-open')"
    )
    assert menu.evaluate("element => document.activeElement === element")

    menu.click()
    page.locator(".dashboard-mobile-nav-backdrop").click(position={"x": 380, "y": 800})
    assert menu.get_attribute("aria-expanded") == "false"
    assert menu.evaluate("element => document.activeElement === element")



def test_dashboard_closed_mobile_sidebar_is_removed_from_keyboard_navigation(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2")
    sidebar = page.locator("body > aside")
    menu = page.locator(".dashboard-mobile-menu")

    assert sidebar.get_attribute("aria-hidden") == "true"
    assert sidebar.evaluate("element => element.inert")
    menu.click()
    assert sidebar.get_attribute("aria-hidden") is None
    assert not sidebar.evaluate("element => element.inert")
    page.keyboard.press("Escape")
    assert sidebar.get_attribute("aria-hidden") == "true"
    assert sidebar.evaluate("element => element.inert")


def test_dashboard_mobile_navigation_closes_after_route_selection(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2")
    page.get_by_role("button", name="Open navigation").click()
    page.locator('aside a[data-path="scope-and-targets"]').click()
    page.wait_for_url("**/ui-v2/scope")
    assert not page.locator("body").evaluate(
        "element => element.classList.contains('dashboard-mobile-nav-open')"
    )



def test_dashboard_all_visible_enabled_buttons_have_real_actions_and_names(page, live_server):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    result = page.locator("button:visible:not(:disabled)").evaluate_all(
        """buttons => ({
          unwired: buttons.filter(button =>
            button.dataset.dashboardWired !== 'true' &&
            !button.classList.contains('dashboard-mobile-menu')
          ).map(button => button.innerText.trim()),
          unnamed: buttons.filter(button =>
            !(button.getAttribute('aria-label') || button.innerText || '').trim()
          ).map(button => button.outerHTML.slice(0, 160))
        })"""
    )
    assert result["unwired"] == []
    assert result["unnamed"] == []
    assert page.get_by_role("heading", name="Recent Job History").is_visible()
    assert page.get_by_role("table", name="Recent recorded WHAXON jobs").is_visible()


def test_dashboard_mobile_layout_has_no_horizontal_page_overflow(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector(".dashboard-mobile-menu", state="attached")
    assert page.evaluate(
        "() => document.documentElement.scrollWidth <= window.innerWidth"
    )


def test_dashboard_mobile_menu_is_not_shown_on_desktop(page, live_server):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector(".dashboard-mobile-menu", state="attached")
    assert page.locator(".dashboard-mobile-menu").count() == 1
    assert not page.locator(".dashboard-mobile-menu").is_visible()


def test_dashboard_sidebar_links_resolve_to_real_ui_routes(page, live_server):
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => [...document.querySelectorAll('aside a[data-path]')].every(link => link.href && link.href !== location.href + '#')",
        timeout=8000,
    )

    links = page.locator("aside a[data-path]")
    assert links.count() >= 15
    for link in links.all():
        href = link.get_attribute("href")
        assert href and href.startswith("/ui-v2"), link.inner_text()
        response = page.request.get(f"{live_server}{href}")
        assert response.status == 200, f"{link.inner_text()} -> {href}: {response.status}"


def test_dashboard_lab_deployment_is_not_present_as_a_live_action(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    assert page.get_by_role("button", name=re.compile(r"Deploy Mock")).count() == 0
    assert page.get_by_text("Explore Lab Environments").is_hidden()

def test_dashboard_engine_state_is_driven_by_live_health_endpoint(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-engine-state')?.textContent === 'ENGINE ONLINE'",
        timeout=8000,
    )
    assert page.get_by_text("WHAXON PLATFORM", exact=True).is_visible()
    assert page.get_by_text("WHAXON OS 3.12-ALPHA", exact=True).count() == 0


def test_dashboard_engine_state_reports_health_failure(page, live_server):
    page.route(
        "**/api/health/simple",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"ok":false}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-engine-state')?.textContent === 'ENGINE UNAVAILABLE'",
        timeout=8000,
    )


def test_dashboard_export_rejects_malformed_history_without_false_success(page, live_server):
    """HTTP 200 with invalid history must not fabricate an empty archive."""
    page.route(
        "**/api/history",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"error":"history temporarily unavailable"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    page.get_by_role("button", name=re.compile(r"Export Archive")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('History API returned an invalid response')",
        timeout=5000,
    )
    assert "Exported 0 recorded job" not in page.locator("#dashboard-action-status").inner_text()
    assert page.locator("#dashboard-action-status").get_attribute("role") == "alert"


def test_dashboard_health_requires_actual_boolean_true(page, live_server):
    """Malformed health data must never claim a connected engine."""
    page.route(
        "**/api/health/simple",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"ok":"true"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-engine-state')?.textContent === 'ENGINE UNAVAILABLE'",
        timeout=8000,
    )
    assert page.get_by_text("ENGINE ONLINE", exact=True).count() == 0


def test_dashboard_import_rejects_invalid_success_response_without_navigation(page, live_server):
    """A malformed successful upload response must not claim findings exist."""
    page.route(
        "**/api/import/burp",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"count":"not-a-number"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    with page.expect_file_chooser() as picker:
        page.get_by_role("button", name=re.compile(r"Upload Artifact")).click()
    picker.value.set_files({
        "name": "test-burp.xml", "mimeType": "application/xml",
        "buffer": b'<?xml version="1.0"?><issues></issues>',
    })
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('Import API returned an invalid response')",
        timeout=8000,
    )
    assert page.url.endswith("/ui-v2")
    assert "Imported" not in page.locator("#dashboard-action-status").inner_text()


def test_dashboard_invalid_history_timestamp_is_honest(page, live_server):
    """Bad historical dates must not render 'Invalid Date' as real telemetry."""
    page.route(
        "**/api/history",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='[{"id":"bad-clock","tool":"nmap","target":"192.0.2.10","status":"finished","created_at":"nonsense"}]',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('bad-clock')",
        timeout=8000,
    )
    row = page.locator("table tbody tr").filter(has_text="bad-clock")
    assert "Not recorded" in row.inner_text()
    assert "Invalid Date" not in row.inner_text()


def test_dashboard_null_scope_payload_fails_closed_without_losing_history(page, live_server):
    """A successful HTTP code with null scope cannot invent an authorization rule."""
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body="null",
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('SCOPE STATUS UNAVAILABLE')",
        timeout=8000,
    )
    assert "target: unavailable" in page.locator("header").inner_text().lower()
    assert "scope enforcement enabled" not in page.locator("header").inner_text().lower()
    assert page.locator("table tbody").get_by_text("seed-job-1", exact=False).count() >= 1


def test_dashboard_null_status_payload_preserves_history_without_fake_engagement(page, live_server):
    """Malformed status data must not abort all independent dashboard panels."""
    page.route(
        "**/api/status",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body="null",
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('seed-job-1')",
        timeout=8000,
    )
    assert page.locator("#dashboard-history-count").inner_text() != "—"
    assert page.get_by_text("Default Credentials Detected").count() == 0
    assert page.get_by_text("Credential Status Unavailable").count() >= 1


def test_dashboard_malformed_report_preserves_independent_live_panels(page, live_server):
    """Bad nested report data must not halt history, scope or tool panels."""
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"jobs":[{"findings":null},{"findings":[null]}]}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('seed-job-1')",
        timeout=8000,
    )
    assert "—" in page.locator(".rounded-lg.bg-surface-container-low.p-space-md").filter(
        has_text="Verified Findings"
    ).inner_text()
    assert "STATUS UNAVAILABLE" in page.locator(
        ".rounded-lg.bg-surface-container-low.p-space-md"
    ).filter(has_text="Verified Findings").inner_text()
    assert page.locator("#dashboard-history-count").inner_text() != "—"


def test_dashboard_malformed_tools_response_is_unavailable_not_zero(page, live_server):
    page.route(
        "**/api/tools",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body='[null]',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('seed-job-1')",
        timeout=8000,
    )
    assert "STATUS UNAVAILABLE" in page.locator(
        ".rounded-lg.bg-surface-container-low.p-space-md"
    ).filter(has_text="Active Adapters").inner_text()


def test_dashboard_malformed_history_rows_do_not_crash_independent_panels(page, live_server):
    page.route(
        "**/api/history",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body='[null]',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('Live job history is unavailable')",
        timeout=8000,
    )
    assert page.locator("#dashboard-history-count").inner_text() == "—"
    assert page.locator("#dashboard-engine-state").inner_text() == "ENGINE ONLINE"


def test_dashboard_emergency_halt_reports_partial_failures_and_continues(page, live_server, workflow_halt_sources):
    calls = []
    workflow_halt_sources(jobs=[
        {"id": "good", "engine_v2_owned": False},
        {"id": "bad", "engine_v2_owned": False},
    ])
    def cancel(route):
        calls.append(route.request.url)
        if route.request.url.endswith("/bad/cancel"):
            route.fulfill(status=503, content_type="application/json", body='{"error":"unavailable"}')
        else:
            route.fulfill(status=200, content_type="application/json", body='{"ok":true}')
    page.route("**/api/jobs/*/cancel", cancel)
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    page.get_by_role("button", name=re.compile(r"Emergency Halt Scan")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('Cancellation requested for 1 of 2')",
        timeout=8000,
    )
    assert len(calls) == 2
    assert "text-error" in page.locator("#dashboard-action-status").get_attribute("class")


def test_dashboard_missing_enforcement_flag_never_claims_scope_enforced(page, live_server):
    """HTTP 200 is not permission to assert the scope enforcement switch."""
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"in_scope":["192.0.2.10"],"engagement":"Fixture"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('SCOPE STATUS UNAVAILABLE')",
        timeout=8000,
    )
    assert "SCOPE ENFORCEMENT ENABLED" not in page.locator("header").inner_text()


def test_dashboard_filter_no_results_has_explicit_empty_state(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('seed-job-1')",
        timeout=8000,
    )
    field = page.get_by_role("textbox", name="Filter recent job history by ID, target, or tool")
    field.fill("does-not-exist-in-history")
    assert page.get_by_text("No recorded jobs match this filter.").is_visible()
    assert page.locator('table tbody tr[data-dashboard-no-match]').count() == 1
    field.fill("seed-job-1")
    assert page.locator('table tbody tr[data-dashboard-no-match]').count() == 0
    assert page.locator("table tbody tr:visible").count() == 1


def test_dashboard_filter_preserves_unavailable_state_when_history_fails(page, live_server):
    page.route(
        "**/api/history",
        lambda route: route.fulfill(
            status=503, content_type="application/json",
            body='{"error":"temporarily unavailable"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('Live job history is unavailable')",
        timeout=8000,
    )
    page.get_by_role("textbox", name="Filter recent job history by ID, target, or tool").fill("nmap")
    assert page.get_by_text("Live job history is unavailable.", exact=False).is_visible()
    assert page.get_by_text("No recorded jobs match this filter.").count() == 0


def test_dashboard_malformed_scope_rules_do_not_claim_authorization(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"enabled":true,"in_scope":{"not":"a-list"},"engagement":"Fixture"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('SCOPE STATUS UNAVAILABLE')",
        timeout=8000,
    )
    assert "target: unavailable" in page.locator("header").inner_text().lower()
    assert "SCOPE ENFORCEMENT ENABLED" not in page.locator("header").inner_text()


def test_dashboard_adapter_count_requires_actual_boolean_readiness(page, live_server):
    page.route(
        "**/api/tools",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='[{"available":"false","adapter_available":"yes","binary_available":"true"}]',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('seed-job-1')",
        timeout=8000,
    )
    card = page.locator(".rounded-lg.bg-surface-container-low.p-space-md").filter(
        has_text="Active Adapters"
    )
    assert "TOOLS AVAILABLE" in card.inner_text()
    assert "0" in card.inner_text()


def test_dashboard_invalid_engagement_type_is_not_rendered_as_object(page, live_server):
    page.route(
        "**/api/status",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"engagement":{"unexpected":"value"},"default_creds":false}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-session-engagement')?.textContent",
        timeout=8000,
    )
    assert "[object Object]" not in page.locator("#dashboard-session-engagement").inner_text()
    assert page.locator("#dashboard-session-engagement").inner_text() != "undefined"


def test_dashboard_verified_metric_requires_independent_verification_field(page, live_server):
    """Generic record status never promotes a candidate to a verified finding."""
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"jobs":[{"findings":[{"status":"verified","verification_status":"candidate"},'
                 '{"status":"verified"},{"verification_status":"verified"}]}]}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('seed-job-1')",
        timeout=8000,
    )
    card = page.locator(".rounded-lg.bg-surface-container-low.p-space-md").filter(
        has_text="Verified Findings"
    )
    assert "1" in card.inner_text()
    assert "0 FALSE POSITIVES" in card.inner_text()


def test_dashboard_mobile_menu_traps_keyboard_focus_and_escape_restores_button(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2")
    menu = page.get_by_role("button", name="Open navigation")
    menu.click()
    links = page.locator("aside a[href]:visible")
    assert links.count() >= 5
    first = links.first
    last = links.last
    first.focus()
    page.keyboard.press("Shift+Tab")
    assert last.evaluate("(node) => document.activeElement === node")
    page.keyboard.press("Tab")
    assert first.evaluate("(node) => document.activeElement === node")
    page.keyboard.press("Escape")
    assert menu.evaluate("(node) => document.activeElement === node")
    assert page.locator("body > aside").get_attribute("aria-hidden") == "true"


def test_dashboard_halt_never_calls_cancel_with_untrusted_object_identity(page, live_server, workflow_halt_sources):
    """Malformed active-job IDs cannot turn into arbitrary cancellation paths."""
    calls = []
    workflow_halt_sources(jobs=[{"id": {"bad": "value"}, "engine_v2_owned": False}])
    page.route(
        "**/api/jobs/*/cancel",
        lambda route: (calls.append(route.request.url), route.fulfill(
            status=200, content_type="application/json", body='{"ok":true}'
        )),
    )
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    page.get_by_role("button", name=re.compile("Emergency Halt Scan")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('Cancellation requested for 0 of 1 legacy job(s)')",
        timeout=8000,
    )
    assert calls == []
    assert page.locator("#dashboard-action-status").get_attribute("role") == "alert"


def test_dashboard_error_message_is_announced_as_accessibility_alert(page, live_server):
    page.route(
        "**/api/history",
        lambda route: route.fulfill(
            status=503, content_type="application/json",
            body='{"error":"unavailable"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    page.get_by_role("button", name=re.compile("Export Archive")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('History export failed')",
        timeout=8000,
    )
    assert page.locator("#dashboard-action-status").get_attribute("role") == "alert"


def test_dashboard_api_connection_abort_is_unavailable_not_empty(page, live_server):
    """An aborted transport must not show fabricated zero metrics."""
    for route_path in ("/api/history", "/api/tools", "/api/jobs/active"):
        page.route(
            f"**{route_path}",
            lambda route: route.abort("timedout"),
        )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.innerText.includes('Live job history is unavailable')",
        timeout=8000,
    )
    cards = page.locator(".rounded-lg.bg-surface-container-low.p-space-md")
    assert "STATUS UNAVAILABLE" in cards.filter(has_text="Active Scans").inner_text()
    assert "STATUS UNAVAILABLE" in cards.filter(has_text="Active Adapters").inner_text()
    assert page.locator("#dashboard-history-count").inner_text() == "—"


def test_dashboard_export_is_single_flight_during_pending_request(page, live_server):
    """Repeated Export clicks cannot cause simultaneous duplicate downloads."""
    calls = []
    def history(route):
        calls.append(route)
        # Keep export response pending until duplicate clicks have been attempted.
        if len(calls) > 1:
            route.fulfill(status=200, content_type="application/json", body="[]")
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    page.route("**/api/history", history)
    button = page.get_by_role("button", name=re.compile("Export Archive"))
    button.click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status') !== null",
        timeout=8000,
    )
    button.click()
    page.wait_for_timeout(150)
    assert len(calls) == 1
    calls[0].fulfill(status=200, content_type="application/json", body="[]")
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('Exported 0 recorded job')",
        timeout=8000,
    )


def test_dashboard_renders_untrusted_history_and_scope_as_text(page, live_server):
    """Records received from APIs must never be interpreted as executable HTML."""
    marker = '<img src=x onerror="window.__dashboardInjected=1">'
    import json
    page.route(
        "**/api/history",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body=json.dumps([{
                "id": "markup-record", "target": marker, "tool": "nmap",
                "status": "finished", "created_at": "2026-11-05T08:00:00Z",
            }]),
        ),
    )
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body=json.dumps({"enabled": True, "in_scope": [marker], "engagement": "Fixture"}),
        ),
    )
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('markup-record')",
        timeout=8000,
    )
    assert marker in page.locator("table tbody").inner_text()
    assert marker in page.locator("#dashboard-session-target").inner_text()
    assert page.evaluate("() => window.__dashboardInjected === 1") is False
    assert page.locator("table tbody img").count() == 0


def test_dashboard_all_visible_links_resolve_to_canonical_ui_pages(page, live_server):
    """Post-initialization navigation must expose no inert or unsafe anchors."""
    page.set_viewport_size({"width": 1280, "height": 900})
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => [...document.querySelectorAll('aside a[data-path]')].every(a => a.getAttribute('href')?.startsWith('/ui-v2'))",
        timeout=8000,
    )
    links = page.locator("a:visible").evaluate_all(
        """elements => elements.map(node => ({
          href: node.getAttribute('href'),
          name: (node.getAttribute('aria-label') || node.innerText || '').trim()
        }))"""
    )
    assert links
    assert all(link["name"] for link in links)
    assert all(link["href"] and link["href"].startswith("/ui-v2") for link in links)


def test_dashboard_rejected_cancel_never_claims_halt_succeeded(page, live_server, workflow_halt_sources):
    workflow_halt_sources(jobs=[{
        "id": "restricted-job", "status": "running", "engine_v2_owned": False,
    }])
    page.route(
        "**/api/jobs/restricted-job/cancel",
        lambda route: route.fulfill(
            status=403, content_type="application/json",
            body='{"error":"not authorized"}',
        ),
    )
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    page.get_by_role("button", name=re.compile("Emergency Halt Scan")).click()
    page.wait_for_function(
        "() => document.querySelector('#dashboard-action-status')?.textContent.includes('Cancellation requested for 0 of 1 legacy job(s)')",
        timeout=8000,
    )
    assert page.locator("#dashboard-action-status").get_attribute("role") == "alert"
    assert "1 of 1" not in page.locator("#dashboard-action-status").inner_text()


def test_dashboard_mobile_header_keeps_critical_actions_onscreen(page, live_server):
    """Neither Terminal Log nor Emergency Halt may be clipped on a phone."""
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_selector("#dashboard-action-status", state="attached")
    for name in ("Terminal Log", "Emergency Halt Scan"):
        button = page.get_by_role("button", name=name)
        assert button.is_visible(), name
        rect = button.bounding_box()
        assert rect is not None
        assert rect["x"] >= 0, (name, rect)
        assert rect["x"] + rect["width"] <= 390, (name, rect)
    assert page.get_by_role("button", name="Open navigation").is_visible()


def test_dashboard_mobile_history_columns_are_scrollable_and_named(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2")
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.innerText.includes('seed-job-1')",
        timeout=8000,
    )
    region = page.get_by_role("region", name="Job history table, scroll horizontally for all columns")
    assert region.is_visible()
    assert region.get_attribute("tabindex") == "0"
    assert page.get_by_text("Swipe or scroll sideways to view every job-history column.").is_visible()
    dimensions = region.evaluate(
        "el => ({scrollWidth:el.scrollWidth, clientWidth:el.clientWidth})"
    )
    assert dimensions["scrollWidth"] > dimensions["clientWidth"]
    region.evaluate("el => {el.scrollLeft = el.scrollWidth}")
    assert region.evaluate("el => el.scrollLeft") > 0
    assert page.locator("table").get_by_role("columnheader", name="Operational Actions").count() == 1


def test_dashboard_uses_packaged_stylesheet_not_runtime_tailwind_cdn(page, live_server):
    """A dashboard must not execute third-party utility CSS generation at runtime."""
    page.route("**/cdn.tailwindcss.com", lambda route: route.abort("blockedbyclient"))
    page.route("**/fonts.googleapis.com/**", lambda route: route.abort("blockedbyclient"))
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    assert 'src="https://cdn.tailwindcss.com"' not in response.text()
    assert 'href="/static/dashboard-v2.css"' in response.text()
    css_response = page.request.get(f"{live_server}/static/dashboard-v2.css")
    assert css_response.status == 200
    assert ".bg-background" in css_response.text()
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('seed-job-1')",
        timeout=8000,
    )
    assert page.evaluate(
        "() => getComputedStyle(document.body).backgroundColor"
    ) == "rgb(15, 19, 28)"


def test_dashboard_document_has_descriptive_browser_and_screen_reader_title(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    assert page.title() == "WHAXON — Security Operations Dashboard"


def test_dashboard_has_no_external_browser_asset_dependencies(page, live_server):
    """The security console must not send page-view telemetry to external CDNs."""
    external_requests = []
    def refuse_external(route):
        external_requests.append(route.request.url)
        route.abort("blockedbyclient")
    page.route("https://**/*", refuse_external)
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.innerText.includes('seed-job-1')",
        timeout=8000,
    )
    page.evaluate("() => document.fonts.ready")
    assert external_requests == []
    assert "fonts.googleapis.com" not in response.text()
    assert "lh3.googleusercontent.com" not in response.text()
    assert "cdn.tailwindcss.com" not in response.text()
    for path in (
        "/static/dashboard-v2.css",
        "/static/dashboard-fonts.css",
        "/static/dashboard-logo.jpg",
        "/static/dashboard-profile.jpg",
    ):
        assert page.request.get(f"{live_server}{path}").status == 200, path
    assert page.evaluate(
        "() => getComputedStyle(document.body).backgroundColor"
    ) == "rgb(15, 19, 28)"
    for alt in ("WHAXON Security Logo", "Profile"):
        image = page.get_by_role("img", name=alt)
        assert image.evaluate("(node) => node.naturalWidth > 0"), alt


def test_dashboard_bundled_font_css_has_no_third_party_urls(page, live_server):
    response = page.request.get(f"{live_server}/static/dashboard-fonts.css")
    assert response.status == 200
    css = response.text()
    assert "@font-face" in css
    assert "/static/dashboard-fonts/" in css
    assert "https://" not in css
