"""Cross-page browser coverage for the integrated canonical UI v2 pages."""
from __future__ import annotations


def test_core_pages_navigate_without_leaving_ui_v2(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/findings")
    assert response is not None and response.status == 200

    page.locator('a[data-path="dashboard-zero-state"]').click()
    assert page.url.endswith("/ui-v2")
    assert page.locator('a[data-path="scope-and-targets"]').is_visible()

    page.locator('a[data-path="scope-and-targets"]').click()
    assert page.url.endswith("/ui-v2/scope")
    assert page.locator("h1").first.is_visible()

    page.locator('a[data-path="run-and-orchestration"]').click()
    assert page.url.endswith("/ui-v2/run")
    page.locator("#run-target-input").wait_for(state="visible", timeout=5000)
    assert page.locator("#run-target-input").is_visible()

    page.locator('a[data-path="trust-layer-and-findings"]').click()
    assert page.url.endswith("/ui-v2/findings")
    assert page.locator("#whaxon-findings-list").is_visible()


def test_ui_v2_entry_route_opens_integrated_interface(page, live_server):
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    assert page.url.endswith("/ui-v2")
    assert page.locator('a[data-path="dashboard-zero-state"]').get_attribute("href") == "/ui-v2"
    assert page.locator('a[data-path="scope-and-targets"]').is_visible()



def test_dashboard_job_history_filter_has_an_accessible_name(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    filter_input = page.get_by_role(
        "textbox", name="Filter recent job history by ID, target, or tool"
    )
    assert filter_input.is_visible()
    filter_input.fill("no-such-job")
    assert page.get_by_role("table", name="Recent recorded WHAXON jobs").is_visible()
    assert page.get_by_text("No job history has been recorded yet.").count() == 0



def test_findings_filter_has_an_accessible_name(page, live_server):
    page.goto(f"{live_server}/ui-v2/findings")
    filter_input = page.get_by_role(
        "textbox", name="Filter findings by proof pattern, URL, or CVE"
    )
    assert filter_input.is_visible()
    filter_input.fill("no-such-finding")
    assert page.locator("#whaxon-findings-list").is_visible()


def test_dashboard_uses_live_state_and_hides_fake_engagements(page, live_server):
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.textContent.includes('No job history') "
        "|| document.querySelector('table tbody tr')?.textContent.length > 0",
        timeout=5000,
    )
    html = response.text()
    assert "api.internal.corp" not in html
    assert "identity.gateway.corp" not in html
    assert "CVE-2023-38606" not in html
    assert page.locator('a[data-path="scope-and-targets"]').get_attribute("href") == "/ui-v2/scope"
    assert page.locator('a[data-path="run-and-orchestration"]').get_attribute("href") == "/ui-v2/run"
    assert page.locator('a[data-path="trust-layer-and-findings"]').get_attribute("href") == "/ui-v2/findings"


def test_dashboard_navigation_exposes_all_advanced_workspaces(page, live_server):
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    expected = {
        "attack-surface-and-continuous-monitoring": "/ui-v2/monitoring",
        "bug-bounty-and-live-browser-studio": "/ui-v2/bug-bounty",
        "ptaas-client-portal": "/ui-v2/ptaas",
        "threat-intel-and-exploit-arsenal": "/ui-v2/threat-intel",
        "bas-and-detection-validation": "/ui-v2/bas",
        "compliance-and-framework-crosswalk": "/ui-v2/compliance",
        "trust-layer-approvals-queue-modal": "/ui-v2/approvals",
    }
    for data_path, href in expected.items():
        link = page.locator(f'a[data-path="{data_path}"]')
        assert link.is_visible(), f"missing visible navigation link: {data_path}"
        assert link.get_attribute("href") == href
