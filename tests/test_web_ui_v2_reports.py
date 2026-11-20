"""Browser coverage for the canonical WHAXON v2 live reports page."""
from __future__ import annotations


def test_reports_page_uses_live_report_endpoints_and_hides_sample_evidence(page, live_server):
    json_response = page.request.get(f"{live_server}/api/report?format=json")
    markdown_response = page.request.get(f"{live_server}/api/report?format=md")
    assert json_response.status == 200
    assert markdown_response.status == 200

    response = page.goto(f"{live_server}/ui-v2/reports")
    assert response is not None and response.status == 200
    assert page.locator("#whaxon-live-report").is_visible()
    assert page.locator("#live-report-json").is_visible()
    assert page.locator("#live-report-md").is_visible()
    for label in ("All Gaps", "Policy", "Safety"):
        assert page.get_by_role("button", name=label, exact=False).count() == 0

    visible = page.locator("body").inner_text()
    for marker in (
        "api.internal.corp",
        "ENG-2026-X892",
        "FINDING-SQLI-001",
        "raw_nmap_syn_scan",
        "sqlmap_session_dump",
        "burp_traffic_proxy",
    ):
        assert marker not in visible, f"Illustrative evidence must not appear as live data: {marker}"


def test_reports_json_and_markdown_export_buttons_download_live_reports(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/reports")
    assert response is not None and response.status == 200

    with page.expect_download() as json_download:
        page.locator("#live-report-json").click()
    assert json_download.value.suggested_filename == "whaxon-report.json"

    with page.expect_download() as markdown_download:
        page.locator("#live-report-md").click()
    assert markdown_download.value.suggested_filename == "whaxon-report.md"


def test_reports_preview_opens_and_closes(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/reports")
    assert response is not None and response.status == 200
    modal = page.locator("#previewModal")
    assert not modal.is_visible()
    page.locator("#live-report-preview").click()
    assert modal.is_visible()
    page.locator("#closePreviewBtn").click()
    assert not modal.is_visible()



def test_reports_reference_configuration_is_disabled_and_evidence_availability_is_truthful(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/reports")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#live-report-summary')?.textContent.includes('Generated from the current WHAXON report API')",
        timeout=8000,
    )
    selectors = page.locator('input[type="checkbox"]')
    assert selectors.count() >= 4
    for index in range(selectors.count()):
        assert selectors.nth(index).is_disabled()
        assert selectors.nth(index).is_checked() is False
    assert page.locator("#live-evidence-unavailable").is_visible()
    assert "NOT CONNECTED" in page.locator("body").inner_text()
    assert "SYNCED" not in page.locator("body").inner_text()
    assert "Reference layout only; this selection is not applied to live exports." in page.locator("body").inner_text()
    assert page.get_by_role("button", name="Export JSON", exact=True).is_enabled()
    assert page.get_by_role("button", name="Download Markdown", exact=True).is_enabled()


def test_reports_unavailable_state_hides_samples_and_disables_exports(page, live_server):
    page.route(
        "**/api/report**",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"report service unavailable"}',
        ),
    )
    response = page.goto(f"{live_server}/ui-v2/reports")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#live-report-summary')?.textContent.includes('could not be loaded')",
        timeout=5000,
    )

    for control in (
        page.locator("#live-report-json"),
        page.locator("#live-report-md"),
        page.locator("button").filter(has_text="Export Findings (.json)"),
        page.locator("button").filter(has_text="Download Full Report (.pdf)"),
    ):
        assert control.is_disabled() or control.is_hidden()

    assert page.get_by_role("button", name="All Gaps", exact=False).count() == 0
    raw_links = page.locator('a[href="#"]').filter(has_text="Raw")
    assert raw_links.count() == 4
    assert all(raw_links.nth(index).is_hidden() for index in range(raw_links.count()))
    visible = page.locator("body").inner_text()
    for marker in (
        "api.internal.corp",
        "ENG-2026-X892",
        "FINDING-SQLI-001",
        "raw_nmap_syn_scan",
        "sqlmap_session_dump",
        "burp_traffic_proxy",
        "Sample Deterministic Proof",
    ):
        assert marker not in visible, f"Illustrative evidence appeared while live reporting was unavailable: {marker}"
