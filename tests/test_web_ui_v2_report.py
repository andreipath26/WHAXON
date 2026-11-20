"""Browser coverage for the canonical live report page (UI v2)."""
from __future__ import annotations

import json
import shutil

import pytest


def test_report_page_loads_and_uses_live_report_counts(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/report")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => [...document.querySelectorAll('main div')].some(n => "
        "document.documentElement.dataset.reportReady === 'true' && n.textContent.includes('Live report data:') && n.textContent.includes('findings'))",
        timeout=8000,
    )
    assert page.locator("#previewBtn").is_visible()
    assert page.get_by_role("button", name="Export Findings (.json)").is_visible()
    assert page.get_by_role("button", name="Download Full Report (.pdf)").is_visible()


def test_report_page_hides_illustrative_proof_and_evidence_panels(page, live_server):
    page.goto(f"{live_server}/ui-v2/report")
    page.wait_for_function(
        "() => [...document.querySelectorAll('main div')].some(n => "
        "document.documentElement.dataset.reportReady === 'true' && n.textContent.includes('Live report data:'))",
        timeout=8000,
    )
    assert page.get_by_text("Sample Deterministic Proof: FINDING-SQLI-001 (auth-endpoint)").is_hidden()
    assert page.get_by_role("heading", name="PTES Phase Execution & Telemetry Tracker").is_hidden()
    assert page.get_by_role("heading", name="Coverage Gap Matrix").is_hidden()
    assert page.get_by_role("heading", name="Report Synthesis & Compliance Profiler").is_visible()
    assert page.get_by_role("heading", name="Evidence Summary").is_hidden()
    assert page.get_by_role("heading", name="Local Evidence Locker").is_hidden()
    assert page.get_by_text("Scope Compliance & Verification").is_hidden()
    assert page.get_by_text("6 curl-verified").is_hidden()
    assert page.get_by_text("STRICT_WHITELIST").is_hidden()
    assert page.get_by_text("Select Report Modules to Compile").is_hidden()
    assert page.get_by_text("Correlate Standards & Compliance Matrix").is_hidden()
    assert page.get_by_text("6 deterministic findings with reproducible curl replay proofs.").is_hidden()


def test_report_preview_fetches_live_markdown_and_close_works(page, live_server):
    page.goto(f"{live_server}/ui-v2/report")
    page.wait_for_function(
        "() => document.documentElement.dataset.reportReady === 'true'",
        timeout=8000,
    )
    with page.expect_response(
        lambda response: response.request.method == "GET"
        and response.url.endswith("/api/report?format=md")
    ) as response_info:
        page.locator("#previewBtn").click()
    assert response_info.value.ok
    modal = page.locator("#previewModal")
    assert modal.is_visible()
    page.wait_for_function(
        "() => { const pre = document.querySelector('#previewModal pre'); "
        "return pre && pre.textContent.length > 0 && !pre.textContent.includes('Loading the current report preview'); }",
        timeout=8000,
    )
    assert "Live report preview will be loaded" not in modal.inner_text()
    page.locator("#closePreviewBtn").click()
    assert modal.is_hidden()


def test_report_exports_live_json_download(page, live_server):
    page.goto(f"{live_server}/ui-v2/report")
    page.wait_for_selector("#whaxon-report-status")
    with page.expect_download() as download_info:
        page.get_by_role("button", name="Export Findings (.json)").click()
    download = download_info.value
    assert download.suggested_filename == "whaxon-report.json"
    path = download.path()
    assert path is not None
    with open(path, encoding="utf-8") as file:
        report = json.load(file)
    assert isinstance(report.get("jobs"), list)
    assert isinstance(report.get("finding_count"), int)
    assert isinstance(report.get("generated"), str)


@pytest.mark.skipif(
    not (shutil.which("pandoc") and shutil.which("weasyprint")),
    reason="pandoc and weasyprint are validated in the Python 3.11 matrix lane",
)
def test_report_exports_pdf_download(page, live_server):
    page.goto(f"{live_server}/ui-v2/report")
    page.wait_for_selector("#whaxon-report-status")
    with page.expect_download() as download_info:
        page.get_by_role("button", name="Download Full Report (.pdf)").click()
    download = download_info.value
    assert download.suggested_filename == "whaxon-report.pdf"
    path = download.path()
    assert path is not None
    with open(path, "rb") as file:
        assert file.read(5) == b"%PDF-"


def test_report_api_failure_is_not_reported_as_zero_findings(page, live_server):
    def unavailable(route):
        route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"test report API outage"}',
        )

    page.route("**/api/report*format=json*", unavailable)
    page.goto(f"{live_server}/ui-v2/report")
    page.wait_for_function(
        "() => document.querySelector('#whaxon-report-status')?.textContent.includes('Live report unavailable')",
        timeout=8000,
    )
    status = page.locator("#whaxon-report-status").inner_text()
    assert "503" in status
    assert "0 jobs" not in status
    assert "0 unique findings" not in status



def test_report_header_does_not_claim_scope_rule_when_no_targets_exist(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"enabled":true,"in_scope":[],"engagement":"empty-report-scope"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/report")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('NO TARGET RULE CONFIGURED')",
        timeout=8000,
    )
    header = page.locator("header").inner_text().lower()
    assert "(no target rule)" in header
    assert "target: no target configured" in header
    assert "(configured rule)" not in header
    assert "scope status from live configuration" not in header


def test_report_header_reports_scope_api_failure_as_unavailable(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"scope backend unavailable"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/report")
    page.wait_for_function(
        "() => document.querySelector('header')?.innerText.includes('SCOPE STATUS UNAVAILABLE')",
        timeout=8000,
    )
    header = page.locator("header").inner_text().lower()
    assert "(status unavailable)" in header
    assert "target: unavailable" in header
    assert "(configured rule)" not in header
    assert "scope status from live configuration" not in header
