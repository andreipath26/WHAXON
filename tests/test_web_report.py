"""Browser behavior tests for engagement report generation."""
from __future__ import annotations

import json


def test_report_summary_uses_current_engagement_data(page, live_server):
    report = {
        "job_count": 2,
        "jobs": [
            {
                "job": {"id": "job-1"},
                "findings": [
                    {"verification_status": "verified"},
                    {"verification_status": "candidate"},
                ],
            },
            {
                "job": {"id": "job-2"},
                "findings": [{"verification_status": "verified"}],
            },
        ],
    }
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(report),
        ),
    )
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="report"]')
    page.wait_for_function(
        "() => document.getElementById('report-summary').textContent.includes('2 job(s)')"
    )
    summary = page.locator("#report-summary").text_content()
    assert "3 finding(s)" in summary
    assert "2 verified finding(s)" in summary


def test_report_markdown_button_downloads_generated_report(page, live_server):
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"job_count": 0, "jobs": []}),
        ),
    )
    page.route(
        "**/api/report?format=md&engagement=default",
        lambda route: route.fulfill(
            status=200,
            content_type="text/markdown",
            body="# WHAXON Engagement Report\n",
        ),
    )
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="report"]')
    with page.expect_download() as download_info:
        page.click("#report-md")
    download = download_info.value
    assert download.suggested_filename == "whaxon-report.md"
