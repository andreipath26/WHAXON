"""Cross-cutting navigation and keyboard tests."""
from __future__ import annotations

import pytest

ALL_PAGES = [
    ("scope", "page-scope"),
    ("run", "page-run"),
    ("findings", "page-findings"),
    ("report", "page-report"),
    ("retest", "page-retest"),
    ("sessions", "page-sessions"),
    ("graph", "page-graph"),
    ("monitoring", "page-monitoring"),
    ("catalog", "page-catalog"),
]


@pytest.mark.parametrize("slug,section_id", ALL_PAGES)
def test_sidebar_activates_correct_section(page, live_server, slug, section_id):
    page.goto(f"{live_server}/ui")
    page.click(f'.sb-item[data-page="{slug}"]')
    page.wait_for_timeout(200)
    assert page.locator(f"#{section_id}").evaluate("el => el.classList.contains('active')")
    # All other pages are inactive
    active_count = page.locator("section.page.active").count()
    assert active_count == 1, f"expected exactly 1 active page, got {active_count}"


def test_breadcrumb_updates_on_navigation(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="scope"]')
    page.wait_for_timeout(200)
    assert page.locator("#crumb-here").text_content().strip().lower() == "scope"
    page.click('.sb-item[data-page="catalog"]')
    page.wait_for_timeout(200)
    assert page.locator("#crumb-here").text_content().strip().lower() == "catalog"


def test_ctrl_k_opens_command_palette(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("Control+k")
    page.wait_for_timeout(200)
    assert page.locator("#palette").evaluate("el => el.classList.contains('open')")


def test_escape_closes_palette(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("Control+k")
    page.wait_for_timeout(200)
    page.keyboard.press("Escape")
    page.wait_for_timeout(200)
    assert not page.locator("#palette").evaluate("el => el.classList.contains('open')")


def test_question_mark_opens_shortcut_legend(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("?")
    page.wait_for_timeout(200)
    assert page.locator("#kbd-legend").evaluate("el => el.classList.contains('open')")


def test_sidebar_collapse_toggle(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click("#collapse-btn")
    page.wait_for_timeout(200)
    assert page.locator("#app").evaluate("el => el.classList.contains('collapsed')")
    page.click("#collapse-btn")
    page.wait_for_timeout(200)
    assert not page.locator("#app").evaluate("el => el.classList.contains('collapsed')")


def test_shell_shows_live_engagement_and_msf_status(page, live_server):
    import json

    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"engagement": "client-lab"}),
        ),
    )
    page.route(
        "**/api/msf/status",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"up": True}),
        ),
    )
    page.goto(f"{live_server}/ui")
    page.wait_for_function(
        "() => document.getElementById('engagement-name').textContent === 'client-lab'"
    )
    assert page.locator("#crumb-engagement").text_content() == "client-lab"
    assert page.locator("#msf-pill").text_content() == "MSF · connected"


def test_workspace_switcher_and_fake_modal_are_not_exposed(page, live_server):
    page.goto(f"{live_server}/ui")
    assert page.locator("#ws-modal").count() == 0
    assert not page.locator(".sb-workspace").is_visible()


def test_command_palette_searches_pages_and_tools(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("Control+k")
    page.fill("#palette-input", "Attack Surface")
    result = page.locator("#palette-results .palette-item").filter(has_text="Attack Surface")
    result.click()
    assert page.locator("#page-graph").evaluate("el => el.classList.contains('active')")

    page.keyboard.press("Control+k")
    page.fill("#palette-input", "nmap")
    tool_result = page.locator("#palette-results .palette-item").filter(has_text="nmap").first
    tool_result.click()
    assert page.locator("#page-run").evaluate("el => el.classList.contains('active')")
    page.wait_for_function(
        "() => document.querySelector('#run-catalog .tool-item.on') !== null"
    )
    assert page.locator("#run-catalog .tool-item.on").get_attribute("data-tool-id") == "nmap"


def test_sidebar_counts_come_from_live_findings_and_coverage(page, live_server):
    import json

    report = {
        "job_count": 1,
        "finding_count": 2,
        "severity_counts": {"high": 1, "medium": 1},
        "jobs": [
            {
                "job": {"id": "job-1", "target": "lab.example"},
                "findings": [
                    {"seq": 1, "severity": "high", "kind": "sqli", "verification_status": "candidate"},
                    {"seq": 2, "severity": "medium", "kind": "xss", "verification_status": "verified"},
                ],
                "coverage": [
                    {"kind": "binary_missing", "tool_id": "nuclei", "target": "lab.example", "detail": "binary unavailable"}
                ],
            }
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
    page.wait_for_function(
        "() => document.getElementById('findings-badge').textContent === '2' && document.getElementById('coverage-badge').textContent === '1'"
    )


def test_documented_keyboard_shortcuts_work(page, live_server):
    page.goto(f"{live_server}/ui")
    page.keyboard.press("g")
    page.keyboard.press("r")
    assert page.locator("#page-run").evaluate("el => el.classList.contains('active')")

    initial = page.locator("body").get_attribute("data-density")
    page.keyboard.press("d")
    assert page.locator("body").get_attribute("data-density") != initial

    page.keyboard.press("n")
    assert page.locator("#page-run").evaluate("el => el.classList.contains('active')")
    assert page.locator("#run-target").evaluate("el => document.activeElement === el")

    page.keyboard.press("/")
    assert page.locator("#palette").evaluate("el => el.classList.contains('open')")


def test_stage_tracker_uses_live_engagement_data(page, live_server):
    import json

    report = {
        "job_count": 1,
        "finding_count": 1,
        "jobs": [{
            "job": {"id": "job-1", "target": "lab.example"},
            "findings": [{"verification_status": "verified"}],
            "coverage": [],
        }],
    }
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(report),
        ),
    )
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"enabled": True, "in_scope": ["lab.example"]}),
        ),
    )
    page.goto(f"{live_server}/ui")
    page.wait_for_function(
        "() => document.getElementById('stage-findings-value').textContent === '1 finding(s)'"
    )
    assert page.locator("#stage-target-value").text_content() == "1 target(s)"
    assert page.locator("#stage-run-value").text_content() == "1 job(s)"
    assert page.locator("#stage-retest-value").text_content() == "1 verified"
