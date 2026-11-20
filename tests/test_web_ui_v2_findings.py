"""Browser coverage for the canonical findings UI (UI v2)."""
from __future__ import annotations

import json
import re


def _stable_report_payload():
    return {
        "jobs": [{
            "job": {"id": "stable-findings-job", "target": "127.0.0.1", "tool": "nuclei"},
            "findings": [
                {
                    "seq": 0, "title": "Stable high severity finding",
                    "severity": "high", "source": "nuclei",
                    "verification_status": "candidate",
                    "data": {"message": "Deterministic browser fixture"},
                },
                {
                    "seq": 1, "title": "Stable medium severity finding",
                    "severity": "medium", "source": "nuclei",
                    "verification_status": "candidate", "data": {},
                },
                {
                    "seq": 2, "title": "Stable low severity finding",
                    "severity": "low", "source": "nuclei",
                    "verification_status": "candidate", "data": {},
                },
            ],
        }],
    }


def _serve_stable_report(route):
    route.fulfill(
        status=200,
        content_type="application/json",
        body=json.dumps(_stable_report_payload()),
    )


def test_canonical_findings_page_renders_report_api_data(page, live_server):
    page.route("**/api/report?format=json", _serve_stable_report)
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-count')?.textContent === 'Live findings: 3'",
        timeout=5000,
    )
    assert page.locator("#whaxon-findings-list [data-finding-index]").count() == 3
    assert "SQLi: Time-based Blind" not in page.locator("#whaxon-findings-list").inner_text()
def test_canonical_findings_page_inspects_report_finding(page, live_server):
    page.route("**/api/report?format=json", _serve_stable_report)
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length === 3",
        timeout=5000,
    )
    page.locator("#whaxon-findings-list [data-finding-index]").first.click()
    detail = page.locator("#whaxon-detail")
    assert detail.is_visible()
    assert detail.locator("#selected-finding-title").text_content().strip() == "Stable high severity finding"
    assert detail.locator("#selected-finding-target").text_content().strip() == "127.0.0.1"
    assert "staging-api.corp.net" not in detail.locator("#curl-proof-payload").text_content()
def test_wired_navigation_is_visible_and_unfinished_navigation_is_hidden(page, live_server):
    page.route("**/api/report?format=json", _serve_stable_report)
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length === 3",
        timeout=5000,
    )
    assert page.locator('a[data-path="trust-layer-and-findings"]').is_visible()
    assert page.locator('a[data-path="scope-and-targets"]').is_visible()
    assert page.locator('a[data-path="scope-and-targets"]').get_attribute("href") == "/ui-v2/scope"
    assert page.locator('a[data-path="run-and-orchestration"]').is_visible()
    assert page.locator('a[data-path="run-and-orchestration"]').get_attribute("href") == "/ui-v2/run"
    reports = page.locator('a[data-path="ptes-coverage-and-reports"]')
    assert reports.is_visible()
    assert reports.get_attribute("href") == "/ui-v2/report"
def test_findings_page_has_no_hardcoded_demo_evidence(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/findings")
    assert response is not None
    html = response.text()
    assert "staging-api.corp.net" not in html
    assert "redacted_token_sess_089" not in html
    assert "5055ms" not in html
    assert "Baseline: 34ms" not in html


def test_verified_finding_action_routes_to_v2_retest_studio(page, live_server):
    legacy_calls = []
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200, content_type="application/json",
            body='{"jobs":[{"job":{"id":"sealed-candidate"},"job_id":"sealed-candidate",'
                 '"findings":[{"seq":1,"title":"Verified candidate",'
                 '"verification_status":"verified","data":{}}]}]}',
        ),
    )
    page.route("**/api/validate/**", lambda route: legacy_calls.append(route.request.url))
    page.route("**/api/retest/**", lambda route: legacy_calls.append(route.request.url))
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length > 0",
        timeout=5000,
    )
    with page.expect_navigation(url=f"{live_server}/ui-v2/retest"):
        page.locator("#replay-btn").evaluate("(button) => button.click()")
    assert legacy_calls == []


def test_finding_filter_chips_toggle_off_and_heading_tracks_visible_count(page, live_server):
    payload = {
        "jobs": [{
            "job": {"id": "filter-fixture", "target": "127.0.0.1", "tool": "nmap"},
            "findings": [
                {"seq": 0, "title": "Verified finding", "severity": "high",
                 "source": "nmap", "verification_status": "verified", "data": {}},
                {"seq": 1, "title": "Candidate finding one", "severity": "medium",
                 "source": "nmap", "verification_status": "candidate", "data": {}},
                {"seq": 2, "title": "Candidate finding two", "severity": "low",
                 "source": "nmap", "verification_status": "candidate", "data": {}},
            ],
        }],
    }
    page.route(
        "**/api/report?format=json",
        lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(payload),
        ),
    )
    page.goto(f"{live_server}/ui-v2/findings")
    # The live report is loaded asynchronously; allow for the shared-server
    # contention seen in the full xdist suite before asserting filter behavior.
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length > 0",
        timeout=15000,
    )
    total = page.locator("#whaxon-findings-list [data-finding-index]:visible").count()
    assert page.get_by_role("button", name="ALL").count() >= 3
    assert page.locator("div.bg-surface-container-lowest.px-space-xs.py-1.rounded button[aria-pressed=true]").count() == 3
    heading = page.locator("#whaxon-findings-heading")
    assert "shown of" in heading.inner_text().lower()
    assert "4 in buffer" not in heading.inner_text().lower()

    verified_filter = page.get_by_role("button", name=re.compile(r"VERIFIED"))
    verified_filter.click()
    assert verified_filter.get_attribute("aria-pressed") == "true"
    verified_filter.click()
    assert page.get_by_role("button", name="ALL").nth(1).get_attribute("aria-pressed") == "true"
    page.wait_for_function(
        "(total) => Array.from(document.querySelectorAll('#whaxon-findings-list [data-finding-index]')).filter(el => getComputedStyle(el).display !== 'none').length === total",
        arg=total,
        timeout=5000,
    )
    assert heading.inner_text().lower() == f"attack surface findings ({total} shown of {total})"

    search = page.locator("#whaxon-finding-filter")
    search.fill("no-such-finding-token-90210")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list #whaxon-findings-empty').length === 1",
        timeout=5000,
    )
    assert page.locator("#whaxon-findings-list [data-finding-index]:visible").count() == 0
    search.fill("")
    page.wait_for_function(
        "(total) => Array.from(document.querySelectorAll('#whaxon-findings-list [data-finding-index]')).filter(el => getComputedStyle(el).display !== 'none').length === total",
        arg=total,
        timeout=5000,
    )
    assert page.locator("#whaxon-findings-list #whaxon-findings-empty").count() == 0

def test_findings_search_includes_structured_data_and_evidence_falls_back_to_raw_line(page, live_server):
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length > 0",
        timeout=15000,
    )

    # "protocol" exists in the structured finding data, not the scanner raw line.
    search = page.locator("#whaxon-finding-filter")
    search.fill("protocol")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length === 2",
        timeout=5000,
    )
    assert page.locator("#whaxon-findings-list [data-finding-index]").count() == 2

    search.fill("")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length === 3",
        timeout=5000,
    )
    ssh_finding = page.locator("#whaxon-findings-list [data-finding-index]").filter(has_text="22/tcp open ssh").first
    ssh_finding.click()
    proof = page.locator("#curl-proof-payload")
    assert "22/tcp open ssh OpenSSH 9.6" in proof.inner_text()
    assert "Verification Outcomes" in page.locator("body").evaluate("(el) => el.textContent")
    assert "Refuted" in page.locator("#whaxon-kpi-fixed").evaluate("(el) => el.parentElement.textContent")


def test_findings_header_uses_live_scope_without_claiming_unverified_enforcement(page, live_server):
    page.route(
        "**/api/scope",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"engagement":"ENG-LIVE-42","in_scope":["example.test"],"enabled":false}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelector('#findings-scope-status')?.textContent.includes('ENG-LIVE-42')",
        timeout=5000,
    )
    status = page.locator("#findings-scope-status")
    assert "example.test" in status.inner_text()
    assert "enforcement disabled" in status.inner_text().lower()
    assert "Scope is checked by the backend for each action" not in page.locator("body").inner_text()


def test_findings_kpi_bars_match_live_report_counts(page, live_server):
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-count')?.textContent.startsWith('Live findings:')",
        timeout=15000,
    )
    total_text = page.locator("#whaxon-findings-count").inner_text()
    total = int(total_text.rsplit(" ", 1)[-1])
    assert total >= 0
    verified = int(page.locator("#whaxon-kpi-verified").inner_text())
    candidate = int(page.locator("#whaxon-kpi-candidate").inner_text())
    verified_width = page.locator("#whaxon-kpi-verified-bar").evaluate("(el) => parseFloat(el.style.width)")
    candidate_width = page.locator("#whaxon-kpi-candidate-bar").evaluate("(el) => parseFloat(el.style.width)")
    expected_verified = verified / total * 100 if total else 0
    expected_candidate = candidate / total * 100 if total else 0
    assert abs(verified_width - expected_verified) < 0.1
    assert abs(candidate_width - expected_candidate) < 0.1
    assert page.locator("#whaxon-kpi-fixed-bar").evaluate("(el) => parseFloat(el.style.width)") >= 0
    assert page.locator("#whaxon-kpi-vulnerable-bar").evaluate("(el) => parseFloat(el.style.width)") >= 0


def test_findings_list_uses_only_records_from_live_report(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/findings")
    assert response is not None
    html = response.text()
    assert "SQLi: Time-based Blind" not in html
    assert "Stored Cross-Site Scripting" not in html
    assert "BOLA Authorization Bypass" not in html
    assert "DB_PASSWORD=" not in html
    assert "OP//7749-ALPHA" not in html
    assert "KERNEL-SEC" not in html
    template = page.locator("#finding-card-template")
    assert template.count() == 1
    assert template.is_hidden()
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length > 0",
        timeout=15000,
    )
    assert page.locator("#whaxon-findings-list [data-finding-index]").count() == 3


def test_findings_page_loads_all_assets_locally(page, live_server):
    external = []
    page.on(
        "request",
        lambda request: external.append(request.url)
        if request.url.startswith(("https://", "http://"))
        and not request.url.startswith(live_server)
        else None,
    )
    page.route("https://**/*", lambda route: route.abort())
    response = page.goto(f"{live_server}/ui-v2/findings")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-count')?.textContent.startsWith('Live findings:')",
        timeout=15000,
    )
    assert page.title() == "WHAXON — Trust Layer & Findings"
    assert external == []
    for asset in (
        "dashboard-fonts.css",
        "findings-v2.css",
        "dashboard-logo.jpg",
    ):
        result = page.request.get(f"{live_server}/static/{asset}")
        assert result.ok and result.body(), (asset, result.status)



def test_findings_reject_malformed_report_and_retry(page, live_server):
    calls = 0

    def malformed_once(route):
        nonlocal calls
        calls += 1
        if calls == 1:
            route.fulfill(
                status=200,
                content_type="application/json",
                body='{"jobs":"not-an-array"}',
            )
        else:
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(_stable_report_payload()),
            )

    page.route("**/api/report**", malformed_once)
    page.goto(f"{live_server}/ui-v2/findings")
    state = page.locator("#whaxon-findings-state")
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-state')?.dataset.state === 'error'",
        timeout=5000,
    )
    assert "invalid report response" in state.inner_text().lower()
    assert page.locator("#whaxon-findings-list [data-finding-index]").count() == 0
    page.get_by_role("button", name="Retry").click()
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length === 3",
        timeout=5000,
    )
    assert calls == 2


def test_findings_empty_report_is_distinct_from_unavailable(page, live_server):
    page.route(
        "**/api/report**",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"jobs":[]}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-count')?.textContent === 'Live findings: 0'",
        timeout=5000,
    )
    assert page.locator("#whaxon-findings-state").is_hidden()
    assert page.locator("#whaxon-findings-list #whaxon-findings-empty").inner_text() == (
        "No findings are recorded in the live report."
    )
    assert page.locator("#whaxon-findings-list [data-finding-index]").count() == 0


def test_findings_403_and_network_error_are_unavailable_and_retryable(page, live_server):
    calls = 0

    def unavailable_then_network(route):
        nonlocal calls
        calls += 1
        if calls == 1:
            route.fulfill(
                status=403,
                content_type="application/json",
                body='{"error":"forbidden"}',
            )
        else:
            route.abort()

    page.route("**/api/report**", unavailable_then_network)
    page.goto(f"{live_server}/ui-v2/findings")
    state = page.locator("#whaxon-findings-state")
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-state')?.dataset.state === 'unavailable'",
        timeout=5000,
    )
    assert "access denied" in state.inner_text().lower()
    assert page.get_by_role("button", name="Retry").is_visible()
    page.get_by_role("button", name="Retry").click()
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-state')?.dataset.state === 'unavailable' && document.querySelector('#whaxon-findings-retry')?.hidden === false",
        timeout=5000,
    )
    assert calls == 2


def test_verified_batch_action_opens_v2_retest_studio_without_legacy_posts(page, live_server):
    payload = {
        "jobs": [{
            "job": {"id": "verified-job", "target": "127.0.0.1", "tool": "nuclei"},
            "findings": [{
                "seq": 0,
                "title": "Recorded verified finding",
                "severity": "high",
                "source": "nuclei",
                "verification_status": "verified",
                "data": {},
                "raw_line": "recorded test finding",
            }],
        }],
    }
    calls = []

    page.route(
        "**/api/report**",
        lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(payload)),
    )

    def reject_retest(route):
        calls.append(route.request.url)
        route.fulfill(
            status=403,
            content_type="application/json",
            body='{"error":"target blocked by scope"}',
        )

    page.route("**/api/retest/**", reject_retest)

    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelectorAll('#whaxon-findings-list [data-finding-index]').length === 1",
        timeout=5000,
    )
    page.locator("#whaxon-findings-list [data-finding-index]").first.click()
    with page.expect_navigation(url=f"{live_server}/ui-v2/retest"):
        hit_test = page.evaluate("""() => {
            const button = document.querySelector("#replay-btn");
            const rect = button.getBoundingClientRect();
            const x = rect.left + rect.width / 2;
            const y = rect.top + rect.height / 2;
            const hit = document.elementFromPoint(x, y);
            const ancestors = [];
            for (let node = button; node && node !== document.body; node = node.parentElement) {
                const style = getComputedStyle(node);
                const box = node.getBoundingClientRect();
                ancestors.push({
                    tag: node.tagName,
                    id: node.id,
                    className: typeof node.className === "string" ? node.className : "",
                    left: box.left,
                    width: box.width,
                    marginLeft: style.marginLeft,
                    paddingLeft: style.paddingLeft,
                    position: style.position,
                    transform: style.transform,
                });
            }
            return {
                rect: {left: rect.left, top: rect.top, width: rect.width, height: rect.height},
                viewport: {width: innerWidth, height: innerHeight},
                scroll: {x: scrollX, y: scrollY},
                hit: hit?.outerHTML?.slice(0, 240),
                ancestors,
            };
        }""")
        print(f"replay hit-test: {hit_test}")
        page.locator("#replay-btn").click()
    assert calls == []
