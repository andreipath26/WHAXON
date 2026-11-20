"""Browser coverage for the live attack-chain graph page."""
from __future__ import annotations

import json


def test_attack_chain_page_uses_live_graph_api(page, live_server):
    graph = page.request.get(f"{live_server}/api/pivot/graph")
    assert graph.status == 200
    assert isinstance(graph.json(), dict)
    response = page.goto(f"{live_server}/ui-v2/chains")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => !document.querySelector('#chains-status')?.textContent.includes('Loading stored')",
        timeout=5000,
    )
    assert page.locator("#whaxon-live-chains").is_visible()
    assert page.locator("#chains-refresh").is_visible()


def test_dashboard_links_to_attack_chain_page(page, live_server):
    page.goto(f"{live_server}/ui-v2")
    link = page.locator('a[data-path="correlated-attack-chains"]')
    assert link.is_visible()
    assert link.get_attribute("href") == "/ui-v2/chains"

def test_attack_chain_page_never_displays_fictional_compromise_evidence(page, live_server):
    response = page.goto(f"{live_server}/ui-v2/chains")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('recorded relationship(s) match the filters') "
        "|| document.querySelector('#chains-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    visible = page.locator("body").inner_text()
    for marker in (
        "dns-egress.corp",
        "K9#xL9!pQ_corp_secret",
        "AKIAIOSFODNN7EXAMPLE",
        "root:x:0:0:root",
        "sys_eval(",
        "ACTIVE EXPLOIT DETECTED",
        "LETHAL COMPROMISE",
        "Simulate Controlled Replay",
    ):
        assert marker not in visible, f"Fictional attack-chain fixture must not be shown: {marker}"
    assert page.locator("#whaxon-live-chains").is_visible()
    assert page.locator("#chains-refresh").is_enabled()

def test_attack_chain_page_renders_recorded_edges_and_refreshes(page, live_server):
    calls = {"count": 0}

    def graph(route):
        calls["count"] += 1
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"edges":[{"parent":{"kind":"exploit","id":"job-a/finding-1"},"child":{"kind":"session","id":"job-b/finding-2"},"relation":"from_exploit","evidence":"recorded test evidence","created_at":1793260000}],"count":1}',
        )

    page.route("**/api/pivot/graph", graph)
    page.goto(f"{live_server}/ui-v2/chains")
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('1 of 1 recorded relationship(s) match the filters')",
        timeout=8000,
    )
    rendered = page.locator("#chains-list").inner_text()
    assert "exploit:job-a/finding-1" in rendered
    assert "session:job-b/finding-2" in rendered
    assert "from_exploit" in rendered
    assert "recorded test evidence" in rendered
    assert calls["count"] == 1

    page.get_by_role("button", name="Refresh").click()
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('1 of 1 recorded relationship(s) match the filters')",
        timeout=8000,
    )
    assert calls["count"] >= 2


def test_attack_chain_page_surfaces_graph_api_errors(page, live_server):
    page.route(
        "**/api/pivot/graph",
        lambda route: route.fulfill(
            status=503,
            content_type="application/json",
            body='{"error":"graph temporarily unavailable"}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/chains")
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    assert "could not be loaded" in page.locator("#chains-status").inner_text()

def test_attack_chain_page_filters_and_exports_recorded_graph(page, live_server):
    page.route(
        "**/api/pivot/graph",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body='{"edges":['
                 '{"source":"node-a","target":"node-b","relation":"connects","evidence":"evidence alpha"},'
                 '{"source":"node-c","target":"node-d","relation":"depends_on","evidence":"evidence beta"}]}',
        ),
    )
    page.goto(f"{live_server}/ui-v2/chains")
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('2 of 2 recorded relationship(s)')",
        timeout=8000,
    )
    assert page.locator("#chains-list article").count() == 2
    page.get_by_label("Filter attack-chain relationships").fill("evidence beta")
    assert page.locator("#chains-list article:visible").count() == 1
    assert "node-c" in page.locator("#chains-list article:visible").inner_text()
    with page.expect_download() as download_info:
        page.locator("#chains-export").click()
    download = download_info.value
    assert download.suggested_filename == "whaxon-attack-chain-graph.json"
    with open(download.path(), encoding="utf-8") as file:
        payload = json.load(file)
    assert payload["source"] == "WHAXON recorded graph API"
    assert len(payload["edges"]) == 2
    assert payload["edges"][1]["evidence"] == "evidence beta"

def test_attack_chain_header_reflects_live_scope_and_navigation(page, live_server):
    page.goto(f"{live_server}/ui-v2/chains")
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('recorded relationship(s) match the filters')"
        " || document.querySelector('#chains-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    page.wait_for_function(
        "() => !document.querySelector('header')?.innerText.includes('api.internal.corp')",
        timeout=8000,
    )
    scope = page.evaluate("() => fetch('/api/scope').then(response => response.json())")
    target = scope["in_scope"][0] if scope.get("in_scope") else "No target configured"
    header = page.locator("header").inner_text()
    assert target in header
    assert "SCOPE CONFIGURATION LOADED" in header or "SCOPE ENFORCEMENT DISABLED" in header

    page.locator("header button").filter(has_text="New").click()
    page.wait_for_url("**/ui-v2/scope")
    assert page.url.endswith("/ui-v2/scope")

    page.goto(f"{live_server}/ui-v2/chains")
    page.locator("header button").filter(has_text="Terminal Log").click()
    page.wait_for_url("**/ui-v2/run")
    assert page.url.endswith("/ui-v2/run")


def test_attack_chain_halt_uses_active_workflow_apis_and_disables_unwired_actions(page, live_server, workflow_halt_sources):
    workflow_halt_sources()
    page.route(
        "**/api/history",
        lambda route: route.fulfill(status=200, content_type="application/json", body="[]"),
    )
    page.goto(f"{live_server}/ui-v2/chains")
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('recorded relationship(s) match the filters')"
        " || document.querySelector('#chains-status')?.textContent.includes('could not be loaded')",
        timeout=8000,
    )
    page.locator("header button").filter(has_text="Emergency Halt Scan").click()
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('No running legacy jobs or durable workflow requests were found')",
        timeout=5000,
    )
    for label in (
        "Export PTES Chapter",
        "Add Custom Mitigation Rule",
        "Generate Red Team Retest Script",
    ):
        button = page.locator("main button").filter(has_text=label).first
        assert button.count() == 1, f"Expected canonical control to remain visible in DOM: {label}"
        assert button.is_disabled(), f"Unsupported action should be disabled: {label}"
    assert page.get_by_role("button", name="Refresh").is_enabled()
    assert page.locator("#chains-export").is_enabled()



def test_attack_chain_failed_refresh_clears_stale_edges_before_export(page, live_server):
    calls = {"count": 0}

    def graph(route):
        calls["count"] += 1
        if calls["count"] == 1:
            route.fulfill(
                status=200,
                content_type="application/json",
                body='{"edges":[{"source":"old-node","target":"stale-node","relation":"connects","evidence":"old evidence"}]}',
            )
        else:
            route.fulfill(
                status=503,
                content_type="application/json",
                body='{"error":"graph temporarily unavailable"}',
            )

    page.route("**/api/pivot/graph", graph)
    page.goto(f"{live_server}/ui-v2/chains")
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('1 of 1 recorded relationship(s)')",
        timeout=8000,
    )
    assert "stale-node" in page.locator("#chains-list").inner_text()

    page.get_by_role("button", name="Refresh").click()
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('Graph data could not be loaded: graph temporarily unavailable')",
        timeout=8000,
    )
    assert page.locator("#chains-list").inner_text() == ""

    with page.expect_download() as download_info:
        page.locator("#chains-export").click()
    with open(download_info.value.path(), encoding="utf-8") as file:
        payload = json.load(file)
    assert payload["edges"] == []
    page.wait_for_function(
        "() => document.querySelector('#chains-status')?.textContent.includes('Exported 0 recorded relationship(s)')",
        timeout=5000,
    )
    assert calls["count"] == 2
