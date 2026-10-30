"""Browser behavior tests for the live Attack Surface graph."""
from __future__ import annotations

import json


def _graph_route(page, edges):
    page.route(
        "**/api/pivot/graph",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"count": len(edges), "edges": edges}),
        ),
    )


def test_graph_renders_live_relationships_and_inspects_nodes(page, live_server):
    edges = [
        {
            "parent": {"kind": "exploit", "id": "exploit-17"},
            "child": {"kind": "session", "id": "session-3"},
            "relation": "from_exploit",
            "evidence": "successful exploit opened session 3",
            "created_at": 1,
        },
        {
            "parent": {"kind": "session", "id": "session-3"},
            "child": {"kind": "forward", "id": "10.0.0.7:80"},
            "relation": "reached_through",
            "evidence": "port forward",
            "created_at": 2,
        },
    ]
    _graph_route(page, edges)
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="graph"]')

    page.wait_for_function(
        "() => document.querySelectorAll('#attack-surface-graph .graph-node').length === 3"
    )
    assert page.locator("#attack-surface-graph line.graph-edge").count() == 2
    assert page.locator("#graph-count").text_content().strip() == "2 edges"
    assert "3 nodes" in page.locator("#graph-summary").text_content()

    page.get_by_role("button", name="exploit:exploit-17").click()
    assert "from_exploit" in page.locator("#graph-selection").text_content()
    assert "session:session-3" in page.locator("#graph-selection").text_content()


def test_graph_shows_real_empty_state_without_mock_nodes(page, live_server):
    _graph_route(page, [])
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="graph"]')
    page.wait_for_selector("#graph-empty", state="visible")
    assert page.locator("#attack-surface-graph .graph-node").count() == 0
    assert "No pivot relationships" in page.locator("#graph-empty").text_content()


def test_graph_refresh_reloads_data(page, live_server):
    calls = {"count": 0}

    def respond(route):
        calls["count"] += 1
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"count": 0, "edges": []}),
        )

    page.route("**/api/pivot/graph", respond)
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="graph"]')
    page.wait_for_selector("#graph-count")
    page.wait_for_function("() => document.getElementById('graph-count').textContent === '0 edges'")
    before = calls["count"]
    with page.expect_response("**/api/pivot/graph") as response_info:
        page.click("#graph-refresh")
    assert response_info.value.status == 200
    assert calls["count"] > before
