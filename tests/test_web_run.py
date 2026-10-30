"""Run page behavior tests.

The Run page fetches the catalog from /api/tools, lets an operator pick a
tool, POSTs to /api/run, then consumes live output via SSE from
/api/jobs/<id>/stream. The fixture's seeded store has no catalog tools
beyond what the server loads by default, so these tests assert the wiring:
the catalog renders, selection works, the run lifecycle runs end to end
using the `echo` test fixture tool (which always succeeds).
"""
from __future__ import annotations


def _open_run(page, live_server):
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="run"]')
    page.wait_for_selector("#run-catalog", timeout=5000)


def test_catalog_renders(page, live_server):
    _open_run(page, live_server)
    page.wait_for_function(
        "() => document.querySelectorAll('#run-catalog .tool-item').length > 0",
        timeout=5000,
    )
    items = page.locator("#run-catalog .tool-item")
    assert items.count() > 0


def test_catalog_count_shows(page, live_server):
    _open_run(page, live_server)
    page.wait_for_function(
        "() => document.getElementById('run-catalog-count').textContent.includes(' tools')",
        timeout=5000,
    )
    count = page.locator("#run-catalog-count").text_content()
    assert "tools" in count


def test_clicking_tool_selects_it(page, live_server):
    _open_run(page, live_server)
    page.wait_for_function(
        "() => document.querySelectorAll('#run-catalog .tool-item').length > 0",
        timeout=5000,
    )
    first = page.locator("#run-catalog .tool-item").first
    first.click()
    page.wait_for_timeout(200)
    assert first.evaluate("el => el.classList.contains('on')")
    btn_text = page.locator("#run-btn").text_content()
    assert "Run" in btn_text


def test_initial_state_has_no_job(page, live_server):
    _open_run(page, live_server)
    assert "No job running" in page.locator("#run-job-id").text_content()
    assert page.locator("#run-output").text_content().strip() == ""


def test_cancel_starts_disabled(page, live_server):
    _open_run(page, live_server)
    assert page.locator("#run-cancel-btn").is_disabled()


def test_scope_pill_hidden_by_default(page, live_server):
    _open_run(page, live_server)
    visible = page.locator("#run-scope-pill").evaluate("el => el.style.display !== 'none'")
    assert visible is False


def test_run_echo_produces_output(page, live_server):
    _open_run(page, live_server)
    # pick the echo tool from the catalog
    echo_item = page.locator('#run-catalog .tool-item[data-tool-id="echo"]')
    assert echo_item.count() == 1, "echo tool not in catalog"
    echo_item.click()
    page.fill("#run-target", "127.0.0.1")
    page.click("#run-btn")
    # the SSE stream should produce at least one line, then finish
    page.wait_for_function(
        "() => document.getElementById('run-output').textContent.includes('finished')",
        timeout=15000,
    )
    output = page.locator("#run-output").text_content()
    assert len(output) > 0
    # job id should be populated
    assert "Job" in page.locator("#run-job-id").text_content()


def test_run_out_of_scope_shows_error(page, live_server):
    _open_run(page, live_server)
    page.wait_for_function(
        "() => document.querySelectorAll('#run-catalog .tool-item').length > 0",
        timeout=5000,
    )
    # pick any tool
    page.locator("#run-catalog .tool-item").first.click()
    page.fill("#run-target", "google.com")
    page.click("#run-btn")
    page.wait_for_function(
        "() => document.getElementById('run-output').textContent.length > 0",
        timeout=8000,
    )
    output = page.locator("#run-output").text_content()
    assert "scope" in output.lower() or "error" in output.lower()


def test_out_of_scope_run_explains_block_and_only_logs_attempt(page, live_server):
    import json

    page.route(
        "**/api/run",
        lambda route: route.fulfill(
            status=403,
            content_type="application/json",
            body=json.dumps({"error": "out of scope", "matched_rule": ""}),
        ),
    )
    page.route(
        "**/api/scope/override",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({"logged": True}),
        ),
    )
    _open_run(page, live_server)
    page.locator('#run-catalog .tool-item[data-tool-id="echo"]').click()
    page.fill("#run-target", "google.com")
    page.click("#run-btn")
    page.wait_for_selector("#scope-modal.open")
    assert page.locator("#scope-modal-target").text_content() == "google.com"
    assert page.locator("#scope-modal-tool").text_content() == "echo"
    assert "will not execute" in page.locator("#scope-modal").text_content()

    with page.expect_response("**/api/scope/override") as response:
        page.click("#scope-override-btn")
    assert response.value.status == 200
    assert "does not authorize execution" in page.locator("#scope-modal-message").text_content()
    assert page.locator("#scope-modal").evaluate("el => el.classList.contains('open')")
