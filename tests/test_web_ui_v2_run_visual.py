"""Desktop Run & Orchestration visual candidate evidence; manual review stays separate."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("width", "height", "label"),
    [(1440, 900, "desktop")],
)
def test_run_visual_candidate(page, live_server, width, height, label):
    page.set_viewport_size({"width": width, "height": height})
    response = page.goto(f"{live_server}/ui-v2/run")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => [...document.querySelector('#run-tool-select').options].some(o => o.value === 'echo')",
        timeout=8000,
    )
    page.evaluate("() => document.fonts.ready")
    output = Path("run-visual-evidence")
    output.mkdir(exist_ok=True)
    page.screenshot(path=str(output / f"run-{label}.png"), full_page=True)
    (output / f"run-{label}.json").write_text(json.dumps({
        "viewport": {"width": width, "height": height},
        "page": "/ui-v2/run",
        "background": page.evaluate("() => getComputedStyle(document.body).backgroundColor"),
        "source": "live seeded acceptance fixture — not owner-approved visual baseline",
    }, indent=2), encoding="utf-8")
    assert page.locator("main").is_visible()
    assert page.evaluate(
        "() => getComputedStyle(document.body).backgroundColor === 'rgb(15, 19, 28)'"
    )


@pytest.mark.parametrize(("width", "height"), [(1440, 900)])
def test_run_automated_accessibility(page, live_server, width, height):
    axe = Path(__file__).resolve().parents[1] / "node_modules" / "axe-core" / "axe.min.js"
    if not axe.is_file():
        pytest.skip("Pinned axe-core is installed and enforced in the dedicated Run acceptance workflow")
    page.set_viewport_size({"width": width, "height": height})
    page.goto(f"{live_server}/ui-v2/run")
    page.wait_for_function(
        "() => [...document.querySelector('#run-tool-select').options].some(o => o.value === 'echo')",
        timeout=8000,
    )
    page.add_script_tag(path=str(axe))
    result = page.evaluate(
        """async () => await axe.run(document, {
          runOnly:{type:'tag', values:['wcag2a','wcag2aa','wcag21a','wcag21aa']}
        })"""
    )
    output = Path("run-visual-evidence")
    output.mkdir(exist_ok=True)
    issues = [{"id": v["id"], "nodes": [n["target"] for n in v["nodes"]]}
              for v in result["violations"]]
    (output / f"run-axe-{width}.json").write_text(
        json.dumps(issues, indent=2), encoding="utf-8")
    assert not issues, issues
