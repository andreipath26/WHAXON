"""Desktop visual candidate and automated WCAG evidence for Findings."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.parametrize(("width", "height", "label"), [(1440, 900, "desktop")])
def test_findings_visual_candidate(page, live_server, width, height, label):
    page.set_viewport_size({"width": width, "height": height})
    response = page.goto(f"{live_server}/ui-v2/findings")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-count')?.textContent.startsWith('Live findings:')",
        timeout=8000,
    )
    page.evaluate("async () => { await document.fonts.ready; return true; }")
    output = Path("findings-visual-evidence")
    output.mkdir(exist_ok=True)
    page.screenshot(path=str(output / f"findings-{label}.png"), full_page=True)
    (output / f"findings-{label}.json").write_text(
        json.dumps({
            "viewport": {"width": width, "height": height},
            "page": "/ui-v2/findings",
            "background": page.evaluate("() => getComputedStyle(document.body).backgroundColor"),
            "source": "live seeded acceptance fixture — not owner-approved visual baseline",
        }, indent=2),
        encoding="utf-8",
    )
    assert page.locator("main").is_visible()
    assert page.evaluate("() => getComputedStyle(document.body).backgroundColor === 'rgb(15, 19, 28)'")


@pytest.mark.parametrize(("width", "height"), [(1440, 900)])
def test_findings_automated_accessibility(page, live_server, width, height):
    axe = Path(__file__).resolve().parents[1] / "node_modules" / "axe-core" / "axe.min.js"
    if not axe.is_file():
        pytest.skip("Pinned axe-core is installed and enforced in the Findings acceptance workflow")
    page.set_viewport_size({"width": width, "height": height})
    page.goto(f"{live_server}/ui-v2/findings")
    page.wait_for_function(
        "() => document.querySelector('#whaxon-findings-count')?.textContent.startsWith('Live findings:')",
        timeout=8000,
    )
    page.add_script_tag(path=str(axe))
    result = page.evaluate(
        """async () => await axe.run(document, {
          runOnly:{type:'tag', values:['wcag2a','wcag2aa','wcag21a','wcag21aa']}
        })"""
    )
    output = Path("findings-visual-evidence")
    output.mkdir(exist_ok=True)
    issues = [
        {"id": violation["id"], "nodes": [node["target"] for node in violation["nodes"]]}
        for violation in result["violations"]
    ]
    (output / f"findings-axe-{width}.json").write_text(json.dumps(issues, indent=2), encoding="utf-8")
    assert not issues, issues
