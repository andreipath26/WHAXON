"""Automated WCAG checks; keep manual a11y acceptance independent."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("width", "height", "name"),
    [(1440, 900, "desktop"), (390, 844, "mobile")],
)
def test_dashboard_automated_wcag_audit(page, live_server, width, height, name):
    axe_script = Path(__file__).resolve().parents[1] / "node_modules" / "axe-core" / "axe.min.js"
    if not axe_script.is_file():
        pytest.skip("Dedicated Dashboard acceptance workflow installs pinned axe-core")
    page.set_viewport_size({"width": width, "height": height})
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.innerText.includes('seed-job-1')",
        timeout=12000,
    )
    page.add_script_tag(path=str(axe_script))
    result = page.evaluate(
        """async () => await axe.run(document, {
          runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']}
        })"""
    )
    output = Path("dashboard-visual-evidence")
    output.mkdir(exist_ok=True)
    violations = [{
        "id": v["id"],
        "impact": v.get("impact"),
        "description": v["description"],
        "nodes": [n["target"] for n in v.get("nodes", [])],
    } for v in result["violations"]]
    (output / f"dashboard-axe-{name}.json").write_text(
        json.dumps({
            "viewport": {"width": width, "height": height},
            "violations": violations,
            "note": "Automated WCAG check only; manual screen-reader review remains required",
        }, indent=2),
        encoding="utf-8",
    )
    assert not violations, f"{name} automated accessibility violations: {violations}"
