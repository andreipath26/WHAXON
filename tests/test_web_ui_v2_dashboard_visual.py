"""Capture auditable candidate screenshots; capture does not mean visual approval."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("width", "height", "label"),
    [(1440, 900, "desktop"), (390, 844, "mobile")],
)
def test_dashboard_visual_candidate(page, live_server, width, height, label):
    page.set_viewport_size({"width": width, "height": height})
    failed_requests = []
    page.on(
        "requestfailed",
        lambda request: failed_requests.append({"url": request.url, "error": request.failure}),
    )
    output = Path("dashboard-visual-evidence")
    output.mkdir(exist_ok=True)
    response = page.goto(f"{live_server}/ui-v2")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('table tbody')?.innerText.includes('seed-job-1')",
        timeout=12000,
    )
    page.evaluate("() => document.fonts.ready")
    # Save evidence even if a later style/deployment assertion fails.
    page.screenshot(path=str(output / f"dashboard-{label}.png"), full_page=True)
    (output / f"dashboard-{label}-metadata.json").write_text(
        json.dumps({
            "viewport": {"width": width, "height": height},
            "candidate_url": "/ui-v2",
            "rendered_background": page.evaluate(
                "() => getComputedStyle(document.body).backgroundColor"
            ),
            "external_request_failures": failed_requests,
            "source": "live seeded integration fixture, not approved visual baseline",
        }, indent=2),
        encoding="utf-8",
    )
    assert page.evaluate("() => document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("main").is_visible()
    assert page.evaluate(
        "() => getComputedStyle(document.body).backgroundColor === 'rgb(15, 19, 28)'"
    ), "Design CSS not loaded: external Tailwind dependency may be unavailable"
