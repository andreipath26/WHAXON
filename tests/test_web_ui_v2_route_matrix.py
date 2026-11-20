"""Route smoke coverage for every page in the canonical Obsidian Kinetic UI.

This deliberately tests the production routes, not the reference PNG assets.
Detailed interaction tests remain in the page-specific test modules.
"""



UI_V2_ROUTES = (
    "/ui-v2",
    "/ui-v2/dashboard",
    "/ui-v2/scope",
    "/ui-v2/run",
    "/ui-v2/findings",
    "/ui-v2/report",
    "/ui-v2/reports",
    "/ui-v2/history",
    "/ui-v2/diagnostics",
    "/ui-v2/evidence",
    "/ui-v2/ai",
    "/ui-v2/retest",
    "/ui-v2/chains",
    "/ui-v2/adapters",
    "/ui-v2/settings",
    "/ui-v2/audit",
    "/ui-v2/monitoring",
    "/ui-v2/bas",
    "/ui-v2/bug-bounty",
    "/ui-v2/compliance",
    "/ui-v2/ptaas",
    "/ui-v2/threat-intel",
    "/ui-v2/approvals",
)


def test_every_canonical_ui_route_renders(page, live_server):
    for route in UI_V2_ROUTES:
        response = page.goto(f"{live_server}{route}")
        assert response is not None, f"{route} did not produce a document response"
        assert response.status == 200, f"{route} returned HTTP {response.status}"
        assert page.locator("body").is_visible()
        assert page.locator("main").count() == 1, f"{route} must render one main workspace"
        assert page.locator("main").inner_text().strip(), f"{route} rendered an empty workspace"
