"""Browser behavior tests for the live tool catalog."""
from __future__ import annotations

import json


def test_catalog_shows_tool_and_adapter_availability(page, live_server):
    tools = [
        {
            "id": "nmap",
            "name": "Nmap",
            "category": "recon",
            "binary": "/usr/bin/nmap",
            "package": "nmap",
            "available": True,
            "adapter": True,
        },
        {
            "id": "custom_probe",
            "name": "Custom probe",
            "category": "recon",
            "binary": "custom-probe",
            "package": "custom-probe",
            "available": False,
            "adapter": False,
        },
    ]
    page.route(
        "**/api/tools",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(tools),
        ),
    )
    page.goto(f"{live_server}/ui")
    page.click('.sb-item[data-page="catalog"]')
    page.wait_for_function(
        "() => document.querySelectorAll('#catalog-tbody tr').length === 2"
    )

    rows = page.locator("#catalog-tbody tr")
    assert "nmap" in rows.nth(0).text_content()
    assert "Available" in rows.nth(0).text_content()
    assert "custom_probe" in rows.nth(1).text_content()
    assert "Not registered" in rows.nth(1).text_content()
    assert "2 tools" in page.locator("#catalog-summary").text_content()
