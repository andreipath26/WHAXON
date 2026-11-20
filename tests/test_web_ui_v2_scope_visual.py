"""Scope UI candidate screenshots and automated accessibility; manual sign-off separate."""
import json
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("width", "height", "label"),
    [(1440, 900, "desktop"), (390, 844, "mobile")],
)
def test_scope_visual_candidate(page, live_server, width, height, label):
    page.set_viewport_size({"width": width, "height": height})
    response = page.goto(f"{live_server}/ui-v2/scope")
    assert response is not None and response.status == 200
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=12000,
    )
    page.evaluate("""async () => await Promise.race([
        document.fonts.ready,
        new Promise(resolve => setTimeout(resolve, 1500)),
    ])""")
    output = Path("scope-visual-evidence")
    output.mkdir(exist_ok=True)
    page.screenshot(path=str(output / f"scope-{label}.png"), full_page=True)
    (output / f"scope-{label}.json").write_text(json.dumps({
        "viewport": {"width": width, "height": height},
        "page": "/ui-v2/scope",
        "background": page.evaluate("() => getComputedStyle(document.body).backgroundColor"),
        "source": "live seeded acceptance fixture — not owner-approved visual baseline",
    }, indent=2), encoding="utf-8")
    assert page.locator("main").is_visible()
    assert page.evaluate(
        "() => getComputedStyle(document.body).backgroundColor === 'rgb(15, 19, 28)'"
    )


@pytest.mark.parametrize(("width", "height"), [(1440, 900), (390, 844)])
def test_scope_automated_accessibility(page, live_server, width, height):
    axe = Path(__file__).resolve().parents[1] / "node_modules" / "axe-core" / "axe.min.js"
    if not axe.is_file():
        pytest.skip("Pinned axe-core is installed and enforced in the dedicated Scope acceptance workflow")
    page.set_viewport_size({"width": width, "height": height})
    page.goto(f"{live_server}/ui-v2/scope")
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=12000,
    )
    page.add_script_tag(path=str(axe))
    result = page.evaluate(
        """async () => await axe.run(document, {
          runOnly:{type:'tag', values:['wcag2a','wcag2aa','wcag21a','wcag21aa']}
        })"""
    )
    output = Path("scope-visual-evidence")
    output.mkdir(exist_ok=True)
    issues = [{"id": v["id"], "nodes": [n["target"] for n in v["nodes"]]}
              for v in result["violations"]]
    (output / f"scope-axe-{width}.json").write_text(
        json.dumps(issues, indent=2), encoding="utf-8")
    assert not issues, issues


def test_scope_mobile_nav_restores_viewport_and_keyboard_focus(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2/scope")
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=12000,
    )
    assert page.evaluate("() => document.documentElement.scrollWidth <= innerWidth")
    button = page.get_by_role("button", name="Open Scope navigation")
    assert button.is_visible()
    assert page.locator("body > aside").get_attribute("aria-hidden") == "true"
    button.click()
    assert page.locator("body > aside").get_attribute("aria-hidden") == "false"
    assert button.get_attribute("aria-expanded") == "true"
    page.keyboard.press("Escape")
    assert button.get_attribute("aria-expanded") == "false"
    assert button.evaluate("(el) => document.activeElement === el")


def test_scope_mobile_primary_actions_are_accessible(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2/scope")
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=12000,
    )
    assert page.locator("#openTargetModalBtn").is_visible()
    assert page.locator("#openImportDrawerBtn").is_visible()


def test_scope_closed_sidebar_is_inert_for_keyboard_and_assistive_technology(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2/scope")
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=12000,
    )
    sidebar = page.locator("#scope-mobile-sidebar")
    assert sidebar.evaluate("(node) => node.inert") is True
    menu = page.get_by_role("button", name="Open Scope navigation")
    menu.click()
    assert sidebar.evaluate("(node) => node.inert") is False
    page.keyboard.press("Escape")
    assert sidebar.evaluate("(node) => node.inert") is True


def test_scope_registry_badge_preserves_material_icon_and_live_rule_count(page, live_server):
    page.goto(f"{live_server}/ui-v2/scope")
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=12000,
    )
    header = page.locator("h2").filter(has_text="In-Scope Target Registry")
    badge = header.locator("xpath=following-sibling::span[1]")
    assert "rules loaded" in badge.inner_text()
    assert "Loading live rules" not in badge.inner_text()
    assert header.locator("xpath=preceding-sibling::span[1]").inner_text() == "verified"


def test_scope_mobile_table_is_keyboard_scrollable(page, live_server):
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{live_server}/ui-v2/scope")
    page.wait_for_function(
        "() => document.querySelector('#scope-ui-notice')?.textContent.includes('Loaded the active scope')",
        timeout=12000,
    )
    region = page.get_by_role("region", name="Scope rule table, scroll horizontally for every rule field")
    assert region.get_attribute("tabindex") == "0"
    assert page.get_by_text("Scroll sideways to view every scope-rule column.").is_visible()
    assert region.evaluate("(node) => node.scrollWidth > node.clientWidth")
    region.evaluate("(node) => node.scrollLeft = node.scrollWidth")
    assert region.evaluate("(node) => node.scrollLeft") > 0
