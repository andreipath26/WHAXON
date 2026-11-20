"""Cross-page navigation contract and reproducible static control inventory.

Static inventory is evidence of source coverage, not functional acceptance.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "src/whaxon/interfaces/web/templates"
ROUTES = {
    "/ui-v2", "/ui-v2/dashboard", "/ui-v2/scope", "/ui-v2/run",
    "/ui-v2/findings", "/ui-v2/report", "/ui-v2/reports", "/ui-v2/history",
    "/ui-v2/diagnostics", "/ui-v2/evidence", "/ui-v2/ai", "/ui-v2/retest",
    "/ui-v2/chains", "/ui-v2/adapters", "/ui-v2/settings", "/ui-v2/audit",
    "/ui-v2/monitoring", "/ui-v2/bas", "/ui-v2/bug-bounty",
    "/ui-v2/compliance", "/ui-v2/ptaas", "/ui-v2/threat-intel", "/ui-v2/approvals",
}
CONTROL_TAGS = {"a", "button", "input", "select", "textarea", "summary"}
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class ControlParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.controls = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        hidden = (
            "hidden" in attributes or attributes.get("aria-hidden") == "true"
            or bool(re.search(r"display\s*:\s*none", attributes.get("style", "")))
            or "hidden" in attributes.get("class", "").split()
            or tag == "template" or any(item[1] for item in self.stack)
        )
        control = None
        if (tag in CONTROL_TAGS or attributes.get("role") in {"button", "link"}
                or any(key.startswith("on") for key in attributes)
                or attributes.get("contenteditable") == "true"
                or (attributes.get("tabindex", "-1").isdigit())):
            line, column = self.getpos()
            control = {
                "tag": tag, "attrs": attributes, "hidden": hidden,
                "position": f"{line}:{column + 1}", "text": [],
            }
            self.controls.append(control)
        if tag not in VOID_TAGS:
            self.stack.append((tag, hidden, control))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        for _, _, control in self.stack:
            if control is not None:
                control["text"].append(data)


def inventory():
    pages = {}
    for path in sorted(TEMPLATES.glob("ui_v2_*.html")):
        source = path.read_text(encoding="utf-8")
        parser = ControlParser()
        parser.feed(source)
        scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", source, re.S))
        controls = []
        for control in parser.controls:
            attrs = control["attrs"]
            label = attrs.get("aria-label") or attrs.get("title") or attrs.get("placeholder") or " ".join(control["text"])
            label = " ".join(label.split()) or attrs.get("id") or "(unnamed)"
            binding = attrs.get("href") or attrs.get("onclick") or attrs.get("data-path") or attrs.get("id")
            if attrs.get("data-filter-action"):
                binding = f"filter:{attrs['data-filter-action']}:{attrs.get('data-filter-value', '')}"
            binding = binding or "—"
            if control["hidden"]:
                state = "source-hidden"
            elif "disabled" in attrs or attrs.get("aria-disabled") == "true":
                state = "disabled"
            elif attrs.get("href", "").startswith("/ui-v2"):
                state = "declared-nav"
            elif any(key.startswith("on") for key in attrs):
                state = "inline-handler"
            elif any(attrs.get(key) and attrs[key] in scripts for key in ("id", "data-path", "data-filter-action", "data-filter-value")):
                state = "script-reference"
            else:
                state = "unresolved-static"
            controls.append({"position": control["position"], "tag": control["tag"], "label": label, "binding": binding, "state": state})
        pages[path.name] = controls
    return pages


def test_visible_sidebar_navigation_has_real_canonical_destinations(page, live_server):
    """Reject exposed placeholder navigation after each page's JS has run."""
    for route in sorted(ROUTES - {"/ui-v2/dashboard"}):
        response = page.goto(f"{live_server}{route}")
        assert response is not None and response.ok, route
        links = page.locator("aside nav a").evaluate_all("""nodes => nodes.filter(node => {
            const style = getComputedStyle(node);
            return node.getClientRects().length && style.visibility !== 'hidden'
                && style.display !== 'none' && !node.closest('[hidden]');
        }).map(node => ({href: node.getAttribute('href'), text: node.textContent.trim()}))""")
        assert links, f"{route}: no visible sidebar destinations"
        for link in links:
            assert link["href"] in ROUTES, f"{route}: exposed inert/unknown destination {link}"


def test_findings_filter_controls_have_explicit_script_bindings():
    controls = inventory()["ui_v2_findings.html"]
    filters = [control for control in controls if control["binding"].startswith("filter:")]
    assert len(filters) == 13
    assert all(control["state"] == "script-reference" for control in filters)
    assert {control["binding"] for control in filters} >= {
        "filter:severity:all", "filter:status:review_needed", "filter:adapter:nikto",
    }
