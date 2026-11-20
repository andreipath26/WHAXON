"""Require the single mandatory UI-wide crosswalk to cover every production screen."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CROSSWALK = ROOT / "docs" / "V2_UI_MANDATORY_CROSSWALK.md"
TEMPLATES = ROOT / "src" / "whaxon" / "interfaces" / "web" / "templates"


def test_ui_crosswalk_enumerates_all_production_pages_and_prework_rules():
    doc = CROSSWALK.read_text(encoding="utf-8")
    instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    templates = sorted(p.name for p in TEMPLATES.glob("ui_v2_*.html"))
    assert len(templates) == 22
    for filename in templates:
        assert doc.count("`" + filename + "`") >= 1, filename
    assert "D1" in doc and "D6" in doc
    assert "E6 UI integration is active work" in doc
    assert "docs/V2_UI_MANDATORY_CROSSWALK.md" in instructions
