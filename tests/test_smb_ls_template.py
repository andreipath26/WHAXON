"""§4.2: smb_ls command is templated, not hardcoded to the 'whaxon' share."""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _smb_ls_entry():
    d = json.loads((REPO / "data" / "tools.json").read_text())
    tools = d if isinstance(d, list) else d.get("tools", [])
    return next(t for t in tools if t["id"] == "smb_ls")


def test_smb_ls_command_is_a_template():
    entry = _smb_ls_entry()
    assert "{command}" in entry["command"], (
        f"smb_ls command is not templated: {entry['command']!r}"
    )


def test_smb_ls_does_not_hardcode_whaxon_share():
    entry = _smb_ls_entry()
    assert "use whaxon" not in entry["command"], (
        "smb_ls still hardcodes the whaxon share"
    )


def test_smb_ls_template_substitutes_share():
    entry = _smb_ls_entry()
    raw = entry["command"]
    # The runner does exactly this substitution.
    command = raw.replace("{command}", "public")
    assert command == "use public\\nls", f"got {command!r}"


def test_smb_ls_description_mentions_required_share():
    entry = _smb_ls_entry()
    desc = entry["description"].lower()
    assert "share" in desc and "extra" in desc, (
        f"description does not tell the user the share is required: {entry['description']!r}"
    )
