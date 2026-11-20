"""Keep the top-level CLI help aligned with dispatched command modes."""
from __future__ import annotations

import ast
import re
from pathlib import Path

from whaxon import cli


def test_every_dispatched_top_level_mode_is_listed_in_help(monkeypatch, capsys):
    source = Path(cli.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    modes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name):
            continue
        if node.left.id != "mode":
            continue
        for comparator in node.comparators:
            try:
                values = ast.literal_eval(comparator)
            except (ValueError, TypeError):
                continue
            if isinstance(values, str):
                values = (values,)
            if isinstance(values, tuple):
                modes.update(
                    value for value in values
                    if isinstance(value, str) and not value.startswith("-")
                )

    monkeypatch.setattr("sys.argv", ["whaxon", "--help"])
    cli.main()
    help_text = capsys.readouterr().out
    listed = set(re.search(r"Usage: whaxon \[([^]]+)\]", help_text).group(1).split("|"))

    assert modes <= listed, f"dispatched modes missing from --help: {modes - listed}"


def test_dispatched_top_level_modes_match_g01_inventory():
    source_path = Path(cli.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    modes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name):
            continue
        if node.left.id != "mode":
            continue
        for comparator in node.comparators:
            try:
                values = ast.literal_eval(comparator)
            except (ValueError, TypeError):
                continue
            if isinstance(values, str):
                values = (values,)
            if isinstance(values, tuple):
                modes.update(
                    value for value in values
                    if isinstance(value, str) and not value.startswith("-")
                )

    inventory_path = (
        source_path.parents[2]
        / "docs"
        / "ENGINE_V2_LEGACY_EXECUTION_INVENTORY.md"
    )
    inventory = inventory_path.read_text(encoding="utf-8")
    section = re.search(
        r"Top-level CLI modes from `src/whaxon/cli\.py` are (.*?)(?:\.|$)",
        inventory,
        re.DOTALL,
    )
    assert section is not None, "G01 inventory is missing its top-level CLI modes section"
    documented = set(re.findall(r"`([^`]+)`", section.group(1)))

    assert documented == modes, f"CLI/G01 inventory drift: missing={modes - documented}, stale={documented - modes}"
