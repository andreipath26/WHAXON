"""Supplemental G01 guard for every top-level WHAXON CLI mode.

This protects the open exhaustive V1 CLI surface inventory without changing
frozen bounded G01 acceptance evidence.
"""
from __future__ import annotations

import ast
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI_SOURCE = ROOT / "src" / "whaxon" / "cli.py"
INVENTORY = ROOT / "docs" / "ENGINE_V2_G01_CLI_MODE_INVENTORY.csv"


def _mode_literals(node: ast.AST) -> set[str]:
    values: set[str] = set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        values.add(node.value)
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for item in node.elts:
            values.update(_mode_literals(item))
    return values


def test_every_top_level_cli_mode_has_an_inventory_disposition():
    source = CLI_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    with INVENTORY.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))

    modes = [row["mode"] for row in rows]
    assert len(modes) == len(set(modes)), "CLI mode inventory has duplicate modes"
    assert "__default__" in modes
    assert {"mode", "dispatcher_source", "engine_owner", "classification", "v1_boundary_or_limit"} <= set(rows[0])

    explicit = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name):
            continue
        if node.left.id != "mode":
            continue
        for operator, comparator in zip(node.ops, node.comparators, strict=True):
            if isinstance(operator, (ast.Eq, ast.In)):
                explicit.update(_mode_literals(comparator))

    inventoried = set(modes) - {"__default__"}
    assert explicit == inventoried, (
        f"CLI dispatcher and inventory differ: missing={sorted(explicit-inventoried)}, "
        f"stale={sorted(inventoried-explicit)}"
    )

    mode_assignment = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "mode" for target in node.targets)
    )
    assert isinstance(mode_assignment.value, ast.IfExp)
    assert isinstance(mode_assignment.value.orelse, ast.Constant)
    assert mode_assignment.value.orelse.value == "tui"

    for row in rows:
        assert row["dispatcher_source"], row["mode"]
        assert (ROOT / row["dispatcher_source"]).is_file(), row["mode"]
        assert row["engine_owner"] and row["classification"] and row["v1_boundary_or_limit"], row["mode"]
