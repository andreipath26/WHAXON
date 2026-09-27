"""whaxon install <tool_id> — install a catalog tool via apt (with confirmation)."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from whaxon.core import Core


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: whaxon install <tool_id> [--data DIR] [--yes]")
        print("       whaxon install --list")
        return

    data_dir = Path("data")
    tool_id = None
    auto_yes = False

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a == "--yes" or a == "-y":
            auto_yes = True; i += 1
        elif a == "--list":
            _list_tools(data_dir)
            return
        elif not tool_id:
            tool_id = a; i += 1
        else:
            print(f"Unknown arg: {a}"); sys.exit(2)

    if not tool_id:
        print("Provide a tool id, or use --list")
        sys.exit(2)

    core = Core(data_dir=data_dir)
    tool = core.catalog.get(tool_id)
    if tool is None:
        print(f"Unknown tool: {tool_id}")
        print("Try: whaxon install --list")
        sys.exit(1)

    binary_present = shutil.which(tool.binary) is not None
    if binary_present:
        print(f"{tool.name} is already installed ({tool.binary})")
        return

    if not tool.package:
        print(f"{tool.name} has no apt package recorded in the catalog.")
        print(f"You'll need to install it manually. Binary name: {tool.binary}")
        sys.exit(1)

    cmd = ["sudo", "apt", "install", "-y", tool.package]

    print(f"Tool:    {tool.name} ({tool.id})")
    print(f"Binary:  {tool.binary}")
    print(f"Package: {tool.package}")
    print()
    print("This will run:")
    print("  " + " ".join(cmd))
    print()

    if not auto_yes:
        try:
            answer = input("Proceed? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    print()
    print("Running install...")
    print()
    result = subprocess.run(cmd)
    sys.exit(result.returncode)


def _list_tools(data_dir: Path) -> None:
    import shutil
    core = Core(data_dir=data_dir)
    print(f"{'ID':12} {'BINARY':14} {'STATUS':10} PACKAGE")
    for t in sorted(core.catalog.list(), key=lambda x: x.id):
        present = shutil.which(t.binary) is not None
        status = "installed" if present else "MISSING"
        print(f"{t.id:12} {t.binary:14} {status:10} {t.package or '(none)'}")
