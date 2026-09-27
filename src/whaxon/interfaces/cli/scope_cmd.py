"""whaxon scope — manage and check the engagement scope."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from whaxon.core import Core
from whaxon.core.scope import _normalize_target


def main(args: list[str] | None = None) -> None:
    args = list(args or [])
    data_dir = Path("data")
    action = "show"
    check_target = None
    set_file = None
    enable_flag = None

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--data" and i + 1 < len(args):
            data_dir = Path(args[i + 1]); i += 2
        elif a in ("-h", "--help"):
            _help(); return
        elif a == "--show" or a == "show":
            action = "show"; i += 1
        elif a == "--check" and i + 1 < len(args):
            action = "check"; check_target = args[i + 1]; i += 2
        elif a == "--set" and i + 1 < len(args):
            action = "set"; set_file = Path(args[i + 1]); i += 2
        elif a == "--enable":
            enable_flag = True; i += 1
        elif a == "--disable":
            enable_flag = False; i += 1
        elif a == "--clear":
            action = "clear"; i += 1
        else:
            print(f"Unknown arg: {a}")
            _help()
            sys.exit(2)

    core = Core(data_dir=data_dir)
    scope = core.scope

    if action == "show":
        info = scope.summary()
        print(f"File:        {info['path']}")
        print(f"Exists:      {Path(info['path']).exists()}")
        print(f"Enabled:     {info['enabled']}")
        print(f"Engagement:  {info['engagement'] or '(none)'}")
        if info["in_scope"]:
            print("In scope:")
            for r in info["in_scope"]:
                print(f"  + {r}")
        if info["out_of_scope"]:
            print("Out of scope:")
            for r in info["out_of_scope"]:
                print(f"  - {r}")
        if info["notes"]:
            print(f"Notes:       {info['notes']}")
        return

    if action == "check":
        if not check_target:
            print("Provide a target: whaxon scope --check <target>")
            sys.exit(2)
        match = scope.check(check_target)
        host, kind = _normalize_target(check_target)
        print(f"Target:   {check_target}")
        print(f"Host:     {host} ({kind})")
        print(f"Allowed:  {'YES' if match.allowed else 'NO'}")
        print(f"Reason:   {match.reason}")
        if match.matched_rule:
            print(f"Rule:     {match.matched_rule}")
        sys.exit(0 if match.allowed else 1)

    if action == "set":
        if not set_file or not set_file.exists():
            print(f"Scope file not found: {set_file}")
            sys.exit(1)
        try:
            data = json.loads(set_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"Invalid JSON: {e}")
            sys.exit(1)
        scope.save(data)
        print(f"Scope loaded from {set_file}")
        print(f"Enabled: {scope.enabled}   In: {len(scope.in_scope)}   Out: {len(scope.out_of_scope)}")
        return

    if action == "clear":
        if scope.path.exists():
            scope.path.unlink()
            print(f"Removed {scope.path}")
        else:
            print("No scope file to remove")
        return

    if enable_flag is not None:
        data = {
            "enabled": enable_flag,
            "engagement": scope.engagement,
            "in_scope": scope.in_scope,
            "out_of_scope": scope.out_of_scope,
            "notes": scope.notes,
        }
        scope.save(data)
        print(f"Scope {'enabled' if enable_flag else 'disabled'}")
        return


def _help() -> None:
    print("Usage:")
    print("  whaxon scope --show                Show current scope")
    print("  whaxon scope --check <target>      Check if target is in scope")
    print("  whaxon scope --set <file.json>     Load scope from a file")
    print("  whaxon scope --enable / --disable  Toggle enforcement")
    print("  whaxon scope --clear               Remove the scope file")
