"""whaxon bounty <policy|run> — bug-bounty add-on CLI (§26.1).

The program gate lives here, not in runner: a bounty run must resolve
to exactly one program policy whose scope.in_scope contains the target,
or it refuses. Non-bounty `whaxon run` is unaffected.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from whaxon.core.bounty_parse import parse_yeswehack
from whaxon.core.program_policy import (
    PolicyError,
    load_policy,
    resolve_for_host,
    validate_policy,
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_POLICY = 3


def _programs_dir(data_dir: Path) -> Path:
    return data_dir / "programs"


def _cmd_policy_init(data_dir: Path, slug: str, from_clipboard: bool) -> int:
    if not slug:
        print("usage: whaxon bounty policy init <slug> [--from-clipboard]", file=sys.stderr)
        return EXIT_USAGE
    if not from_clipboard:
        print("only --from-clipboard is supported in v1", file=sys.stderr)
        return EXIT_USAGE
    text = sys.stdin.read()
    if not text.strip():
        print("no input on stdin", file=sys.stderr)
        return EXIT_USAGE
    policy = parse_yeswehack(text, slug=slug)
    try:
        validate_policy(policy)
    except PolicyError as e:
        print(f"parsed policy is invalid: {e}", file=sys.stderr)
        return EXIT_POLICY
    out = _programs_dir(data_dir) / f"{slug}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    print("review it: the parser does not fill qualifying/non-qualifying lists,")
    print("out-of-scope text, or required report fields. Edit before use.")
    return EXIT_OK


def _cmd_policy_list(data_dir: Path) -> int:
    d = _programs_dir(data_dir)
    if not d.exists() or not any(d.glob("*.json")):
        print("no program policies")
        return EXIT_OK
    for f in sorted(d.glob("*.json")):
        try:
            p = load_policy(data_dir, f.stem)
            print(f"{p.slug}\t{p.platform}\t{len(p.in_scope)} scopes")
        except PolicyError as e:
            print(f"{f.stem}\tINVALID: {e}")
    return EXIT_OK


def _cmd_policy_validate(data_dir: Path, slug: str) -> int:
    try:
        p = load_policy(data_dir, slug)
    except PolicyError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return EXIT_POLICY
    print(f"ok: {p.slug} ({p.platform}), {len(p.in_scope)} scopes")
    return EXIT_OK


def _cmd_run(data_dir: Path, target: str, rest: list[str]) -> int:
    if not target:
        print("usage: whaxon bounty run <target> -- <tool> [args]", file=sys.stderr)
        return EXIT_USAGE
    try:
        policy = resolve_for_host(data_dir, target)
    except PolicyError as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_POLICY
    if policy is None:
        print(f"refused: no program policy matches {target}", file=sys.stderr)
        return EXIT_POLICY
    if not rest:
        print("usage: whaxon bounty run <target> -- <tool> [args]", file=sys.stderr)
        return EXIT_USAGE
    tool = rest[0]
    tools_cfg = policy.data.get("tools") or {}
    mode = str(tools_cfg.get("mode") or "").lower()
    allow = set(tools_cfg.get("allowlist") or [])
    deny = set(tools_cfg.get("denylist") or [])
    if mode == "allowlist" and tool not in allow:
        print(f"refused: {tool} is not on {policy.slug}'s allowlist", file=sys.stderr)
        return EXIT_POLICY
    if mode == "denylist" and tool in deny:
        print(f"refused: {tool} is on {policy.slug}'s denylist", file=sys.stderr)
        return EXIT_POLICY
    if mode not in {"allowlist", "denylist"}:
        print(f"refused: unsupported tool policy mode '{mode}'", file=sys.stderr)
        return EXIT_POLICY
    print(f"policy {policy.slug} permits {tool} on {target}")
    print("note: dispatch is not wired in v1; this command validates the gate only")
    return EXIT_OK


def main(args: list[str]) -> int:
    data_dir = Path("data")
    if "--data" in args:
        i = args.index("--data")
        data_dir = Path(args[i + 1])
        args = args[:i] + args[i + 2:]
    if not args:
        print("usage: whaxon bounty <policy|run> ...", file=sys.stderr)
        return EXIT_USAGE
    sub = args[0]
    if sub == "policy":
        if len(args) < 2:
            print("usage: whaxon bounty policy <init|list|validate>", file=sys.stderr)
            return EXIT_USAGE
        op = args[1]
        if op == "init":
            return _cmd_policy_init(data_dir, args[2] if len(args) > 2 else "",
                                    "--from-clipboard" in args)
        if op == "list":
            return _cmd_policy_list(data_dir)
        if op == "validate":
            return _cmd_policy_validate(data_dir, args[2] if len(args) > 2 else "")
        print(f"unknown policy op: {op}", file=sys.stderr)
        return EXIT_USAGE
    if sub == "run":
        target = args[1] if len(args) > 1 else ""
        rest = args[3:] if len(args) > 3 and args[2] == "--" else []
        return _cmd_run(data_dir, target, rest)
    print(f"unknown bounty subcommand: {sub}", file=sys.stderr)
    return EXIT_USAGE
