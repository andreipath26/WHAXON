"""Program policy loader, validator, resolver (docs/bounty-addon.md §26.1).

A per-program policy file gates every bounty operation. Without a valid
policy matching the target host, the add-on refuses. This is the outer
gate; core/scope.py remains the inner host-level gate.

Platform-agnostic: `platform_extras` is validated only for the named
platform; `reward_model` is a tagged union. v1 implements `grid` only.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

PROGRAMS_DIR = "programs"
KNOWN_PLATFORMS = ("yeswehack", "hackerone", "bugcrowd", "intigriti", "immunefi", "other")
REWARD_TYPES = ("grid", "severity_table", "vrt_tier", "range", "impact_matrix")
V1_REWARD_TYPES = ("grid",)

_TOP_KEYS = {
    "slug", "platform", "program_url", "title", "organization",
    "program_type", "visibility", "last_reviewed", "last_update",
    "supported_languages", "identity", "account_access", "rate",
    "reward_model", "scope", "hunting_requirements", "tools",
    "ai_policy", "reporting", "bug_classes", "platform_extras",
    "population", "override_log",
}


class PolicyError(RuntimeError):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class ScopeEntry:
    scope: str
    type: str = "web"
    asset_value: str = "medium"

    def to_dict(self) -> dict:
        return {"scope": self.scope, "type": self.type, "asset_value": self.asset_value}


@dataclass(frozen=True)
class ProgramPolicy:
    slug: str
    platform: str
    data: dict
    in_scope: tuple[ScopeEntry, ...] = field(default_factory=tuple)

    def matches(self, host: str) -> bool:
        h = (host or "").strip().lower()
        if not h:
            return False
        for e in self.in_scope:
            s = e.scope.lower()
            if s.startswith("*."):
                if h.endswith(s[1:]) or h == s[2:]:
                    return True
            else:
                bare = s.split("://", 1)[-1].split("/", 1)[0]
                if h in (bare, s):
                    return True
        return False


def _program_path(data_dir: str | Path, slug: str) -> Path:
    return Path(data_dir) / PROGRAMS_DIR / f"{slug}.json"


def _parse_scopes(raw) -> tuple[ScopeEntry, ...]:
    out = []
    for item in raw or []:
        if isinstance(item, str):
            out.append(ScopeEntry(scope=item))
        elif isinstance(item, dict) and item.get("scope"):
            out.append(ScopeEntry(
                scope=str(item["scope"]),
                type=str(item.get("type") or "web"),
                asset_value=str(item.get("asset_value") or "medium"),
            ))
        else:
            raise PolicyError(f"scope.in_scope entry malformed: {item!r}")
    return tuple(out)


def load_policy(data_dir: str | Path, slug: str) -> ProgramPolicy:
    path = _program_path(data_dir, slug)
    if not path.exists():
        raise PolicyError(f"policy file missing: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        raise PolicyError(f"policy file malformed ({path}): {e}") from e
    return validate_policy(data, source=str(path))


def validate_policy(data: dict, source: str = "<inline>") -> ProgramPolicy:
    if not isinstance(data, dict):
        raise PolicyError(f"policy is not an object ({source})")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise PolicyError(f"unknown policy key(s) {sorted(unknown)} ({source})")

    platform = str(data.get("platform") or "").strip().lower()
    if platform not in KNOWN_PLATFORMS:
        raise PolicyError(f"unknown platform '{platform}' ({source})")

    slug = str(data.get("slug") or "").strip()
    if not slug:
        raise PolicyError(f"missing slug ({source})")

    tools = data.get("tools") or {}
    if not isinstance(tools, dict) or not tools.get("mode"):
        raise PolicyError(f"missing tools.mode ({source})")

    scope = data.get("scope") or {}
    raw_in = scope.get("in_scope") if isinstance(scope, dict) else None
    if not raw_in:
        raise PolicyError(f"empty scope.in_scope ({source})")
    in_scope = _parse_scopes(raw_in)

    rm = data.get("reward_model") or {}
    rtype = str(rm.get("type") or "").strip().lower()
    if rtype not in REWARD_TYPES:
        raise PolicyError(f"unknown reward_model.type '{rtype}' ({source})")
    if rtype not in V1_REWARD_TYPES:
        raise PolicyError(
            f"reward_model.type '{rtype}' is not implemented in v1 "
            f"(v1 implements: {', '.join(V1_REWARD_TYPES)}) ({source})"
        )

    return ProgramPolicy(slug=slug, platform=platform, data=data, in_scope=in_scope)


def resolve_for_host(data_dir: str | Path, host: str) -> ProgramPolicy | None:
    d = Path(data_dir) / PROGRAMS_DIR
    if not d.exists():
        return None
    matches = []
    for f in sorted(d.glob("*.json")):
        try:
            p = load_policy(data_dir, f.stem)
        except PolicyError:
            continue
        if p.matches(host):
            matches.append(p)
    if len(matches) > 1:
        raise PolicyError(f"multiple policies match {host}: {[m.slug for m in matches]}")
    return matches[0] if matches else None
