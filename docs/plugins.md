# Writing a WHAXON Plugin

A WHAXON plugin is a pip-installable package that adds an adapter for a
tool WHAXON doesn't ship. Once installed, the tool shows up alongside the
built-in ones — no fork, no patch, no rebuild.

This doc is for the case: **you use a tool, WHAXON doesn't parse it,
you want to fix that.** If you want to add an adapter to WHAXON itself
(inside the repo), read [`adapters.md`](adapters.md) instead. That's a
shorter path, but it means maintaining a fork.

## 1. The contract

An adapter is a Python class that:

- Subclasses `whaxon.adapters.base.Adapter`
- Sets `tool_id` to the tool's id (as it appears in `data/tools.json`)
- Implements `parse(lines, ctx=None) -> list[Finding]`

Everything else — the `remediate`, `impact`, `cvss`, `suggest_next_steps`
hooks on the ABC — is optional and has sensible defaults.

```python
from whaxon.adapters.base import Adapter
from whaxon.core.findings import Finding


class MyAdapter(Adapter):
    tool_id = "mytool"

    def parse(self, lines, ctx=None):
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            # parse text, append Finding(...) objects
        return findings
```

## 2. What `parse` receives

**`lines`** — a list of `(stream, text)` tuples. `stream` is either
`"stdout"` or `"stderr"`. Each tuple is one line of the tool's output,
with the trailing newline stripped.

**`ctx`** — a dict the runner passes through, containing:

| Key | Value |
|-----|-------|
| `tool_id` | The tool id (same as `self.tool_id` in most cases) |
| `target` | The target the operator passed |
| `extra_args` | The raw extra-args string |
| `argv` | The full argv that was executed |

Use `ctx["extra_args"]` when your tool has subtools, e.g.
`impacket-secretsdump` vs. `impacket-smbclient` — the `extra_args` field
distinguishes them, and the adapter can branch on it.

## 3. What a `Finding` is

```python
Finding(
    kind="open_port",              # required; a short classifier
    severity="info",               # required; critical/high/medium/low/info
    source="mytool",               # required; usually the tool id
    data={"port": 80},             # required; structured payload
    raw_line="80/tcp open http",   # the original line, truncated
    remediation="...",             # optional; human-readable fix
    impact="...",                  # optional; business impact
    cvss=5.3,                      # optional; CVSS 3.1 base score
    cwe="CWE-200",                 # optional; CWE id
    references=(),                 # optional; tuple of URLs
    lookup_hint="apache 2.4.7",    # optional; search string for exploit lookup
)
```

**`kind`** is what the correlator keys on. Two adapters that emit findings
with the same `kind` and the same target will be cross-referenced. Common
kinds in the built-in set: `open_port`, `found_path`, `web_issue`,
`vulnerability`, `ntlm_hash`, `smb_share`, `sqli`, `tech_detected`.

**`lookup_hint`** is new (v0.3). Set it when your finding identifies a
versioned service — e.g. `"apache 2.4.7"` or `"openssh 6.6.1"`. WHAXON
will cross-reference it against the local Exploit-DB mirror and print
matches in the engagement report. Leave it empty if the tool doesn't
report a version.

## 4. A worked example: `masscan`

Masscan is a port scanner. Its default text output looks like:

```
Discovered open port 80/tcp on 10.0.0.5
Discovered open port 443/tcp on 10.0.0.5
```

Here's a full plugin that wraps it.

### 4a. Project layout

```
whaxon-masscan/
├── pyproject.toml
├── README.md
├── src/
│   └── whaxon_masscan/
│       └── __init__.py
└── tests/
    └── test_masscan.py
```

### 4b. `src/whaxon_masscan/__init__.py`

```python
"""Masscan adapter for WHAXON."""
from __future__ import annotations

import re

from whaxon.adapters.base import Adapter
from whaxon.core.findings import Finding


_LINE_RE = re.compile(
    r"^Discovered open port (?P<port>\d+)/(?P<proto>tcp|udp) on (?P<ip>\S+)$"
)


class MasscanAdapter(Adapter):
    tool_id = "masscan"

    def parse(self, lines, ctx=None):
        findings = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            m = _LINE_RE.match(text.strip())
            if not m:
                continue
            port = int(m.group("port"))
            findings.append(Finding(
                kind="open_port",
                severity="info",
                source="masscan",
                data={
                    "port": port,
                    "protocol": m.group("proto"),
                    "ip": m.group("ip"),
                },
                raw_line=text,
            ))
        return findings
```

**Nothing is registered here.** The registry finds the class via the
entry-point declaration in `pyproject.toml` (next section). That's the
whole point of the plugin mechanism — you don't reach into WHAXON's
package to register yourself.

### 4c. `pyproject.toml`

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "whaxon-masscan"
version = "0.1.0"
description = "Masscan adapter for WHAXON"
requires-python = ">=3.11"
dependencies = ["whaxon>=0.3"]

[project.entry-points."whaxon.adapters"]
masscan = "whaxon_masscan:MasscanAdapter"

[tool.hatch.build.targets.wheel]
packages = ["src/whaxon_masscan"]
```

The important line is `[project.entry-points."whaxon.adapters"]`. The
left side is the entry-point name (any short identifier); the right
side is `<module>:<ClassName>`. WHAXON reads this dict at startup,
imports your class, instantiates it, and calls `register()` on it.

### 4d. The test

```python
# tests/test_masscan.py
from whaxon_masscan import MasscanAdapter


def test_parses_open_port():
    lines = [
        ("stdout", "Discovered open port 80/tcp on 10.0.0.5"),
        ("stdout", "Discovered open port 443/tcp on 10.0.0.5"),
        ("stdout", "Discovered open port 22/tcp on 10.0.0.6"),
    ]
    findings = MasscanAdapter().parse(lines)
    assert len(findings) == 3
    assert findings[0].kind == "open_port"
    assert findings[0].data["port"] == 80
    assert findings[1].data["protocol"] == "tcp"


def test_ignores_noise():
    lines = [
        ("stdout", "Starting masscan 1.3.2"),
        ("stdout", "rate: 100 packets/second"),
        ("stderr", "Discovered open port 22/tcp on 10.0.0.6"),
    ]
    assert MasscanAdapter().parse(lines) == []
```

### 4e. Installing locally

From the plugin project directory:

```
pip install -e .
```

WHAXON will pick it up on the next invocation. Confirm:

```
python -c "import whaxon.adapters as a; print(a.list_adapters())"
```

You should see `masscan` in the list.

## 5. What not to do

- **Don't spawn the tool from `parse`.** The runner already ran it. You
  receive its output; you don't re-run it.
- **Don't mutate `lines`.** Read it, don't modify it.
- **Don't import from `whaxon.ai`.** The adapter layer is deterministic
  and offline. The AI layer is on the other side of a hard boundary that
  WHAXON's CI enforces. Adapters that import `whaxon.ai` will fail the
  boundary test.
- **Don't swallow exceptions.** If your parser raises, WHAXON catches it
  and logs it with the tool id. That's more useful than silently returning
  `[]` and pretending the tool found nothing.

## 6. Adding to the catalog

Installing the adapter makes WHAXON able to *parse* the tool. To make it
able to *run* the tool, add an entry to `data/tools.json`:

```json
{
  "id": "masscan",
  "name": "Masscan",
  "category": "recon",
  "binary": "masscan",
  "description": "Fast port scanner",
  "args": "-p1-65535 --rate=1000 {target}",
  "package": "apt install masscan"
}
```

Then `whaxon run masscan 10.0.0.5` works, and any findings carry your
adapter's `source: "masscan"`.

## 7. Publishing to PyPI

Once the adapter works locally, publish it the same way you'd publish any
package:

```
pip install build twine
python -m build
twine upload dist/*
```

Naming convention: `whaxon-<tool>` on PyPI, so a search for `whaxon`
surfaces your plugin. Add `whaxon-plugin` and the tool name to your
package's keywords for discoverability.

## 8. What's available to import

From `whaxon.core.findings`:

- `Finding` — the dataclass you return

From `whaxon.adapters.base`:

- `Adapter` — the ABC you subclass

From `whaxon.adapters.registry`:

- `register(adapter)` — manual registration; not needed for entry-point
  plugins, but available if you're writing a local-only adapter

That's the whole public surface a plugin needs. Anything else in `whaxon`
is internal and may change without notice.

## 9. What the built-in adapters look like

Reference implementations, roughly in order of complexity:

| Adapter | Lines | What it demonstrates |
|---------|-------|----------------------|
| `dig.py` | ~40 | Simplest — one regex, info-only findings |
| `gobuster.py` | ~110 | Status-to-severity lookup table |
| `nmap.py` | ~265 | Service knowledge table + `lookup_hint` emission |
| `nikto.py` | ~215 | Issue pattern matching |
| `impacket.py` | ~150 | Sub-tool dispatch via `ctx["extra_args"]` |
| `msf.py` | ~260 | Running a tool through RPC, not a subprocess |

Start with `dig.py` or `gobuster.py` if you're modeling a new adapter.
Start with `nmap.py` if your tool reports versioned services and you
want to set `lookup_hint`.