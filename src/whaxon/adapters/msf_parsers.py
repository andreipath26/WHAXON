"""Per-module loot parsers for MSF console output.

Each parser takes the raw console_output string from MSFClient.execute()
and returns a list of dicts shaped like:

    {"kind": "<finding kind>", "data": {...}, "raw": "<short line>"}

The adapter converts each into a Finding.
"""
from __future__ import annotations

import re
from typing import Callable


Result = dict


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _strip_banner(out: str) -> str:
    """Drop the msfconsole banner / version block that precedes module output."""
    # cut everything up to the last occurrence of the metasploit version block
    marker = "Metasploit Documentation:"
    i = out.rfind(marker)
    if i >= 0:
        nl = out.find("\n", i)
        if nl >= 0:
            out = out[nl + 1:]
    return out


def _kv_lines(block: str, pattern: str = r"^([A-Z_][A-Z0-9_]*)=(.*)$") -> list[tuple[str, str]]:
    rx = re.compile(pattern)
    out = []
    for line in block.splitlines():
        m = rx.match(line.strip())
        if m:
            out.append((m.group(1), m.group(2)))
    return out


# --------------------------------------------------------------------------
# per-module parsers
# --------------------------------------------------------------------------

def parse_env(out: str) -> list[Result]:
    body = _strip_banner(out)
    results = []
    for k, v in _kv_lines(body):
        results.append({
            "kind": "env_var",
            "data": {"name": k, "value": v},
            "raw": f"{k}={v}",
        })
    return results


def parse_sysinfo(out: str) -> list[Result]:
    body = _strip_banner(out)
    results = []
    # sysinfo prints "Key  : Value" pairs
    rx = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _\-/]+?)\s*:\s*(.+?)\s*$")
    for line in body.splitlines():
        m = rx.match(line)
        if m:
            k, v = m.group(1).strip(), m.group(2).strip()
            if k and v and len(k) < 40:
                results.append({
                    "kind": "sysinfo",
                    "data": {"field": k, "value": v},
                    "raw": f"{k}: {v}",
                })
    return results


def parse_platform(out: str) -> list[Result]:
    body = _strip_banner(out)
    for line in body.splitlines():
        m = re.match(r"^\s*Platform\s*:\s*(.+)$", line.strip(), re.I)
        if m:
            return [{"kind": "platform", "data": {"platform": m.group(1).strip()}, "raw": line.strip()}]
    return []


def parse_hashdump(out: str) -> list[Result]:
    body = _strip_banner(out)
    results = []
    # classic format:   user:uid:LMHASH:NTHASH:::
    rx = re.compile(r"^([^:\s]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")
    for line in body.splitlines():
        m = rx.match(line.strip())
        if m:
            results.append({
                "kind": "ntlm_hash",
                "data": {
                    "user": m.group(1),
                    "uid": m.group(2),
                    "lm_hash": m.group(3).lower(),
                    "nt_hash": m.group(4).lower(),
                },
                "raw": f"{m.group(1)}:{m.group(2)}:{m.group(3)}:{m.group(4)}",
            })
    return results


def parse_services(out: str) -> list[Result]:
    body = _strip_banner(out)
    results = []
    # services prints lines like "  80/tcp   open  http"
    rx = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(.+?)$")
    for line in body.splitlines():
        m = rx.match(line.strip())
        if m:
            results.append({
                "kind": "service",
                "data": {
                    "port": int(m.group(1)),
                    "proto": m.group(2),
                    "state": m.group(3),
                    "name": m.group(4).strip(),
                },
                "raw": line.strip(),
            })
    return results


# --------------------------------------------------------------------------
# registry + dispatcher
# --------------------------------------------------------------------------



def parse_local_exploit_suggester(out: str) -> list[Result]:
    """Parses post/multi/recon/local_exploit_suggester output."""
    body = _strip_banner(out)
    results = []
    # lines look like:  [+] 10.0.0.5 - exploit/linux/local/foo_bar
    rx = re.compile(r"^\s*\[\+\]\s*\S+\s*-\s*(exploit|post|auxiliary)/(\S+)")
    for line in body.splitlines():
        m = rx.match(line)
        if m:
            results.append({
                "kind": "exploit_suggestion",
                "data": {"module_type": m.group(1), "module": m.group(2)},
                "raw": line.strip(),
            })
    return results


def parse_enum_network(out: str) -> list[Result]:
    """Parses post/linux/gather/enum_network output (interfaces, routes)."""
    body = _strip_banner(out)
    results = []
    ip_rx = re.compile(r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s")
    for line in body.splitlines():
        m = ip_rx.match(line)
        if m:
            results.append({
                "kind": "network_iface",
                "data": {"ip": m.group(1), "cidr": m.group(2)},
                "raw": line.strip(),
            })
    return results


def parse_enum_system(out: str) -> list[Result]:
    """Fallback: extract section headers from enum_system."""
    body = _strip_banner(out)
    results = []
    header_rx = re.compile(r"^\[\+\]\s*[A-Z][A-Za-z ]+$")
    for line in body.splitlines():
        if header_rx.match(line.strip()):
            results.append({
                "kind": "system_section",
                "data": {"section": line.strip()[4:]},
                "raw": line.strip(),
            })
    return results

# --------------------------------------------------------------------------
# SQLmap / Nuclei style parsers (may be invoked by their own adapters,
# registered here so the aggregate loot view sees them)
# --------------------------------------------------------------------------

def parse_sqlmap_dump(out: str) -> list[Result]:
    """Extract dumped rows from sqlmap console output.

    sqlmap prints lines like:
        Database: dvwa
        Table: users
        [2 entries]
        +----+-------+----------+
        | id | user  | password |
        +----+-------+----------+
        | 1  | admin | 5f4dcc3b |
        +----+-------+----------+
    We heuristically pull table/database headers and pipe-row data.
    """
    body = _strip_banner(out)
    results = []
    db_rx = re.compile(r"^Database:\s*(\S+)")
    tbl_rx = re.compile(r"^Table:\s*(\S+)")
    row_rx = re.compile(r"^\|\s*(.+?)\s*\|$")
    cur_db = ""
    cur_tbl = ""
    for line in body.splitlines():
        m = db_rx.match(line.strip())
        if m:
            cur_db = m.group(1)
            results.append({"kind": "sqlmap_database",
                            "data": {"database": cur_db},
                            "raw": line.strip()})
            continue
        m = tbl_rx.match(line.strip())
        if m:
            cur_tbl = m.group(1)
            results.append({"kind": "sqlmap_table",
                            "data": {"database": cur_db, "table": cur_tbl},
                            "raw": line.strip()})
            continue
        m = row_rx.match(line.strip())
        if m:
            cells = [c.strip() for c in m.group(1).split("|")]
            # skip the divider rows (+---) that sometimes match
            if all(set(c) <= set("+-") for c in cells):
                continue
            results.append({"kind": "sqlmap_row",
                            "data": {"database": cur_db, "table": cur_tbl,
                                     "cells": cells},
                            "raw": line.strip()})
    return results


def parse_nuclei_findings(out: str) -> list[Result]:
    """Extract [template-id] [protocol] [severity] host lines from nuclei."""
    body = _strip_banner(out)
    results = []
    # nuclei -v output: [template-id] [http] [severity] http://host/path
    rx = re.compile(r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)")
    for line in body.splitlines():
        m = rx.match(line.strip())
        if m:
            results.append({
                "kind": "nuclei_finding",
                "data": {"template": m.group(1), "protocol": m.group(2),
                         "severity": m.group(3), "url": m.group(4)},
                "raw": line.strip(),
            })
    # also match CVE tags inside the template name
    for r in list(results):
        tmpl = r["data"]["template"]
        cve = re.search(r"(CVE-\d{4}-\d{4,7})", tmpl, re.I)
        if cve:
            results.append({
                "kind": "cve",
                "data": {"cve": cve.group(1).upper(),
                         "template": tmpl, "url": r["data"]["url"]},
                "raw": f"{cve.group(1).upper()} via {tmpl}",
            })
    return results


PARSERS: dict[str, Callable[[str], list[Result]]] = {
    "sqlmap": parse_sqlmap_dump,
    "nuclei": parse_nuclei_findings,
    "multi/recon/local_exploit_suggester": parse_local_exploit_suggester,
    "post/multi/recon/local_exploit_suggester": parse_local_exploit_suggester,
    "post/linux/gather/enum_network": parse_enum_network,
    "post/linux/gather/enum_system":  parse_enum_system,
    "multi/gather/env":         parse_env,
    "multi/gather/checkvm":     parse_sysinfo,
    "multi/gather/hashdump":    parse_hashdump,
    "multi/gather/ssh_creds":   parse_env,
    "multi/gather/win_privs":   parse_sysinfo,
    "multi/gather/credentials": parse_env,
    "post/multi/gather/env":    parse_env,
    "post/multi/gather/hashdump": parse_hashdump,
    "post/multi/recon/local_exploit_suggester": parse_sysinfo,
    "multi/recon/local_exploit_suggester": parse_sysinfo,
    "post/windows/gather/enum_services": parse_services,
    "post/linux/gather/enum_system":     parse_sysinfo,
    "post/linux/gather/enum_network":    parse_sysinfo,
}


def parse_loot(module_path: str, console_output: str) -> list[Result]:
    """Return a list of structured loot dicts for a module run."""
    if not console_output:
        return []
    parser = PARSERS.get(module_path)
    if parser is None:
        # try suffix match: if any registered key ends with the module path
        for k, fn in PARSERS.items():
            if k.endswith(module_path) or module_path.endswith(k.split("/", 1)[-1]):
                parser = fn
                break
    if parser is None:
        return []
    try:
        return parser(console_output)
    except Exception:
        return []
