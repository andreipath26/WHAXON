"""Impacket adapter — SMB / SAM / WMI."""
from __future__ import annotations

import re
import shutil
import subprocess

from ..core.findings import Finding
from .base import Adapter
from .registry import register

_SAM_RX = re.compile(
    r"^(?P<domain>[^\\]+)\\(?P<user>[^:]+):(?P<uid>\d+):"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::"
)
_BARE_RX = re.compile(
    r"^(?P<user>[^:\\]+):(?P<uid>\d+):"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::"
)


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    except FileNotFoundError:
        return ""
    except Exception as e:
        return f"[impacket] {type(e).__name__}: {e}"


def _parse_secretsdump(out):
    res = []
    for line in out.splitlines():
        line = line.strip()
        m = _SAM_RX.match(line) or _BARE_RX.match(line)
        if m:
            gd = m.groupdict()
            res.append(Finding(
                kind="ntlm_hash", severity="critical", source="impacket",
                data={
                    "user": gd["user"], "uid": gd["uid"],
                    "lm_hash": gd["lm"].lower(), "nt_hash": gd["nt"].lower(),
                    "domain": gd.get("domain") or "",
                },
                raw_line=f"secretsdump: {gd.get('domain','')}\\{gd['user']} nt={gd['nt']}",
                remediation="Rotate the account password.",
                impact="NTLM hash extracted.",
                cvss=9.8, cwe="CWE-522",
            ))
        elif line.startswith("[*]") or line.startswith("[+]"):
            res.append(Finding(
                kind="impacket_loot", severity="info", source="impacket",
                data={"line": line}, raw_line=line[:200],
            ))
    return res


def _parse_smbclient(out):
    res = []
    rx = re.compile(r"^\s*(?P<share>[A-Za-z0-9_\-$\.]+)\s+(?P<type>Disk|IPC|Printer)\s")
    for line in out.splitlines():
        m = rx.match(line)
        if m:
            res.append(Finding(
                kind="smb_share", severity="info", source="impacket",
                data={"share": m.group("share"), "type": m.group("type")},
                raw_line=line.strip()[:200],
            ))
    return res


def _parse_wmiexec(out):
    return [
        Finding(kind="wmi_result", severity="info", source="impacket",
                data={"line": l.strip()}, raw_line=l.strip()[:200])
        for l in out.splitlines() if l.strip()
    ]


class ImpacketAdapter(Adapter):
    tool_id = "impacket"

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        if isinstance(lines, list):
            parts = []
            for item in lines:
                if isinstance(item, tuple) and len(item) == 2:
                    parts.append(str(item[1]))
                else:
                    parts.append(str(item))
            out = "\n".join(parts)
        else:
            out = lines or ""

        # Prefer explicit subtool from ctx (runner passes extra_args/argv).
        extra = (ctx.get("extra_args") or "").strip()
        argv = ctx.get("argv") or []
        if extra:
            subtool = extra.split()[0]
        elif len(argv) > 1:
            subtool = argv[1]
        else:
            subtool = ""

        if subtool == "secretsdump":
            return _parse_secretsdump(out)
        if subtool == "smbclient":
            return _parse_smbclient(out)
        if subtool == "wmiexec":
            return _parse_wmiexec(out)

        # Fallback: content autodetect (keeps behaviour when ctx is empty).
        for fn in (_parse_secretsdump, _parse_smbclient, _parse_wmiexec):
            r = fn(out)
            if r:
                return r
        return []
    def run_module(self, tool_id, extra_args, ctx=None):
        ctx = ctx or {}
        toks = (extra_args or "").strip().split()
        if not toks:
            return [Finding(kind="impacket_error", severity="info", source="impacket",
                            raw_line="usage: <subtool> <args...>")]
        subtool, rest = toks[0], toks[1:]
        bn = "impacket-" + subtool
        bp = shutil.which(bn)
        if not bp:
            return [Finding(kind="impacket_error", severity="info", source="impacket",
                            raw_line=f"{bn} not found in PATH")]
        target = ctx.get("target") or "127.0.0.1"
        cmd = [bp] + rest
        if target and target not in rest:
            cmd.append(target)
        out = _run(cmd)
        if subtool == "secretsdump":
            r = _parse_secretsdump(out)
        elif subtool == "smbclient":
            r = _parse_smbclient(out)
        elif subtool == "wmiexec":
            r = _parse_wmiexec(out)
        else:
            r = []
        if not r:
            return [Finding(kind="impacket_error", severity="info", source="impacket",
                            raw_line=f"impacket-{subtool}: no findings")]
        return r


register(ImpacketAdapter())
