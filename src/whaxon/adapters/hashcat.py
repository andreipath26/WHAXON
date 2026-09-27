"""Hashcat adapter - crack NTLM hashes from MSF loot."""
from __future__ import annotations
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from ..core.findings import Finding
from .base import Adapter
from .registry import register


def _find_hashes(store):
    out = []
    for job in store.history(limit=500):
        try:
            for f in store.get_findings(job["id"]) or []:
                if f.get("kind") == "ntlm_hash":
                    out.append(f.get("data") or {})
        except Exception:
            continue
    return out


class HashcatAdapter(Adapter):
    tool_id = "hashcat"

    def parse(self, lines, ctx=None):
        return []

    def run_module(self, tool_id, extra_args, ctx=None):
        ctx = ctx or {}
        store = ctx.get("store")
        bin_path = shutil.which("hashcat")
        if not bin_path:
            return [Finding(kind="hashcat_skip", severity="info", source="hashcat",
                            raw_line="hashcat: binary not installed")]
        if store is None:
            return [Finding(kind="hashcat_skip", severity="info", source="hashcat",
                            raw_line="hashcat: no store in context")]
        hashes = _find_hashes(store)
        if not hashes:
            return [Finding(kind="hashcat_skip", severity="info", source="hashcat",
                            raw_line="hashcat: no ntlm_hash findings yet")]
        lines = []
        for h in hashes:
            nt = (h.get("nt_hash") or "").strip()
            if nt:
                lines.append("%s:%s:%s" % (nt, h.get("user", ""), h.get("uid", "")))
        if not lines:
            return [Finding(kind="hashcat_skip", severity="info", source="hashcat",
                            raw_line="hashcat: no usable nt_hash values")]
        wordlist = None
        for tok in (extra_args or "").split():
            if tok.startswith("--wordlist="):
                wl = Path(tok.split("=", 1)[1])
                if wl.exists():
                    wordlist = wl
        hf = Path(tempfile.mkstemp(suffix=".txt")[1])
        hf.write_text("\n".join(lines), encoding="utf-8")
        tmp_out = Path(tempfile.mkstemp(prefix="hashcat_out_")[1])
        try:
            cmd = [bin_path, "-m", "1000", "--quiet", "--potfile-disable",
                   "-o", str(tmp_out), str(hf)]
            if wordlist:
                cmd += ["-a", "0", str(wordlist)]
            else:
                cmd += ["-a", "3", "?a?a?a?a?a?a"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
            out = tmp_out.read_text(encoding="utf-8", errors="replace") if tmp_out.exists() else ""
        finally:
            for f in (hf, tmp_out):
                try: f.unlink()
                except Exception: pass
        findings = []
        for line in (out or "").splitlines():
            m = re.match(r"^([0-9a-fA-F]{32}):([^:]*):([^:]*):(.+)$", line.strip())
            if m:
                findings.append(Finding(
                    kind="hashcat_crack", severity="critical", source="hashcat",
                    data={"nt_hash": m.group(1).lower(), "user": m.group(2),
                          "uid": m.group(3), "password": m.group(4)},
                    raw_line="cracked: %s = %s" % (m.group(2), m.group(4)),
                    remediation="Rotate credentials.",
                    impact="Plaintext password recovered.",
                    cvss=9.8, cwe="CWE-521"))
        if not findings:
            findings.append(Finding(kind="hashcat_done", severity="info", source="hashcat",
                                    raw_line="hashcat ran on %d hashes; none cracked" % len(lines)))
        return findings


register(HashcatAdapter())
