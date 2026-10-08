"""Tests for the impacket adapter's parse() dispatch.

Guards two contracts:
  1. parse() consumes list[tuple[stream, text]] as declared by Adapter.parse.
  2. subtool dispatch prefers ctx["extra_args"] over content autodetection.

secretsdump output shape is frozen from a stub that mirrors Impacket 0.11.
"""
from __future__ import annotations

from whaxon.adapters.impacket import ImpacketAdapter

SAM = [
    "Impacket v0.11.0 - Copyright 2023 Fortra",
    "",
    "[*] Target system bootKey: 0x1a2b3c4d5e6f",
    "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)",
    "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
    "alice:1001:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::",
    "[*] Cleaning up...",
]

SHARES = [
    "[*] Retrieving shares",
    "Sharename       Type      Comment",
    "---------       ----      -------",
    "ADMIN$          Disk      Remote Admin",
    "C$              Disk      Default share",
    "IPC$            IPC       Remote IPC",
    "public          Disk      Public files",
]


def _as_tuples(lines):
    return [("stdout", l) for l in lines]


def test_parse_secretsdump_via_extra_args():
    a = ImpacketAdapter()
    findings = a.parse(_as_tuples(SAM), ctx={"extra_args": "secretsdump -just-dc"})
    kinds = [f.kind for f in findings]
    assert kinds.count("ntlm_hash") == 3
    assert all(f.severity == "critical" for f in findings if f.kind == "ntlm_hash")
    users = {f.data["user"] for f in findings if f.kind == "ntlm_hash"}
    assert users == {"Administrator", "Guest", "alice"}
    alice = next(f for f in findings if f.kind == "ntlm_hash" and f.data["user"] == "alice")
    assert alice.data["nt_hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert alice.data["uid"] == "1001"


def test_parse_smbclient_via_extra_args():
    a = ImpacketAdapter()
    findings = a.parse(_as_tuples(SHARES), ctx={"extra_args": "smbclient -U alice%pw"})
    shares = {f.data["share"] for f in findings if f.kind == "smb_share"}
    assert {"ADMIN$", "C$", "IPC$", "public"} <= shares


def test_parse_via_argv_when_extra_args_missing():
    a = ImpacketAdapter()
    findings = a.parse(_as_tuples(SAM),
                       ctx={"argv": ["/tmp/impacket_stub/impacket-secretsdump",
                                     "secretsdump", "-just-dc", "10.10.10.20"]})
    assert any(f.kind == "ntlm_hash" for f in findings)


def test_parse_autodetect_fallback_no_ctx():
    a = ImpacketAdapter()
    findings = a.parse(_as_tuples(SAM), ctx=None)
    assert any(f.kind == "ntlm_hash" for f in findings)


def test_parse_empty_returns_empty():
    a = ImpacketAdapter()
    assert a.parse([], ctx={}) == []
