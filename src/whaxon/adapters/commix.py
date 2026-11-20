"""Commix adapter — OS command injection (CWE-78) findings.

Commix v4 logs with a timestamp/level prefix and an ANSI-coloured verdict:

    [09:56:05] [info] POST parameter 'ip' appears to be injectable via results-based
                      classic command injection technique.
    POST parameter 'ip' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
    Identified the following injection point(s) with a total of 7 HTTP(S) requests:
    Parameter: ip (POST)
     * Technique: Results-based
     * Type: Classic command injection
     * Payload: VUZ;echo XDEZJP$((27+8))$(echo XDEZJP)XDEZJP;

Older releases print `[+] The (POST) 'ip' parameter is vulnerable to OS command
injection.`. Both shapes are accepted; the injection-point block supplies the
technique and the exact payload commix used.
"""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register

# "[09:56:05] [info] " / "[+] " / "[*] " prefixes and ANSI colour codes.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_PREFIX_RE = re.compile(r"^(?:\[\d{2}:\d{2}:\d{2}\]\s*)?\[[^\]]{1,12}\]\s*")

# "POST parameter 'ip' appears to be injectable via results-based classic ..."
# "POST parameter 'ip' is vulnerable."
_VERDICT_RE = re.compile(
    r"^(?P<where>[\w-]+(?:\s[\w-]+)?)\s+parameter\s+'(?P<param>[^']+)'\s+"
    r"(?:is|appears\s+to\s+be)\s+(?:vulnerable|injectable)"
    r"(?:\s+via\s+(?P<technique>[^.]+))?",
    re.IGNORECASE,
)

# Older style: "The (POST) 'ip' parameter is vulnerable to OS command injection."
_LEGACY_VERDICT_RE = re.compile(
    r"The\s+\((?P<where>[^)]+)\)\s+'(?P<param>[^']+)'\s+parameter\s+"
    r"(?:is|appears\s+to\s+be)\s+(?:vulnerable\s+to|injectable)",
    re.IGNORECASE,
)

# Injection-point block: "Parameter: ip (POST)"
_BLOCK_PARAM_RE = re.compile(
    r"^Parameter:\s*(?P<param>[^\s(]+)\s*\((?P<where>[^)]+)\)"
)

# " * Technique: Results-based" / " * Type: Classic command injection"
_META_RE = re.compile(
    r"^(?:\*\s*)?(?P<key>Technique|Type):\s*(?P<value>.+?)\s*$", re.IGNORECASE
)

# " * Payload: VUZ;echo XDEZJP..."
_PAYLOAD_RE = re.compile(r"^(?:\*\s*)?Payload:\s*(?P<payload>.+?)\s*$", re.IGNORECASE)

# commix's POST body argument: --data="ip=1&Submit=Submit" / -d 'ip=1'
_DATA_ARG_RE = re.compile(r"(?:--data|-d)[=\s]+[\"']?(?P<data>[^\"']+)")

REMEDIATION = (
    "Never pass user-controlled data to a shell. Use an execution API that takes "
    "an argument vector (no shell), allowlist the accepted values (for example "
    "validate that the input is a literal IP address with a strict parser), and "
    "run the process with the least privilege the feature needs."
)

IMPACT = (
    "The application runs attacker-supplied shell commands with the privileges of "
    "the service account, which typically means arbitrary file read/write, "
    "credential theft from configuration, and a route to full host compromise."
)


def _clean(text: str) -> str:
    return _PREFIX_RE.sub("", _ANSI_RE.sub("", text)).strip()


class CommixAdapter(Adapter):
    tool_id = "commix"

    @staticmethod
    def _request_context(where: str, param: str, ctx: dict | None) -> dict:
        """Describe the request commix exercised, so a proof can be rendered.

        Only built when the adapter was given an absolute target URL: a proof
        for a guessed URL would be worse than no proof.
        """
        target = (ctx or {}).get("target") or ""
        if not target.startswith(("http://", "https://")):
            return {}
        method = "POST" if where.upper() == "POST" else "GET"
        body = ""
        if method == "POST":
            m = _DATA_ARG_RE.search((ctx or {}).get("extra_args") or "")
            if m:
                body = m.group("data").strip()
        return {"method": method, "url": target, "parameter": param, "body": body}

    def parse(self, lines, ctx=None):
        verdicts: list[tuple[str, str, str]] = []  # (where, param, raw line)
        technique = ""
        injection_type = ""
        payload = ""

        for stream, text in lines:
            if stream != "stdout":
                continue
            stripped = _clean(text)
            if not stripped:
                continue

            m = _BLOCK_PARAM_RE.match(stripped)
            if m:
                verdicts.append((m.group("where").strip(), m.group("param").strip(), stripped))
                continue

            m = _PAYLOAD_RE.match(stripped)
            if m:
                payload = m.group("payload")
                continue

            m = _META_RE.match(stripped)
            if m:
                if m.group("key").lower() == "technique":
                    technique = m.group("value")
                else:
                    injection_type = m.group("value")
                continue

            m = _VERDICT_RE.match(stripped) or _LEGACY_VERDICT_RE.search(stripped)
            if m:
                if not technique and m.groupdict().get("technique"):
                    technique = m.group("technique").strip()
                verdicts.append((m.group("where").strip(), m.group("param").strip(), stripped))

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for where, param, raw in verdicts:
            key = (where.upper(), param)
            if key in seen:
                continue
            seen.add(key)
            data = {
                "parameter": param,
                "where": where.upper(),
                "technique": technique,
                "type": injection_type,
                "payload": payload,
            }
            request_context = self._request_context(where, param, ctx)
            if request_context:
                data["_request_context"] = request_context

            findings.append(Finding(
                kind="command_injection",
                severity="critical",
                source="commix",
                data=data,
                raw_line=raw,
                remediation=REMEDIATION,
                impact=IMPACT,
                cvss=9.8,
                cwe="CWE-78",
                references=(
                    "https://cwe.mitre.org/data/definitions/78.html",
                    "https://owasp.org/www-community/attacks/Command_Injection",
                ),
            ))
        return findings


register(CommixAdapter())
