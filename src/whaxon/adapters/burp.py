"""Burp Suite adapter — parses exported issue XML files.

Burp doesn't run as a subprocess; the user scans manually and exports.
This adapter takes an XML file path via ctx={"file_path": ...} and
returns fully-formed Findings, using Burp's own severity, confidence,
and remediation fields.
"""
from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from pathlib import Path

from ..core.findings import Finding
from .base import Adapter
from .registry import register

BURP_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
}


class BurpAdapter(Adapter):
    tool_id = "burp"

    def parse(self, lines, ctx=None):
        ctx = ctx or {}
        path = ctx.get("file_path")
        if not path:
            return []
        return self.parse_file(Path(path))

    def parse_file(self, path: Path) -> list[Finding]:
        try:
            tree = ET.parse(str(path))
        except (ET.ParseError, FileNotFoundError):
            return []
        root = tree.getroot()
        issues = [root] if root.tag == "issue" else root.findall(".//issue")
        out = []
        for issue in issues:
            f = self._parse_issue(issue)
            if f is not None:
                out.append(f)
        return out

    def _parse_issue(self, issue) -> Finding | None:
        name = (issue.findtext("name") or "").strip()
        if not name:
            return None

        host_el = issue.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        path = (issue.findtext("path") or "").strip()
        location = (issue.findtext("location") or "").strip()
        severity_raw = (issue.findtext("severity") or "Information").strip().lower()
        confidence = (issue.findtext("confidence") or "").strip()
        severity = BURP_SEVERITY_MAP.get(severity_raw, "info")

        rem_bg = (issue.findtext("remediationBackground") or "").strip()
        rem_detail = (issue.findtext("remediationDetail") or "").strip()
        remediation = "\n\n".join([x for x in (rem_bg, rem_detail) if x])

        imp_bg = (issue.findtext("issueBackground") or "").strip()
        issue_detail = (issue.findtext("issueDetail") or "").strip()
        impact = "\n\n".join([x for x in (imp_bg, issue_detail) if x])

        data = {
            "name": name,
            "host": host,
            "path": path,
            "location": location,
            "confidence": confidence,
        }
        if issue_detail:
            data["issue_detail"] = issue_detail[:4000]

        rr = issue.find("requestresponse")
        if rr is not None:
            req_el, resp_el = rr.find("request"), rr.find("response")
            if req_el is not None and req_el.text:
                data["request"] = self._decode(req_el)[:2000]
            if resp_el is not None and resp_el.text:
                data["response"] = self._decode(resp_el)[:2000]

        type_id = (issue.findtext("type") or "").strip()
        refs = (f"burp:type:{type_id}",) if type_id else ()

        raw = location or (host + path if host or path else name)

        return Finding(
            kind="web_issue",
            severity=severity,
            source="burp",
            data=data,
            raw_line=raw,
            remediation=remediation,
            impact=impact,
            cvss=None,
            cwe="",
            references=refs,
        )

    @staticmethod
    def _decode(el) -> str:
        txt = el.text or ""
        if el.get("base64") == "true":
            try:
                return base64.b64decode(txt).decode("utf-8", errors="replace")
            except Exception:
                return txt
        return txt


register(BurpAdapter())
