"""sqlmap adapter — extracts SQL injection milestones and info.

sqlmap output is a chain: the tool prints milestones as it progresses.
We extract each milestone as a finding so the suggest engine can see
what stage the user is at.
"""
from __future__ import annotations

import re

from ..core.findings import Finding
from .base import Adapter
from .registry import register


# --- Patterns for the milestones ---

# "Parameter: id (GET)"
_PARAM_RE = re.compile(r"^Parameter:\s*(?P<name>\S+)\s*\((?P<where>[^)]+)\)")

# "    Type: boolean-based blind"
_TYPE_RE = re.compile(r"^\s+Type:\s*(?P<type>.+)$")

# "    Title: AND boolean-based blind - WHERE or HAVING clause"
_TITLE_RE = re.compile(r"^\s+Title:\s*(?P<title>.+)$")

# "    Payload: id=1 AND 1234=1234"
_PAYLOAD_RE = re.compile(r"^\s+Payload:\s*(?P<payload>.+)$")

# "current database: 'dvwa'"
_DB_RE = re.compile(r"current database:\s*'(?P<db>[^']+)'", re.IGNORECASE)

# "current user: 'root@localhost'"
_USER_RE = re.compile(r"current user:\s*'(?P<user>[^']+)'", re.IGNORECASE)

# "back-end DBMS: MySQL >= 5.0"
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>.+)$", re.IGNORECASE)

# "available databases [3]:"  followed by "* dvwa"
_DBS_HEADER_RE = re.compile(r"available databases\s*\[(?P<n>\d+)\]:", re.IGNORECASE)
_DB_ITEM_RE = re.compile(r"^\[\*\]\s*(?P<name>\S+)")

# "Database: dvwa"
_DB_START_RE = re.compile(r"^Database:\s*(?P<name>\S+)")

# "[2 tables]"
_TABLES_HEADER_RE = re.compile(r"^\[(?P<n>\d+)\s+tables?\]")

# "| users |" (with leading pipe)
_TABLE_ITEM_RE = re.compile(r"^\|\s*(?P<name>[A-Za-z0-9_]+)\s*\|")


class SqlmapAdapter(Adapter):
    tool_id = "sqlmap"

    def parse(self, lines, ctx=None):
        findings = []
        seen_params = set()
        seen_dbs = set()
        seen_info = set()
        seen_tables = set()
        seen_dumps = set()

        current_param = None
        current_type = None
        current_title = None
        current_payload = None
        in_dbs_list = False
        current_db_context = None
        in_tables_section = False
        in_dump_section = False
        dump_columns = []

        for stream, text in lines:
            if stream != "stdout":
                continue
            line = text.rstrip()

            # --- Parameter blocks ---
            m = _PARAM_RE.match(line)
            if m:
                current_param = m.group("name")
                current_type = None
                current_title = None
                current_payload = None
                continue

            m = _TYPE_RE.match(line)
            if m and current_param:
                current_type = m.group("type").strip()
                continue

            m = _TITLE_RE.match(line)
            if m and current_param:
                current_title = m.group("title").strip()
                continue

            m = _PAYLOAD_RE.match(line)
            if m and current_param and current_type:
                current_payload = m.group("payload").strip()
                key = (current_param, current_type, current_payload)
                if key not in seen_params:
                    seen_params.add(key)
                    findings.append(Finding(
                        kind="sqli",
                        severity="critical",
                        source="sqlmap",
                        data={
                            "parameter": current_param,
                            "type": current_type,
                            "title": current_title or "",
                            "payload": current_payload,
                        },
                        raw_line=line,
                        remediation=(
                            "Use parameterized queries (prepared statements) for every "
                            "database interaction. Never concatenate user input into SQL "
                            "strings. Add a WAF with SQL-injection rules as defense in depth."
                        ),
                        impact=(
                            "Confirmed SQL injection permits arbitrary database "
                            "read/write, often leading to full application compromise "
                            "and lateral movement."
                        ),
                        cvss=9.8,
                        cwe="CWE-89",
                    ))
                continue

            # --- Info lines ---
            m = _DB_RE.search(line)
            if m:
                key = ("current_db", m.group("db"))
                if key not in seen_info:
                    seen_info.add(key)
                    findings.append(Finding(
                        kind="sqli_info", severity="high", source="sqlmap",
                        data={"key": "current_database", "value": m.group("db")},
                        raw_line=line,
                        remediation="Restrict the application's database user to the minimum required privileges.",
                        impact="Exposes the database the application is currently using.",
                        cvss=7.5, cwe="CWE-89",
                    ))
                continue

            m = _USER_RE.search(line)
            if m:
                key = ("current_user", m.group("user"))
                if key not in seen_info:
                    seen_info.add(key)
                    findings.append(Finding(
                        kind="sqli_info", severity="high", source="sqlmap",
                        data={"key": "current_user", "value": m.group("user")},
                        raw_line=line,
                        remediation="Use a least-privilege database account for the application.",
                        impact="Reveals the database account, aiding privilege escalation.",
                        cvss=7.5, cwe="CWE-89",
                    ))
                continue

            m = _DBMS_RE.search(line)
            if m:
                dbms = m.group("dbms").strip()
                key = ("dbms", dbms)
                if key not in seen_info:
                    seen_info.add(key)
                    findings.append(Finding(
                        kind="sqli_info", severity="medium", source="sqlmap",
                        data={"key": "dbms", "value": dbms},
                        raw_line=line,
                        remediation="Keep the DBMS patched and restrict network access to it.",
                        impact="Identifies the DBMS, enabling targeted follow-up.",
                        cvss=5.3, cwe="CWE-89",
                    ))
                continue

            # --- Available databases list ---
            if _DBS_HEADER_RE.search(line):
                in_dbs_list = True
                continue
            if in_dbs_list:
                m = _DB_ITEM_RE.match(line.strip())
                if m:
                    db = m.group("name")
                    if db not in seen_dbs:
                        seen_dbs.add(db)
                        findings.append(Finding(
                            kind="sqli_database", severity="info", source="sqlmap",
                            data={"name": db},
                            raw_line=line,
                            remediation="Enumerate tables with `--tables -D <db>`.",
                            impact="Enumerated a database.",
                        ))
                    continue
                if line.strip() == "":
                    in_dbs_list = False

            # --- Per-database tables section ---
            m = _DB_START_RE.match(line)
            if m:
                current_db_context = m.group("name")
                in_tables_section = False
                in_dump_section = False
                continue

            if _TABLES_HEADER_RE.match(line) and current_db_context:
                in_tables_section = True
                continue

            if in_tables_section and current_db_context:
                m = _TABLE_ITEM_RE.match(line)
                if m:
                    tbl = m.group("name")
                    if tbl.lower() in ("table", "tables"):
                        continue
                    key = (current_db_context, tbl)
                    if key not in seen_tables:
                        seen_tables.add(key)
                        findings.append(Finding(
                            kind="sqli_table", severity="info", source="sqlmap",
                            data={"database": current_db_context, "table": tbl},
                            raw_line=line,
                            remediation=f"Enumerate or dump this table: `--dump -T {tbl} -D {current_db_context}`.",
                            impact="Discovered a table in the target database.",
                        ))
                    continue
                if line.strip() == "":
                    in_tables_section = False

            # --- Dump markers (row data) ---
            if in_dump_section and "|" in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if parts and len(parts) > 1:
                    key = (current_db_context, tuple(parts[:3]))
                    if key not in seen_dumps:
                        seen_dumps.add(key)
                        findings.append(Finding(
                            kind="sqli_dump", severity="high", source="sqlmap",
                            data={"database": current_db_context, "row": parts[:6]},
                            raw_line=line,
                            remediation="Rotate any credentials exposed by the dump.",
                            impact="Data extracted from the database.",
                            cvss=8.1, cwe="CWE-89",
                        ))

        return findings


register(SqlmapAdapter())
