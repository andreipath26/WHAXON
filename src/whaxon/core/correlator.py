"""Deterministic cross-finding correlation.

Subscribes to JobFindings. On each event, pulls all findings for the
same target (across every job) and runs a small registry of rules.
A rule that fires produces a new Finding of kind "correlated", which
is persisted alongside the raw findings for the job that triggered
the correlation.

No LLM. No imports from whaxon.ai. Boundary intact.
"""
from __future__ import annotations

from typing import Callable

from .events import EventBus, JobFindings
from .findings import Finding


Rule = Callable[[str, list], Finding | None]

_WEB_PORTS = {80, 443, 8000, 8080, 8180, 8443, 8888, 9000}
_HIGH_RISK_PORTS = {139, 445, 3389, 5900}
_WEAK_NT_HASHES = {"", "aad3b435b51404eeaad3b435b51404ee"}


def rule_web_service(target, findings):
    ports = set()
    has_tls = False
    service_names = set()
    for f in findings:
        d = f.get("data") or {}
        if f.get("kind") == "open_port" and isinstance(d.get("port"), int):
            ports.add(d["port"])
        svc = str(d.get("service") or "").lower()
        if svc:
            service_names.add(svc)
            if "ssl" in svc or "https" in svc or "tls" in svc:
                has_tls = True
    web = ports & _WEB_PORTS
    if not web:
        return None
    # Any recognized web port with an HTTP-ish service fires the rule.
    http_ports = {80, 443, 8000, 8080, 8180, 8443, 8888, 9000}
    if not (has_tls or (ports & http_ports)):
        return None
    return Finding(
        kind="correlated",
        severity="medium",
        source="correlator",
        data={"pattern": "web_service", "target": target,
              "ports": sorted(web), "services": sorted(service_names)},
        raw_line="web_service: %s ports=%s" % (target, sorted(web)),
        impact="Web-facing service on target; confirm TLS posture.",
        remediation="Ensure current TLS, disable legacy ciphers, patch server software.",
        cwe="CWE-319",
)


def rule_exposed_service(target, findings):
    """High-risk admin/legacy port OR service name open -> exposed_service."""
    _RISKY_PORTS = {139, 445, 3389, 5900}
    _RISKY_SERVICES = {'netbios-ssn', 'microsoft-ds', 'ms-wbt-server', 'vnc', 'rfb', 'msrpc'}
    hits = []
    for f in findings:
        d = f.get('data') or {}
        if f.get('kind') != 'open_port':
            continue
        port = d.get('port')
        svc = str(d.get('service') or '').lower()
        if port in _RISKY_PORTS or svc in _RISKY_SERVICES:
            hits.append({'port': port, 'service': svc})
    if not hits:
        return None
    ports = sorted({h['port'] for h in hits if h['port']})
    svcs = sorted({h['service'] for h in hits if h['service']})
    return Finding(
        kind='correlated',
        severity='high',
        source='correlator',
        data={'pattern': 'exposed_service', 'target': target,
              'ports': ports, 'services': svcs},
        raw_line='exposed_service: %s ports=%s services=%s' % (target, ports, svcs),
        impact='Admin or legacy service reachable; high attacker interest.',
        remediation='Restrict by network ACL; require strong auth; disable legacy protocols.',
        cwe='CWE-284',
    )

def rule_weak_credential(target, findings):
    weak_users = []
    for f in findings:
        if f.get("kind") != "ntlm_hash":
            continue
        d = f.get("data") or {}
        nt = str(d.get("nt_hash") or "").lower()
        if nt in _WEAK_NT_HASHES:
            weak_users.append(str(d.get("user") or "?"))
    if not weak_users:
        return None
    return Finding(
        kind="correlated",
        severity="critical",
        source="correlator",
        data={"pattern": "weak_credential", "target": target,
              "users": sorted(set(weak_users))},
        raw_line="weak_credential: %s users=%s" % (target, sorted(set(weak_users))),
        impact="Credentials recoverable; lateral movement likely.",
        remediation="Rotate credentials immediately; enforce strong password policy.",
        cwe="CWE-521",
        cvss=9.8,
)


def rule_web_vuln(target, findings):
    has_sql = False
    has_web = False
    for f in findings:
        k = f.get("kind")
        d = f.get("data") or {}
        if k == "sql_injection":
            has_sql = True
        if k == "open_port" and d.get("port") in _WEB_PORTS:
            has_web = True
    if not (has_sql and has_web):
        return None
    return Finding(
        kind="correlated",
        severity="critical",
        source="correlator",
        data={"pattern": "web_vuln", "target": target},
        raw_line="web_vuln: %s sql_injection on web service" % target,
        impact="SQL injection reachable over the network.",
        remediation="Parameterise queries; validate input; review DBMS privileges.",
        cwe="CWE-89",
        cvss=9.8,
)


def rule_weak_tls(target, findings):
    has_cert_issue = False
    has_web = False
    for f in findings:
        d = f.get("data") or {}
        if f.get("kind") == "open_port" and d.get("port") in _WEB_PORTS:
            has_web = True
        raw = str(f.get("raw_line") or "").lower()
        if "self-signed" in raw or "self signed" in raw:
            has_cert_issue = True
        if "expired" in raw and ("cert" in raw or "ssl" in raw or "tls" in raw):
            has_cert_issue = True
    if not (has_web and has_cert_issue):
        return None
    return Finding(
        kind="correlated",
        severity="medium",
        source="correlator",
        data={"pattern": "weak_tls", "target": target},
        raw_line="weak_tls: %s cert issue on web service" % target,
        impact="Web service presents a certificate that undermines trust.",
        remediation="Replace with a valid certificate from a trusted CA.",
        cwe="CWE-295",
    )


def rule_recon_burst(target, findings):
    kinds = set()
    for f in findings:
        kinds.add(f.get("kind"))
    if len(kinds) >= 5:
        return Finding(
            kind="correlated",
            severity="info",
            source="correlator",
            data={"pattern": "recon_activity_burst", "target": target,
                  "kinds": sorted(kinds)},
            raw_line="recon_activity_burst: %s %d distinct kinds" % (target, len(kinds)),
            impact="Broad reconnaissance surface indicates active testing.",
            remediation="Confirm scope coverage; investigate each kind.",
        )
    return None

_VULNERABLE_VERSIONS = [
    ("vsftpd", "2.3.4", "critical", "CVE-2011-2523 vsftpd 2.3.4 backdoor"),
    ("openssh", "4.7p1", "high", "OpenSSH 4.7p1 EOL, weak ciphers"),
    ("apache", "2.2.8", "high", "Apache httpd 2.2.8 EOL (CVE-2017-7679 family)"),
    ("tomcat", "1.1", "medium", "Apache Tomcat Coyote 1.1 legacy"),
    ("proftpd", "1.3.1", "medium", "ProFTPD 1.3.1 CVE-2010-4221"),
]


def rule_vulnerable_service(target, findings):
    """Return one Finding per vulnerable-service match (list, not single)."""
    out = []
    for f in findings:
        if f.get("kind") != "open_port":
            continue
        raw = (f.get("raw_line") or "").lower()
        port = (f.get("data") or {}).get("port")
        for svc, ver, sev, desc in _VULNERABLE_VERSIONS:
            if svc in raw and ver in raw:
                out.append(Finding(
                    kind="correlated",
                    severity=sev,
                    source="correlator",
                    data={"pattern": "vulnerable_service", "target": target,
                          "service": svc, "version": ver, "cve": desc,
                          "port": port},
                    raw_line="vulnerable_service: %s %s %s - %s" % (svc, ver, target, desc),
                    impact="Service running a known-vulnerable version.",
                    remediation="Patch or replace the affected service.",
                ))
    return out  # may be empty list -> no findings


RULES = (
    rule_web_service, rule_exposed_service, rule_weak_credential,
    rule_web_vuln, rule_weak_tls, rule_recon_burst, rule_vulnerable_service,
)


def correlate(target, findings):
    out = []
    for rule in RULES:
        try:
            result = rule(target, findings)
        except Exception:
            continue
        if result is None:
            continue
        if isinstance(result, list):
            out.extend(result)
        else:
            out.append(result)
    return out


class Correlator:
    def __init__(self, bus, store):
        self.bus = bus
        self.store = store

    def attach(self):
        self.bus.subscribe(JobFindings, self._on_findings)

    def _on_findings(self, e):
        job = self.store.get(e.job_id)
        if not job:
            return
        target = job.get("target") or ""
        if not target:
            return
        own = self.store.get_findings(e.job_id) or []
        all_findings = self._all_findings_for(target)
        if not all_findings:
            all_findings = list(own)
        correlated = correlate(target, all_findings)
        if not correlated:
            return
        existing = self.store.get_findings(e.job_id) or []
        seq = 1000
        existing_keys = set()
        for f in existing:
            d = f.get("data") or {}
            existing_keys.add((f.get("kind"), d.get("pattern")))
        for cf in correlated:
            d = cf.data or {}
            key = (cf.kind, d.get("pattern"), d.get("cve") or d.get("service") or "")
            if key in existing_keys:
                continue
            seq += 1
            self.store.append_finding(e.job_id, cf.to_dict(), seq)

    def _all_findings_for(self, target):
        fn = getattr(self.store, "findings_by_target", None)
        if fn is None:
            return []
        try:
            groups = fn(limit=500)
        except Exception:
            return []
        if not isinstance(groups, list):
            return []
        for g in groups:
            if not isinstance(g, dict):
                continue
            if (g.get("target") or "") == target:
                return list(g.get("findings") or [])
        return []



