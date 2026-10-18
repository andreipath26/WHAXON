# WHAXON Engagement Report

Scope: **default**  
Generated: 2026-10-17T17:29:27  
Jobs: 4  Findings: 32

## Executive Summary

No critical findings. **1 high**-severity findings were identified across 2 targets.

**Top findings:**

- [high] + [007224] /.gitignore: .gitignore file found. It is possible to grasp the directory structure.

**Recommended action:** Block access to .git, .svn, and .hg directories at the web server level. Ensure deployment scripts do not copy VCS metadata into the web root.

### Findings by severity

- **High**: 1
- **Medium**: 4
- **Low**: 16
- **Info**: 11

## Remediation Roadmap

Findings grouped by urgency. Immediate items have a known-exploited CVE, high EPSS, or CVSS 9.0+. Backlog items are informational. Each item is shown once; counts indicate how many jobs produced it.

### Short-term (3)

- web_service: 172.17.0.3 ports=[80] (x3)
- web_login_surface: 172.17.0.3 (1 login/admin pages) (x2)
- + [007224] /.gitignore: .gitignore file found. It is possible to grasp the directory structure. _(CVSS 7.5)_

### Medium-term (18)

- .htaccess (x2) _(CVSS 3.7)_
- config (x2) _(CVSS 3.7)_
- docs (x2) _(CVSS 3.7)_
- external (x2) _(CVSS 3.7)_
- favicon.ico (x2) _(CVSS 3.7)_
- .hta (x2) _(CVSS 3.7)_
- .htpasswd (x2) _(CVSS 3.7)_
- index.php (x2) _(CVSS 3.7)_
- phpinfo.php (x2) _(CVSS 3.7)_
- robots.txt (x2) _(CVSS 3.7)_
- server-status (x2) _(CVSS 3.7)_
- php.ini (x2) _(CVSS 3.7)_
- + [013587] /: Suggested security header missing: x-content-type-options. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options _(CVSS 3.7)_
- + [013587] /: Suggested security header missing: strict-transport-security. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Secu _(CVSS 4.3)_
- + [750500] /config/: Directory indexing found. See: CWE-548 (x2) _(CVSS 5.3)_
- + [750500] /docs/: Directory indexing found. See: CWE-548 _(CVSS 5.3)_
- + [007342] /: X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive. See: https: _(CVSS 4.3)_
- + [007352] /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME _(CVSS 3.7)_

### Backlog (11)

- + Platform:           Linux/Unix
- + No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped. (x2)
- + [013587] /: Suggested security header missing: referrer-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
- + [013587] /: Suggested security header missing: permissions-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
- + [013587] /: Suggested security header missing: content-security-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- + [600050] Apache/2.4.25 appears to be outdated (current is at least 2.4.68).
- + [003584] /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
- + [006333] /login.php: Admin login page/section found.
- 80/tcp open  http    Apache httpd 2.4.25 ((Debian))
- Nikto web scan on port 80
- Gobuster directory busting on port 80

## Known Vulnerabilities

Service versions detected during the engagement, cross-referenced against the local Exploit-DB mirror. This is a starting point for manual review, not a definitive list.

### apache httpd 2.4.25

_No results._

## Appendix: Technical Findings

### High (1)

- **[high]** + [007224] /.gitignore: .gitignore file found. It is possible to grasp the directory structure.

## Appendix: Job History

| Job | Tool | Target | Status | Exit |
|-----|------|--------|--------|------|
| `d76244691d83` | ffuf | 172.17.0.3 | finished | 0 |
| `137b9002ee9a` | gobuster | 172.17.0.3 | finished | 0 |
| `deaa28ed3bcf` | nikto | 172.17.0.3:80 | finished | 0 |
| `3fec9011c57f` | nmap | 172.17.0.3 | finished | 0 |
