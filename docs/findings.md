# Findings

Findings are structured records extracted from tool output by an adapter.

## Shape

Every finding is a whaxon.core.findings.Finding:

- kind (str): discriminator, e.g. open_port, ntlm_hash, smb_share, impacket_loot
- severity (str): critical / high / medium / low / info
- source (str): adapter that produced it (usually the tool id)
- raw_line (str): original output line, truncated to ~200 chars
- data (dict): structured payload, adapter-specific
- cvss (float or None): CVSS base score
- cwe (str): CWE id, e.g. CWE-522
- impact (str): business impact text
- remediation (str): remediation advice
- references (list[str]): URLs

## Lifecycle

1. Adapter returns list[Finding] from parse().
2. Runner publishes JobFindings(job_id, findings=[...]) on the EventBus.
3. Store subscribes and persists each finding row (JSON-encoded data and references).
4. Web UI renders findings as a color-coded expandable table.
5. Reports include findings grouped by severity; loot-kind findings go into Loot Summary.

## Kinds used today

- open_port          - nmap
- service            - nmap
- web_issue          - nikto
- sql_injection      - sqlmap
- dbms               - sqlmap
- smb_share          - impacket
- ntlm_hash          - impacket
- impacket_loot      - impacket
- cracked_hash       - hashcat
- msf_session        - msf
- exploit_suggestion - suggest
- burp_issue         - burp

Adapters can introduce new kinds freely - the store persists any string.

## Querying

- Per job: GET /api/jobs/<job_id>/findings
- Loot-only: GET /api/loot
- In reports: GET /api/report?format=md includes critical/high findings plus Loot Summary

## Severity ordering

Reports order severities critical -> high -> medium -> low -> info (_SEV_ORDER in whaxon.core.report).