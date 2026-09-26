# Findings

Findings are structured records extracted from tool output.

## Shape

    {
      "kind": "open_port",
      "severity": "medium",
      "source": "nmap",
      "data": {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
      "raw_line": "22/tcp   open  ssh"
    }

Fields:

    kind       Type of finding (open_port, web_issue, sqli, ...)
    severity   info, low, medium, high, critical
    source     Parser that produced it (usually tool id)
    data       Parser-specific structured data
    raw_line   Original output line

## Supported parsers

    nmap      open_port
    nikto     web_issue
    gobuster  found_path
    sqlmap    sqli, sqli_param
    whois     domain_expiry, registrar, nameserver
    dig       a_record, aaaa_record, ns_record, mx_record
    nuclei    vulnerability
    ffuf      found_path
    wpscan    wp_version, wp_vulnerability

Tools without a parser produce zero findings. Output still streams and is
saved in job history.

## Severity scale

    critical  Immediate, exploitable, high impact
    high      Serious, likely exploitable
    medium    Notable weakness worth investigating
    low       Minor issue or informational
    info      Contextual information

Severities are heuristics based on the raw output, not judgments.

## Where findings appear

- Web UI: table below the output pane, color-coded
- Reports: summary table + per-finding detail
- API: GET /api/jobs/<job_id>/findings
- Database: findings table in data/whaxon.db

## Writing a parser

Parsers live in src/whaxon/core/findings.py. Each takes a list of
(stream, text) tuples and returns Finding objects:

    def parse_mytool(lines):
        out = []
        for stream, text in lines:
            if stream != "stdout":
                continue
            if "CRITICAL" in text:
                out.append(Finding(
                    kind="vulnerability",
                    severity="critical",
                    source="mytool",
                    data={"message": text.strip()},
                    raw_line=text,
                ))
        return out

Register in the PARSERS dict at the bottom of the file.
