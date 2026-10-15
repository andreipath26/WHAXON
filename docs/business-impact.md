# Business-impact severity — PR 3 design

Status: active
Non-goals: this doc does not design the web UI's use of the field (a later UI session). The report-rendering changes are in scope and described below.

## 1. What this adds

A second severity scale on every finding, alongside technical severity.
Technical severity answers "how bad is the CVE" (CVSS, EPSS, KEV).
Business impact answers "what does this cost us" — the finding's kind,
the engagement context, and the incident-cost distributions the finding
class maps to.

The two scales are shown side-by-side. Neither collapses into the other.

## 2. Where it is computed

At resolve time, in `core/severity.py`, stored on the finding's
enrichment. Not at render time.

Reason: the web UI's Findings page needs the same value. Computing once
at resolve time and storing it means both surfaces read the same field,
the same way `severity_source` (PR 1a) does.

The field is `business_impact`. Vocabulary: `"critical"`, `"high"`,
`"medium"`, `"low"` — lowercase, same words as technical severity.

## 3. How the band is computed

Table-driven, in `core/business_impact.py::base_band`. Deterministic, no
LLM (R71).

Base band per finding kind, with three special cases:

- **correlated / vulnerable_service** — inherit the CVSS-derived
  severity from the severity resolver.
- **open_port** — `high` when the nmap adapter sets `lookup_hint`
  (indicating a versioned service), else `low`.
- **web_issue** — `high` for exploitability classes (SQLi, command
  injection, RCE, XSS, XXE, SSRF, LFI, RFI, matched on the finding's
  message and raw_line); else `low`.

Every other kind uses `_BASE_BY_KIND`. Unknown kinds default to `low`.

**Target modifier.** A finding against a production target shifts up
one band. Production is defined by `_is_production_target`:
hostnames with a real TLD, and IPs outside RFC1918/loopback and the lab
markers (`.test`, `.local`, `localhost`, `::1`, `scanme.nmap.org`).

## 4. Cost ranges

Each finding class carries a cost-range row: incident pattern, median
USD, p90 USD (or `None` when not published), source string.

Rows cite Cyentia IRIS 2025 (median and p90 by pattern), Verizon DBIR
2026 (median ransom payment), and — listed in `SOURCES_NOTE` but not
yet cited by any row — the Zenodo ICS Ransomware Dataset, ITIC 2025,
GDPR Article 83, and HIPAA Journal 2025.

**The mapping from WHAXON finding kind to incident pattern is WHAXON's
derivation, not the sources'.** This is stated in the module docstring
and in `SOURCES_NOTE`, and appears in the report.

## 5. Known gaps, deferred with rationale

- **`_COST_RANGES["web_app_breach"]` cites IRIS 2022 while every other
  row cites IRIS 2025.** Deferred until the 2025 row is confirmed;
  cross-source citing is defensible but should be uniform.
- **`_COST_RANGES["ransom_payment"]` names DBIR 2026 as the source but
  the Zenodo dataset is listed in `SOURCES_NOTE` and not cited on any
  row.** Either Zenodo-backed rows get added, or it comes out of the
  note.
- **`_BASE_BY_KIND` has `open_port_vulnerable` and
  `web_issue_exploitable` keys that no branch reaches** — the actual
  kinds are handled by dedicated branches. Dead rows.
- **`_annotate`'s `except Exception` swallows all failures** to `"low"`
  with no log. Same shape as the silent-swallow that hid the dead
  correlation rule in §21.13.
- **Report rendering of `business_impact` is not in this PR.** Edit A
  (rank top findings by business impact), Edit B (shift remediation
  bands by business impact), Edit C (print both scales in the appendix)
  are a follow-on unit.

## 6. Test plan

- Unit tests for `base_band`: every kind in `_BASE_BY_KIND`, plus
  correlated with each severity level, plus open_port with and without
  `lookup_hint`, plus web_issue with each exploitability keyword.
- Unit tests for `_is_production_target`: RFC1918, loopback, `.test`,
  `.local`, `localhost`, `::1`, `scanme.nmap.org`, real TLD, IP with
  port.
- Unit tests for `_shift_up`: already-critical stays critical;
  high→critical; medium→high; low→medium.
- Integration test: `severity.resolve` annotates the finding on all
  three return paths.
- Integration test: `resolve_stored.resolve_stored` writes the field
  into enrichment.
- Determinism test: two calls to `base_band` on the same finding return
  the same band (R71, R78).

## 7. Sequencing

PR 3 lands the resolver and this doc. The report edits (A/B/C) are
PR 4. The web UI's use of the field is a later session.

## 8. Cold resume state

- Repo at `9fc5d1c` when PR 3 started.
- Working tree has `business_impact.py` (untracked), `severity.py` and
  `resolve_stored.py` (modified), and this doc.
- Tests pass: `.venv/bin/pytest -q` → 673 passed.
- Bare `pytest` fails with 70 collection errors (no `pythonpath = ["src"]`
  in `pyproject.toml`).
- Version drift: `__init__.py` 0.9.0 vs `pyproject.toml` 0.10.0.

## Report rendering

The business-impact scale appears in three places:

1. **Executive brief** - top findings re-ranked by business impact, technical severity as tiebreaker.
2. **Remediation Roadmap** - a finding shifts up one band when business impact is higher than technical severity. Never lowers.
3. **Appendix: Technical Findings** - each finding shows both scales: `[critical / Business: high]`.

## Full cost-range table

| Finding class | Incident pattern | Median | 90th percentile | Source |
|---|---|---|---|---|
| ntlm_hash, nxc_credential (admin) | System intrusion | 150,200 | 7,400,000 | Cyentia IRIS 2025 |
| sqli, sqli_dump | Data breach (web app) | 266,000 | - | Cyentia IRIS 2022 (geometric mean) |
| correlated (ransomware-class) | Ransomware | 155,500 | 5,000,000 | Cyentia IRIS 2025 |
| correlated (ransomware-class) | Ransom payment | 139,875 | - | Verizon DBIR 2026 (median) |
| web_issue (disclosure) | Accidental disclosure | 56,900 | - | Cyentia IRIS 2025 |
| open_port (vulnerable version) | System intrusion | 150,200 | 7,400,000 | Cyentia IRIS 2025 |

## Downtime per hour

| Organisation size | Cost/hour | Source |
|---|---|---|
| Small (< 100 employees) | 100,000 | ITIC 2025 |
| Mid-size (100-1000) | 300,000 | ITIC 2025 |
| Enterprise (> 1000) | 1,100,000 | ITIC 2025 |

## Regulatory fines

| Framework | Range | Source |
|---|---|---|
| GDPR (Article 83) | up to EUR 20M or 4% global turnover | GDPR Article 83 |
| HIPAA (typical settlement) | 500,000 - 3,000,000 | HIPAA Journal 2025 |
