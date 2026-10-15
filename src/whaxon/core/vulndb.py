"""Local vulnerability database.

A single SQLite file at data/vulndb.db, built from three sources:

- NVD      CVSS v3/v4 scores, severity, descriptions (annual JSON feeds)
- EPSS     exploitation probability, 0.0 to 1.0 (daily gzipped CSV)
- CISA KEV known exploited vulnerabilities catalog (daily JSON)

Downloaded explicitly via `whaxon vulndb update`. No network calls at
finding-creation time or anywhere in the runtime pipeline. Fits R103
(local by default) and R71 (deterministic pipelines).

Lookup is a single indexed SELECT by cve_id. Cache the connection.
"""
from __future__ import annotations

import gzip
import json
import sqlite3
import time
import urllib.request
from pathlib import Path
from typing import Any

NVD_FEED_TEMPLATE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
NVD_YEARS = list(range(2002, 2027))
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    cve_id            TEXT PRIMARY KEY,
    cvss_v3_score     REAL,
    cvss_v3_severity  TEXT,
    cvss_v4_score     REAL,
    cvss_v4_severity  TEXT,
    epss_score        REAL,
    epss_percentile   REAL,
    kev               INTEGER DEFAULT 0,
    kev_ransomware    INTEGER DEFAULT 0,
    published         TEXT,
    modified          TEXT,
    description       TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_id ON cve(cve_id);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _cvss_to_severity(score: float | None) -> str:
    """NVD qualitative rating bands."""
    if score is None:
        return "info"
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


class VulnDB:
    """Local vulnerability database."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None

    def _c(self) -> sqlite3.Connection:
        if self._conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            c = sqlite3.connect(str(self.path), check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.executescript(SCHEMA)
            self._conn = c
        return self._conn

    def exists(self) -> bool:
        return self.path.exists()

    def lookup(self, cve_id: str) -> dict[str, Any] | None:
        if not cve_id:
            return None
        row = self._c().execute(
            "SELECT * FROM cve WHERE cve_id = ?", (cve_id.strip().upper(),)
        ).fetchone()
        return dict(row) if row else None

    def count(self) -> int:
        return self._c().execute("SELECT COUNT(*) FROM cve").fetchone()[0]

    def set_meta(self, key: str, value: str) -> None:
        c = self._c()
        c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
        c.commit()

    def get_meta(self, key: str) -> str | None:
        row = self._c().execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def status(self) -> dict[str, Any]:
        c = self._c()
        total = self.count()
        with_epss = c.execute("SELECT COUNT(*) FROM cve WHERE epss_score IS NOT NULL").fetchone()[0]
        with_kev = c.execute("SELECT COUNT(*) FROM cve WHERE kev = 1").fetchone()[0]
        with_cvss = c.execute("SELECT COUNT(*) FROM cve WHERE cvss_v3_score IS NOT NULL").fetchone()[0]
        return {
            "path": str(self.path),
            "rows": total,
            "with_cvss": with_cvss,
            "with_epss": with_epss,
            "with_kev": with_kev,
            "last_nvd_update": self.get_meta("last_nvd_update") or "never",
            "last_epss_update": self.get_meta("last_epss_update") or "never",
            "last_kev_update": self.get_meta("last_kev_update") or "never",
        }


def _http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "whaxon-vulndb/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def update_nvd(db: VulnDB, years: list[int] | None = None, log=print) -> int:
    """Download NVD annual feeds and upsert CVSS scores + descriptions."""
    years = years or NVD_YEARS
    c = db._c()
    count = 0
    for year in years:
        url = NVD_FEED_TEMPLATE.format(year=year)
        try:
            log(f"  nvd {year}: downloading")
            raw = _http_get(url, timeout=180)
            data = json.loads(gzip.decompress(raw))
        except Exception as e:
            log(f"  nvd {year}: skipped ({e})")
            continue
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            v3_score = v3_sev = v4_score = v4_sev = None
            for m in cve.get("metrics", {}).get("cvssMetricV31", []) + cve.get("metrics", {}).get("cvssMetricV30", []):
                d = m.get("cvssData", {})
                if d.get("baseScore") is not None:
                    v3_score = d["baseScore"]
                    v3_sev = d.get("baseSeverity")
                    break
            for m in cve.get("metrics", {}).get("cvssMetricV40", []):
                d = m.get("cvssData", {})
                if d.get("baseScore") is not None:
                    v4_score = d["baseScore"]
                    v4_sev = d.get("baseSeverity")
                    break
            c.execute(
                "INSERT INTO cve (cve_id, cvss_v3_score, cvss_v3_severity, cvss_v4_score, cvss_v4_severity, published, modified, description) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(cve_id) DO UPDATE SET "
                "cvss_v3_score=excluded.cvss_v3_score, cvss_v3_severity=excluded.cvss_v3_severity, "
                "cvss_v4_score=excluded.cvss_v4_score, cvss_v4_severity=excluded.cvss_v4_severity, "
                "published=excluded.published, modified=excluded.modified, description=excluded.description",
                (cve_id, v3_score, v3_sev, v4_score, v4_sev,
                 cve.get("published"), cve.get("lastModified"), desc),
            )
            count += 1
        c.commit()
        log(f"  nvd {year}: {count} rows so far")
    db.set_meta("last_nvd_update", time.strftime("%Y-%m-%dT%H:%M:%S"))
    return count


def update_epss(db: VulnDB, log=print) -> int:
    """Download the EPSS current CSV and upsert scores."""
    log("  epss: downloading")
    try:
        raw = _http_get(EPSS_URL, timeout=120)
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except Exception as e:
        log(f"  epss: failed ({e})")
        return 0
    c = db._c()
    count = 0
    for line in text.splitlines():
        if line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        cve_id, epss, pct = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if not cve_id.upper().startswith("CVE-"):
            continue
        try:
            score = float(epss)
            percentile = float(pct)
        except ValueError:
            continue
        c.execute(
            "INSERT INTO cve (cve_id, epss_score, epss_percentile) VALUES (?, ?, ?) "
            "ON CONFLICT(cve_id) DO UPDATE SET epss_score=excluded.epss_score, epss_percentile=excluded.epss_percentile",
            (cve_id.upper(), score, percentile),
        )
        count += 1
    c.commit()
    db.set_meta("last_epss_update", time.strftime("%Y-%m-%dT%H:%M:%S"))
    return count


def update_kev(db: VulnDB, log=print) -> int:
    """Download the CISA KEV catalog and mark known-exploited CVEs."""
    log("  kev: downloading")
    try:
        raw = _http_get(KEV_URL, timeout=60)
        data = json.loads(raw)
    except Exception as e:
        log(f"  kev: failed ({e})")
        return 0
    c = db._c()
    count = 0
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        ransomware = 1 if (item.get("knownRansomwareCampaignUse") or "").lower() == "known" else 0
        c.execute(
            "INSERT INTO cve (cve_id, kev, kev_ransomware) VALUES (?, 1, ?) "
            "ON CONFLICT(cve_id) DO UPDATE SET kev=1, kev_ransomware=excluded.kev_ransomware",
            (cve_id.upper(), ransomware),
        )
        count += 1
    c.commit()
    db.set_meta("last_kev_update", time.strftime("%Y-%m-%dT%H:%M:%S"))
    return count


def update_all(db: VulnDB, years: list[int] | None = None, log=print) -> dict[str, int]:
    """Update all three sources. Slow on first run (NVD is large)."""
    log("updating vulnerability database")
    nvd = update_nvd(db, years=years, log=log)
    epss = update_epss(db, log=log)
    kev = update_kev(db, log=log)
    return {"nvd": nvd, "epss": epss, "kev": kev}
