"""Vulnerability database tests.

The VulnDB is a local SQLite file. No network calls happen in tests; the
schema, lookup, upsert, meta, and status methods are exercised against a
fresh file in tmp_path.
"""
from __future__ import annotations

from whaxon.core.vulndb import VulnDB


def test_schema_creates_on_fresh_path(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    assert db.count() == 0
    assert db.exists() is True  # the connection opens on first query


def test_lookup_returns_none_for_unknown(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    assert db.lookup("CVE-2099-99999") is None


def test_lookup_empty_string(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    assert db.lookup("") is None


def test_meta_roundtrip(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    assert db.get_meta("last_nvd_update") is None
    db.set_meta("last_nvd_update", "2026-10-15T00:00:00")
    assert db.get_meta("last_nvd_update") == "2026-10-15T00:00:00"


def test_insert_and_lookup(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    c = db._c()
    c.execute(
        "INSERT INTO cve (cve_id, cvss_v3_score, cvss_v3_severity) VALUES (?, ?, ?)",
        ("CVE-2021-44228", 10.0, "CRITICAL"),
    )
    c.commit()
    rec = db.lookup("CVE-2021-44228")
    assert rec is not None
    assert rec["cvss_v3_score"] == 10.0
    assert rec["cvss_v3_severity"] == "CRITICAL"


def test_lookup_is_case_insensitive(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    c = db._c()
    c.execute(
        "INSERT INTO cve (cve_id, cvss_v3_score) VALUES (?, ?)",
        ("CVE-2021-44228", 10.0),
    )
    c.commit()
    assert db.lookup("cve-2021-44228") is not None
    assert db.lookup("CVE-2021-44228") is not None


def test_upsert_updates_rather_than_duplicates(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    c = db._c()
    c.execute(
        "INSERT INTO cve (cve_id, cvss_v3_score, epss_score) VALUES (?, ?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET cvss_v3_score=excluded.cvss_v3_score, epss_score=excluded.epss_score",
        ("CVE-2021-44228", 10.0, None),
    )
    c.execute(
        "INSERT INTO cve (cve_id, cvss_v3_score, epss_score) VALUES (?, ?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET cvss_v3_score=excluded.cvss_v3_score, epss_score=excluded.epss_score",
        ("CVE-2021-44228", 9.8, 0.97),
    )
    c.commit()
    assert db.count() == 1
    rec = db.lookup("CVE-2021-44228")
    assert rec["cvss_v3_score"] == 9.8
    assert rec["epss_score"] == 0.97


def test_status_shape(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    s = db.status()
    for key in ("path", "rows", "with_cvss", "with_epss", "with_kev",
                "last_nvd_update", "last_epss_update", "last_kev_update"):
        assert key in s, f"missing status key: {key}"
    assert s["rows"] == 0
    assert s["last_nvd_update"] == "never"


def test_status_counts(tmp_path):
    db = VulnDB(tmp_path / "vulndb.db")
    c = db._c()
    c.execute("INSERT INTO cve (cve_id, cvss_v3_score, epss_score, kev) VALUES (?, ?, ?, ?)",
              ("CVE-2021-44228", 10.0, 0.97, 1))
    c.execute("INSERT INTO cve (cve_id, cvss_v3_score) VALUES (?, ?)",
              ("CVE-2019-0708", 9.8))
    c.execute("INSERT INTO cve (cve_id) VALUES (?)", ("CVE-2020-0001",))
    c.commit()
    s = db.status()
    assert s["rows"] == 3
    assert s["with_cvss"] == 2
    assert s["with_epss"] == 1
    assert s["with_kev"] == 1
