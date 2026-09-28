"""Tests for whaxon.interfaces.cli.cve_cmd.

NVD is mocked via urllib.request.urlopen patching. No network calls.
The cache is a real SQLite file in tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import io

import pytest

from whaxon.interfaces.cli import cve_cmd


# ---------------------------------------------------------------- fixtures

_LOG4SHELL = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2026-01-01T00:00:00.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2026-08-11T19:33:44.513",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI RCE (Log4Shell)."},
                    {"lang": "es", "value": "no importa"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        }}
                    ]
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-20"}]},
                    {"description": [{"lang": "en", "value": "CWE-502"}]},
                ],
                "references": [
                    {"url": "https://example.com/ref1"},
                    {"url": "https://example.com/ref2"},
                ],
            }
        }
    ],
}

_KEYWORD = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2011-2523",
                "published": "2011-07-01T00:00:00.000",
                "lastModified": "2021-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {"lang": "en", "value": "vsftpd 2.3.4 backdoor."}
                ],
                "metrics": {},
                "weaknesses": [],
                "references": [],
            }
        }
    ],
}


class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")
        self.status = 200

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(payload):
    """Patch urlopen in cve_cmd to return the given payload."""
    return patch.object(
        cve_cmd.urllib.request, "urlopen",
        return_value=_FakeResponse(payload),
    )


# ---------------------------------------------------------------- validation

def test_no_args_prints_usage(capsys):
    cve_cmd.main([])
    assert "Usage" in capsys.readouterr().out


def test_help_prints_usage(capsys):
    cve_cmd.main(["--help"])
    assert "Usage" in capsys.readouterr().out


def test_unknown_flag_exits_usage(capsys):
    with pytest.raises(SystemExit) as ei:
        cve_cmd.main(["--bogus"])
    assert ei.value.code == cve_cmd.EXIT_USAGE


def test_bad_limit_exits_usage(capsys):
    with pytest.raises(SystemExit) as ei:
        cve_cmd.main(["--keyword", "x", "--limit", "nope"])
    assert ei.value.code == cve_cmd.EXIT_USAGE


def test_invalid_cve_id_exits_usage(capsys):
    with pytest.raises(SystemExit) as ei:
        cve_cmd.main(["NOTACVE"])
    assert ei.value.code == cve_cmd.EXIT_USAGE


# ---------------------------------------------------------------- exact ID

def test_exact_lookup_from_nvd(tmp_path, capsys):
    with _patch_urlopen(_LOG4SHELL):
        cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path), "--no-cache"])
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out
    assert "10.0" in out
    assert "CRITICAL" in out
    assert "CWE-20" in out
    assert "Log4Shell" in out


def test_exact_lookup_json(tmp_path, capsys):
    with _patch_urlopen(_LOG4SHELL):
        cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path),
                      "--no-cache", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["id"] == "CVE-2021-44228"
    assert data["vulnStatus"] == "Analyzed"


def test_exact_lookup_populates_cache(tmp_path, capsys):
    with _patch_urlopen(_LOG4SHELL):
        cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path)])
    # Cache file must exist now
    cache = tmp_path / "cve_cache.db"
    assert cache.exists()
    # Second call: urlopen must NOT be called
    import unittest.mock
    with patch.object(cve_cmd.urllib.request, "urlopen",
                      side_effect=AssertionError("should not hit NVD")):
        cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out


def test_cache_bypassed_with_no_cache(tmp_path, capsys):
    """--no-cache forces a fetch even when a cached copy exists."""
    with _patch_urlopen(_LOG4SHELL):
        cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path)])
    calls = []
    def spy(*a, **kw):
        calls.append(a)
        return _FakeResponse(_LOG4SHELL)
    with patch.object(cve_cmd.urllib.request, "urlopen", side_effect=spy):
        cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path), "--no-cache"])
    assert calls, "urlopen was not called with --no-cache"


# ---------------------------------------------------------------- keyword

def test_keyword_search(tmp_path, capsys):
    with _patch_urlopen(_KEYWORD):
        cve_cmd.main(["--keyword", "vsftpd 2.3.4", "--data", str(tmp_path)])
    out = capsys.readouterr().out
    assert "vsftpd 2.3.4" in out
    assert "CVE-2011-2523" in out


def test_keyword_json(tmp_path, capsys):
    with _patch_urlopen(_KEYWORD):
        cve_cmd.main(["--keyword", "vsftpd", "--data", str(tmp_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["totalResults"] == 1
    assert data["vulnerabilities"][0]["cve"]["id"] == "CVE-2011-2523"


# ---------------------------------------------------------------- errors

def test_rate_limit_exits_3(tmp_path, capsys):
    import urllib.error
    err = urllib.error.HTTPError("url", 429, "Too Many Requests", {}, io.BytesIO())
    with patch.object(cve_cmd.urllib.request, "urlopen", side_effect=err):
        with pytest.raises(SystemExit) as ei:
            cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path), "--no-cache"])
    assert ei.value.code == cve_cmd.EXIT_RATE_LIMITED


def test_network_error_exits_4(tmp_path, capsys):
    import urllib.error
    err = urllib.error.URLError("connection refused")
    with patch.object(cve_cmd.urllib.request, "urlopen", side_effect=err):
        with pytest.raises(SystemExit) as ei:
            cve_cmd.main(["CVE-2021-44228", "--data", str(tmp_path), "--no-cache"])
    assert ei.value.code == cve_cmd.EXIT_NETWORK


def test_no_results_exits_2(tmp_path, capsys):
    empty = {**_LOG4SHELL, "vulnerabilities": []}
    with _patch_urlopen(empty):
        with pytest.raises(SystemExit) as ei:
            cve_cmd.main(["CVE-2099-99999", "--data", str(tmp_path), "--no-cache"])
    assert ei.value.code == cve_cmd.EXIT_NO_RESULTS