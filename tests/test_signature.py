"""Signature dedup tests.

_signature_for produces the key that collapses duplicate findings across
jobs. A collision between two distinct findings silently drops one from
the report. These tests lock in that distinct findings produce distinct
signatures.
"""
from __future__ import annotations

from whaxon.core.store import _signature_for


def test_correlated_vsftpd_vs_apache_differ():
    vsftpd = _signature_for("correlated", {
        "pattern": "vulnerable_service", "service": "vsftpd",
        "version": "2.3.4", "cve": "CVE-2011-2523",
    })
    apache = _signature_for("correlated", {
        "pattern": "vulnerable_service", "service": "apache",
        "version": "2.2.8", "cve": "CVE-2017-7679",
    })
    assert vsftpd != apache


def test_correlated_same_data_same_sig():
    a = _signature_for("correlated", {
        "pattern": "vulnerable_service", "service": "vsftpd",
        "version": "2.3.4", "cve": "CVE-2011-2523",
    })
    b = _signature_for("correlated", {
        "pattern": "vulnerable_service", "service": "vsftpd",
        "version": "2.3.4", "cve": "CVE-2011-2523",
    })
    assert a == b


def test_unknown_kind_hashes_whole_dict():
    a = _signature_for("some_new_kind", {"alpha": "same", "beta": "one"})
    b = _signature_for("some_new_kind", {"alpha": "same", "beta": "two"})
    assert a != b


def test_open_port_signature_uses_port_and_protocol():
    a = _signature_for("open_port", {"port": 22, "protocol": "tcp"})
    b = _signature_for("open_port", {"port": 80, "protocol": "tcp"})
    assert a != b


def test_web_issue_signature_uses_path():
    a = _signature_for("web_issue", {"path": "/login"})
    b = _signature_for("web_issue", {"path": "/admin"})
    assert a != b
