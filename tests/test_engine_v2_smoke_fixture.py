"""The SQLmap loopback oracle must distinguish multi-condition probes."""
from __future__ import annotations

import runpy
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
_ORACLE = runpy.run_path(str(_SCRIPT_DIR / "sqlmap_boolean_oracle.py"))[
    "sqlmap_boolean_oracle"
]


def test_boolean_oracle_accepts_multiple_true_conjuncts():
    assert _ORACLE("1 AND 123=123 AND 456=456") == b"Product: fixture-item\n"


def test_boolean_oracle_rejects_false_later_conjunct():
    assert _ORACLE("1 AND 123=123 AND 456=457") == b"No products found\n"


def test_boolean_oracle_leaves_non_boolean_lookup_stable():
    assert _ORACLE("1") == b"Product: fixture-item\n"


def test_boolean_oracle_handles_whitespace_around_comparisons():
    assert _ORACLE("1 AND 123 = 123 AND 456 = 457") == b"No products found\n"


def test_boolean_oracle_honors_or_precedence_and_negation():
    assert _ORACLE("1=0 OR 1=1 AND NOT 2=3") == b"Product: fixture-item\n"
    assert _ORACLE("(1=0 OR 2=3) AND 4=4") == b"No products found\n"


def test_boolean_oracle_fails_closed_on_unsupported_sql():
    assert _ORACLE("1 UNION SELECT 1") == b"No products found\n"
    assert _ORACLE("1 AND 'x'='x'") == b"No products found\n"
