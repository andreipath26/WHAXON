"""Deterministic Boolean SQLi oracle for isolated scanner fixtures."""
from __future__ import annotations

import re

_TOKEN = re.compile(r"\s*(?:(-?\d+)|(>=|<=|!=|=|>|<)|(AND|OR|NOT)|([()]))", re.I)
_COMPARATORS = {
    "=": lambda left, right: left == right,
    "!=": lambda left, right: left != right,
    ">=": lambda left, right: left >= right,
    "<=": lambda left, right: left <= right,
    ">": lambda left, right: left > right,
    "<": lambda left, right: left < right,
}


def sqlmap_boolean_oracle(value: str) -> bytes:
    """Evaluate the fixture's bounded integer AND/OR/NOT SQL predicates.

    Only ID 1 exists in the seeded fixture. Unsupported SQL syntax returns the
    negative response, so unknown payloads cannot accidentally confirm a hit.
    """
    expression = re.sub(r"--.*?$|#.*?$", "", value, flags=re.MULTILINE).strip()
    tokens = []
    position = 0
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        if match is None:
            return b"No products found\n"
        number, comparator, keyword, punctuation = match.groups()
        tokens.append((number, comparator, keyword.upper() if keyword else punctuation))
        position = match.end()
    if not tokens:
        return b"No products found\n"

    cursor = 0

    def parse_primary() -> bool:
        nonlocal cursor
        if cursor >= len(tokens):
            raise ValueError("missing primary")
        number, _, keyword = tokens[cursor]
        if keyword == "(":
            cursor += 1
            result = parse_or()
            if cursor >= len(tokens) or tokens[cursor][2] != ")":
                raise ValueError("unclosed group")
            cursor += 1
            return result
        if number is None:
            raise ValueError("expected integer")
        left = int(number)
        cursor += 1
        if cursor < len(tokens) and tokens[cursor][1] is not None:
            comparator = tokens[cursor][1]
            cursor += 1
            if cursor >= len(tokens) or tokens[cursor][0] is None:
                raise ValueError("expected comparison integer")
            right = int(tokens[cursor][0])
            cursor += 1
            return _COMPARATORS[comparator](left, right)
        return left == 1

    def parse_not() -> bool:
        nonlocal cursor
        if cursor < len(tokens) and tokens[cursor][2] == "NOT":
            cursor += 1
            return not parse_not()
        return parse_primary()

    def parse_and() -> bool:
        nonlocal cursor
        result = parse_not()
        while cursor < len(tokens) and tokens[cursor][2] == "AND":
            cursor += 1
            right = parse_not()
            result = result and right
        return result

    def parse_or() -> bool:
        nonlocal cursor
        result = parse_and()
        while cursor < len(tokens) and tokens[cursor][2] == "OR":
            cursor += 1
            right = parse_and()
            result = result or right
        return result

    try:
        result = parse_or()
        if cursor != len(tokens):
            return b"No products found\n"
    except (KeyError, ValueError):
        return b"No products found\n"
    return b"Product: fixture-item\n" if result else b"No products found\n"
