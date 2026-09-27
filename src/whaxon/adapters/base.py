"""Adapter ABC — the interface every tool adapter implements."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ..core.findings import Finding


class Adapter(ABC):
    """Per-tool knowledge: how to parse output and how to remediate.

    Subclasses set ``tool_id`` to the tool id in the catalog, then implement
    ``parse``. Remediation, impact, and CVSS are optional — the defaults
    return empty values, but real adapters should override them.
    """

    tool_id: ClassVar[str] = ""

    @abstractmethod
    def parse(self, lines: list[tuple[str, str]], ctx: dict | None = None) -> list[Finding]:
        """Turn raw output lines into Finding objects.

        Args:
            lines: list of (stream, text) tuples, stream is "stdout" or "stderr"
            ctx: arbitrary context — target, tool args, input file path, etc.

        Returns:
            A list of Finding objects. Each may be enriched with remediation,
            impact, cvss, cwe, and references.
        """

    # ---- optional enrichment hooks ----

    def remediate(self, finding: Finding) -> str:
        """Return a remediation string for a finding (or empty)."""
        return finding.remediation

    def impact(self, finding: Finding) -> str:
        """Return a business-impact string for a finding (or empty)."""
        return finding.impact

    def cvss(self, finding: Finding) -> float | None:
        """Return a CVSS 3.1 base score for a finding (or None)."""
        return finding.cvss
