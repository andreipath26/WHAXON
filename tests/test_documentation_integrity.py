"""Prevent obsolete source/test references in canonical Engine V2 ledgers."""
from __future__ import annotations

import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGERS = (
    ROOT / "docs/ENGINE_V2_ROADMAP_REQUIREMENTS.csv",
    ROOT / "docs/ENGINE_V2_AUDIT_CHECKPOINTS_2026-11-03.csv",
)
PATH = re.compile(r"(?:docs|src|tests|scripts)/[A-Za-z0-9_./-]+\.(?:md|csv|py)")


def test_acceptance_ledgers_reference_existing_repository_files():
    missing = []
    for ledger in LEDGERS:
        with ledger.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                key = row.get("requirement_id") or row.get("checkpoint_id")
                for field in ("implementation_candidate", "test_candidate",
                              "source_paths", "related_test_definition"):
                    for path in PATH.findall(row.get(field, "") or ""):
                        if not (ROOT / path).is_file():
                            missing.append(f"{ledger.name}:{key}:{field}:{path}")
    assert not missing, "Stale file references in acceptance ledgers:\n" + "\n".join(missing)


def test_roadmap_ledger_has_75_unique_entries():
    with LEDGERS[0].open(newline="", encoding="utf-8") as handle:
        entries = list(csv.DictReader(handle))
    ids = [row["requirement_id"] for row in entries]
    assert len(ids) == len(set(ids)) == 75
    assert all(row["acceptance"] in {"ACCEPTED", "NOT_ACCEPTED"} for row in entries)


# Only live navigation references in canonical masters are required to remain
# addressable; dated source snapshots may still mention superseded source names.
CANONICAL_DOCUMENTS = (
    "README.md",
    "WHAXON ROAD MAP - WHATS NEXT - FULL SCOPE.md",
    "docs/README.md",
    "docs/DOCUMENTATION_OWNERSHIP.md",
    "docs/ENGINE_V2_MASTER.md",
    "docs/V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md",
    "docs/V2_UI_MANDATORY_CROSSWALK.md",
    "docs/APPLICATION_ARCHITECTURE_MASTER.md",
    "docs/OPERATIONS_MASTER.md",
    "docs/EVIDENCE_AND_REPORTING_MASTER.md",
    "docs/PROJECT_GOVERNANCE_MASTER.md",
    "docs/CBC_2026_WHAXON_PARTNERSHIP_AND_INVESTOR_PLAYBOOK.md",
    "docs/CHANGELOG.md",
)
MARKDOWN_LINK = re.compile(r"\]\(([^)\n]+)\)")


def test_canonical_markdown_local_links_resolve():
    """Detect broken clickable navigation after future documentation consolidation."""
    from urllib.parse import unquote

    missing = []
    for relative in CANONICAL_DOCUMENTS:
        doc = ROOT / relative
        for match in MARKDOWN_LINK.finditer(doc.read_text(encoding="utf-8")):
            raw = match.group(1).split(' "', 1)[0].strip("<> ")
            if not raw or raw.startswith(("#", "/", "https:", "http:", "mailto:", "data:")):
                continue
            target = unquote(raw.split("#", 1)[0].split("?", 1)[0])
            if target and not (doc.parent / target).is_file():
                missing.append(f"{relative}: {raw}")
    assert not missing, "Broken canonical Markdown links:\n" + "\n".join(missing)


def test_active_release_guidance_does_not_reopen_fixed_one_shot_bug():
    """Keep dated historical source evidence separate from active work items."""
    roadmap = (ROOT / "WHAXON ROAD MAP - WHATS NEXT - FULL SCOPE.md").read_text(
        encoding="utf-8"
    ).split("## Part II", 1)[0]
    baseline = (ROOT / "docs/V1_0_BASELINE_AND_ACCEPTANCE_REGISTER.md").read_text(
        encoding="utf-8"
    ).split("## Part II", 1)[0]
    assert "### Newly identified correctness dependency" not in roadmap
    assert "new startup issue open" not in roadmap
    assert "Correct desktop `embed.URL` from legacy" not in roadmap
    assert "## 4. Open correctness finding: initialization dispatch" not in baseline
