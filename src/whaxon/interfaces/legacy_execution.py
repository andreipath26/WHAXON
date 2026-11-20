"""Explicit compatibility gates for retired direct-execution interfaces."""
from __future__ import annotations

import os


def legacy_gui_execution_enabled() -> bool:
    """Require an operator opt-in before dormant Qt code can dispatch tools."""
    return os.environ.get(
        "WHAXON_LEGACY_GUI_EXECUTION_ENABLED", "false",
    ).strip().lower() in {"1", "true", "yes"}
