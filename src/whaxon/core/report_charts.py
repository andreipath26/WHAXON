"""Inline SVG charts for the report renderer."""
from __future__ import annotations

_SEV_COLORS = {
    "screen": {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e", "info": "#64748b"},
    "print":  {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a", "info": "#475569"},
}
_ORDER = ("critical", "high", "medium", "low", "info")


def severity_donut(counts: dict, mode: str = "screen", diameter: int = 200) -> str:
    """Return an inline SVG donut for severity counts."""
    colors = _SEV_COLORS.get(mode, _SEV_COLORS["screen"])
    total = sum(int(counts.get(s, 0) or 0) for s in _ORDER)
    r = diameter // 2
    cx = cy = r
    stroke = max(8, diameter // 12)
    inner = r - stroke
    if total == 0:
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{diameter}" height="{diameter}"><circle cx="{cx}" cy="{cy}" r="{inner}" fill="none" stroke="#888" stroke-width="{stroke}"/></svg>'
    circumference = 2 * 3.141592653589793 * inner
    offset = 0.0
    parts = []
    for sev in _ORDER:
        n = int(counts.get(sev, 0) or 0)
        if n <= 0:
            continue
        frac = n / total
        length = frac * circumference
        parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{inner}" fill="none" stroke="{colors[sev]}" stroke-width="{stroke}" stroke-dasharray="{length:.2f} {circumference - length:.2f}" stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += length
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + str(diameter) + '" height="' + str(diameter) + '">' + ''.join(parts) + '</svg>'
