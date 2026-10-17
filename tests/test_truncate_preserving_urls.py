"""Tests for §21.6: URL-preserving truncation in report rendering."""
from whaxon.core.report import _truncate_preserving_urls


def test_short_text_unchanged():
    assert _truncate_preserving_urls("short line", 200) == "short line"


def test_long_text_truncated_with_marker():
    text = "x" * 300
    out = _truncate_preserving_urls(text, 200)
    assert len(out) <= 203  # 200 + "..."
    assert out.endswith("...")


def test_url_straddling_limit_kept_whole():
    # URL starts at 180, ends at 260 — would be cut by hard [:200]
    prefix = "a" * 180
    url = "https://example.com/" + "b" * 60  # 80 chars, ends at 260
    text = prefix + url
    out = _truncate_preserving_urls(text, 200)
    assert url in out, f"URL was cut: {out!r}"
    assert out.endswith("...")


def test_url_entirely_before_limit_untouched():
    url = "https://example.com/path"
    text = url + " " + "x" * 300
    out = _truncate_preserving_urls(text, 200)
    assert url in out


def test_no_url_hard_truncates():
    text = "z" * 250
    out = _truncate_preserving_urls(text, 200)
    assert len(out) == 203


def test_empty_input():
    assert _truncate_preserving_urls("", 200) == ""
    assert _truncate_preserving_urls(None, 200) is None


def test_exactly_at_limit_unchanged():
    text = "a" * 200
    assert _truncate_preserving_urls(text, 200) == text
