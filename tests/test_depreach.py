import pytest
from depreach import format_description


def test_format_description_empty():
    assert format_description("") == ""
    assert format_description(None) == ""


def test_format_description_strips_markdown():
    desc = "## Heading\n\nSome `code` and **bold** text."
    out = format_description(desc)
    assert "Heading" in out or "Some" in out
    assert "`" not in out or "**" not in out


def test_format_description_first_line():
    desc = "First line.\nSecond line."
    out = format_description(desc)
    assert "First" in out
    assert out.strip() != ""


def test_format_description_links_removed():
    desc = "See [link](https://example.com) for more."
    out = format_description(desc)
    assert "https://" not in out or "link" in out
