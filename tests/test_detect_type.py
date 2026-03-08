import pytest
from scripts.detect_type import is_binary_string


def test_is_binary_string_text():
    assert is_binary_string(b"hello world") is False
    assert is_binary_string(b"Python 3.10") is False
    assert is_binary_string(b"\n\t\r") is False


def test_is_binary_string_binary():
    assert is_binary_string(b"\x00\x01\x02") is True
    assert is_binary_string(b"hello\x00world") is True
    assert is_binary_string(b"text\x7fmore") is True


def test_is_binary_string_empty():
    assert is_binary_string(b"") is False
