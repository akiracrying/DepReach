import os

import pytest
from scripts.detect_type import is_binary_string, detect_project_type


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


def test_detect_project_type_with_uv_lock(tmp_path):
    # simulate a project that only has uv.lock and python files
    (tmp_path / "uv.lock").write_text("", encoding="utf-8")
    (tmp_path / "main.py").write_text("print('hi')", encoding="utf-8")

    types = detect_project_type(str(tmp_path))
    assert "python" in types
