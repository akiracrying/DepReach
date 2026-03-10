import os

import pytest
from scripts.bom import _choose_python_provider


def test_choose_provider_poetry(tmp_path):
    (tmp_path / "poetry.lock").write_text("", encoding="utf-8")
    provider, args = _choose_python_provider(str(tmp_path))
    assert provider == "poetry"
    assert args == [os.path.abspath(tmp_path)]


def test_choose_provider_pipfile(tmp_path):
    (tmp_path / "Pipfile").write_text("", encoding="utf-8")
    provider, args = _choose_python_provider(str(tmp_path))
    assert provider == "pipenv"
    assert args == [os.path.abspath(tmp_path)]


def test_choose_provider_pipfile_lock_only(tmp_path):
    (tmp_path / "Pipfile.lock").write_text("{}", encoding="utf-8")
    provider, args = _choose_python_provider(str(tmp_path))
    assert provider == "pipenv"
    assert args == [os.path.abspath(tmp_path)]


def test_choose_provider_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    provider, args = _choose_python_provider(str(tmp_path))
    assert provider == "requirements"
    assert len(args) == 1
    assert args[0].endswith("requirements.txt")


def test_choose_provider_requirements_subdir(tmp_path):
    req_dir = tmp_path / "requirements"
    req_dir.mkdir()
    (req_dir / "requirements.txt").write_text("", encoding="utf-8")
    provider, args = _choose_python_provider(str(tmp_path))
    assert provider == "requirements"
    assert len(args) == 1
    assert "requirements" in args[0] and "requirements.txt" in args[0]


def test_choose_provider_poetry_over_requirements(tmp_path):
    (tmp_path / "poetry.lock").write_text("", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    provider, _ = _choose_python_provider(str(tmp_path))
    assert provider == "poetry"


def test_choose_provider_venv_over_lock(tmp_path):
    venv_dir = tmp_path / ".venv"
    bin_dir = venv_dir / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python").write_text("", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("", encoding="utf-8")
    provider, args = _choose_python_provider(str(tmp_path))
    assert provider == "environment"
    assert len(args) == 1
    assert "python" in args[0]
