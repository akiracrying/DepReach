import os
import subprocess
import sys

def _find_venv_python(src_dir: str):
    abs_src = os.path.abspath(src_dir)
    for venv_name in (".venv", "venv", "env"):
        venv_dir = os.path.join(abs_src, venv_name)
        if not os.path.isdir(venv_dir):
            continue
        candidates = [
            os.path.join(venv_dir, "Scripts", "python.exe"),
            os.path.join(venv_dir, "bin", "python"),
        ]
        for py_path in candidates:
            if os.path.isfile(py_path):
                return py_path
    return None


def _choose_python_provider(src_dir):
    abs_src = os.path.abspath(src_dir)
    venv_python = _find_venv_python(src_dir)
    if venv_python:
        return "environment", [venv_python]
    if os.path.isfile(os.path.join(abs_src, "poetry.lock")):
        return "poetry", [abs_src]
    if os.path.isfile(os.path.join(abs_src, "Pipfile")):
        return "pipenv", [abs_src]
    req_files = [
        os.path.join(abs_src, "requirements.txt"),
        os.path.join(abs_src, "requirements", "requirements.txt"),
    ]
    for p in req_files:
        if os.path.isfile(p):
            return "requirements", [p]
    return "requirements", [os.path.join(abs_src, "requirements.txt")]


def generate_sbom_python(src_dir=".", output_file="sbom.json"):
    abs_src = os.path.abspath(src_dir)
    abs_out = os.path.abspath(output_file)

    if os.path.exists(abs_out):
        try:
            os.remove(abs_out)
        except OSError:
            pass

    provider, provider_args = _choose_python_provider(src_dir)
    cmd = [sys.executable, "-m", "cyclonedx_py", provider] + provider_args + [
        "-o", abs_out,
        "--of", "JSON",
        "--sv", "1.5",
    ]
    try:
        subprocess.run(
            cmd,
            cwd=abs_src,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        return os.path.exists(abs_out)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False