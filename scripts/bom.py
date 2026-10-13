import os
import subprocess
import sys
import tempfile
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)

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
    if os.path.isfile(os.path.join(abs_src, "Pipfile")) or os.path.isfile(os.path.join(abs_src, "Pipfile.lock")):
        return "pipenv", [abs_src]
    for req_path in [
        os.path.join(abs_src, "requirements.txt"),
        os.path.join(abs_src, "requirements", "requirements.txt"),
    ]:
        if os.path.isfile(req_path):
            return "requirements", [req_path]
    raise ValueError("No supported Python inventory found. Provide a resolved virtualenv, poetry.lock, Pipfile.lock, or pinned requirements.txt. pyproject.toml / uv.lock alone are not supported yet.")


def generate_sbom_python(src_dir=".", output_file="sbom.json", *, target_environment=None, all_environments=False, requirements_file=None):
    abs_src = os.path.abspath(src_dir)
    abs_out = os.path.abspath(output_file)

    if requirements_file:
        selected_file = Path(requirements_file)
        if not selected_file.is_absolute():
            selected_file = Path(abs_src) / selected_file
        provider, provider_args = "requirements", [str(selected_file.resolve())]
    else:
        provider, provider_args = _choose_python_provider(src_dir)
    if provider != "requirements" and (target_environment is not None or all_environments):
        raise ValueError("Target marker overrides currently require a pinned requirements inventory; do not apply a foreign target to an installed environment")
    inventory, prepared = None, None
    if provider == "requirements":
        from scripts.inventory import pinned_requirements
        prepared, inventory = pinned_requirements(provider_args[0], environment=target_environment, all_environments=all_environments)
    os.makedirs(os.path.dirname(abs_out), exist_ok=True)
    handle, temporary = tempfile.mkstemp(suffix=".json", prefix=".sbom-", dir=os.path.dirname(abs_out))
    os.close(handle)
    prepared_path = None
    if prepared is not None:
        fd, prepared_path = tempfile.mkstemp(suffix=".txt", prefix=".requirements-", dir=os.path.dirname(abs_out))
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(prepared)
        provider_args = [prepared_path]
    cmd = [sys.executable, "-m", "cyclonedx_py", provider] + provider_args + [
        "-o", temporary,
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
            timeout=300,
        )
        if os.path.getsize(temporary) == 0:
            return False
        if inventory is not None:
            from scripts.inventory import annotate_sbom
            bom = json.loads(Path(temporary).read_text(encoding="utf-8"))
            Path(temporary).write_text(json.dumps(annotate_sbom(bom, inventory), indent=2), encoding="utf-8")
        os.replace(temporary, abs_out)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        logger.error("SBOM generation failed: %s", exc)
        return False
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
        if prepared_path and os.path.exists(prepared_path):
            os.remove(prepared_path)
