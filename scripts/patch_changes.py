"""Structured unified-diff records, including non-text and metadata-only files."""
import ast
import re
import shlex
from pathlib import PurePosixPath

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _path(text):
    text = text.split("\t", 1)[0]
    if text.startswith('"'):
        try:
            text = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return "<unparsed-path>"
    return text[2:] if text.startswith(("a/", "b/")) else text


def parse_patch_files(diff):
    files, current, hunk = [], None, None
    def finish_hunk():
        if hunk is not None:
            hunk["valid"] = len(hunk["old"]) == hunk["old_count"] and hunk["new_seen"] == hunk["new_count"]
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            finish_hunk()
            current = {"old_file": "", "new_file": "", "hunks": [], "binary": False, "metadata": []}
            try:
                parts = shlex.split(line[len("diff --git "):])
                if len(parts) == 2:
                    current.update(old_file=_path(parts[0]), new_file=_path(parts[1]))
            except ValueError:
                pass
            files.append(current)
            hunk = None
        elif current is not None:
            if line.startswith("--- ") and hunk is None:
                current["old_file"] = _path(line[4:])
            elif line.startswith("+++ ") and hunk is None:
                current["new_file"] = _path(line[4:])
            elif match := HUNK.match(line):
                finish_hunk()
                hunk = {"file": current["old_file"], "new_file": current["new_file"],
                        "old_start": int(match[1]), "old_count": int(match[2] or 1),
                        "new_start": int(match[3]), "new_count": int(match[4] or 1),
                        "old": [], "changed": [], "new_seen": 0}
                current["hunks"].append(hunk)
            elif hunk is not None:
                if line.startswith((" ", "-")):
                    if line.startswith("-"):
                        hunk["changed"].append((len(hunk["old"]), "removed", line[1:]))
                    else:
                        hunk["new_seen"] += 1
                    hunk["old"].append(line[1:])
                elif line.startswith("+"):
                    hunk["changed"].append((max(0, len(hunk["old"]) - 1), "added", line[1:]))
                    hunk["new_seen"] += 1
            elif line.startswith(("Binary files ", "GIT binary patch")):
                current["binary"] = True
            elif line.startswith(("rename from ", "rename to ", "old mode ", "new mode ", "new file mode ", "deleted file mode ")):
                current["metadata"].append(line)
    finish_hunk()
    return files


def change_kind(file, *, binary=False):
    path = PurePosixPath(file)
    parts = {p.lower() for p in path.parts}
    if parts & {"test", "tests", "docs", "examples", ".github", "news", "changelog.d"} or path.name.startswith("test_"):
        return "non_runtime_documentation_or_test"
    if path.stem.lower() in {"changes", "changelog", "history", "readme", "license", "authors"}:
        return "non_runtime_documentation_or_test"
    suffix = path.suffix.lower()
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".pyx", ".pxd", ".so", ".dll", ".pyd"}:
        return "native_code_or_extension"
    if binary:
        return "binary_resource"
    if suffix == ".py":
        return "python_source"
    if suffix in {".pem", ".crt", ".cer", ".der"}:
        return "certificate_or_trust_data"
    if path.name in {"pyproject.toml", "setup.cfg", "MANIFEST.in", "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock"}:
        return "package_or_build_configuration"
    if suffix in {".json", ".yaml", ".yml", ".csv", ".txt", ".toml", ".ini", ".cfg"}:
        return "data_or_configuration"
    return "non_python_source_or_resource"
