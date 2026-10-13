"""Resolve explicit requirements and target markers without installing code.

This reads a pinned inventory, not a package resolver: unpinned requirements
must be constrained exactly or supplied via a resolved environment/lockfile.
"""
import json
import re
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement, InvalidRequirement
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion


def target_environment(overrides=None):
    environment = default_environment()
    if overrides is None:
        return environment
    if isinstance(overrides, (str, Path)):
        overrides = json.loads(Path(overrides).read_text(encoding="utf-8"))
    if not isinstance(overrides, dict):
        raise ValueError("Target environment must be a JSON object")
    if any(key not in environment or not isinstance(value, str) for key, value in overrides.items()):
        raise ValueError("Target environment contains unknown fields or non-string values")
    if "python_version" in overrides and "python_full_version" not in overrides:
        raise ValueError("Specify python_full_version with python_version")
    if "python_full_version" in overrides:
        full = Version(overrides["python_full_version"])
        short = ".".join(map(str, full.release[:2]))
        if overrides.get("python_version", short) != short:
            raise ValueError("Target Python versions disagree")
        overrides = {**overrides, "python_version": short}
    environment.update(overrides)
    return environment


def _lines(path):
    pending = ""
    start = 0
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not pending:
            start = number
        text = raw.strip()
        if text.endswith("\\"):
            pending += text[:-1] + " "
            continue
        text = re.sub(r"\s+#.*$", "", pending + text).strip()
        pending = ""
        if text and not text.startswith("#"):
            yield start, text
    if pending:
        raise ValueError(f"Unterminated requirements continuation: {path}:{start}")


def pinned_requirements(path, *, environment=None, all_environments=False):
    environment = target_environment(environment)
    declarations, constraints, skipped = [], [], []
    def read(file, constraint=False, chain=()):
        file = Path(file).resolve()
        if file in chain:
            raise ValueError(f"Cyclic requirements include: {file}")
        for line, text in _lines(file):
            include = re.fullmatch(r"(-r|-c|--requirement|--constraint)(?:=|\s+)(.+)", text)
            if include:
                child = include[2].strip().strip('"').strip("'")
                if "://" in child:
                    raise ValueError("Remote requirements includes are unsupported")
                read(file.parent / child, constraint or include[1] in {"-c", "--constraint"}, (*chain, file))
                continue
            if text.startswith("-"):
                raise ValueError(f"Unsupported requirements directive at {file}:{line}: {text.split()[0]}")
            text = re.sub(r"\s+--hash(?:=|\s+)\S+", "", text)
            try:
                requirement = Requirement(text)
            except InvalidRequirement as exc:
                raise ValueError(f"Invalid requirement at {file}:{line}: {text}") from exc
            record = {"requirement": str(requirement), "file": str(file), "line": line,
                      "marker": str(requirement.marker) if requirement.marker else None,
                      "scope": "declared", "extras": sorted(requirement.extras)}
            if not all_environments and requirement.marker and not requirement.marker.evaluate({**environment, "extra": ""}):
                skipped.append(record)
                continue
            if requirement.url:
                raise ValueError(f"Direct URL requirement needs a resolved package identity: {file}:{line}")
            (constraints if constraint else declarations).append((requirement, record))
    read(path)
    selected = {}
    for req, record in declarations:
        name = canonicalize_name(req.name)
        applicable = [c for c, _ in constraints if canonicalize_name(c.name) == name]
        specs = [req.specifier, *(c.specifier for c in applicable)]
        versions = {s.version for spec in specs for s in spec if s.operator == "==" and "*" not in s.version}
        if len(versions) != 1:
            raise ValueError(f"An exact resolved version is required for {name} ({record['file']}:{record['line']})")
        version = versions.pop()
        try:
            parsed = Version(version)
        except InvalidVersion as exc:
            raise ValueError(f"Invalid pinned version for {name}: {version}") from exc
        if any(not spec.contains(parsed, prereleases=True) for spec in specs):
            raise ValueError(f"Conflicting constraints for {name}=={version}")
        key = (name, version)
        selected.setdefault(key, {"name": name, "version": version, "declarations": [], "extras": []})
        selected[key]["declarations"].append(record)
        selected[key]["extras"] = sorted(set(selected[key]["extras"]) | req.extras)
    if not all_environments:
        names = {}
        for name, version in selected:
            if name in names and names[name] != version:
                raise ValueError(f"Multiple active versions for {name}: {names[name]} and {version}")
            names[name] = version
    rows = list(selected.values())
    lines = [r["name"] + ("[" + ",".join(r["extras"]) + "]" if r["extras"] else "") + "==" + r["version"] for r in rows]
    return "\n".join(lines) + "\n", {
        "provider": "pinned_requirements", "environment": environment,
        "all_environments": all_environments, "selected": rows, "skipped": skipped,
        "completeness": "declared_inventory; transitive closure not established",
        "dependency_scope": "declared; runtime/dev cannot be inferred from package names",
    }


def annotate_sbom(bom, inventory):
    properties = bom.setdefault("metadata", {}).setdefault("properties", [])
    properties.append({"name": "depreach:inventory", "value": json.dumps(inventory, sort_keys=True)})
    rows = {(r["name"], r["version"]): r for r in inventory["selected"]}
    for component in bom.get("components", []):
        row = rows.get((canonicalize_name(component.get("name", "")), component.get("version")))
        if row:
            component.setdefault("properties", []).extend([
                {"name": "depreach:declarations", "value": json.dumps(row["declarations"], sort_keys=True)},
                {"name": "depreach:requested-extras", "value": json.dumps(row["extras"])},
                {"name": "depreach:dependency-scope", "value": "declared"},
            ])
    return bom
