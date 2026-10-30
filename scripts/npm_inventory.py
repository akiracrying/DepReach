"""Read npm's locked installation tree without installing or executing packages.

Instance identity is a lockfile location, not just a package name or PURL.
This module is the inventory boundary for the Node frontend; it does not claim
that a lockfile is installed, verify tarballs or analyze JavaScript calls.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit

from packageurl import PackageURL

DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
NAME = re.compile(r"(?:@[A-Za-z0-9_~.-]+/)?[A-Za-z0-9_~.-]+\Z")
_NUMBER = r"(?:0|[1-9][0-9]*)"
_PRE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
VERSION = re.compile(rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:-{_PRE}(?:\.{_PRE})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _location(value, *, allow_root=False):
    if allow_root and value == "":
        return value
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ValueError(f"Invalid project-relative npm location: {value!r}")
    return value


def _declarations(record, field):
    result = record.get(field, {})
    if not isinstance(result, dict) or any(not NAME.fullmatch(name) or not isinstance(spec, str) for name, spec in result.items()):
        raise ValueError(f"Invalid npm {field}")
    return result


def _name(location, record):
    name = record.get("name")
    if name is None:
        parts = location.split("/node_modules/")[-1].removeprefix("node_modules/")
        name = parts if NAME.fullmatch(parts) else None
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError(f"Package identity missing or invalid at {location}")
    return name


def _platform_match(allowed, target):
    if not isinstance(allowed, list) or any(not isinstance(value, str) for value in allowed):
        raise ValueError("npm os/cpu constraints must be lists of strings")
    if not allowed or target is None:
        return True
    denied = {value[1:] for value in allowed if value.startswith("!")}
    positive = {value for value in allowed if not value.startswith("!")}
    return target not in denied and (not positive or target in positive or "any" in positive)


def _resolve(location, name, packages):
    """Node's nearest ancestor node_modules lookup within the captured tree."""
    base = PurePosixPath(location or ".")
    for parent in (base, *base.parents):
        if parent.name == "node_modules":
            continue
        candidate = (parent / "node_modules" / name).as_posix()
        if candidate in packages:
            return candidate
    return None


def _effective(location, packages):
    seen = set()
    while packages[location].get("link"):
        if location in seen:
            raise ValueError(f"Cyclic npm workspace link: {location}")
        seen.add(location)
        location = _location(packages[location].get("resolved"))
        if location not in packages:
            raise ValueError(f"npm workspace link target absent from lockfile: {location}")
    return location, packages[location]


def read_npm_inventory(directory, *, omit_dev=False, omit_optional=False, target_os=None, target_cpu=None):
    root = Path(directory).resolve()
    # npm-shrinkwrap.json takes precedence when both files exist.
    lock_path = root / ("npm-shrinkwrap.json" if (root / "npm-shrinkwrap.json").is_file() else "package-lock.json")
    raw_lock = lock_path.read_bytes()
    raw_package = (root / "package.json").read_bytes()
    lock = json.loads(raw_lock, object_pairs_hook=_unique_object)
    package = json.loads(raw_package, object_pairs_hook=_unique_object)
    if not isinstance(lock, dict) or not isinstance(package, dict):
        raise ValueError("npm manifests must contain JSON objects")
    if lock.get("lockfileVersion") not in {2, 3}:
        raise ValueError("npm inventory requires lockfileVersion 2 or 3 with a packages table")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise ValueError("npm lockfile has no root packages entry")
    for location, record in packages.items():
        _location(location, allow_root=True)
        if not isinstance(record, dict):
            raise ValueError(f"Invalid npm package record at {location}")
        for flag in ("dev", "optional", "devOptional", "link", "hasInstallScript", "inBundle"):
            if flag in record and not isinstance(record[flag], bool):
                raise ValueError(f"npm {flag} flag must be boolean at {location}")
        peer_meta = record.get("peerDependenciesMeta", {})
        if not isinstance(peer_meta, dict) or any(not isinstance(value, dict) for value in peer_meta.values()):
            raise ValueError(f"Invalid npm peerDependenciesMeta at {location}")
        for field in DEPENDENCY_FIELDS:
            _declarations(record, field)
    for field in DEPENDENCY_FIELDS:
        if _declarations(package, field) != _declarations(packages[""], field):
            raise ValueError(f"package.json and lockfile disagree on {field}; refresh the lockfile")
    issues, omitted, instances = [], [], []
    active = {""}
    excluded_locations = set()
    effective = {location: _effective(location, packages) for location in packages}
    for location, original in sorted(packages.items()):
        if not location:
            continue
        excluded_parent = next((parent.as_posix() for parent in PurePosixPath(location).parents
                                if parent.as_posix() in excluded_locations), None)
        if excluded_parent:
            omitted.append({"location": location, "reasons": ["ancestor_omitted"], "ancestor": excluded_parent})
            excluded_locations.add(location)
            continue
        source_location, record = effective[location]
        flags = {key: bool(original.get(key, record.get(key, False))) for key in ("dev", "optional", "devOptional")}
        reasons = []
        if omit_dev and flags["dev"]:
            reasons.append("dev")
        if omit_optional and flags["optional"]:
            reasons.append("optional")
        if omit_dev and omit_optional and flags["devOptional"]:
            reasons.append("dev_and_optional")
        for key, target in (("os", target_os), ("cpu", target_cpu)):
            allowed = record.get(key, [])
            if not _platform_match(allowed, target):
                reasons.append(f"target_{key}")
        if reasons:
            omitted.append({"location": location, "reasons": reasons})
            excluded_locations.add(location)
            continue
        name = _name(location, record)
        version = record.get("version")
        namespace, _, short_name = name.rpartition("/")
        purl = None
        if isinstance(version, str) and VERSION.fullmatch(version):
            purl = PackageURL(type="npm", namespace=namespace or None, name=short_name, version=version).to_string()
        else:
            issues.append({"reason": "exact_package_version_missing", "location": location, "version": version})
        resolved = record.get("resolved")
        source_kind = "workspace" if original.get("link") or "node_modules" not in PurePosixPath(location).parts else "registry_tarball" if isinstance(resolved, str) and urlsplit(resolved).hostname == "registry.npmjs.org" else "bundled" if record.get("inBundle") else "other_or_unspecified"
        for key, target in (("os", target_os), ("cpu", target_cpu)):
            if record.get(key) and target is None:
                issues.append({"reason": "target_platform_unspecified", "location": location, "dimension": key, "constraint": record[key]})
        instance = {"location": location, "source_location": source_location, "name": name, "version": version,
                    "purl": purl, "source_kind": source_kind, "resolved": resolved, "integrity": record.get("integrity"),
                    "link": bool(original.get("link")), "flags": flags,
                    "conditions": {key: record[key] for key in ("os", "cpu", "engines") if key in record},
                    "has_install_script": bool(record.get("hasInstallScript")),
                    "declared_dependencies": {field: _declarations(record, field) for field in DEPENDENCY_FIELDS}}
        instances.append(instance)
        active.add(location)
    edges = []
    for location in sorted(active):
        source_location, record = effective[location]
        fields = ["dependencies", "optionalDependencies", "peerDependencies"]
        # Development dependencies belong to the root and local workspaces,
        # not the development manifest of an installed registry dependency.
        if not omit_dev and (not location or "node_modules" not in PurePosixPath(source_location).parts):
            fields.append("devDependencies")
        declarations = {}
        for field in fields:
            for name, spec in _declarations(record, field).items():
                if name in _declarations(record, "optionalDependencies") and field == "dependencies":
                    continue
                if field == "optionalDependencies" and omit_optional:
                    continue
                declarations.setdefault(name, []).append((field, spec))
        for name, contracts in sorted(declarations.items()):
            target = _resolve(source_location, name, packages)
            status = "resolved" if target in active else "omitted" if target in packages else "missing"
            for field, spec in contracts:
                optional = field == "optionalDependencies" or (field == "peerDependencies" and record.get("peerDependenciesMeta", {}).get(name, {}).get("optional") is True)
                edge = {"from": location, "to": target, "name": name, "requested": spec,
                        "kind": field, "optional": optional, "status": status}
                edges.append(edge)
                if status != "resolved" and not optional:
                    issues.append({"reason": "dependency_instance_unresolved", **edge})
    options = {"omit_dev": omit_dev, "omit_optional": omit_optional, "target_os": target_os, "target_cpu": target_cpu}
    return {"schema_version": 1, "ecosystem": "npm", "root": str(root), "project_name": package.get("name", root.name),
            "lockfile": lock_path.name, "lockfile_version": lock["lockfileVersion"],
            "input_sha256": hashlib.sha256(raw_package + b"\0" + raw_lock + b"\0" + json.dumps(options, sort_keys=True).encode()).hexdigest(),
            "selection": options, "instances": instances, "edges": edges, "omitted": omitted, "issues": issues,
            "tree_complete": not issues, "version_range_validation": "not_performed",
            "source_artifacts_verified": False, "installed_tree_verified": False,
            "resolution_scope": "locked_node_modules_ancestor_lookup_default_symlink_behavior"}


def npm_sbom(inventory):
    def ref(location):
        return "npm-instance:" + (quote(location, safe="/@") if location else "root")
    components = []
    for instance in inventory["instances"]:
        component = {"type": "library", "bom-ref": ref(instance["location"]), "name": instance["name"],
                     "properties": [{"name": "depreach:npm-instance", "value": json.dumps(instance, sort_keys=True)}]}
        if instance["version"]:
            component["version"] = instance["version"]
        if instance["purl"]:
            component["purl"] = instance["purl"]
        components.append(component)
    adjacency = {ref(""): set(), **{c["bom-ref"]: set() for c in components}}
    for edge in inventory["edges"]:
        if edge["status"] == "resolved":
            adjacency[ref(edge["from"])].add(ref(edge["to"]))
    summary = {key: value for key, value in inventory.items() if key not in {"instances", "edges"}}
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "bom-ref": ref(""), "name": inventory["project_name"]},
                         "properties": [{"name": "depreach:npm-inventory", "value": json.dumps(summary, sort_keys=True)}]},
            "components": components, "dependencies": [{"ref": name, "dependsOn": sorted(targets)} for name, targets in sorted(adjacency.items())]}


def scan_npm_inventory(inventory, output_dir, source_context=None, *, module_resolution=None):
    """Run or resume SCA using an already captured inventory and SBOM."""
    from scripts.composition_analysis import check_vulnerabilities_from_sbom
    from scripts.reachability_result import result
    from scripts.sarif_report import write_sarif
    from scripts.html_report import generate_html_report
    output = Path(output_dir)
    findings = check_vulnerabilities_from_sbom(inventory["root"], str(output / "sbom.json"))
    for finding in findings:
        finding["reachability"] = result("unsupported", reasons=["javascript_reachability_not_implemented"],
            analyzer_version="npm-inventory-v2", ecosystem="npm", inventory_scope=inventory["selection"],
            source_manifest=inventory.get("source_manifest"), syntax_manifest=inventory.get("syntax_manifest"),
            sources_complete=source_context["complete"] if source_context else None,
            module_resolution_manifest=inventory.get("module_resolution_manifest"))
        if module_resolution is not None:
            finding["reachability"]["module_lookup_summary"] = {
                "scope": "scan_wide_candidates", "counts": module_resolution["counts"],
                "input_sha256": module_resolution["input_sha256"],
                "binding_resolution_implemented": False, "call_graph_implemented": False}
    (output / "vulnerabilities.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    write_sarif(findings, str(output / "vulnerabilities.sarif"), project_uri=inventory["root"])
    generate_html_report(inventory["project_name"], str(output / "sbom.json"),
                         str(output / "vulnerabilities.json"), str(output / "report.html"))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect an npm lockfile and export its instance tree; no source reachability analysis yet.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True, help="New directory for inventory.json and sbom.json")
    parser.add_argument("--omit-dev", action="store_true")
    parser.add_argument("--omit-optional", action="store_true")
    parser.add_argument("--target-os")
    parser.add_argument("--target-cpu")
    parser.add_argument("--scan", action="store_true", help="Query configured local VDB and export findings; JS/TS reachability remains unsupported")
    parser.add_argument("--resolve-imports", action="store_true", help="Audit Node module path candidates; implies --syntax and --sources, not call reachability")
    parser.add_argument("--condition", action="append", default=[], help="Additional Node package export condition for --resolve-imports")
    parser.add_argument("--syntax", action="store_true", help="Extract JS/TS AST facts, including dependency sources; requires the node extra")
    parser.add_argument("--sources", action="store_true", help="Fetch and verify locked npm tarballs without installing packages")
    parser.add_argument("--source-cache", default="data/npm-archives")
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error("jobs must be positive")
    if args.condition and not args.resolve_imports:
        parser.error("--condition requires --resolve-imports")
    args.syntax = args.syntax or args.resolve_imports
    args.sources = args.sources or args.syntax
    if args.syntax:
        from scripts.javascript_syntax import _parser
        try:
            _parser(".js")
        except RuntimeError as exc:
            parser.error(str(exc))
    try:
        inventory = read_npm_inventory(args.input, omit_dev=args.omit_dev, omit_optional=args.omit_optional,
                                       target_os=args.target_os, target_cpu=args.target_cpu)
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=False)
        inventory["scan_output_root"] = str(output.resolve())
        (output / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
        (output / "sbom.json").write_text(json.dumps(npm_sbom(inventory), indent=2), encoding="utf-8")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    source_context = None
    if args.sources:
        from scripts.npm_sources import prepare_npm_sources
        source_context = prepare_npm_sources(inventory, output / "sources", archive_cache=args.source_cache, jobs=args.jobs)
        manifest_path = output / "dependency-sources.json"
        manifest_path.write_text(json.dumps(source_context, indent=2), encoding="utf-8")
        inventory["source_manifest"] = str(manifest_path.resolve())
        inventory["source_artifacts_verified"] = source_context["complete"] and all(s.get("archive_sha256") for s in source_context["sources"])
        (output / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
        (output / "sbom.json").write_text(json.dumps(npm_sbom(inventory), indent=2), encoding="utf-8")
        print(f"npm sources: {len(source_context['sources'])}/{source_context['metrics']['instances']}; source issues: {len(source_context['issues'])}")
    syntax_context = None
    if args.syntax:
        from scripts.javascript_syntax import audit_javascript_sources
        syntax_context = audit_javascript_sources(args.input, source_context, output / "syntax", exclude_roots=[output])
        inventory["syntax_manifest"] = str((output / "syntax/summary.json").resolve())
        (output / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
        (output / "sbom.json").write_text(json.dumps(npm_sbom(inventory), indent=2), encoding="utf-8")
        print(f"JS/TS syntax: {syntax_context['counts']['modules']} files; {syntax_context['counts']['functions']} functions; {len(syntax_context['issues'])} parse issues")
    resolution_context = None
    if args.resolve_imports:
        from scripts.node_imports import audit_node_imports
        try:
            resolution_context = audit_node_imports(inventory, source_context, output / "module-resolution", conditions=args.condition)
        except (ValueError, OSError, RuntimeError) as exc:
            parser.error("Node module lookup failed: " + str(exc))
        inventory["module_resolution_manifest"] = str((output / "module-resolution/summary.json").resolve())
        (output / "inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
        (output / "sbom.json").write_text(json.dumps(npm_sbom(inventory), indent=2), encoding="utf-8")
        print("Node module candidates: " + json.dumps(resolution_context["counts"]["by_status"], sort_keys=True))
    print(f"npm instances: {len(inventory['instances'])}; edges: {len(inventory['edges'])}; omitted: {len(inventory['omitted'])}; issues: {len(inventory['issues'])}")
    if args.scan:
        findings = scan_npm_inventory(inventory, output, source_context, module_resolution=resolution_context)
        print(f"Package/advisory findings: {len(findings)}; JavaScript/TypeScript reachability is unsupported.")
        if findings:
            return 3
    print("JavaScript/TypeScript reachability is not implemented yet.")
    return 0 if (inventory["tree_complete"] and (source_context is None or source_context["complete"])
                 and (syntax_context is None or syntax_context["syntax_complete"])
                 and (resolution_context is None or resolution_context["candidate_lookup_complete"])) else 3


if __name__ == "__main__":
    raise SystemExit(main())
