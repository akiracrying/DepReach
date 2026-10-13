"""Obtain and validate sources for the exact declared inventory.

No target interpreter, build backend, installer or resolver is executed.
Missing transitive versions are reported instead of selecting today's latest.
"""
import hashlib
import json
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from packageurl import PackageURL
from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.utils import canonicalize_name

from scripts.inventory import target_environment
from scripts.source_store import download_purl_source


from scripts.package_metadata import package_metadata


def prepare_source_context(sbom, *, directory="data", overrides=None, jobs=4):
    if isinstance(sbom, (str, Path)):
        sbom = json.loads(Path(sbom).read_text(encoding="utf-8"))
    overrides = overrides or {}
    environment = target_environment()
    for prop in sbom.get("metadata", {}).get("properties", []):
        if prop["name"] == "depreach:inventory":
            environment = json.loads(prop["value"])["environment"]
    components, by_name, issues = {}, defaultdict(list), []
    requested_extras = defaultdict(set)
    for component in sbom.get("components", []):
        purl = component.get("purl")
        if not purl:
            issues.append({"reason": "missing_component_identity", "package": component.get("name")})
            continue
        try:
            package = PackageURL.from_string(purl)
            if package.type != "pypi" or not package.version or package.namespace or package.subpath:
                raise ValueError("Expected exact PyPI identity")
        except ValueError:
            issues.append({"reason": "unsupported_component_identity", "purl": purl})
            continue
        name = canonicalize_name(package.name)
        components[purl] = (name, package.version)
        if purl not in by_name[name]: by_name[name].append(purl)
        for prop in component.get("properties", []):
            if prop["name"] == "depreach:requested-extras":
                requested_extras[purl].update(json.loads(prop["value"]))
    conflicts = {name for name, purls in by_name.items() if len(purls) > 1}
    for name in sorted(conflicts):
        issues.append({"reason": "conflicting_component_versions", "package": name, "purls": by_name[name]})
    sources, metadata = {}, {}
    def fetch(purl):
        record, failures = {"purl": purl}, []
        try:
            record["source"] = str(Path(overrides[purl] if purl in overrides else download_purl_source(purl, directory)).resolve())
            if not Path(record["source"]).is_dir(): raise ValueError("Source directory does not exist")
            record["provenance"] = "user_supplied_version" if purl in overrides else "pypi_versioned_sdist"
        except (ValueError, OSError, requests.RequestException) as exc:
            failures.append({"reason": "dependency_source_unavailable", "purl": purl, "error": str(exc)})
        try:
            record["metadata"] = package_metadata(purl, directory, environment=environment)
        except (ValueError, KeyError, OSError, requests.RequestException) as exc:
            failures.append({"reason": "dependency_metadata_unavailable", "purl": purl, "error": str(exc)})
        return record, failures
    with ThreadPoolExecutor(max_workers=max(1, min(jobs, 8))) as executor:
        futures = [executor.submit(fetch, p) for p, (name, _) in components.items() if name not in conflicts]
        for future in as_completed(futures):
            record, failures = future.result()
            issues.extend(failures)
            if record.get("source"): sources[record["purl"]] = record
            if record.get("metadata"): metadata[record["purl"]] = record["metadata"]
    edges = set()
    # Extras requested by dependency metadata propagate until a fixed point.
    for _ in range(len(components) + 1):
        changed = False
        for purl, info in sorted(metadata.items()):
            if info["requires_dist"] is None:
                continue
            for raw in info["requires_dist"]:
                try: requirement = Requirement(raw)
                except InvalidRequirement: continue
                extras = {"", *requested_extras[purl]}
                if requirement.marker and not any(requirement.marker.evaluate({**environment, "extra": extra}) for extra in extras):
                    continue
                matches = by_name.get(canonicalize_name(requirement.name), [])
                if len(matches) == 1:
                    target = matches[0]
                    edges.add((purl, target, raw))
                    previous = len(requested_extras[target])
                    requested_extras[target].update(requirement.extras)
                    changed |= len(requested_extras[target]) != previous
        if not changed: break
    for purl, info in sorted(metadata.items()):
        try:
            if info.get("requires_python") and not SpecifierSet(info["requires_python"]).contains(environment["python_full_version"], prereleases=True):
                issues.append({"reason": "incompatible_target_python", "purl": purl, "requires_python": info["requires_python"]})
        except InvalidSpecifier:
            issues.append({"reason": "invalid_dependency_metadata", "purl": purl, "requires_python": info["requires_python"]})
        if info["requires_dist"] is None:
            issues.append({"reason": "dependency_metadata_incomplete", "purl": purl})
            continue
        for raw in info["requires_dist"]:
            try: requirement = Requirement(raw)
            except InvalidRequirement:
                issues.append({"reason": "invalid_dependency_metadata", "purl": purl, "requirement": raw}); continue
            if requirement.marker and not any(requirement.marker.evaluate({**environment, "extra": extra}) for extra in {"", *requested_extras[purl]}):
                continue
            matches = by_name.get(canonicalize_name(requirement.name), [])
            if len(matches) != 1:
                issues.append({"reason": "transitive_version_unresolved", "purl": purl, "requirement": raw})
            elif requirement.url or not requirement.specifier.contains(components[matches[0]][1], prereleases=True):
                issues.append({"reason": "transitive_version_conflict", "purl": purl, "requirement": raw, "selected": matches[0]})
    # JSON order and manifest hash must not depend on worker completion order.
    manifest = {"environment": environment, "sources": [sources[p] for p in sorted(sources)],
                "dependency_edges": [{"from": a, "to": b, "requirement": r} for a,b,r in sorted(edges)],
                "issues": sorted(issues, key=lambda x: json.dumps(x, sort_keys=True)),
                "complete": not issues}
    manifest["fingerprint"] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return manifest
