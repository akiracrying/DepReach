"""Resolve Node module specifiers against captured, instance-specific sources.

No target module or loader runs. The profile is modern Node 22/24's default node/import/
require conditions, including module-sync. Custom loaders, NODE_PATH and TS
compiler path mappings are outside this resolver. Resolution is not invocation.
"""
import hashlib
import json
import os
import posixpath
import stat
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
MAX_ROOT_BYTES = 128 * 1024 * 1024
MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_ROOT_FILES = 20000

from scripts.npm_inventory import _location, NAME

BUILTINS = set("_http_agent _http_client _http_common _http_incoming _http_outgoing _http_server _stream_duplex _stream_passthrough _stream_readable _stream_transform _stream_wrap _stream_writable _tls_common _tls_wrap assert assert/strict async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns dns/promises domain events fs fs/promises http http2 https inspector inspector/promises module net os path path/posix path/win32 perf_hooks process punycode querystring readline readline/promises repl stream stream/consumers stream/promises stream/web string_decoder sys timers timers/promises tls trace_events tty url util util/types v8 vm wasi worker_threads zlib".split())
PREFIX_ONLY_BUILTINS = {"sea", "sqlite", "test", "test/reporters"}
UNDEFINED = object()
CAPTURE_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".json"}


class ResolutionError(ValueError):
    def __init__(self, reason, status="unresolved"):
        self.reason, self.status = reason, status
        super().__init__(reason)


def _normalize(path):
    if not isinstance(path, str) or "\\" in path or ":" in path or "\0" in path or path.startswith("/"):
        raise ResolutionError("module_path_outside_captured_tree", "unsupported")
    value = posixpath.normpath(path)
    if value == ".." or value.startswith("../"):
        raise ResolutionError("module_path_outside_captured_tree", "unsupported")
    return "" if value == "." else value


def _target_segments(value):
    decoded = unquote(value)
    return "\\" not in decoded and not any(part.lower() in {".", "..", "node_modules", ""} for part in decoded.split("/"))


class NodeResolver:
    def __init__(self, inventory, source_context, *, conditions=()):
        self.inventory = inventory
        self.target_os = inventory.get("selection", {}).get("target_os") or sys.platform
        if (source_context.get("inventory_sha256") is not None
                and source_context["inventory_sha256"] != inventory.get("input_sha256")):
            raise ValueError("node_source_inventory_mismatch")
        self.instances = {}
        for item in inventory["instances"]:
            location = _location(item["location"])
            if location in self.instances:
                raise ValueError("node_duplicate_instance_location")
            self.instances[location] = item
        seen_sources = set()
        for source in source_context["sources"]:
            location = _location(source["location"])
            if location in seen_sources:
                raise ValueError("node_duplicate_source_location")
            seen_sources.add(location)
            if location not in self.instances or source.get("purl") != self.instances[location].get("purl"):
                raise ValueError("node_source_instance_identity_mismatch")
        self.instances[""] = {"location": "", "source_location": "", "name": inventory.get("project_name"), "purl": None}
        self.roots = {"": str(Path(inventory["root"]).resolve())}
        self.roots.update({s["location"]: str(Path(s["source"]).resolve()) for s in source_context["sources"]})
        if any(not isinstance(c, str) or not c or c.startswith(".") or "," in c for c in conditions):
            raise ValueError("Invalid Node condition")
        self.conditions = {"node", "node-addons", "module-sync", *conditions}
        self.excluded_application_roots = []
        if inventory.get("scan_output_root"):
            output = Path(inventory["scan_output_root"]).resolve()
            application = Path(self.roots[""])
            if output == application:
                raise ValueError("node_output_cannot_be_application_root")
            if application in output.parents:
                self.excluded_application_roots.append(output)
        self.templates = {}
        total = 0
        for root in sorted(set(self.roots.values())):
            captured = self._capture(Path(root), self.excluded_application_roots if root == self.roots[""] else ())
            total += sum(len(raw) for raw in captured["contents"].values())
            if total > MAX_CAPTURE_BYTES:
                raise ValueError("node_source_capture_byte_limit")
            self.templates[root] = captured
        for source in source_context["sources"]:
            instance = self.instances.get(source["location"])
            if instance is None or source.get("purl") != instance.get("purl"):
                raise ValueError("node_source_instance_identity_mismatch")
            captured = self.templates[self.roots[source["location"]]]
            raw = captured["contents"].get("package.json")
            if source.get("package_json_sha256") and (raw is None or hashlib.sha256(raw).hexdigest() != source["package_json_sha256"]):
                raise ValueError("node_package_json_changed_since_source_verification")
            package = captured["manifests"].get("package.json")
            if package is not None and (package.get("name") != instance.get("name") or package.get("version") != instance.get("version")):
                raise ValueError("node_package_version_identity_mismatch")
        self.instance_order = sorted(self.roots, key=len, reverse=True)

    @staticmethod
    def _capture(root, excluded=()):
        if not root.is_dir():
            raise ValueError(f"Module source root does not exist: {root}")
        files, contents, manifests, errors, warnings = set(), {}, {}, {}, {}
        total = 0
        def failed(error):
            raise error
        for folder, dirs, names in os.walk(root, followlinks=False, onerror=failed):
            dirs[:] = sorted(d for d in dirs if d not in {"node_modules", ".git", ".venv", "venv", "__pycache__"}
                             and not Path(folder, d).is_symlink()
                             and not any(Path(folder, d).resolve() == path or path in Path(folder, d).resolve().parents for path in excluded))
            for name in sorted(names):
                path = Path(folder, name)
                if path.is_symlink():
                    continue
                resolved = path.resolve(strict=True)
                if root not in resolved.parents or not stat.S_ISREG(resolved.stat().st_mode):
                    raise ValueError("node_source_path_outside_root_or_not_regular")
                if len(files) >= MAX_ROOT_FILES:
                    raise ValueError("node_source_file_count_limit")
                relative = path.relative_to(root).as_posix()
                files.add(relative)
                if path.suffix.lower() in CAPTURE_EXTENSIONS:
                    with resolved.open("rb") as stream:
                        raw = stream.read(MAX_SOURCE_FILE_BYTES + 1)
                    total += len(raw)
                    if len(raw) > MAX_SOURCE_FILE_BYTES or total > MAX_ROOT_BYTES:
                        raise ValueError("node_source_root_byte_limit")
                    contents[relative] = raw
                if name == "package.json":
                    try:
                        duplicates = set()
                        def node_object(pairs):
                            result = {}
                            for key, value in pairs:
                                if key in result: duplicates.add(key)
                                result[key] = value
                            return result
                        value = json.loads(contents[relative].decode("utf-8-sig"), object_pairs_hook=node_object)
                        if duplicates:
                            warnings[relative] = sorted(duplicates)
                        if not isinstance(value, dict):
                            raise ValueError("package.json must be an object")
                        manifests[relative] = value
                    except (ValueError, UnicodeError):
                        errors[relative] = "invalid_package_json"
        digest = hashlib.sha256()
        for name in sorted(files):
            digest.update(name.encode() + b"\0" + contents.get(name, b"") + b"\0")
        return {"files": files, "contents": contents, "manifests": manifests, "errors": errors, "warnings": warnings, "sha256": digest.hexdigest()}

    def canonical_instance(self, instance):
        if instance not in self.instances:
            raise ResolutionError("unknown_package_instance")
        location = self.instances[instance].get("source_location", instance)
        # Workspace aliases resolve from their captured real source location.
        if location != instance and location not in self.roots:
            raise ResolutionError("workspace_realpath_source_unavailable", "unsupported")
        return location if location in self.roots else instance

    def _physical(self, virtual):
        virtual = _normalize(virtual)
        for instance in self.instance_order:
            if instance and not virtual.startswith(instance + "/"):
                continue
            relative = virtual[len(instance) + 1:] if instance else virtual
            template = self.templates[self.roots[instance]]
            if relative in template["files"]:
                return instance, relative, template
        return None

    def _manifest(self, directory):
        physical = self._physical(posixpath.join(directory, "package.json"))
        if not physical:
            return {}
        _, relative, template = physical
        if relative in template["errors"]:
            raise ResolutionError(template["errors"][relative], "unsupported")
        return template["manifests"].get(relative, {})

    def _scope(self, importer):
        folder = PurePosixPath(importer).parent
        for directory in (folder, *folder.parents):
            name = "" if str(directory) == "." else directory.as_posix()
            if directory.name == "node_modules":
                break
            if self._physical(posixpath.join(name, "package.json")):
                return name, self._manifest(name)
        return None, {}

    def _file(self, candidate):
        physical = self._physical(candidate)
        if not physical:
            return None
        instance, relative, template = physical
        suffix = PurePosixPath(relative).suffix
        scope, package = self._scope(candidate)
        known_formats = {".mjs": "esm", ".cjs": "commonjs", ".json": "json_data", ".node": "native_addon"}
        if suffix in known_formats:
            format_name = known_formats[suffix]
        elif suffix in {".ts", ".tsx", ".mts", ".cts"}:
            format_name = "typescript_requires_runtime_profile"
        elif suffix in {".js", ""}:
            kind = package.get("type")
            format_name = "esm" if kind == "module" else "commonjs" if kind == "commonjs" else "javascript_auto"
        else:
            format_name = "unsupported_extension"
        raw = template["contents"].get(relative)
        return {"status": "resolved", "instance": instance, "relative_file": relative,
                "file": str(Path(self.roots[instance], relative)), "purl": self.instances[instance].get("purl"),
                "module_format": format_name, "source_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
                "resolution_is_invocation": False}

    def _file_with_extensions(self, candidate):
        for suffix in ("", ".js", ".json", ".node"):
            result = self._file(candidate + suffix)
            if result:
                return result
        return None

    def _index(self, directory):
        for suffix in (".js", ".json", ".node"):
            result = self._file(posixpath.join(directory, "index" + suffix))
            if result:
                return result
        return None

    def _legacy(self, candidate, *, allow_file=True):
        result = self._file_with_extensions(candidate) if allow_file else None
        if result:
            return result
        package = self._manifest(candidate)
        main = package.get("main")
        if main:
            if not isinstance(main, str):
                raise ResolutionError("invalid_package_main", "unsupported")
            entry = _normalize(posixpath.join(candidate, main))
            result = self._file_with_extensions(entry) or self._index(entry) or self._index(candidate)
            if not result:
                raise ResolutionError("package_main_not_found")
            return result
        return self._index(candidate)

    def _select_target(self, value, conditions, pattern=None, *, imports=False, depth=0):
        if depth > 32:
            raise ResolutionError("package_target_depth_limit", "unsupported")
        if value is None:
            return None
        if isinstance(value, str):
            if not value.startswith("./"):
                if imports and not value.startswith(("../", "/", "#")) and ":" not in value:
                    return ("external", value.replace("*", pattern) if pattern is not None else value)
                raise ResolutionError("invalid_package_target", "unsupported")
            if not _target_segments(value[2:]):
                raise ResolutionError("invalid_package_target", "unsupported")
            if any(c in value for c in ("%", "?", "#")):
                raise ResolutionError("encoded_or_url_package_target_unsupported", "unsupported")
            if pattern is not None and not _target_segments(pattern):
                raise ResolutionError("invalid_pattern_subpath", "unsupported")
            return ("relative", value.replace("*", pattern) if pattern is not None else value)
        if isinstance(value, list):
            last_error = None
            for target in value:
                try:
                    selected = self._select_target(target, conditions, pattern, imports=imports, depth=depth + 1)
                except ResolutionError as exc:
                    if exc.reason != "invalid_package_target":
                        raise
                    last_error = exc
                    continue
                if selected is None:
                    last_error = None
                    continue
                if selected is not UNDEFINED:
                    return selected
            if last_error:
                raise last_error
            return None
        if isinstance(value, dict):
            if any(len(key) <= 10 and key.isascii() and key.isdecimal() and str(int(key)) == key and int(key) < 4294967295 for key in value):
                raise ResolutionError("invalid_numeric_export_condition", "unsupported")
            for condition, target in value.items():
                if condition == "default" or condition in conditions:
                    selected = self._select_target(target, conditions, pattern, imports=imports, depth=depth + 1)
                    if selected is not UNDEFINED:
                        return selected
            return UNDEFINED
        raise ResolutionError("invalid_package_target", "unsupported")

    def _match(self, mapping, key, conditions, *, imports=False):
        if key in mapping and "*" not in key:
            return self._select_target(mapping[key], conditions, imports=imports)
        patterns = sorted((p for p in mapping if p.count("*") == 1), key=lambda p: (p.index("*"), len(p)), reverse=True)
        for pattern in patterns:
            before, after = pattern.split("*")
            if key.startswith(before) and len(key) > len(before) and key.endswith(after) and len(key) >= len(pattern):
                wildcard = key[len(before):len(key) - len(after)] if after else key[len(before):]
                return self._select_target(mapping[pattern], conditions, wildcard, imports=imports)
        return None

    def _exports(self, exports, subpath, conditions):
        if isinstance(exports, dict):
            keys = list(exports)
            if any(k.startswith(".") for k in keys) and not all(k.startswith(".") for k in keys):
                raise ResolutionError("mixed_export_keys", "unsupported")
            if keys and all(k.startswith(".") for k in keys):
                return self._match(exports, subpath, conditions)
        return self._select_target(exports, conditions) if subpath == "." else None

    def _mapped(self, directory, selected, mode, conditions, chain):
        if selected is None or selected is UNDEFINED:
            raise ResolutionError("package_path_not_exported", "blocked")
        kind, target = selected
        if kind == "external":
            result = self._resolve(posixpath.join(directory, "package.json"), target, mode, conditions, chain)
            if mode == "require" and result.get("status") == "builtin":
                raise ResolutionError("commonjs_import_mapping_to_builtin", "blocked")
            return result
        # exports/imports targets are exact files, with no extension or index fallback.
        candidate = _normalize(posixpath.join(directory, target))
        result = self._file(candidate)
        if result is None:
            raise ResolutionError("mapped_module_file_not_found")
        return result

    def _resolve(self, importer, specifier, mode, conditions, chain):
        identity = (importer, specifier, mode)
        if identity in chain or len(chain) >= 32:
            raise ResolutionError("cyclic_package_mapping", "unsupported")
        chain = (*chain, identity)
        if specifier in BUILTINS or (specifier.startswith("node:") and specifier[5:] in BUILTINS | PREFIX_ONLY_BUILTINS):
            return {"status": "builtin", "module": specifier, "resolution_is_invocation": False}
        if any(c in specifier for c in ("\\", "\0", "%", "?")) or ("#" in specifier and not specifier.startswith("#")):
            raise ResolutionError("encoded_or_url_module_specifier", "unsupported")
        if specifier in {".", ".."} or specifier.startswith(("./", "../")):
            candidate = _normalize(posixpath.join(posixpath.dirname(importer), specifier))
            if mode == "require":
                result = self._legacy(candidate, allow_file=not specifier.endswith("/"))
            elif specifier.endswith("/") and self.target_os != "win32":
                result = None
            else:
                result = self._file(candidate)
                if result and specifier.endswith("/"):
                    result["module_format"] = "requires_loader_format_check"
                    result["url_path_suffix"] = "/"
            if result is None:
                raise ResolutionError("relative_module_not_found")
            return result
        if specifier.startswith(("/", "node:")) or ":" in specifier:
            raise ResolutionError("module_protocol_or_absolute_path_unsupported", "unsupported")
        scope, package = self._scope(importer)
        if specifier.startswith("#"):
            if specifier == "#" or specifier.startswith("#/") or scope is None:
                raise ResolutionError("invalid_package_import", "unsupported")
            imports = package.get("imports")
            if not isinstance(imports, dict):
                raise ResolutionError("package_import_not_defined", "blocked")
            return self._mapped(scope, self._match(imports, specifier, conditions, imports=True), mode, conditions, chain)
        parts = specifier.split("/")
        length = 2 if specifier.startswith("@") else 1
        name = "/".join(parts[:length])
        if not NAME.fullmatch(name) or name in {".", ".."}:
            raise ResolutionError("invalid_package_specifier", "unsupported")
        rest = "/".join(parts[length:])
        if rest and not _target_segments(rest):
            raise ResolutionError("invalid_package_subpath", "unsupported")
        subpath = "./" + rest if len(parts) > length else "."
        if package.get("name") == name and package.get("exports") is not None:
            return self._mapped(scope, self._exports(package["exports"], subpath, conditions), mode, conditions, chain)
        folder = PurePosixPath(importer).parent
        for ancestor in (folder, *folder.parents):
            if ancestor.name == "node_modules":
                continue
            candidate = _normalize((ancestor / "node_modules" / name).as_posix())
            if candidate not in self.instances:
                continue
            if candidate not in self.roots:
                raise ResolutionError("dependency_source_unavailable")
            actual = self.canonical_instance(candidate)
            package = self._manifest(actual)
            if package.get("exports") is not None:
                return self._mapped(actual, self._exports(package["exports"], subpath, conditions), mode, conditions, chain)
            target = posixpath.join(actual, rest) if rest else actual
            result = self._legacy(target, allow_file=not specifier.endswith("/")) if mode == "require" or subpath == "." else (None if specifier.endswith("/") else self._file(target))
            if result:
                return result
            if mode == "import":
                raise ResolutionError("package_module_not_found")
        raise ResolutionError("package_not_in_captured_tree")

    def resolve(self, instance, relative_file, specifier, *, mode="require"):
        evidence = {"importer_instance": instance, "importer_file": relative_file, "specifier": specifier, "mode": mode,
                    "profile": "node22_24_default", "target_os": self.target_os, "conditions": sorted(self.conditions | {mode}),
                    "resolution_is_invocation": False}
        try:
            if mode not in {"require", "import"}:
                raise ResolutionError("unsupported_module_resolution_mode", "unsupported")
            if not isinstance(specifier, str) or not specifier:
                raise ResolutionError("nonliteral_module_specifier")
            instance = self.canonical_instance(instance)
            importer = _normalize(posixpath.join(instance, relative_file))
            if self._physical(importer) is None:
                raise ResolutionError("importer_not_in_captured_tree")
            return {**evidence, **self._resolve(importer, specifier, mode, self.conditions | {mode}, ())}
        except ResolutionError as exc:
            return {**evidence, "status": exc.status, "reason": exc.reason}
