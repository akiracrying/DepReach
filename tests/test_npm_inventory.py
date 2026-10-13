import json

import pytest

from scripts.npm_inventory import read_npm_inventory, npm_sbom


def manifests(tmp_path, entries, root=None, version=3):
    root = root or {}
    package = {"name": "fixture", "version": "1.0.0", **root}
    lock = {"lockfileVersion": version, "packages": {"": package, **entries}}
    (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    return lock


def test_distinct_instances_resolve_to_nearest_version(tmp_path):
    manifests(tmp_path, {
        "node_modules/front": {"version": "1.0.0", "dependencies": {"leaf": "^2"}},
        "node_modules/front/node_modules/leaf": {"version": "2.1.0"},
        "node_modules/other": {"version": "1.0.0", "dependencies": {"leaf": "^1"}},
        "node_modules/leaf": {"version": "1.2.0"},
    }, {"dependencies": {"front": "1", "other": "1"}})
    inventory = read_npm_inventory(tmp_path)
    assert inventory["tree_complete"]
    assert len(inventory["instances"]) == 4
    selected = {edge["from"]: edge["to"] for edge in inventory["edges"] if edge["name"] == "leaf"}
    assert selected == {"node_modules/front": "node_modules/front/node_modules/leaf", "node_modules/other": "node_modules/leaf"}
    sbom = npm_sbom(inventory)
    assert len({c["bom-ref"] for c in sbom["components"]}) == 4
    assert {c["purl"] for c in sbom["components"] if c["name"] == "leaf"} == {"pkg:npm/leaf@1.2.0", "pkg:npm/leaf@2.1.0"}


def test_scoped_name_and_alias_use_real_package_identity(tmp_path):
    manifests(tmp_path, {"node_modules/alias": {"name": "@scope/real", "version": "2.0.0"}}, {"dependencies": {"alias": "npm:@scope/real@2"}})
    inventory = read_npm_inventory(tmp_path)
    assert inventory["instances"][0]["purl"] == "pkg:npm/%40scope/real@2.0.0"
    assert inventory["edges"][0]["to"] == "node_modules/alias"


@pytest.mark.parametrize("omit_dev,omit_optional,expected", [(False,False,4),(True,False,2),(False,True,2),(True,True,0)])
def test_dev_optional_flags_are_not_conflated(tmp_path, omit_dev, omit_optional, expected):
    manifests(tmp_path, {
        "node_modules/d": {"version": "1.0.0", "dev": True},
        "node_modules/o": {"version": "1.0.0", "optional": True},
        "node_modules/both": {"version": "1.0.0", "dev": True, "optional": True},
        "node_modules/either": {"version": "1.0.0", "devOptional": True},
    })
    inventory = read_npm_inventory(tmp_path, omit_dev=omit_dev, omit_optional=omit_optional)
    assert len(inventory["instances"]) == expected


def test_optional_override_and_optional_peer_absence(tmp_path):
    manifests(tmp_path, {"node_modules/foo": {"version": "2.0.0"}},
               {"dependencies": {"foo": "^1"}, "optionalDependencies": {"foo": "^2"},
                "peerDependencies": {"peer": "^1"}, "peerDependenciesMeta": {"peer": {"optional": True}}})
    inventory = read_npm_inventory(tmp_path)
    assert inventory["tree_complete"]
    assert [e["requested"] for e in inventory["edges"] if e["name"] == "foo"] == ["^2"]
    assert next(e for e in inventory["edges"] if e["name"] == "peer")["status"] == "missing"


def test_workspace_links_resolve_from_real_source_location(tmp_path):
    manifests(tmp_path, {
        "node_modules/work": {"resolved": "packages/work", "link": True},
        "packages/work": {"name": "work", "version": "1.0.0", "dependencies": {"leaf": "^2"}},
        "packages/work/node_modules/leaf": {"version": "2.0.0"},
        "node_modules/leaf": {"version": "1.0.0"},
    }, {"dependencies": {"work": "file:packages/work"}})
    inventory = read_npm_inventory(tmp_path)
    edge = next(e for e in inventory["edges"] if e["from"] == "node_modules/work")
    assert edge["to"] == "packages/work/node_modules/leaf"
    assert next(i for i in inventory["instances"] if i["location"] == "node_modules/work")["source_kind"] == "workspace"


def test_required_missing_instance_prevents_complete_tree(tmp_path):
    manifests(tmp_path, {}, {"dependencies": {"missing": "^1"}})
    inventory = read_npm_inventory(tmp_path)
    assert not inventory["tree_complete"]
    assert inventory["issues"][0]["reason"] == "dependency_instance_unresolved"


def test_platform_constraints_require_target_and_filter_explicitly(tmp_path):
    manifests(tmp_path, {"node_modules/native": {"version": "1.0.0", "optional": True, "os": ["!win32"], "cpu": ["x64"]}},
               {"optionalDependencies": {"native": "^1"}})
    assert not read_npm_inventory(tmp_path)["tree_complete"]
    windows = read_npm_inventory(tmp_path, target_os="win32", target_cpu="x64")
    assert not windows["instances"] and windows["tree_complete"]
    assert len(read_npm_inventory(tmp_path, target_os="linux", target_cpu="x64")["instances"]) == 1


def test_stale_manifest_and_duplicate_keys_are_rejected(tmp_path):
    manifests(tmp_path, {})
    (tmp_path / "package.json").write_text('{"dependencies":{"missing":"1"}}', encoding="utf-8")
    with pytest.raises(ValueError, match="disagree"):
        read_npm_inventory(tmp_path)
    (tmp_path / "package.json").write_text('{"dependencies":{},"dependencies":{}}', encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        read_npm_inventory(tmp_path)


@pytest.mark.parametrize("location", ["../outside", "C:/outside", "/absolute", "node_modules/../outside", "node_modules//x", "node_modules\\x"])
def test_locations_cannot_escape_or_normalize_ambiguously(tmp_path, location):
    manifests(tmp_path, {location: {"version": "1.0.0"}})
    with pytest.raises(ValueError, match="location"):
        read_npm_inventory(tmp_path)


def test_link_cycle_is_rejected(tmp_path):
    manifests(tmp_path, {"node_modules/a": {"link": True, "resolved": "node_modules/b"},
                          "node_modules/b": {"link": True, "resolved": "node_modules/a"}})
    with pytest.raises(ValueError, match="Cyclic"):
        read_npm_inventory(tmp_path)


def test_shrinkwrap_precedes_lockfile_and_v1_is_not_invented(tmp_path):
    lock = manifests(tmp_path, {"node_modules/foo": {"version": "1.0.0"}}, version=2)
    lock["packages"]["node_modules/foo"]["version"] = "2.0.0"
    (tmp_path / "npm-shrinkwrap.json").write_text(json.dumps(lock), encoding="utf-8")
    assert read_npm_inventory(tmp_path)["instances"][0]["version"] == "2.0.0"
    lock["lockfileVersion"] = 1
    (tmp_path / "npm-shrinkwrap.json").write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(ValueError, match="2 or 3"):
        read_npm_inventory(tmp_path)


def test_content_and_selection_are_in_fingerprint(tmp_path):
    lock = manifests(tmp_path, {"node_modules/foo": {"version": "1.0.0"}})
    before = read_npm_inventory(tmp_path)
    assert before["input_sha256"] != read_npm_inventory(tmp_path, omit_dev=True)["input_sha256"]
    lock["packages"]["node_modules/foo"]["version"] = "2.0.0"
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    assert before["input_sha256"] != read_npm_inventory(tmp_path)["input_sha256"]


@pytest.mark.parametrize("version", ["1.0.0-a..b", "1.0.0-01", "1.0.0+", "01.0.0", "^1.0.0"])
def test_nonexact_or_malformed_versions_have_no_purl(tmp_path, version):
    manifests(tmp_path, {"node_modules/foo": {"version": version}})
    inventory = read_npm_inventory(tmp_path)
    assert inventory["instances"][0]["purl"] is None
    assert not inventory["tree_complete"]


def test_prerelease_and_build_version_identity_is_preserved(tmp_path):
    manifests(tmp_path, {"node_modules/foo": {"version": "1.0.0-rc.1+build.7"}})
    assert read_npm_inventory(tmp_path)["instances"][0]["version"] == "1.0.0-rc.1+build.7"


@pytest.mark.parametrize("extra", [{"dev": "false"}, {"peerDependenciesMeta": []}])
def test_malformed_flags_are_rejected_instead_of_filtering_packages(tmp_path, extra):
    manifests(tmp_path, {"node_modules/foo": {"version": "1.0.0", **extra}})
    with pytest.raises(ValueError):
        read_npm_inventory(tmp_path, omit_dev=True)



def test_npm_scan_exports_findings_without_claiming_js_reachability(tmp_path, monkeypatch):
    from scripts.npm_inventory import main
    from scripts import composition_analysis
    manifests(tmp_path, {"node_modules/foo": {"version": "1.0.0"}})
    monkeypatch.setattr(composition_analysis, "check_vulnerabilities_from_sbom", lambda *args: [
        {"purl": "pkg:npm/foo@1.0.0", "package": "foo", "installed_version": "1.0.0", "cve": "CVE-X", "component_refs": ["npm-instance:node_modules/foo"]}])
    output = tmp_path / "report"
    assert main(["--input", str(tmp_path), "--output", str(output), "--scan"]) == 3
    finding = json.loads((output / "vulnerabilities.json").read_text(encoding="utf-8"))[0]
    assert finding["reachability"]["status"] == "unsupported"
    assert finding["reachability"]["is_reachable"] is None
    assert (output / "vulnerabilities.sarif").is_file()
    assert "SBOM instances: npm-instance:node_modules/foo" in (output / "report.html").read_text(encoding="utf-8")


@pytest.mark.parametrize("options,parent_flags", [
    ({"target_os": "linux"}, {"os": ["darwin"], "optional": True}),
    ({"omit_dev": True}, {"dev": True}),
    ({"omit_optional": True}, {"optional": True}),
])
def test_omitted_parent_excludes_descendant_installations(tmp_path, options, parent_flags):
    manifests(tmp_path, {
        "node_modules/parent": {"version": "1.0.0", **parent_flags},
        "node_modules/parent/node_modules/leaf": {"version": "2.0.0", "inBundle": True},
        "node_modules/parent/node_modules/leaf/node_modules/deep": {"version": "3.0.0"},
        "node_modules/parent-extra": {"version": "1.0.0"},
        "node_modules/leaf": {"version": "2.0.0"},
    })
    inventory = read_npm_inventory(tmp_path, **options)
    assert {i["location"] for i in inventory["instances"]} == {"node_modules/parent-extra", "node_modules/leaf"}
    assert len(inventory["omitted"]) == 3
    assert sum("ancestor_omitted" in i["reasons"] for i in inventory["omitted"]) == 2
