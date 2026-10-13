import json
import pytest
from scripts.inventory import pinned_requirements, target_environment, annotate_sbom


def test_marker_selects_exactly_one_version_and_preserves_provenance(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("cryptography==3.3.2; platform_machine == 'armv7l'\ncryptography==39.0.1; platform_machine != 'armv7l'\n", encoding="utf-8")
    text, meta = pinned_requirements(req, environment={"platform_machine": "x86_64"})
    assert text == "cryptography==39.0.1\n"
    assert len(meta["skipped"]) == 1
    assert meta["selected"][0]["declarations"][0]["line"] == 2
    other, _ = pinned_requirements(req, environment={"platform_machine": "armv7l"})
    assert other == "cryptography==3.3.2\n"
    text, meta = pinned_requirements(req, all_environments=True)
    assert len(meta["selected"]) == 2 and meta["all_environments"]


def test_includes_constraints_and_hash_continuation(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r prod.txt\n-c pins.txt\n", encoding="utf-8")
    (tmp_path / "prod.txt").write_text("requests[socks]>=2.28 # explanation\n", encoding="utf-8")
    (tmp_path / "pins.txt").write_text("requests==2.31.0 \\\n --hash=sha256:abc\n", encoding="utf-8")
    text, meta = pinned_requirements(tmp_path / "requirements.txt")
    assert text == "requests[socks]==2.31.0\n"
    assert meta["selected"][0]["extras"] == ["socks"]


def test_conflicting_active_versions_fail(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("demo==1\ndemo==2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Multiple active"):
        pinned_requirements(req)


@pytest.mark.parametrize("text", ["demo>=1", "demo @ https://example.invalid/package.whl", "-e .", "demo==1.*"])
def test_unresolved_or_external_inventory_is_not_guessed(tmp_path, text):
    req = tmp_path / "requirements.txt"; req.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError): pinned_requirements(req)


def test_conflicting_constraints_fail(tmp_path):
    (tmp_path / "r.txt").write_text("demo==1\n-c c.txt\n", encoding="utf-8")
    (tmp_path / "c.txt").write_text("demo>=2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Conflicting"):
        pinned_requirements(tmp_path / "r.txt")


def test_include_cycle_fails(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("-r a.txt\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Cyclic"):
        pinned_requirements(tmp_path / "a.txt")


def test_target_python_version_consistency():
    assert target_environment({"python_full_version": "3.11.9"})["python_version"] == "3.11"
    with pytest.raises(ValueError): target_environment({"python_version": "3.11"})
    with pytest.raises(ValueError): target_environment({"python_version": "3.10", "python_full_version": "3.11.9"})
    with pytest.raises(ValueError): target_environment({"unknown": "yes"})


def test_scope_is_declared_not_inferred_from_package_name(tmp_path):
    req = tmp_path / "requirements.txt"; req.write_text("pytest==7.2.1\n", encoding="utf-8")
    _, meta = pinned_requirements(req)
    bom = annotate_sbom({"components": [{"name": "pytest", "version": "7.2.1"}]}, meta)
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["depreach:dependency-scope"] == "declared"
    assert json.loads(props["depreach:declarations"])[0]["file"] == str(req)
