import pytest
from scripts import fix_references as resolver
from scripts.analysis_session import AnalysisSession

GHSA = "GHSA-j8r2-6x86-q33q"
ADVISORY = "https://github.com/advisories/" + GHSA
PR = "https://github.com/example/lib/pull/12"
COMMIT = "https://github.com/example/lib/commit/" + "a" * 40


def setup(monkeypatch, objects):
    calls = []
    def read(url):
        calls.append(url)
        value = objects[url]
        if isinstance(value, Exception): raise value
        return value, "body-digest"
    monkeypatch.setattr(resolver, "_read_json", read)
    return calls


def test_direct_commit_avoids_api_calls(monkeypatch):
    calls = setup(monkeypatch, {})
    links, evidence = resolver.resolve_fix_references([COMMIT, ADVISORY])
    assert links == [COMMIT] and calls == []
    assert evidence["provenance"][0]["basis"] == "direct_reference"


def test_advisory_references_resolve_commit_and_keep_provenance(monkeypatch):
    calls = setup(monkeypatch, {"https://api.github.com/advisories/" + GHSA:
        {"ghsa_id": GHSA, "references": [COMMIT], "description": ""}})
    links, evidence = resolver.resolve_fix_references([ADVISORY])
    assert links == [COMMIT] and len(calls) == 1
    assert evidence["provenance"][0]["chain"][0]["response_sha256"] == "body-digest"


def test_advisory_description_to_merged_pull_request(monkeypatch):
    setup(monkeypatch, {"https://api.github.com/advisories/" + GHSA:
        {"ghsa_id": GHSA, "references": [], "description": "Fixed in [PR](" + PR + ")."},
        "https://api.github.com/repos/example/lib/pulls/12":
        {"number": 12, "base": {"repo": {"full_name": "example/lib"}}, "merged": True, "merge_commit_sha": "a" * 40}})
    links, evidence = resolver.resolve_fix_references([ADVISORY])
    assert links == [COMMIT]
    assert evidence["provenance"][0]["basis"] == "merged_pull_request"
    assert len(evidence["provenance"][0]["chain"]) == 2


@pytest.mark.parametrize("merged, sha", [(False, "a" * 40), (None, "a" * 40), (True, "branch-name")])
def test_unmerged_or_unresolved_pr_does_not_supply_fix(monkeypatch, merged, sha):
    setup(monkeypatch, {"https://api.github.com/repos/example/lib/pulls/12":
        {"number": 12, "base": {"repo": {"full_name": "example/lib"}}, "merged": merged, "merge_commit_sha": sha}})
    links, evidence = resolver.resolve_fix_references([PR])
    assert links == []
    assert evidence["issues"][0]["reason"] == "pull_request_not_merged"


@pytest.mark.parametrize("payload", [
    {"ghsa_id": "GHSA-wrong-xxxx-xxxx", "references": [COMMIT]},
    {"ghsa_id": GHSA, "withdrawn_at": "2025-01-01", "references": [COMMIT]},
    ValueError("rate limit"),
])
def test_untrusted_identity_withdrawal_and_errors_do_not_supply_fix(monkeypatch, payload):
    setup(monkeypatch, {"https://api.github.com/advisories/" + GHSA: payload})
    links, evidence = resolver.resolve_fix_references([ADVISORY])
    assert links == [] and evidence["issues"]


def test_duplicate_advisory_urls_and_session_reuse(monkeypatch):
    calls = setup(monkeypatch, {"https://api.github.com/advisories/" + GHSA:
        {"ghsa_id": GHSA, "references": [COMMIT]}})
    session = AnalysisSession()
    for _ in range(2):
        links, _ = resolver.resolve_fix_references([ADVISORY, "https://github.com/example/lib/security/advisories/" + GHSA], session=session)
        assert links == [COMMIT]
    assert len(calls) == 1


def test_unknown_hosts_and_issue_urls_are_not_fetched(monkeypatch):
    calls = setup(monkeypatch, {})
    links, evidence = resolver.resolve_fix_references(["https://github.com.evil.invalid/advisories/" + GHSA,
        "https://github.com/example/lib/issues/12", "http://github.com/advisories/" + GHSA])
    assert links == [] and calls == []


def test_advisory_only_reference_reaches_patch_mapping(tmp_path, monkeypatch):
    from scripts.reachability import check_reachability
    setup(monkeypatch, {"https://api.github.com/advisories/" + GHSA:
        {"ghsa_id": GHSA, "references": [COMMIT]}})
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "main.py").write_text("from lib import danger\ndanger()\n", encoding="utf-8")
    (lib / "lib.py").write_text("def danger():\n    return 1\n", encoding="utf-8")
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n")
    report = check_reachability([ADVISORY], project_dir=app, library_source=lib, purl="pkg:pypi/lib@1")
    assert report["status"] == "reachable"
    assert report["mappings"][0]["reference"] == COMMIT
    assert report["reference_discovery"]["provenance"][0]["basis"] == "advisory_reference"


def test_description_commit_at_sentence_end(monkeypatch):
    setup(monkeypatch, {"https://api.github.com/advisories/" + GHSA:
        {"ghsa_id": GHSA, "references": [], "description": "Fixed in " + COMMIT + "."}})
    links, _ = resolver.resolve_fix_references([ADVISORY])
    assert links == [COMMIT]


def test_partial_discovery_failure_blocks_negative_finding(tmp_path, monkeypatch):
    from scripts.reachability import check_reachability
    setup(monkeypatch, {"https://api.github.com/advisories/" + GHSA:
        {"ghsa_id": GHSA, "references": [COMMIT, PR]},
        "https://api.github.com/repos/example/lib/pulls/12": ValueError("unavailable")})
    app, lib = tmp_path / "app", tmp_path / "lib"
    app.mkdir(); lib.mkdir()
    (app / "main.py").write_text("pass\n", encoding="utf-8")
    (lib / "lib.py").write_text("def danger():\n    return 1\n", encoding="utf-8")
    monkeypatch.setattr("scripts.reachability.get_diff", lambda _: "diff --git a/lib.py b/lib.py\n--- a/lib.py\n+++ b/lib.py\n@@ -1,2 +1,2 @@\n def danger():\n-    return 1\n+    return 2\n")
    report = check_reachability([ADVISORY], project_dir=app, library_source=lib, purl="pkg:pypi/lib@1")
    assert report["status"] == "unknown"
    assert "reference_resolution_failed" in report["reasons"]
    assert report["references"][COMMIT]["status"] == "unknown"
