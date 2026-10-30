import hashlib
import json
from pathlib import Path

import pytest

from scripts import ai_review as ai
from scripts import review_sources as sources
from scripts.python_graph import capture_sources


def fixture(tmp_path, code="def danger():\n    return 1\n", *, name="demo.py"):
    root = tmp_path / "app"
    root.mkdir()
    file = root / name
    file.write_bytes(code.encode("utf-8"))
    snapshot = capture_sources(root)
    finding = {"purl": "pkg:pypi/demo@1", "cve": "CVE-TEST", "reachability": {
        "status": "unknown", "is_reachable": None,
        "mappings": [{"symbol": "demo.danger", "file": str(file), "line": 1}],
        "source_snapshot": {"inputs": [{"root": str(root), "sha256": snapshot.digest, "include_tests": False}]}}}
    return root, file, finding


def test_exact_function_bytes_and_paths_are_auditable(tmp_path):
    root, file, finding = fixture(tmp_path)
    collected = sources.ReviewSources([root]).collect(finding)
    assert not collected["issues"]
    fragment = collected["excerpts"][0]
    assert fragment["code"] == "def danger():\n    return 1\n"
    assert fragment["whole_definition"] and fragment["excerpt_start_line"] == 1
    assert fragment["excerpt_end_line"] == 2
    assert fragment["file_sha256"] == hashlib.sha256(file.read_bytes()).hexdigest()
    assert fragment["excerpt_utf8_sha256"] == hashlib.sha256(fragment["code"].encode()).hexdigest()
    assert fragment["provenance"] == "matches_scan_snapshot"
    assert str(root) not in json.dumps(collected)
    assert fragment["relative_path"] == "demo.py"


def test_changed_source_and_missing_snapshot_are_omitted(tmp_path):
    root, file, finding = fixture(tmp_path)
    file.write_text("def danger(): return 2\n", encoding="utf-8")
    result = sources.ReviewSources([root]).collect(finding)
    assert not result["excerpts"]
    assert result["issues"][0]["reason"] == "source_snapshot_changed_since_scan"
    finding["reachability"].pop("source_snapshot")
    result = sources.ReviewSources([root]).collect(finding)
    assert result["issues"][0]["reason"] == "scan_snapshot_missing_for_root"


def test_unselected_root_is_not_read(tmp_path, monkeypatch):
    root, file, finding = fixture(tmp_path)
    allowed = tmp_path / "other"
    allowed.mkdir()
    def forbidden(*args): raise AssertionError("Unselected root must never be captured")
    monkeypatch.setattr(sources, "_capture", forbidden)
    result = sources.ReviewSources([allowed]).collect(finding)
    assert result["issues"][0]["reason"] == "source_root_not_selected"
    assert not result["excerpts"]


def test_symbol_identity_and_reference_line_must_match(tmp_path):
    root, file, finding = fixture(tmp_path)
    finding["reachability"]["mappings"][0]["symbol"] = "other.danger"
    assert sources.ReviewSources([root]).collect(finding)["issues"][0]["reason"] == "source_symbol_not_unique"
    finding["reachability"]["mappings"][0].update(symbol="demo.danger", line=100)
    assert sources.ReviewSources([root]).collect(finding)["issues"][0]["reason"] == "source_line_out_of_range"


def test_duplicate_definitions_never_borrow_identity(tmp_path):
    root, file, finding = fixture(tmp_path, "def danger(): return 1\ndef danger(): return 2\n")
    result = sources.ReviewSources([root]).collect(finding)
    assert not result["excerpts"] and result["issues"][0]["reason"] == "source_symbol_not_unique"


def test_large_function_excerpt_keeps_real_line_range_and_hash(tmp_path):
    text = "def danger():\n" + "".join(f"    value_{i} = {i}\n" for i in range(100)) + "    return value_99\n"
    root, file, finding = fixture(tmp_path, text)
    finding["reachability"]["mappings"][0]["line"] = 70
    value = sources.ReviewSources([root]).collect(finding)["excerpts"][0]
    assert not value["whole_definition"]
    assert value["excerpt_start_line"] <= 70 <= value["excerpt_end_line"]
    assert len(value["code"]) <= sources.MAX_EXCERPT_CHARS
    assert value["excerpt_end_line"] - value["excerpt_start_line"] + 1 <= sources.MAX_EXCERPT_LINES
    assert value["code"] == "".join(text.splitlines(keepends=True)[value["excerpt_start_line"] - 1:value["excerpt_end_line"]])


def test_encoded_source_and_decorators_preserve_text(tmp_path):
    root, file, finding = fixture(tmp_path)
    raw = b'# coding: latin-1\n@decorate\ndef danger():\n    return "caf\xe9"\n'
    file.write_bytes(raw)
    finding["reachability"]["mappings"][0]["line"] = 3
    finding["reachability"]["source_snapshot"]["inputs"][0]["sha256"] = capture_sources(root).digest
    value = sources.ReviewSources([root]).collect(finding)["excerpts"][0]
    assert value["excerpt_start_line"] == 2 and value["code"].startswith("@decorate\n")
    assert "caf\u00e9" in value["code"] and value["encoding"] == "iso-8859-1"
    assert value["file_sha256"] == hashlib.sha256(raw).hexdigest()


def test_captured_bytes_reused_within_batch_but_new_batch_checks_edits(tmp_path):
    root, file, finding = fixture(tmp_path)
    context = sources.ReviewSources([root])
    before = context.collect(finding)["excerpts"][0]
    file.write_text("def danger(): return 3\n", encoding="utf-8")
    assert context.collect(finding)["excerpts"][0] == before
    assert sources.ReviewSources([root]).collect(finding)["issues"][0]["reason"] == "source_snapshot_changed_since_scan"


def test_root_byte_limit_and_parse_error_remain_issues(tmp_path, monkeypatch):
    root, file, finding = fixture(tmp_path)
    monkeypatch.setattr(sources, "MAX_ROOT_BYTES", 1)
    result = sources.ReviewSources([root]).collect(finding)
    assert not result["excerpts"] and result["issues"][0]["reason"] == "source_snapshot_byte_limit"
    monkeypatch.setattr(sources, "MAX_ROOT_BYTES", 10000)
    file.write_text("def broken(\n", encoding="utf-8")
    finding["reachability"]["source_snapshot"]["inputs"][0]["sha256"] = capture_sources(root).digest
    assert sources.ReviewSources([root]).collect(finding)["issues"][0]["reason"] == "source_parse_failed"


def test_module_call_excerpt_is_not_a_function_body(tmp_path):
    root, file, finding = fixture(tmp_path, "danger()\n\ndef danger():\n    return 1\n")
    finding["reachability"]["mappings"] = []
    finding["reachability"]["paths"] = [[{"symbol": "demo.<module>", "file": str(file), "line": 1, "call_line": 1}]]
    result = sources.ReviewSources([root]).collect(finding)
    assert result["excerpts"][0]["kind"] == "module_line_context"
    finding["reachability"]["paths"][0][0]["call_line"] = 4
    assert sources.ReviewSources([root]).collect(finding)["issues"][0]["reason"] == "module_reference_inside_function"


def test_dry_run_contains_verified_code_and_requires_opt_in(tmp_path, monkeypatch):
    root, file, finding = fixture(tmp_path)
    input_file, output = tmp_path / "scan.json", tmp_path / "preview.json"
    input_file.write_text(json.dumps([finding]), encoding="utf-8")
    def forbidden(*a, **k): raise AssertionError("Preview cannot call providers")
    monkeypatch.setattr(ai.requests, "post", forbidden)
    args = ["--input", str(input_file), "--output", str(output), "--provider", "openai", "--model", "model", "--dry-run", "--source-root", str(root)]
    with pytest.raises(SystemExit): ai.main(args)
    assert ai.main(args + ["--include-code"]) == 0
    request = json.loads(output.read_text(encoding="utf-8"))["requests"][0]["body"]
    packet = json.loads(request["input"])
    source = next(e for e in packet["evidence"] if e["kind"] == "source_excerpt")
    assert source["value"]["code"] == "def danger():\n    return 1\n"
    assert source["value"]["file_sha256"] == hashlib.sha256(file.read_bytes()).hexdigest()
    assert str(root) not in json.dumps(request)


def test_excerpts_do_not_execute_target_code(tmp_path):
    marker = tmp_path / "MUST_NOT_EXIST"
    code = "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\ndef danger(): return 1\n"
    root, file, finding = fixture(tmp_path, code)
    finding["reachability"]["mappings"][0]["line"] = 3
    assert sources.ReviewSources([root]).collect(finding)["excerpts"]
    assert not marker.exists()


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_original_line_endings_are_preserved_in_hash_and_excerpt(tmp_path, ending):
    code = "def danger():" + ending + "    return 1" + ending
    root, file, finding = fixture(tmp_path, code)
    value = sources.ReviewSources([root]).collect(finding)["excerpts"][0]
    assert value["code"] == code
    assert value["excerpt_utf8_sha256"] == hashlib.sha256(code.encode()).hexdigest()


def test_outside_files_are_rejected_before_opening(tmp_path, monkeypatch):
    root, file, finding = fixture(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"PRIVATE_DATA")
    monkeypatch.setattr(sources, "python_files", lambda *a: iter([outside]))
    result = sources.ReviewSources([root]).collect(finding)
    assert not result["excerpts"]
    assert result["issues"][0]["reason"] == "source_path_outside_allowed_root"
    assert "PRIVATE_DATA" not in json.dumps(result)


def test_batch_bytes_have_bounds(tmp_path, monkeypatch):
    root, file, finding = fixture(tmp_path)
    monkeypatch.setattr(sources, "MAX_BATCH_BYTES", 1)
    result = sources.ReviewSources([root]).collect(finding)
    assert result["issues"][0]["reason"] == "source_batch_byte_limit"


def test_input_paths_with_traversal_do_not_read_arbitrary_files(tmp_path):
    root, file, finding = fixture(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"PRIVATE_DATA")
    finding["reachability"]["mappings"][0]["file"] = str(root / ".." / "outside.py")
    result = sources.ReviewSources([root]).collect(finding)
    assert not result["excerpts"]
    assert "PRIVATE_DATA" not in json.dumps(result)


def test_single_long_line_is_omitted_instead_of_inaccurate_line_spans(tmp_path):
    root, file, finding = fixture(tmp_path, "def danger(): return " + repr("x" * 4000) + "\n")
    result = sources.ReviewSources([root]).collect(finding)
    assert not result["excerpts"] and result["issues"][0]["reason"] == "source_line_exceeds_excerpt_limit"


def test_repeated_patch_targets_do_not_evict_caller_context(tmp_path):
    root, file, finding = fixture(tmp_path, "def danger():\n    return 1\n\ndef caller():\n    danger()\n")
    finding["reachability"]["mappings"] *= 4
    finding["reachability"]["paths"] = [[
        {"symbol": "demo.caller", "file": str(file), "line": 4, "call_line": 5},
        {"symbol": "demo.danger", "file": str(file), "line": 1}]]
    values = sources.ReviewSources([root]).collect(finding)["excerpts"]
    assert len(values) == 2
    assert {v["symbol"] for v in values} == {"demo.danger", "demo.caller"}
    assert values[0]["roles"] == ["patch_target", "call_path"]


def test_class_definition_is_labeled_separately(tmp_path):
    root, file, finding = fixture(tmp_path, "@decorate\nclass Example:\n    def danger(self): return 1\n")
    finding["reachability"]["mappings"] = [{"symbol": "demo.Example", "file": str(file), "line": 2}]
    value = sources.ReviewSources([root]).collect(finding)["excerpts"][0]
    assert value["kind"] == "python_class" and value["whole_definition"]
    assert value["code"].startswith("@decorate\nclass Example")
    finding["reachability"]["mappings"][0].update(symbol="demo.Example.danger", line=3)
    method = sources.ReviewSources([root]).collect(finding)["excerpts"][0]
    assert method["kind"] == "python_function"


def test_speculative_paths_and_unresolved_callers_keep_their_roles(tmp_path):
    root, file, finding = fixture(tmp_path)
    finding["reachability"]["mappings"] = []
    finding["reachability"]["speculative_paths"] = [[{"symbol": "demo.danger", "file": str(file), "line": 1}]]
    finding["reachability"]["diagnostics"] = [{"caller": "demo.danger", "file": str(file), "line": 2}]
    value = sources.ReviewSources([root]).collect(finding)["excerpts"][0]
    assert value["roles"] == ["speculative_path", "unresolved_caller"]
    assert value["reference_lines"] == [1, 2]


@pytest.mark.parametrize("provider", ai.PROVIDERS)
def test_provider_request_contains_same_verified_excerpts_as_preview(tmp_path, monkeypatch, provider):
    root, file, finding = fixture(tmp_path)
    context = sources.ReviewSources([root])
    packet = ai.evidence_packet(finding, include_code=True, source_context=context)
    calls = []
    class Response:
        status_code = 200
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def iter_content(self, size):
            value = {"assessment": "supports_static", "summary": "Evidence inspected", "reasoning": "Selected evidence supports the supplied conclusion", "evidence_ids": [next(e["id"] for e in packet["evidence"] if e["kind"] == "source_excerpt")], "next_steps": []}
            content = json.dumps(value)
            if provider == "openai": body = {"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": content}]}]}
            elif provider == "deepseek": body = {"choices": [{"finish_reason": "stop", "message": {"content": content}}]}
            else: body = {"stop_reason": "end_turn", "content": [{"type": "text", "text": content}]}
            yield json.dumps(body).encode()
    def post(url, **kwargs):
        calls.append(kwargs["json"])
        return Response()
    monkeypatch.setattr(ai.requests, "post", post)
    review = ai.review_finding(finding, provider, "model", api_key="key", include_code=True, source_context=context)
    assert calls == [ai.request_body(provider, "model", packet, 1600)]
    assert review["status"] == "completed" and review["evidence_packet"] == packet
    assert review["prompt_version"] == "review-v2"
    assert finding["reachability"]["status"] == "unknown"


def test_missing_snapshot_does_not_capture_even_selected_root(tmp_path, monkeypatch):
    root, file, finding = fixture(tmp_path)
    finding["reachability"].pop("source_snapshot")
    def forbidden(*a): raise AssertionError("Missing snapshot must prevent file reads")
    monkeypatch.setattr(sources, "_capture", forbidden)
    result = sources.ReviewSources([root]).collect(finding)
    assert result["issues"][0]["reason"] == "scan_snapshot_missing_for_root"


def test_readable_html_source_context_is_escaped_and_separate(tmp_path):
    from scripts.html_report import generate_html_report
    root, file, finding = fixture(tmp_path, 'def danger():\n    return "<script>bad()</script>"\n')
    packet = ai.evidence_packet(finding, include_code=True, source_context=sources.ReviewSources([root]))
    finding["reachability"]["mappings"] = []
    finding["ai_reviews"] = [{"provider": "openai", "model": "mock", "status": "completed", "evidence_packet": packet,
                              "assessment": "insufficient_evidence", "summary": "Needs context", "reasoning": "Inspect", "evidence_ids": ["e3"], "next_steps": []}]
    sbom, report, output = (tmp_path / p for p in ('sbom.json', 'report.json', 'report.html'))
    sbom.write_text('{"components":[]}', encoding='utf-8')
    report.write_text(json.dumps([finding]), encoding='utf-8')
    generate_html_report('example', sbom, report, output)
    html = output.read_text(encoding='utf-8')
    assert 'Source e3: demo.danger' in html and 'Whole definition' in html
    assert '<script>bad()' not in html and '&lt;script&gt;bad()' in html
    assert 'File SHA256:' in html


def test_excerpt_limit_is_explicit_after_deduplication(tmp_path, monkeypatch):
    code = "".join(f"def function_{i}(): pass\n" for i in range(12))
    root, file, finding = fixture(tmp_path, code)
    finding["reachability"]["mappings"] = []
    finding["reachability"]["paths"] = [[{"symbol": f"demo.function_{i}", "file": str(file), "line": i + 1} for i in range(12)]]
    monkeypatch.setattr(sources, "MAX_EXCERPTS", 2)
    value = sources.ReviewSources([root]).collect(finding)
    assert len(value["excerpts"]) == 2
    assert value["issues"][-1]["reason"] == "source_excerpt_count_limit"


def test_test_scope_must_match_scan_snapshot(tmp_path):
    root, file, finding = fixture(tmp_path)
    (root / "test_hidden.py").write_bytes(b"def test_hidden(): pass\n")
    # The scanner's excluded tests must not change the default snapshot identity.
    value = sources.ReviewSources([root]).collect(finding)
    assert value["excerpts"] and not value["issues"]
    finding["reachability"]["source_snapshot"]["inputs"][0]["include_tests"] = True
    value = sources.ReviewSources([root]).collect(finding)
    assert value["issues"][0]["reason"] == "source_snapshot_changed_since_scan"


def test_scan_wide_diagnostic_is_not_presented_as_a_finding_path(tmp_path):
    root, file, finding = fixture(tmp_path, "def danger(): return 1\ndef unrelated(): return 2\n")
    finding["reachability"]["diagnostics"] = [{"caller": "demo.unrelated", "file": str(file), "line": 2}]
    context = sources.ReviewSources([root])
    diagnostic = context.collect(finding)["excerpts"][-1]
    assert diagnostic["evidence_scope"] == "scan_wide_diagnostic"
    finding["reachability"]["paths"] = [[{"symbol": "demo.danger", "file": str(file), "line": 1}]]
    assert all(e["symbol"] != "demo.unrelated" for e in context.collect(finding)["excerpts"])


@pytest.mark.parametrize("separator", ["\u2028", "\u0085", "\f"])
def test_non_newline_separators_inside_literals_do_not_change_ast_line_ranges(tmp_path, separator):
    text = 'def danger():\n    return "before' + separator + 'after"\n'
    root, file, finding = fixture(tmp_path, text)
    finding["reachability"]["mappings"][0]["line"] = 2
    value = sources.ReviewSources([root]).collect(finding)["excerpts"][0]
    assert value["code"] == text and value["whole_definition"]
    assert value["excerpt_start_line"] == 1 and value["excerpt_end_line"] == 2


def test_dry_run_html_is_labeled_preview_and_never_calls_provider(tmp_path, monkeypatch):
    root, file, finding = fixture(tmp_path)
    input_file, output, sbom = (tmp_path / p for p in ('scan.json', 'preview.json', 'sbom.json'))
    input_file.write_text(json.dumps([finding]), encoding='utf-8')
    sbom.write_text('{"components":[]}', encoding='utf-8')
    def forbidden(*a, **k): raise AssertionError("Dry-run must not call provider")
    monkeypatch.setattr(ai.requests, "post", forbidden)
    # Complete the static mapping fields consumed by existing report rendering.
    finding['reachability']['mappings'][0]['method'] = 'fixture'
    input_file.write_text(json.dumps([finding]), encoding='utf-8')
    assert ai.main(['--input', str(input_file), '--output', str(output), '--provider', 'claude', '--model', 'model',
                    '--include-code', '--source-root', str(root), '--dry-run', '--sbom', str(sbom)]) == 0
    requests = json.loads(output.read_text(encoding='utf-8'))
    assert len(requests['requests']) == 1
    html = output.with_suffix('.html').read_text(encoding='utf-8')
    assert 'AI request preview' in html and 'No API request has been sent' in html
    assert 'def danger():' in html and 'Whole definition' in html
    assert 'unknown</span>' in html and 'supports_static' not in html
    assert 'ai_reviews' not in json.loads(input_file.read_text(encoding='utf-8'))[0]


def test_reference_selection_omissions_are_explicit(tmp_path):
    root, file, finding = fixture(tmp_path, "".join(f"def function_{i}(): pass\n" for i in range(6)))
    finding['reachability']['mappings'] = [{'symbol': f'demo.function_{i}', 'file': str(file), 'line': i + 1} for i in range(6)]
    result = sources.ReviewSources([root]).collect(finding)
    assert len(result['excerpts']) == 4
    assert result['issues'][0] == {'reason': 'source_reference_selection_limit', 'kind': 'mapping_targets', 'total': 6, 'selected': 4}


def test_many_hunks_on_one_function_do_not_hide_other_targets(tmp_path):
    root, file, finding = fixture(tmp_path, "def danger(): return 1\ndef other(): return 2\n")
    finding['reachability']['mappings'] *= 12
    finding['reachability']['mappings'].append({'symbol': 'demo.other', 'file': str(file), 'line': 2})
    result = sources.ReviewSources([root]).collect(finding)
    assert {e['symbol'] for e in result['excerpts']} == {'demo.danger', 'demo.other'}
    assert not result['issues']
