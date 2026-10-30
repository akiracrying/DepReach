import copy
import json

import pytest
import requests

from scripts import ai_review as ai
from scripts.html_report import generate_html_report
from scripts.sarif_report import vulns_to_sarif


def finding():
    return {"cve": "CVE-TEST", "package": "demo", "purl": "pkg:pypi/demo@1",
            "reachability": {"status": "unknown", "is_reachable": None, "reasons": ["unresolved_call"],
                "patch_evidence": [{"reference": "https://example.org/fix", "outcome": "mapped", "file": "demo.py", "old_start": 1,
                                    "old_context": "PRIVATE_CODE", "changes": [{"kind": "added", "text": "NEW_CODE"}]}]}}


def answer(**overrides):
    return {"assessment": "insufficient_evidence", "summary": "Caller needs review",
            "reasoning": "An unresolved call prevents a conclusion.", "evidence_ids": ["e1"],
            "next_steps": ["Inspect caller"], **overrides}


def payload(provider, value=None):
    content = json.dumps(answer() if value is None else value)
    if provider == "openai":
        return {"id": "response-1", "status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": content}]}], "usage": {"input_tokens": 50}}
    if provider == "deepseek":
        return {"choices": [{"finish_reason": "stop", "message": {"content": content}}], "usage": {"prompt_tokens": 50}}
    return {"content": [{"type": "text", "text": content}], "stop_reason": "end_turn", "usage": {"input_tokens": 50}}


class Response:
    def __init__(self, value, status=200):
        self.raw = json.dumps(value).encode()
        self.status_code = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size):
        for i in range(0, len(self.raw), size):
            yield self.raw[i:i + size]


@pytest.mark.parametrize("provider", ai.PROVIDERS)
def test_provider_contracts_and_static_result_preserved(monkeypatch, provider):
    original = finding()
    before = copy.deepcopy(original)
    calls = []
    def post(url, **kwargs):
        calls.append((url, kwargs))
        return Response(payload(provider))
    monkeypatch.setattr(ai.requests, "post", post)
    result = ai.review_finding(original, provider, "explicit-model", api_key="PRIVATE_KEY")
    assert original == before
    assert result["status"] == "completed" and result["static_result_unchanged"]
    assert result["evidence_packet"]["evidence"][0]["id"] == "e1"
    assert "PRIVATE_KEY" not in json.dumps(result)
    url, request = calls[0]
    assert url == ai.PROVIDERS[provider][0]
    assert request["allow_redirects"] is False and request["stream"] is True
    assert request["timeout"] == (10, 60)
    body = request["json"]
    assert body["model"] == "explicit-model"
    if provider == "openai":
        assert body["store"] is False and body["text"]["format"]["strict"]
        assert body["max_output_tokens"] == 1600
    elif provider == "deepseek":
        assert body["response_format"] == {"type": "json_object"}
    else:
        assert request["headers"]["x-api-key"] == "PRIVATE_KEY"
        assert request["headers"]["anthropic-version"] == "2023-06-01"


def test_code_opt_in_and_bounded_evidence():
    value = finding()
    value["reachability"]["paths"] = [[{"symbol": "caller", "file": "C:/private/app.py", "source": "HIDDEN_SOURCE", "api_key": "HIDDEN_KEY"}]]
    value["description"] = "a" * 100000
    default = json.dumps(ai.evidence_packet(value))
    assert all(secret not in default for secret in ("PRIVATE_CODE", "NEW_CODE", "HIDDEN_SOURCE", "HIDDEN_KEY", "C:/private"))
    assert len(default.encode()) < 48000
    with_code = json.dumps(ai.evidence_packet(value, include_code=True))
    assert "PRIVATE_CODE" in with_code and "NEW_CODE" in with_code


@pytest.mark.parametrize("status", [301, 401, 429, 500])
def test_http_errors_never_store_response_bodies_or_retry(monkeypatch, status):
    calls = []
    def post(*args, **kwargs):
        calls.append(1)
        return Response({"error": "PRIVATE_KEY"}, status)
    monkeypatch.setattr(ai.requests, "post", post)
    result = ai.review_finding(finding(), "openai", "model", api_key="PRIVATE_KEY")
    assert result["error"] == "http_" + str(status)
    assert len(calls) == 1 and "PRIVATE_KEY" not in json.dumps(result)


@pytest.mark.parametrize("bad, error", [
    (answer(evidence_ids=["fabricated"]), "unknown_evidence_id"),
    (answer(assessment="supports_static", evidence_ids=[]), "uncited_review_conclusion"),
    (answer(assessment="safe"), "invalid_review_assessment"),
    (answer(status="no_path_found"), "invalid_review_schema"),
    (answer(next_steps="run code"), "invalid_review_list"),
])
def test_invalid_reviews_remain_errors(monkeypatch, bad, error):
    monkeypatch.setattr(ai.requests, "post", lambda *a, **k: Response(payload("openai", bad)))
    result = ai.review_finding(finding(), "openai", "model", api_key="key")
    assert result["status"] == "error" and result["error"] == error


@pytest.mark.parametrize("provider", ai.PROVIDERS)
def test_truncated_generations_are_rejected(monkeypatch, provider):
    value = payload(provider)
    if provider == "openai": value["status"] = "incomplete"
    elif provider == "deepseek": value["choices"][0]["finish_reason"] = "length"
    else: value["stop_reason"] = "max_tokens"
    monkeypatch.setattr(ai.requests, "post", lambda *a, **k: Response(value))
    assert ai.review_finding(finding(), provider, "model", api_key="key")["error"] == "incomplete_provider_response"


def test_response_size_limit_and_transport_error(monkeypatch):
    monkeypatch.setattr(ai, "MAX_RESPONSE_BYTES", 2)
    monkeypatch.setattr(ai.requests, "post", lambda *a, **k: Response(payload("openai")))
    assert ai.review_finding(finding(), "openai", "model", api_key="key")["error"] == "provider_response_too_large"
    def fail(*a, **k): raise requests.Timeout("PRIVATE_KEY")
    monkeypatch.setattr(ai.requests, "post", fail)
    result = ai.review_finding(finding(), "openai", "model", api_key="key")
    assert result["error"] == "provider_transport_error" and "PRIVATE_KEY" not in json.dumps(result)


def test_dry_run_is_exact_and_never_calls_network_or_needs_key(tmp_path, monkeypatch):
    source, output = tmp_path / "input.json", tmp_path / "preview.json"
    source.write_text(json.dumps([finding(), finding()]), encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    def forbidden(*a, **k): raise AssertionError("Network must not run")
    monkeypatch.setattr(ai.requests, "post", forbidden)
    assert ai.main(["--input", str(source), "--output", str(output), "--provider", "openai", "--model", "chosen", "--limit", "1", "--dry-run"]) == 0
    preview = json.loads(output.read_text(encoding="utf-8"))
    assert len(preview["requests"]) == 1
    body = preview["requests"][0]["body"]
    assert body == ai.request_body("openai", "chosen", ai.evidence_packet(finding()), 1600)
    assert "ai_reviews" not in json.loads(source.read_text(encoding="utf-8"))[0]
    with pytest.raises(SystemExit):
        ai.main(["--input", str(source), "--output", str(source), "--provider", "openai", "--model", "chosen"])


def test_cli_review_selection_and_report_surfaces(tmp_path, monkeypatch):
    f = finding()
    f["description"] = "A finding"
    source, output = tmp_path / "input.json", tmp_path / "reviewed.json"
    sbom = tmp_path / "sbom.json"
    source.write_text(json.dumps([f, {**f, "cve": "OTHER"}]), encoding="utf-8")
    sbom.write_text('{"components":[]}', encoding="utf-8")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "key")
    malicious = answer(summary="</script><img src=x onerror=alert(1)>")
    monkeypatch.setattr(ai.requests, "post", lambda *a, **k: Response(payload("deepseek", malicious)))
    assert ai.main(["--input", str(source), "--output", str(output), "--provider", "deepseek", "--model", "chosen", "--finding", "CVE-TEST", "--sbom", str(sbom), "--sarif", str(tmp_path / "reviewed.sarif")]) == 0
    results = json.loads(output.read_text(encoding="utf-8"))
    assert results[0]["reachability"] == f["reachability"]
    assert "ai_reviews" not in results[1]
    html = output.with_suffix('.html').read_text(encoding="utf-8")
    assert "AI second opinion" in html and "Static verdict unchanged" in html
    assert "<img src=x" not in html and "&lt;img" in html
    assert json.loads((tmp_path / "reviewed.sarif").read_text(encoding="utf-8"))["runs"][0]["results"][0]["properties"]["aiReviews"]
    props = vulns_to_sarif(results)["runs"][0]["results"][0]["properties"]
    assert props["isReachable"] is None and props["aiReviews"][0]["status"] == "completed"


def test_packet_byte_limit_includes_large_unicode_static_reasons():
    value = finding()
    value["description"] = "\U0001f600" * 20000
    value["reachability"]["reasons"] = ["\U0001f600" * 20000] * 12
    packet = ai.evidence_packet(value)
    assert len(json.dumps(packet, ensure_ascii=False).encode()) <= 48000
    assert packet["evidence"][0]["value"]["omitted"] == "record_size_limit"


@pytest.mark.parametrize("collision", ["json_html", "sarif_html"])
def test_export_paths_cannot_overwrite_each_other_before_requests(tmp_path, monkeypatch, collision):
    source, sbom = tmp_path / "scan.json", tmp_path / "sbom.json"
    source.write_text(json.dumps([finding()]), encoding="utf-8")
    sbom.write_text('{"components":[]}', encoding="utf-8")
    output = tmp_path / ("reviewed.html" if collision == "json_html" else "reviewed.json")
    def forbidden(*a, **k): raise AssertionError("Must validate paths before API requests")
    monkeypatch.setattr(ai.requests, "post", forbidden)
    args = ["--input", str(source), "--output", str(output), "--provider", "openai", "--model", "model", "--sbom", str(sbom)]
    if collision == "sarif_html": args += ["--sarif", str(output.with_suffix('.html'))]
    with pytest.raises(SystemExit): ai.main(args)
    assert not output.exists()
