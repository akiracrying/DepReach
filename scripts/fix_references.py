"""Discover candidate fix commits from explicitly supplied GitHub references.

A linked commit remains a patch candidate, not a verified vulnerability sink.
Only known advisory and pull-request API resources are traversed, with bounded
requests; repository issues, arbitrary pages and instructions are not executed.
"""
import hashlib
import json
import re
from collections import deque
from urllib.parse import urlsplit

import requests

GHSA = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}", re.I)
PR = re.compile(r"/([\w.-]+)/([\w.-]+)/pull/(\d+)/?$")
LINK = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/(?:commit/[0-9a-fA-F]{7,40}|pull/\d+)(?![A-Za-z0-9])")
MAX_RESOURCES = 8
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _read_json(url):
    raw = bytearray()
    with requests.get(url, headers={"Accept": "application/vnd.github+json"}, stream=True, timeout=20) as response:
        response.raise_for_status()
        for chunk in response.iter_content(65536):
            raw.extend(chunk)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("GitHub reference response exceeds size limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Expected a GitHub API object")
    return value, hashlib.sha256(raw).hexdigest()


def _resource(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        return None
    path = parsed.path.rstrip("/")
    advisory = GHSA.fullmatch(path.rsplit("/", 1)[-1])
    if advisory and (path.startswith("/advisories/") or "/security/advisories/" in path):
        identifier = "GHSA-" + advisory[0][5:].lower()
        return "advisory", f"https://api.github.com/advisories/{identifier}", identifier
    pull = PR.fullmatch(path)
    if pull:
        owner, repo, number = pull.groups()
        return "pull_request", f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}", (owner, repo, number)
    return None


def resolve_fix_references(references, *, session=None):
    from scripts.reachability import extract_commit_links
    direct = extract_commit_links(references)
    provenance = [{"commit": link, "basis": "direct_reference", "source": link} for link in direct]
    # Avoid unrelated advisory round trips when immutable fix evidence already exists.
    if direct:
        return direct, {"provenance": provenance, "resources": [], "issues": []}
    pending = deque((url, 0, []) for url in sorted(set(references)) if isinstance(url, str))
    visited, commits, resources, issues = set(), set(), [], []
    while pending and len(visited) < MAX_RESOURCES:
        source, depth, chain = pending.popleft()
        if depth > 2:
            continue
        resource = _resource(source)
        if not resource:
            continue
        kind, api_url, identity = resource
        if api_url in visited:
            continue
        visited.add(api_url)
        record = {"source": source, "api_url": api_url, "kind": kind}
        resources.append(record)
        try:
            fetch = lambda: _read_json(api_url)
            payload, digest = session.reference(api_url, fetch) if session else fetch()
            record["response_sha256"] = digest
            chain = [*chain, {"source": source, "api_url": api_url, "response_sha256": digest}]
            if kind == "advisory":
                if payload.get("ghsa_id", "").lower() != identity.lower():
                    raise ValueError("Advisory identity mismatch")
                if payload.get("withdrawn_at"):
                    record["outcome"] = "withdrawn_advisory"
                    issues.append({"reason": "withdrawn_advisory", "source": source})
                    continue
                linked = [(url, "advisory_reference") for url in payload.get("references", []) if isinstance(url, str)]
                linked += [(url, "advisory_description_link") for url in LINK.findall(payload.get("description") or "")]
                for url, basis in linked:
                    found = extract_commit_links([url])
                    for commit in found:
                        commits.add(commit)
                        provenance.append({"commit": commit, "basis": basis, "source": source, "chain": chain})
                    if not found:
                        pending.append((url, depth + 1, chain))
                record["outcome"] = "references_examined"
            else:
                owner, repo, number = identity
                if payload.get("number") != int(number) or payload.get("base", {}).get("repo", {}).get("full_name", "").lower() != f"{owner}/{repo}".lower():
                    raise ValueError("Pull request identity mismatch")
                sha = payload.get("merge_commit_sha") or ""
                if payload.get("merged") is not True or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                    record["outcome"] = "pull_request_not_merged"
                    issues.append({"reason": "pull_request_not_merged", "source": source})
                    continue
                commit = f"https://github.com/{owner}/{repo}/commit/{sha.lower()}"
                commits.add(commit)
                provenance.append({"commit": commit, "basis": "merged_pull_request", "source": source, "chain": chain})
                record["outcome"] = "merge_commit_resolved"
        except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError) as exc:
            record["outcome"] = "reference_resolution_failed"
            issues.append({"reason": "reference_resolution_failed", "source": source, "error": str(exc)})
    if pending:
        issues.append({"reason": "reference_resolution_limit", "remaining": len(pending)})
    return sorted(commits), {"provenance": provenance, "resources": resources, "issues": issues}
