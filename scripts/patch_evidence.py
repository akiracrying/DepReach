"""Read immutable fix-parent source without cloning or executing repository code."""
import ast
import hashlib
import re
from functools import lru_cache
from urllib.parse import quote

import requests

COMMIT = re.compile(r"https://github\.com/([\w.-]+)/([\w.-]+)/commit/([0-9a-fA-F]{40})(?:\.diff)?/?$")
MAX_SOURCE_BYTES = 4 * 1024 * 1024


@lru_cache(maxsize=256)
def get_parent_source(reference, file):
    match = COMMIT.fullmatch(reference)
    if not match or not file.endswith(".py") or any(p in {"..", "."} for p in file.split("/")):
        return None
    owner, repo, commit = match.groups()
    # A full commit SHA plus ^ denotes its immutable first parent.
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}^/{quote(file, safe='/')}"
    try:
        chunks, size = [], 0
        with requests.get(url, stream=True, timeout=20) as response:
            response.raise_for_status()
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    return None
                chunks.append(chunk)
        raw = b"".join(chunks)
        # Respect PEP 263 source encodings, as Python's parser does.
        import io, tokenize
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        source = raw.decode(encoding)
        ast.parse(source)
        return {"source": source, "url": url, "revision": commit + "^",
                "sha256": hashlib.sha256(raw).hexdigest()}
    except (requests.RequestException, SyntaxError, UnicodeError, LookupError):
        return None


def function_spans(source):
    spans = []
    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scope = []
        def visit_ClassDef(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()
        def visit_FunctionDef(self, node):
            self.scope.append(node.name)
            spans.append({"name": ".".join(self.scope), "line": node.lineno,
                          "source_start_line": min([node.lineno, *(d.lineno for d in node.decorator_list)]),
                          "end_line": node.end_lineno, "column": node.col_offset,
                          "ast": ast.dump(node, include_attributes=False)})
            self.generic_visit(node)
            self.scope.pop()
        visit_AsyncFunctionDef = visit_FunctionDef
    Visitor().visit(ast.parse(source))
    return spans


def function_source_sha256(source, span):
    """Version-independent source fingerprint, including decorators and docstrings."""
    text = "\n".join(source.splitlines()[span.get("source_start_line", span["line"]) - 1:span["end_line"]]) + "\n"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
