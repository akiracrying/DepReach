import pytest
from scripts.composition_analysis import (
    extract_version_from_purl,
    find_by_path,
    find_affected_version,
    extract_metrics,
)


def test_extract_version_from_purl():
    assert extract_version_from_purl("pkg:pypi/foo@1.2.3") == "1.2.3"
    assert extract_version_from_purl("pkg:pypi/bar@0.0.1") == "0.0.1"
    assert extract_version_from_purl("pkg:pypi/baz") is None
    assert extract_version_from_purl("") is None


def test_find_by_path_dict():
    obj = {"a": 1, "b": {"c": 2}}
    assert find_by_path(obj, ["a"]) == [1]
    assert find_by_path(obj, ["b", "c"]) == [2]
    assert find_by_path(obj, ["b"]) == [{"c": 2}]
    assert find_by_path(obj, ["x"]) == []


def test_find_by_path_list():
    obj = {"items": [10, 20]}
    assert find_by_path(obj, ["items", "0"]) == [10]
    assert find_by_path(obj, ["items", "1"]) == [20]


def test_find_by_path_nested():
    obj = {"containers": [{"cna": {"metrics": [{"cvssV3_1": {"baseScore": 7.5}}]}}]}
    metrics = find_by_path(obj, ["containers", "cna", "metrics", "0"])
    assert len(metrics) == 1
    assert metrics[0]["cvssV3_1"]["baseScore"] == 7.5


def test_find_affected_version():
    cve = {
        "containers": [{
            "cna": {
                "affected": [{
                    "versions": [{"lessThan": "2.0.0"}]
                }]
            }
        }]
    }
    assert find_affected_version(cve) == "<2.0.0"

    cve2 = {
        "containers": [{
            "cna": {
                "affected": [{"versions": [{"lessThanOrEqual": "1.9"}]}]
            }
        }]
    }
    assert find_affected_version(cve2) == "<=1.9"


def test_find_affected_version_empty():
    assert find_affected_version({}) is None
    assert find_affected_version({"containers": []}) is None


def test_extract_metrics():
    cve = {
        "containers": [{
            "cna": {
                "metrics": [{
                    "cvssV3_1": {"baseScore": 8.1, "baseSeverity": "HIGH"}
                }]
            }
        }]
    }
    score, severity = extract_metrics(cve)
    assert score == 8.1
    assert severity == "HIGH"


def test_extract_metrics_empty():
    assert extract_metrics({}) == (None, None)
    assert extract_metrics({"containers": []}) == (None, None)
