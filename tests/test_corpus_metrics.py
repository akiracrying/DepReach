import pytest
from scripts.evaluate_corpus import classification, metrics, load_cases


def test_abstention_is_not_counted_as_correct_negative():
    rows = [{"truth": truth, "classification": classification(truth, status)} for truth, status in [
        ("present", "reachable"), ("present", "unknown"), ("absent", "no_path_found"),
        ("absent", "unknown"), ("undetermined", "unknown")]]
    result = metrics(rows)
    assert result["decision_coverage"] == 0.5
    assert result["present_target_coverage"] == 0.5
    assert result["absent_target_coverage"] == 0.5
    assert result["classifications"]["abstention"] == 2
    assert result["incorrect_conclusions"] == 0


def test_wrong_conclusions_are_distinguished():
    assert classification("present", "no_path_found") == "false_negative"
    assert classification("absent", "reachable") == "false_positive"
    assert classification("undetermined", "reachable") == "unsupported_conclusion"
    assert classification("undetermined", "no_path_found") == "unsupported_conclusion"
    assert metrics([])["positive_precision"] is None


def test_shipped_labels_have_all_truth_classes_and_real_source_evidence():
    from pathlib import Path
    data, digest = load_cases(Path(__file__).parent / "corpus/cases.json")
    assert len(digest) == 64
    assert {case["truth"] for case in data["cases"]} == {"present", "absent", "undetermined"}
    assert {case["kind"] for case in data["cases"]} == {"fixture", "library", "application"}
    assert len(data["cases"]) >= 30
