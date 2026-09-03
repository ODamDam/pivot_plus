import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/outcome_gt/build_outcome_rule_calibration_v1.py"


def load_module():
    spec = importlib.util.spec_from_file_location("outcome_rule_calibration_v1", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def test_selection_population_and_family_distribution():
    module = load_module()
    rows, audit = module.build_calibration_rows()
    counts = Counter(row["structural_family"] for row in rows)

    assert len(rows) == 45
    assert len({row["production_case_id"] for row in rows}) == 45
    assert counts == {"T1_document": 10, "T2_plain_text": 10, "T3_code": 8, "T4_structured": 7, "T5_tool_action": 10}
    assert audit["source_row_count"] == 582
    assert audit["unknown_source_cases"] == 0


def test_projection_matches_blind_source_losslessly():
    module = load_module()
    rows, _ = module.build_calibration_rows()
    source = {row["production_case_id"]: row for row in read_jsonl(module.SOURCE)}

    for row in rows:
        original = source[row["production_case_id"]]
        for field in module.LOSSLESS_FIELDS:
            assert row[field] == original[field]
        assert row["source_metadata"] == module.project_source_metadata(original)


def test_recursive_blindness_and_no_results_dependency():
    module = load_module()
    rows, audit = module.build_calibration_rows()
    assert audit["leakage_violations"] == 0
    assert all(not module.find_forbidden_keys(row) for row in rows)

    source = SCRIPT.read_text(encoding="utf-8")
    assert "results.jsonl" not in source
    assert "ground_truth_decision" not in source
    assert 'source_row["case_gt"]' not in source
    assert 'source_case_gt' not in source
    assert "RuleBasedBoundaryEvaluator" not in source


def test_selection_and_rendering_are_deterministic():
    module = load_module()
    rows_a, _ = module.build_calibration_rows()
    rows_b, _ = module.build_calibration_rows()
    assert [row["production_case_id"] for row in rows_a] == [row["production_case_id"] for row in rows_b]
    assert module.canonical_jsonl_bytes(rows_a) == module.canonical_jsonl_bytes(rows_b)
    assert module.render_review(rows_a) == module.render_review(rows_b)


def test_required_calibration_coverage_is_present():
    module = load_module()
    rows, audit = module.build_calibration_rows()
    tags = {tag for row in rows for tag in row["provisional_goal_candidates"]}
    flags = {flag for row in rows for flag in row["relevant_exception_flags"]}
    t5_domains = {
        row["source_metadata"]["representation_context"]
        for row in rows
        if row["structural_family"] == "T5_tool_action"
    }

    assert {"healthcare", "ecommerce"} <= t5_domains
    assert audit["multi_goal_case_count"] > 0
    assert audit["uncertain_or_other_case_count"] > 0
    assert "instruction_override" in tags
    assert "task_redirection" in tags
    assert "unauthorized_action" in tags
    assert ({"synthetic_secret_disclosure", "unauthorized_information_disclosure"} & tags)
    assert "uncertain_goal" in flags
    if audit["source_designated_output_available"]:
        assert "designated_output" in tags


def test_write_refuses_overwrite_and_manifest_hash_matches(tmp_path):
    module = load_module()
    rows, audit = module.build_calibration_rows()
    output = tmp_path / "calibration.jsonl"
    manifest = tmp_path / "manifest.json"
    review = tmp_path / "review.md"
    value = module.write_artifacts(rows, audit, output, manifest, review)
    assert value["output_row_count"] == 45
    assert value["output_sha256"] == module.sha256_file(output)
    assert value["review_sha256"] == module.sha256_file(review)
    with pytest.raises(FileExistsError):
        module.write_artifacts(rows, audit, output, manifest, review)


def test_materialized_artifacts_match_deterministic_build_and_manifest():
    module = load_module()
    rows, _ = module.build_calibration_rows()
    materialized = read_jsonl(module.DEFAULT_OUTPUT)
    manifest = json.loads(module.DEFAULT_MANIFEST.read_text(encoding="utf-8"))

    assert materialized == rows
    assert module.sha256_file(module.DEFAULT_OUTPUT) == manifest["output_sha256"]
    assert module.sha256_file(module.DEFAULT_REVIEW) == manifest["review_sha256"]
    assert manifest["source_blind_input_sha256"] == module.sha256_file(module.SOURCE)
    assert manifest["contains_approved_rules"] is False
    assert manifest["contains_final_bindings"] is False
