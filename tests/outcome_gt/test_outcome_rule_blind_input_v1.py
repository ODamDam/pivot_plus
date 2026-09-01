import importlib.util
import json
from pathlib import Path

import pytest


jsonschema = pytest.importorskip("jsonschema")
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/outcome_gt/build_outcome_rule_blind_input_v1.py"


def load_module():
    spec = importlib.util.spec_from_file_location("outcome_rule_blind_v1", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def test_authoritative_population_and_joins():
    module = load_module()
    audit = module.load_and_validate_sources()

    assert audit["manifest_row_count"] == 1207
    assert audit["manifest_unique_case_count"] == 1207
    assert audit["plan_row_count"] == 2661
    assert audit["plan_unique_generation_count"] == 2661
    assert audit["dataset_a_attack_generation_count"] == 1746
    assert audit["dataset_a_runtime_case_count"] == 582
    assert audit["supplemental_direct_generation_count"] == 915
    assert audit["dataset_a_standalone_case_count"] == 320
    assert audit["replicate_counts"] == {"r1": 582, "r2": 582, "r3": 582}
    assert audit["manifest_join_failures"] == 0
    assert audit["dataset_join_failures"] == 0
    assert audit["runtime_field_missing_count"] == 0
    assert audit["replicate_runtime_mismatch_count"] == 0
    assert audit["source_hash_integrity"] is True


def test_blind_projection_is_case_level_complete_and_leak_free():
    module = load_module()
    rows, audit = module.build_rows()

    assert len(rows) == 582
    assert len({row["production_case_id"] for row in rows}) == 582
    assert len({row["blind_rule_case_id"] for row in rows}) == 582
    assert all(len(row["expected_replicates"]) == 3 for row in rows)
    assert all(
        {rep["replicate_index"] for rep in row["expected_replicates"]}
        == {"r1", "r2", "r3"}
        for row in rows
    )
    assert audit["leakage_violations"] == 0
    assert all(not module.find_forbidden_keys(row) for row in rows)

    manifest = read_jsonl(module.MANIFEST_PATH)
    excluded = {
        row["production_case_id"]
        for row in manifest
        if row["source_pool"] == "dataset_a"
        and row["runtime_outcome_applicability"]
        == "not_applicable_no_runtime_boundary"
    }
    assert len(excluded) == 320
    assert excluded.isdisjoint({row["production_case_id"] for row in rows})

    schema = json.loads(
        (ROOT / "schemas/outcome_rule_blind_input_v1.schema.json").read_text(encoding="utf-8")
    )
    validator = jsonschema.Draft202012Validator(schema)
    assert not [error for row in rows for error in validator.iter_errors(row)]


def test_nested_leakage_scan_rejects_prohibited_metadata():
    module = load_module()
    assert module.find_forbidden_keys(
        {"safe": {"nested": [{"evaluator_verdict": "vulnerable"}]}}
    ) == {"evaluator_verdict"}
    assert module.find_forbidden_keys(
        {"safe": {"nested": {"response_text": "do not leak"}}}
    ) == {"response_text"}
    assert module.find_forbidden_keys({"source_case_gt": {"maliciousness": "malicious"}}) == {
        "source_case_gt"
    }


def test_build_is_deterministic_and_refuses_overwrite(tmp_path):
    module = load_module()
    rows_a, _ = module.build_rows()
    rows_b, _ = module.build_rows()
    assert module.canonical_jsonl_bytes(rows_a) == module.canonical_jsonl_bytes(rows_b)

    output = tmp_path / "blind.jsonl"
    provenance = tmp_path / "manifest.json"
    first = module.write_artifacts(rows_a, output, provenance)
    assert first["output_row_count"] == 582
    with pytest.raises(FileExistsError):
        module.write_artifacts(rows_a, output, provenance)


def test_materializer_has_no_results_dependency_or_case_gt_copy_logic():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "results.jsonl" not in source
    assert "ground_truth_decision" not in source
    assert "RuleBasedBoundaryEvaluator" not in source
    assert 'manifest_row["source_case_gt"]' not in source
    assert 'source_row["case_gt"]' not in source
    assert "maliciousness" not in source
    assert "outcome_label" not in source
    assert "production_execution_plan_4523_v1.jsonl" not in source
    assert "production_main_execution_plan_2661_v1_1.jsonl" in source
