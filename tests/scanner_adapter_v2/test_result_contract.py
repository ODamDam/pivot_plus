from __future__ import annotations

import copy
import json
import socket
from dataclasses import FrozenInstanceError
from pathlib import Path

import jsonschema
import pytest

from test_replay_contract import artifacts
from src.scanner_adapter_v2 import load_replay_cases
from src.scanner_adapter_v2.results import (
    ScannerRawEvaluatorResult, ScannerNormalizedResult, build_raw_result,
    canonical_hash, validate_raw_result, validate_normalized_result, verify_raw_lineage,
)
from src.scanner_adapter_v2.normalization import normalize_raw_result


@pytest.fixture
def replay(artifacts):
    return load_replay_cases(**artifacts[0])[0]


def provenance():
    return {"adapter_version": "synthetic-v1", "git_commit": "b" * 40,
            "execution_id": "fixture-execution-1", "random_seed": 42,
            "configuration": {"identity": "fixture-config-v1", "sha256": "c" * 64},
            "runtime": {"identifier": "offline-fixture", "python_version": "3.9", "dependencies": []},
            "llm_judge": None}


def raw(replay, output=None, status="success", error=None, judge=False):
    prov = provenance()
    if judge:
        prov["llm_judge"] = {"provider": "synthetic", "model": "mock-judge", "model_version": None,
                             "rubric": {"identity": "fixture-rubric", "sha256": "d" * 64},
                             "random_seed": None, "options": {"temperature": 0}, "runtime_identifier": "offline-mock"}
    return build_raw_result(replay, scanner_run_id="fixture-run", evaluation_id="eval-1",
        scanner={"name": "synthetic", "version": "1"},
        evaluator={"name": "synthetic-evaluator", "version": "1", "kind": "llm_judge" if judge else "deterministic"},
        observation_surface="response_only", evaluator_input={"response_text": replay.to_dict()["response_text"]},
        execution_status=status, error_type=error, native_output=output, provenance=prov)


def policy(kind="boolean"):
    value = {"schema_version": "scanner_mapping_policy.v1", "policy_id": "synthetic-mapping", "version": "1",
             "scanner": {"name": "synthetic", "version": "1"},
             "evaluator": {"name": "synthetic-evaluator", "version": "1"},
             "kind": kind, "value_path": ["value"], "basis": "Synthetic evaluator contract, section 1",
             "native_direction": "boolean_only", "threshold": None, "comparator": None,
             "values": [{"native_value": True, "verdict": "flagged"}, {"native_value": False, "verdict": "not_flagged"}]}
    if kind == "categorical":
        value["native_direction"] = "categorical"
        value["values"] = [{"native_value": "alert", "verdict": "flagged"},
                           {"native_value": "clear", "verdict": "not_flagged"},
                           {"native_value": "uncertain", "verdict": "indeterminate"}]
    elif kind == "numeric_threshold":
        value.update(native_direction="higher_is_more_suspicious", values=[], comparator="gte",
                     threshold={"source": "scanner_native", "identifier": "fixture-native-threshold",
                                "value": None, "path": ["threshold"]})
    return value


@pytest.mark.parametrize("kind,output,verdict", [
    ("boolean", {"value": True, "pass": False, "rationale": "native output"}, "flagged"),
    ("boolean", {"value": False}, "not_flagged"),
    ("numeric_threshold", {"value": 72.5, "threshold": 60}, "flagged"),
    ("numeric_threshold", {"value": 59, "threshold": 60}, "not_flagged"),
    ("categorical", {"value": "alert"}, "flagged"),
    ("categorical", {"value": "uncertain"}, "indeterminate"),
    ("categorical", {"value": "never-seen"}, "indeterminate"),
    ("boolean", {}, "no_result"), ("boolean", None, "no_result"),
    ("boolean", {"value": 0}, "no_result"),
])
def test_mapping_smoke(replay, kind, output, verdict):
    original = copy.deepcopy(output)
    result = raw(replay, output)
    before = result.to_dict()
    mapping = policy(kind)
    normalized = normalize_raw_result(result, mapping)
    assert normalized == normalize_raw_result(result, mapping)
    data = normalized.to_dict()
    assert data["normalized_verdict"] == verdict
    assert data["execution_status"] == "success"
    assert data["generation_id"] == replay.to_dict()["generation_id"]
    assert data["raw_result"]["sha256"] == canonical_hash(before)
    assert data["mapping_policy"]["sha256"] == canonical_hash(mapping)
    assert data["provenance"] == before["provenance"]
    assert result.to_dict() == before and output == original
    validate_raw_result(before)
    validate_normalized_result(data, raw_result=result)
    with pytest.raises(FrozenInstanceError): result._serialized = "modified"
    data["provenance"]["adapter_version"] = "modified"
    assert normalized.to_dict()["provenance"] == before["provenance"]


@pytest.mark.parametrize("status,error", [("error", "evaluator_error"), ("error", "parser_error"),
    ("timeout", "timeout"), ("dependency_error", "dependency_error"), ("configuration_error", "configuration_error"),
    ("unsupported", "unsupported_result"), ("skipped", None)])
def test_failure_never_safe(replay, status, error):
    result = raw(replay, {"value": False}, status, error)
    norm = normalize_raw_result(result, policy()).to_dict()
    assert norm["execution_status"] == status
    assert norm["error_type"] == error
    assert norm["normalized_verdict"] == "no_result"
    norm["normalized_verdict"] = "not_flagged"
    with pytest.raises(ValueError): validate_normalized_result(norm)
    schema = json.loads((Path(__file__).resolve().parents[2] / "schemas/scanner_normalized_result_v1.schema.json").read_text())
    assert not jsonschema.Draft202012Validator(schema).is_valid(norm)


def test_score_threshold_preservation_and_direction(replay):
    mapping = policy("numeric_threshold")
    result = raw(replay, {"value": -4.5, "threshold": -3})
    mapping.update(native_direction="lower_is_more_suspicious", comparator="lte")
    data = normalize_raw_result(result, mapping).to_dict()
    assert data["native_score"] == -4.5
    assert data["native_threshold"] == -3
    assert data["native_direction"] == "lower_is_more_suspicious"
    assert data["threshold_source"] == "scanner_native"
    assert data["normalized_verdict"] == "flagged"
    assert "normalized_score" not in data
    mapping["threshold"] = {"source": "evaluator_contract", "identifier": "rubric-v1-section-2", "value": -10, "path": None}
    assert normalize_raw_result(result, mapping).to_dict()["normalized_verdict"] == "not_flagged"


@pytest.mark.parametrize("output", [{"value": float("nan")}, {"value": float("inf")}, {"value": float("-inf")},
                                    {1: "nonstring key"}, {"value": object()}, {"value": (1, 2)}, {"value": {1, 2}}])
def test_strict_json_boundary(replay, output):
    with pytest.raises(ValueError): raw(replay, output)


@pytest.mark.parametrize("key", ["correct", "incorrect", "true_positive", "FalseNegative", "scannerAccuracy",
    "expected_verdict", "Outcome_GT", "pi_status", "maliciousness", "derived_class", "GT_rationale",
    "judge_a_decision", "judge_b", "outcome_rule_verdict", "otherScannerResult", "scanner_results"])
def test_result_leakage(replay, key):
    with pytest.raises(ValueError, match="native_output"):
        raw(replay, {"wrapper": [{key: True}]})


def test_native_text_and_own_judge_output_preserved(replay):
    output = {"value": "alert", "judge_response": "pass false_positive is quoted text", "score_rationale": "native rationale",
              "componentResults": [{"pass": False, "score": 0.1}], "response": " exact\r\n한글 "}
    result = raw(replay, output, judge=True)
    assert result.to_dict()["native_output"] == output
    assert normalize_raw_result(result, policy("categorical")).to_dict()["provenance"]["llm_judge"] == result.to_dict()["provenance"]["llm_judge"]


@pytest.mark.parametrize("mutation", ["scanner", "generation", "status", "extra", "nested_extra", "hash", "llm_missing", "llm_unexpected", "error_type"])
def test_raw_invalid_schema_and_semantics(replay, mutation):
    data = raw(replay, {"value": True}).to_dict()
    if mutation == "scanner": del data["scanner"]
    elif mutation == "generation": del data["generation_id"]
    elif mutation == "status": data["execution_status"] = "mystery"
    elif mutation == "extra": data["extra"] = True
    elif mutation == "nested_extra": data["provenance"]["runtime"]["extra"] = True
    elif mutation == "hash": data["native_output_sha256"] = "f" * 64
    elif mutation == "llm_missing": data["evaluator"]["kind"] = "llm_judge"
    elif mutation == "llm_unexpected": data["provenance"]["llm_judge"] = raw(replay, judge=True).to_dict()["provenance"]["llm_judge"]
    elif mutation == "error_type": data["error_type"] = "evaluator_error"
    with pytest.raises(ValueError): validate_raw_result(data)


@pytest.mark.parametrize("mutation", ["unknown_safe", "direction", "threshold_type", "threshold_source", "identity", "duplicate", "extra", "nan"])
def test_invalid_policy(replay, mutation):
    mapping = policy("numeric_threshold" if mutation in ("direction", "threshold_type", "threshold_source", "nan") else "boolean")
    if mutation == "unknown_safe": mapping["unknown_verdict"] = "not_flagged"
    elif mutation == "direction": mapping["native_direction"] = "lower_is_more_suspicious"
    elif mutation == "threshold_type": mapping["threshold"] = {"source": "evaluator_contract", "identifier": "rule", "value": "0.5", "path": None}
    elif mutation == "threshold_source": mapping["threshold"]["source"] = "adapter_imposed"
    elif mutation == "identity": mapping["scanner"]["name"] = "another"
    elif mutation == "duplicate": mapping["values"].append(copy.deepcopy(mapping["values"][0]))
    elif mutation == "extra": mapping["extra"] = True
    elif mutation == "nan": mapping["threshold"]["value"] = float("nan")
    with pytest.raises(ValueError): normalize_raw_result(raw(replay, {"value": True}), mapping)


def test_missing_threshold_and_parser_failure(replay):
    for output in ({"value": 0.2}, {"value": 0.2, "threshold": "bad"}, []):
        norm = normalize_raw_result(raw(replay, output), policy("numeric_threshold")).to_dict()
        assert norm["normalized_verdict"] == "no_result"
        assert norm["normalization_error"] in ("parser_error", "invalid_native_result")


def test_lineage_binding_and_tamper_detection(replay):
    result = raw(replay, {"value": False})
    inp = {"response_text": replay.to_dict()["response_text"]}
    verify_raw_lineage(result, replay, inp)
    with pytest.raises(ValueError): verify_raw_lineage(result, replay, {"response_text": "wrong"})
    for key in ("generation_id", "production_case_id"):
        data = result.to_dict()
        data[key] = "wrong"
        with pytest.raises(ValueError): verify_raw_lineage(ScannerRawEvaluatorResult.from_dict(data), replay, inp)
    data = normalize_raw_result(result, policy()).to_dict()
    data["raw_result"]["sha256"] = "f" * 64
    with pytest.raises(ValueError): validate_normalized_result(data, raw_result=result)


def test_schemas_check_and_valid_payloads(replay):
    for filename, data in (("scanner_raw_evaluator_result_v1.schema.json", raw(replay, {"value": True}).to_dict()),
                           ("scanner_normalized_result_v1.schema.json", normalize_raw_result(raw(replay, {"value": True}), policy()).to_dict()),
                           ("scanner_mapping_policy_v1.schema.json", policy())):
        schema = json.loads((Path(__file__).resolve().parents[2] / "schemas" / filename).read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(data)


@pytest.mark.parametrize("key", ["judge_a_evidence", "judge_b_rationale", "expected_scanner_correctness", "scanners", "garak", "pyrit", "promptfoo"])
def test_nested_foreign_evaluation_metadata(replay, key):
    with pytest.raises(ValueError): raw(replay, {"nested": [{key: {"score": 1}}]})


def test_serialized_duplicate_key_rejection(replay):
    value = raw(replay, {"value": True})._serialized
    duplicated = value.replace('"native_output":', '"native_output":null,"native_output":', 1)
    with pytest.raises(ValueError): ScannerRawEvaluatorResult(duplicated)


def test_normalized_schema_rejects_missing_evidence(replay):
    value = normalize_raw_result(raw(replay, {}), policy()).to_dict()
    value.update(normalized_verdict="not_flagged", normalization_error=None)
    with pytest.raises(ValueError): validate_normalized_result(value)


def test_multiple_generations_evaluations_and_surface_binding(artifacts):
    cases = load_replay_cases(**artifacts[0])
    hashes = set()
    for case in cases:
        for surface in ("response_only", "request_and_response", "trusted_context_untrusted_input_and_response"):
            result = build_raw_result(case, scanner_run_id="synthetic-run", evaluation_id=case.to_dict()["generation_id"] + "::" + surface,
                scanner={"name": "synthetic", "version": "1"}, evaluator={"name": "synthetic-evaluator", "version": "1", "kind": "deterministic"},
                observation_surface=surface, evaluator_input={"synthetic_formatted_input": "fixture"}, execution_status="success", error_type=None,
                native_output={"value": True}, provenance=provenance())
            verify_raw_lineage(result, case, {"synthetic_formatted_input": "fixture"})
            hashes.add(canonical_hash(result.to_dict()))
            normalized = normalize_raw_result(result, policy()).to_dict()
            assert normalized["observation_surface"] == surface
            assert normalized["sample_id"] == case.to_dict()["sample_id"]
    assert len(hashes) == 9


def test_threshold_edge_and_policy_immutability(replay):
    mapping = policy("numeric_threshold")
    original = copy.deepcopy(mapping)
    result = raw(replay, {"value": 60, "threshold": 60})
    assert normalize_raw_result(result, mapping).to_dict()["normalized_verdict"] == "flagged"
    assert mapping == original
    mapping["comparator"] = "gt"
    assert normalize_raw_result(result, mapping).to_dict()["normalized_verdict"] == "not_flagged"


def test_unprepared_input_allowed_only_on_failure(replay):
    data = raw(replay, None, "skipped", None).to_dict()
    data["evaluator_input"] = None
    result = ScannerRawEvaluatorResult.from_dict(data)
    assert normalize_raw_result(result, policy()).to_dict()["normalized_verdict"] == "no_result"
    data["execution_status"] = "success"
    with pytest.raises(ValueError): ScannerRawEvaluatorResult.from_dict(data)


def test_normalized_tampering_and_schema_additional_properties(replay):
    result = raw(replay, {"value": True})
    norm = normalize_raw_result(result, policy()).to_dict()
    for key in ("provenance", "mapping_policy"):
        changed = copy.deepcopy(norm)
        changed[key]["extra"] = True
        with pytest.raises(ValueError): validate_normalized_result(changed)
    changed = copy.deepcopy(norm)
    changed["native_threshold"] = "bad"
    with pytest.raises(ValueError): validate_normalized_result(changed)
    changed = copy.deepcopy(norm)
    changed["production_case_id"] = "other-case"
    with pytest.raises(ValueError): validate_normalized_result(changed, raw_result=result)
