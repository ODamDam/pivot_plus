import hashlib
import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / "scripts" / "outcome_gt"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import materialize_outcome_gt_judge_requests_v2 as materialize
import materialize_outcome_gt_common_canary_v1 as common_canary
import run_outcome_gt_judge_v2 as runner


def load_schema(name):
    value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(value)
    return jsonschema.Draft202012Validator(value)


def test_prompt_v2_and_semantic_schema_hashes_are_frozen():
    prompt = ROOT / "docs/outcome_gt/OUTCOME_GT_JUDGE_SYSTEM_PROMPT_v2.txt"
    semantic = ROOT / "schemas/outcome_gt_judge_semantic_response_v1.schema.json"
    assert hashlib.sha256(prompt.read_bytes()).hexdigest() == materialize.PROMPT_SHA256
    assert hashlib.sha256(semantic.read_bytes()).hexdigest() == runner.STRUCTURED_OUTPUT_SCHEMA_SHA256


def test_request_v2_id_is_stable_and_uses_existing_request_id_namespace():
    first = materialize.request_id("pass_a", "OGTAS-V1-A-0123456789ABCDEF")
    second = materialize.request_id("pass_a", "OGTAS-V1-A-0123456789ABCDEF")
    assert first == second
    assert first.startswith("OGTJR-V1-A-")


def test_structured_output_schema_removes_metadata_only():
    schema = runner.structured_output_schema()
    assert "$schema" not in schema
    assert "$id" not in schema
    assert "title" not in schema
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    supports = schema["properties"]["evidence"]["items"]["properties"]["supports"]["enum"]
    assert "attacker_goal_achieved" in supports
    assert "attacker_goal_success_criterion" not in supports


def test_stable_v2_run_id_changes_with_model_or_limit():
    common = {
        "pass_id": "pass_a",
        "request_sha256": "a" * 64,
        "model_digest": "b" * 64,
        "provider_version": "0.32.15",
        "runner_commit": "c" * 40,
        "seed": 4101,
        "max_tokens": 768,
    }
    full = runner.stable_run_id(model="judge-a", limit=None, **common)
    same = runner.stable_run_id(model="judge-a", limit=None, **common)
    other = runner.stable_run_id(model="judge-b", limit=None, **common)
    canary = runner.stable_run_id(model="judge-a", limit=10, **common)
    assert full == same
    assert full == "OGTJRUN-V2-A-E82CFAE3FDE148A9"
    assert full.startswith("OGTJRUN-V2-A-")
    assert len({full, other, canary}) == 3

    selected = runner.stable_run_id(
        model="judge-a", limit=None, selection_sha256="d" * 64, **common
    )
    assert selected != full


def test_final_run_status_supports_legacy_limit_and_selection_canaries():
    assert runner.final_run_status(10, 10, limit=10, selection_used=False) == "CANARY_COMPLETE"
    assert runner.final_run_status(10, 10, limit=None, selection_used=True) == "CANARY_COMPLETE"
    assert runner.final_run_status(9, 10, limit=None, selection_used=True) == "INCOMPLETE"
    assert runner.final_run_status(1746, 1746, limit=None, selection_used=False) == "COMPLETE"


def test_provenance_v2_schema_requires_structured_output_hash_and_no_semantic_retry():
    row = {
        "schema_version": "outcome_gt_annotator_provenance.v2",
        "run_id": "OGTJRUN-V2-A-0123456789ABCDEF",
        "pass_id": "pass_a",
        "annotator_id": "judge-a",
        "provider": "ollama",
        "provider_version": "0.32.15",
        "model_id": "model-a",
        "model_digest": "a" * 64,
        "runner_version": "outcome-gt-judge-runner-v2",
        "runner_commit": "b" * 40,
        "prompt_version": "outcome-gt-judge-system-prompt-v2",
        "prompt_path": "docs/outcome_gt/OUTCOME_GT_JUDGE_SYSTEM_PROMPT_v2.txt",
        "prompt_sha256": materialize.PROMPT_SHA256,
        "assignment_sha256": "c" * 64,
        "request_sha256": "d" * 64,
        "structured_output_schema_sha256": runner.STRUCTURED_OUTPUT_SCHEMA_SHA256,
        "selection_path": None,
        "selection_sha256": None,
        "sampling": {"temperature": 0.0, "top_p": 1.0, "seed": 4101, "max_tokens": 768},
        "retry_policy": {"max_transport_retries": 1, "semantic_retry": False, "parse_retry": False},
        "started_at": "2026-09-03T00:00:00Z",
        "finished_at": None,
        "status": "RUNNING",
        "rows_target": 1746,
        "rows_completed": 0,
        "rows_failed": 0,
    }
    validator = load_schema("outcome_gt_annotator_provenance_v2.schema.json")
    assert not list(validator.iter_errors(row))
    row["retry_policy"]["semantic_retry"] = True
    assert list(validator.iter_errors(row))


def _selection_document(generation_ids, source_sha="a" * 64):
    return {
        "schema_version": "outcome_gt_common_canary_selection.v1",
        "selection_version": "outcome-gt-common-canary-v1",
        "selection_algorithm": "sha256-rank-ascending-v1",
        "selection_namespace": common_canary.SELECTION_NAMESPACE,
        "source_population": {
            "path": "input.jsonl",
            "sha256": source_sha,
            "count": len(generation_ids),
        },
        "source_requests": {
            "pass_a": {"path": "a.jsonl", "sha256": "b" * 64, "count": len(generation_ids)},
            "pass_b": {"path": "b.jsonl", "sha256": "c" * 64, "count": len(generation_ids)},
        },
        "selected_count": min(10, len(generation_ids)),
        "ordered_generation_ids": common_canary.rank_generation_ids(
            generation_ids, count=min(10, len(generation_ids))
        ),
        "creation_provenance": {
            "generator": "scripts/outcome_gt/materialize_outcome_gt_common_canary_v1.py",
            "identifier": "generation_id",
            "response_content_used": False,
            "ground_truth_used": False,
            "judge_result_used": False,
            "judge_model_used": False,
        },
    }


def test_common_canary_selection_is_deterministic_and_pass_independent():
    generation_ids = [f"generation-{index:02d}" for index in range(30)]
    forward = common_canary.rank_generation_ids(generation_ids)
    reverse = common_canary.rank_generation_ids(reversed(generation_ids))
    assert forward == reverse
    assert len(forward) == len(set(forward)) == 10

    document = _selection_document(generation_ids)
    common_canary.validate_selection_document(
        document,
        source_generation_ids=generation_ids,
        source_population_sha256="a" * 64,
        pass_generation_ids={"pass_a": generation_ids, "pass_b": list(reversed(generation_ids))},
        request_sha256_by_pass={"pass_a": "b" * 64, "pass_b": "c" * 64},
    )


def test_common_canary_selection_rejects_duplicate_missing_and_stale_population():
    generation_ids = [f"generation-{index:02d}" for index in range(30)]
    document = _selection_document(generation_ids)
    kwargs = {
        "source_generation_ids": generation_ids,
        "source_population_sha256": "a" * 64,
        "pass_generation_ids": {"pass_a": generation_ids, "pass_b": generation_ids},
        "request_sha256_by_pass": {"pass_a": "b" * 64, "pass_b": "c" * 64},
    }

    duplicate = json.loads(json.dumps(document))
    duplicate["ordered_generation_ids"][1] = duplicate["ordered_generation_ids"][0]
    with pytest.raises(ValueError, match="unique"):
        common_canary.validate_selection_document(duplicate, **kwargs)

    missing = json.loads(json.dumps(document))
    missing["ordered_generation_ids"][0] = "missing-generation"
    with pytest.raises(ValueError, match="canonical population"):
        common_canary.validate_selection_document(missing, **kwargs)

    with pytest.raises(ValueError, match="source population SHA-256"):
        common_canary.validate_selection_document(
            document, **{**kwargs, "source_population_sha256": "f" * 64}
        )


def test_runner_selection_file_filtering_preserves_common_order_and_fails_closed():
    generation_ids = [f"generation-{index:02d}" for index in range(30)]
    document = _selection_document(generation_ids)
    selected = document["ordered_generation_ids"]
    requests = [
        {"assignment_item_id": f"assignment-{index:02d}", "judge_request_id": f"request-{index:02d}"}
        for index in range(30)
    ]
    keys = [
        {"assignment_item_id": f"assignment-{index:02d}", "generation_id": generation_id}
        for index, generation_id in enumerate(generation_ids)
    ]
    filtered = runner.filter_requests_by_selection(requests, keys, document)
    assignment_to_generation = {row["assignment_item_id"]: row["generation_id"] for row in keys}
    assert [assignment_to_generation[row["assignment_item_id"]] for row in filtered] == selected

    missing_assignment = next(
        row["assignment_item_id"] for row in keys if row["generation_id"] == selected[0]
    )
    with pytest.raises(ValueError, match="missing selected generation"):
        runner.filter_requests_by_selection(
            [row for row in requests if row["assignment_item_id"] != missing_assignment], keys, document
        )


def test_legacy_limit_filtering_is_unchanged():
    requests = [{"judge_request_id": str(index)} for index in range(20)]
    assert runner.limit_requests(requests, 10) == requests[:10]
    assert runner.limit_requests(requests, None) == requests
