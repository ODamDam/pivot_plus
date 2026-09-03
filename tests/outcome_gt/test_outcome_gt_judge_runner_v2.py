import hashlib
import json
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / "scripts" / "outcome_gt"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import materialize_outcome_gt_judge_requests_v2 as materialize
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
    assert full.startswith("OGTJRUN-V2-A-")
    assert len({full, other, canary}) == 3


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
