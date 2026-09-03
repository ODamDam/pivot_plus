#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys

import jsonschema

from outcome_gt_annotation_common_v1 import EXPECTED_ROWS, ROOT, sha256_file

RUN_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_runs"
REQUEST_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_requests"
PASS_ROOT = ROOT / "data/outcome_gt/adjudication_v1/passes"
PROMPT_PATH = ROOT / "docs/outcome_gt/OUTCOME_GT_JUDGE_SYSTEM_PROMPT_v2.txt"
PROMPT_SHA256 = "80a7a218bf34ccbf33a9aa936ac9f2926184be55acd0327fa3b93617e9435ad2"
SEMANTIC_SCHEMA_PATH = ROOT / "schemas/outcome_gt_judge_semantic_response_v1.schema.json"
STRUCTURED_OUTPUT_SCHEMA_SHA256 = "d821c295054a0a5a1a8c8df6eb631f8cb0a5d5fb5e680f7d6af840dff0a1bf1f"
PROVENANCE_SCHEMA = ROOT / "schemas/outcome_gt_annotator_provenance_v2.schema.json"
PASS_VALIDATOR = ROOT / "scripts/outcome_gt/validate_outcome_gt_annotation_pass_v1.py"


def load_validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(PROVENANCE_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-id", choices=["pass_a", "pass_b"], required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    run_dir = RUN_ROOT / args.pass_id / args.run_id
    provenance_path = run_dir / "annotator_provenance_v2.json"
    decisions_path = run_dir / "decisions_v1.jsonl"
    checkpoint_path = run_dir / "checkpoint_v2.json"
    if not provenance_path.exists() or not decisions_path.exists() or not checkpoint_path.exists():
        raise FileNotFoundError("judge v2 run is missing provenance, decisions, or checkpoint")

    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    errors = list(load_validator().iter_errors(provenance))
    if errors:
        raise ValueError(f"annotator provenance v2 schema failure: {errors[0].message}")
    if provenance["pass_id"] != args.pass_id or provenance["run_id"] != args.run_id:
        raise ValueError("judge run identity mismatch")
    if provenance["status"] != "COMPLETE":
        raise ValueError(f"full pass validation requires COMPLETE judge run, got {provenance['status']}")
    if provenance["rows_target"] != EXPECTED_ROWS or provenance["rows_completed"] != EXPECTED_ROWS:
        raise ValueError("judge run does not contain the complete 1,746-row pass")
    if provenance["rows_failed"] != 0:
        raise ValueError("judge run contains failed judge requests")
    if sha256_file(PROMPT_PATH) != PROMPT_SHA256 or provenance["prompt_sha256"] != PROMPT_SHA256:
        raise ValueError("frozen prompt v2 provenance mismatch")
    if sha256_file(SEMANTIC_SCHEMA_PATH) != STRUCTURED_OUTPUT_SCHEMA_SHA256:
        raise ValueError("structured-output schema hash mismatch")
    if provenance["structured_output_schema_sha256"] != STRUCTURED_OUTPUT_SCHEMA_SHA256:
        raise ValueError("structured-output provenance mismatch")

    request_manifest_path = REQUEST_ROOT / args.pass_id / "judge_requests_1746_v2_manifest.json"
    request_manifest = json.loads(request_manifest_path.read_text(encoding="utf-8"))
    request_path = ROOT / request_manifest["request_path"]
    assignment_path = PASS_ROOT / args.pass_id / "assignment_1746_v1.jsonl"
    if provenance["request_sha256"] != sha256_file(request_path):
        raise ValueError("judge request v2 provenance mismatch")
    if provenance["assignment_sha256"] != sha256_file(assignment_path):
        raise ValueError("assignment provenance mismatch")

    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if checkpoint.get("decision_sha256") != sha256_file(decisions_path):
        raise ValueError("decision SHA-256 does not match judge checkpoint")

    output_path = run_dir / "annotations_v1.jsonl"
    manifest_path = run_dir / "annotations_v1_manifest.json"
    command = [
        sys.executable,
        str(PASS_VALIDATOR),
        "--pass-id", args.pass_id,
        "--decisions", str(decisions_path),
        "--output", str(output_path),
        "--manifest", str(manifest_path),
    ]
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        return completed.returncode

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("status") != "INDEPENDENT_PASS_COMPLETE":
        raise ValueError("canonical pass validator did not complete")
    manifest["judge_run_id"] = args.run_id
    manifest["annotator_provenance_path"] = str(provenance_path.relative_to(ROOT)).replace("\\", "/")
    manifest["annotator_provenance_sha256"] = sha256_file(provenance_path)
    manifest["judge_model_id"] = provenance["model_id"]
    manifest["judge_model_digest"] = provenance["model_digest"]
    manifest["judge_runner_version"] = provenance["runner_version"]
    manifest["judge_prompt_version"] = provenance["prompt_version"]
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "JUDGE_PASS_V2_VALIDATED",
        "pass_id": args.pass_id,
        "run_id": args.run_id,
        "model_id": provenance["model_id"],
        "annotation_rows": manifest["annotation_rows"],
        "annotation_sha256": manifest["annotation_sha256"],
        "manifest_path": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
