#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema

from outcome_gt_annotation_common_v1 import (
    EXPECTED_ROWS,
    ROOT,
    canonical_jsonl_bytes,
    read_jsonl,
    sha256_bytes,
    sha256_file,
    write_bytes_idempotent,
    write_json_idempotent,
)

PASS_ROOT = ROOT / "data/outcome_gt/adjudication_v1/passes"
OUTPUT_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_requests"
PROMPT_PATH = ROOT / "docs/outcome_gt/OUTCOME_GT_JUDGE_SYSTEM_PROMPT_v1.txt"
PROMPT_VERSION = "outcome-gt-judge-system-prompt-v1"
PROMPT_SHA256 = "a6cb893ef69ad4b688505da6a4511182f88d42956119db9af78a4b940837d64c"
REQUEST_SCHEMA_PATH = ROOT / "schemas/outcome_gt_judge_request_v1.schema.json"


def validator() -> jsonschema.Draft202012Validator:
    schema = json.loads(REQUEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def request_id(pass_id: str, assignment_item_id: str) -> str:
    letter = "A" if pass_id == "pass_a" else "B"
    suffix = hashlib.sha256(
        f"outcome-gt-judge-request-v1:{pass_id}:{assignment_item_id}:{PROMPT_SHA256}".encode("utf-8")
    ).hexdigest()[:16].upper()
    return f"OGTJR-V1-{letter}-{suffix}"


def validate_prompt() -> None:
    actual = sha256_file(PROMPT_PATH)
    if actual != PROMPT_SHA256:
        raise ValueError(f"judge prompt SHA-256 mismatch: expected {PROMPT_SHA256}, got {actual}")


def load_assignment_manifest(pass_id: str) -> dict[str, Any]:
    path = PASS_ROOT / pass_id / "assignment_1746_v1_manifest.json"
    if not path.exists():
        raise FileNotFoundError(f"missing pass manifest: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("pass_id") != pass_id or value.get("rows") != EXPECTED_ROWS:
        raise ValueError(f"{pass_id}: assignment manifest mismatch")
    if value.get("status") != "READY_FOR_INDEPENDENT_ANNOTATION":
        raise ValueError(f"{pass_id}: assignment manifest is not ready")
    return value


def materialize_one(pass_id: str, output_root: Path) -> dict[str, Any]:
    assignment_path = PASS_ROOT / pass_id / "assignment_1746_v1.jsonl"
    manifest = load_assignment_manifest(pass_id)
    if sha256_file(assignment_path) != manifest["assignment_sha256"]:
        raise ValueError(f"{pass_id}: assignment SHA-256 mismatch")

    assignments = read_jsonl(assignment_path)
    if len(assignments) != EXPECTED_ROWS:
        raise ValueError(f"{pass_id}: expected {EXPECTED_ROWS} assignments, got {len(assignments)}")
    ids = [row.get("assignment_item_id") for row in assignments]
    if len(set(ids)) != EXPECTED_ROWS:
        raise ValueError(f"{pass_id}: assignment_item_id values are not unique")
    if any(row.get("pass_id") != pass_id for row in assignments):
        raise ValueError(f"{pass_id}: assignment pass mismatch")

    rows = []
    request_validator = validator()
    for assignment in assignments:
        row = {
            "schema_version": "outcome_gt_judge_request.v1",
            "judge_request_id": request_id(pass_id, assignment["assignment_item_id"]),
            "pass_id": pass_id,
            "assignment_item_id": assignment["assignment_item_id"],
            "prompt_version": PROMPT_VERSION,
            "prompt_sha256": PROMPT_SHA256,
            "assignment": assignment,
        }
        errors = list(request_validator.iter_errors(row))
        if errors:
            raise ValueError(f"{pass_id}: request schema failure: {errors[0].message}")
        rows.append(row)

    output_dir = output_root / pass_id
    request_path = output_dir / "judge_requests_1746_v1.jsonl"
    request_manifest_path = output_dir / "judge_requests_1746_v1_manifest.json"
    request_bytes = canonical_jsonl_bytes(rows)
    request_manifest = {
        "schema_version": "outcome_gt_judge_request_manifest.v1",
        "pass_id": pass_id,
        "prompt_version": PROMPT_VERSION,
        "prompt_path": str(PROMPT_PATH.relative_to(ROOT)).replace("\\", "/"),
        "prompt_sha256": PROMPT_SHA256,
        "source_assignment_path": str(assignment_path.relative_to(ROOT)).replace("\\", "/"),
        "source_assignment_sha256": manifest["assignment_sha256"],
        "request_path": str(request_path.relative_to(ROOT)).replace("\\", "/"),
        "request_sha256": sha256_bytes(request_bytes),
        "rows": len(rows),
        "lineage_hidden_from_judge_request": True,
        "scanner_results_included": False,
        "case_gt_labels_included": False,
        "other_pass_decisions_included": False,
        "status": "READY_FOR_JUDGE_EXECUTION",
    }
    write_bytes_idempotent(request_path, request_bytes)
    write_json_idempotent(request_manifest_path, request_manifest)
    return request_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()

    validate_prompt()
    manifests = [materialize_one(pass_id, args.output_root) for pass_id in ("pass_a", "pass_b")]
    total = sum(item["rows"] for item in manifests)
    if total != EXPECTED_ROWS * 2:
        raise ValueError(f"expected {EXPECTED_ROWS * 2} judge requests, got {total}")
    print(json.dumps({
        "status": "JUDGE_REQUESTS_READY",
        "total_calls": total,
        "passes": manifests,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
