#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import jsonschema

from outcome_gt_annotation_common_v1 import (
    EXPECTED_INPUT_SHA256,
    EXPECTED_ROWS,
    PASS_ANNOTATION,
    ROOT,
    SOURCE_DATASET_SHA256,
    canonical_json,
    canonical_jsonl_bytes,
    derive_outcome_label,
    read_jsonl,
    require_input_hash,
    review_rule,
    sha256_bytes,
    sha256_file,
    validate_adjudication_population,
    validate_evidence,
    write_bytes_idempotent,
    write_json_idempotent,
)

DEFAULT_INPUT = ROOT / "data/outcome_gt/adjudication_v1/input/outcome_gt_adjudication_input_1746_v1.jsonl"
DEFAULT_PASS_ROOT = ROOT / "data/outcome_gt/adjudication_v1/passes"
ASSIGNMENT_SCHEMA = ROOT / "schemas/outcome_gt_annotation_assignment_v1.schema.json"
DECISION_SCHEMA = ROOT / "schemas/outcome_gt_independent_decision_v1.schema.json"
ANNOTATION_SCHEMA = ROOT / "schemas/outcome_gt_annotation_v1.schema.json"


def load_validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def validate_schema_rows(rows: list[dict[str, Any]], validator: jsonschema.Draft202012Validator, label: str) -> None:
    for index, row in enumerate(rows, 1):
        errors = sorted(validator.iter_errors(row), key=lambda e: list(e.path))
        if errors:
            message = "; ".join(error.message for error in errors[:5])
            raise ValueError(f"{label} row {index} schema failure: {message}")


def validate_key_rows(keys: list[dict[str, Any]], pass_id: str) -> None:
    if len(keys) != EXPECTED_ROWS:
        raise ValueError(f"private key must contain {EXPECTED_ROWS} rows")
    ids = [row.get("assignment_item_id") for row in keys]
    if len(set(ids)) != EXPECTED_ROWS:
        raise ValueError("private key assignment_item_id values are not unique")
    for row in keys:
        if row.get("schema_version") != "outcome_gt_assignment_key.v1" or row.get("pass_id") != pass_id:
            raise ValueError("private key pass/schema mismatch")
        if row.get("adjudication_input_sha256") != EXPECTED_INPUT_SHA256:
            raise ValueError("private key source hash mismatch")


def population_specific_checks(decision: dict[str, Any]) -> None:
    if decision["execution_failure"]:
        raise ValueError("this frozen 1,746-generation population contains completed responses; execution_failure must be false")


def compile_pass(
    *,
    pass_id: str,
    source_rows: list[dict[str, Any]],
    assignments: list[dict[str, Any]],
    keys: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    allow_partial: bool,
) -> list[dict[str, Any]]:
    assignment_by_id = {row["assignment_item_id"]: row for row in assignments}
    key_by_id = {row["assignment_item_id"]: row for row in keys}
    source_by_item = {row["adjudication_item_id"]: row for row in source_rows}

    if len(assignment_by_id) != EXPECTED_ROWS or set(assignment_by_id) != set(key_by_id):
        raise ValueError("assignment/private-key population mismatch")
    decision_ids = [row["assignment_item_id"] for row in decisions]
    if len(set(decision_ids)) != len(decision_ids):
        raise ValueError("decision assignment_item_id values are not unique")
    if not set(decision_ids).issubset(assignment_by_id):
        raise ValueError("decision file contains unknown assignment_item_id")
    if not allow_partial and len(decisions) != EXPECTED_ROWS:
        raise ValueError(f"complete pass requires {EXPECTED_ROWS} decisions, got {len(decisions)}")

    output: list[dict[str, Any]] = []
    for decision in decisions:
        assignment_id = decision["assignment_item_id"]
        if decision["pass_id"] != pass_id:
            raise ValueError(f"{assignment_id}: decision pass mismatch")
        assignment = assignment_by_id[assignment_id]
        key = key_by_id[assignment_id]
        source = source_by_item[key["adjudication_item_id"]]

        if key["generation_id"] != source["generation_id"] or key["production_case_id"] != source["production_case_id"]:
            raise ValueError(f"{assignment_id}: lineage mismatch")
        if key["response_sha256"] != source["response_sha256"] or assignment["response_sha256"] != source["response_sha256"]:
            raise ValueError(f"{assignment_id}: response lineage mismatch")
        if key["rule_id"] != source["rule"]["rule_id"] or assignment["rule"] != review_rule(source["rule"]):
            raise ValueError(f"{assignment_id}: rule lineage mismatch")
        if assignment["request_context"] != source["request_context"] or assignment["response_text"] != source["response_text"]:
            raise ValueError(f"{assignment_id}: reviewer view differs from source item")
        if key["source_item_sha256"] != hashlib.sha256(canonical_json(source).encode("utf-8")).hexdigest():
            raise ValueError(f"{assignment_id}: source-item hash mismatch")

        population_specific_checks(decision)
        validate_evidence(decision, source)
        outcome_label = derive_outcome_label(decision)
        output.append({
            "schema_version": "outcome_gt_annotation.v1",
            "generation_id": source["generation_id"],
            "production_case_id": source["production_case_id"],
            "source_case_id": source["source_case_id"],
            "rule_id": source["rule"]["rule_id"],
            "outcome_applicability": "applicable",
            "normal_task_completed": decision["normal_task_completed"],
            "attacker_goal_achieved": decision["attacker_goal_achieved"],
            "boundary_violated": decision["boundary_violated"],
            "refusal": decision["refusal"],
            "execution_failure": False,
            "outcome_label": outcome_label,
            "evidence": decision["evidence"],
            "rationale": decision["rationale"],
            "annotator": decision["annotator"],
            "annotation_pass": PASS_ANNOTATION[pass_id],
            "adjudication_status": "independent_complete",
            "policy_version": "outcome-gt-contract-v1",
            "rule_catalog_version": "outcome-rule-catalog-v1",
            "response_sha256": source["response_sha256"],
            "source_dataset_sha256": SOURCE_DATASET_SHA256,
        })

    output.sort(key=lambda row: row["generation_id"])
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-id", choices=["pass_a", "pass_b"], required=True)
    parser.add_argument("--source-input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--assignments", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args()

    pass_dir = DEFAULT_PASS_ROOT / args.pass_id
    assignment_path = args.assignments or pass_dir / "assignment_1746_v1.jsonl"
    key_path = args.private_key or pass_dir / "private_key_1746_v1.jsonl"
    output_path = args.output or pass_dir / "annotations_v1.jsonl"
    manifest_path = args.manifest or pass_dir / "annotations_v1_manifest.json"

    require_input_hash(args.source_input)
    source_rows = read_jsonl(args.source_input)
    source_audit = validate_adjudication_population(source_rows)
    assignments = read_jsonl(assignment_path)
    keys = read_jsonl(key_path)
    decisions = read_jsonl(args.decisions)

    validate_schema_rows(assignments, load_validator(ASSIGNMENT_SCHEMA), "assignment")
    validate_schema_rows(decisions, load_validator(DECISION_SCHEMA), "decision")
    validate_key_rows(keys, args.pass_id)
    annotations = compile_pass(
        pass_id=args.pass_id,
        source_rows=source_rows,
        assignments=assignments,
        keys=keys,
        decisions=decisions,
        allow_partial=args.allow_partial,
    )
    validate_schema_rows(annotations, load_validator(ANNOTATION_SCHEMA), "annotation")

    output_bytes = canonical_jsonl_bytes(annotations)
    write_bytes_idempotent(output_path, output_bytes)
    label_counts = Counter(row["outcome_label"] for row in annotations)
    manifest = {
        "schema_version": "outcome_gt_independent_annotation_manifest.v1",
        "pass_id": args.pass_id,
        "annotation_pass": PASS_ANNOTATION[args.pass_id],
        "source_adjudication_input_sha256": EXPECTED_INPUT_SHA256,
        "assignment_sha256": sha256_file(assignment_path),
        "private_key_sha256": sha256_file(key_path),
        "decision_sha256": sha256_file(args.decisions),
        "annotation_sha256": sha256_bytes(output_bytes),
        "annotation_rows": len(annotations),
        "source_audit": source_audit,
        "outcome_label_counts": dict(sorted(label_counts.items())),
        "status": "INDEPENDENT_PASS_COMPLETE" if len(annotations) == EXPECTED_ROWS else "INDEPENDENT_PASS_PARTIAL",
    }
    write_json_idempotent(manifest_path, manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
