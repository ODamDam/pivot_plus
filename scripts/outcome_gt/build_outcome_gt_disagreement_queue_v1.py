#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import jsonschema

from outcome_gt_annotation_common_v1 import (
    EXPECTED_ROWS,
    ROOT,
    canonical_jsonl_bytes,
    disagreement_id,
    read_jsonl,
    sha256_bytes,
    sha256_file,
    write_bytes_idempotent,
    write_json_idempotent,
)

DEFAULT_ROOT = ROOT / "data/outcome_gt/adjudication_v1/passes"
DEFAULT_QUEUE = ROOT / "data/outcome_gt/adjudication_v1/disagreements/outcome_gt_disagreement_queue_v1.jsonl"
DEFAULT_MANIFEST = ROOT / "data/outcome_gt/adjudication_v1/disagreements/outcome_gt_disagreement_queue_v1_manifest.json"
ANNOTATION_SCHEMA = ROOT / "schemas/outcome_gt_annotation_v1.schema.json"
DISAGREEMENT_SCHEMA = ROOT / "schemas/outcome_gt_disagreement_v1.schema.json"
COMPARE_FIELDS = (
    "normal_task_completed",
    "attacker_goal_achieved",
    "boundary_violated",
    "refusal",
    "execution_failure",
    "outcome_label",
)


def validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def validate_rows(rows: list[dict[str, Any]], v: jsonschema.Draft202012Validator, label: str) -> None:
    for index, row in enumerate(rows, 1):
        errors = list(v.iter_errors(row))
        if errors:
            raise ValueError(f"{label} row {index}: {errors[0].message}")


def snapshot(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "annotation_pass": row["annotation_pass"],
        "normal_task_completed": row["normal_task_completed"],
        "attacker_goal_achieved": row["attacker_goal_achieved"],
        "boundary_violated": row["boundary_violated"],
        "refusal": row["refusal"],
        "execution_failure": row["execution_failure"],
        "outcome_label": row["outcome_label"],
        "evidence": row["evidence"],
        "rationale": row["rationale"],
        "annotator": row["annotator"],
    }


def build(pass_a: list[dict[str, Any]], pass_b: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if len(pass_a) != EXPECTED_ROWS or len(pass_b) != EXPECTED_ROWS:
        raise ValueError(f"both independent passes must contain {EXPECTED_ROWS} rows")
    if any(row["annotation_pass"] != "first_pass" for row in pass_a):
        raise ValueError("pass A contains non-first_pass annotation")
    if any(row["annotation_pass"] != "second_pass" for row in pass_b):
        raise ValueError("pass B contains non-second_pass annotation")

    a_by_gid = {row["generation_id"]: row for row in pass_a}
    b_by_gid = {row["generation_id"]: row for row in pass_b}
    if len(a_by_gid) != EXPECTED_ROWS or len(b_by_gid) != EXPECTED_ROWS:
        raise ValueError("duplicate generation_id in independent pass")
    if set(a_by_gid) != set(b_by_gid):
        raise ValueError("independent pass generation_id sets differ")

    queue: list[dict[str, Any]] = []
    differing_counts: Counter[str] = Counter()
    lineage_fields = ("production_case_id", "source_case_id", "rule_id", "response_sha256", "policy_version", "rule_catalog_version", "source_dataset_sha256")
    for gid in sorted(a_by_gid):
        a = a_by_gid[gid]
        b = b_by_gid[gid]
        for field in lineage_fields:
            if a[field] != b[field]:
                raise ValueError(f"{gid}: independent-pass lineage mismatch at {field}")
        differing = [field for field in COMPARE_FIELDS if a[field] != b[field]]
        if not differing:
            continue
        differing_counts.update(differing)
        queue.append({
            "schema_version": "outcome_gt_disagreement.v1",
            "disagreement_id": disagreement_id(gid),
            "generation_id": gid,
            "production_case_id": a["production_case_id"],
            "source_case_id": a["source_case_id"],
            "rule_id": a["rule_id"],
            "response_sha256": a["response_sha256"],
            "differing_fields": differing,
            "pass_a": snapshot(a),
            "pass_b": snapshot(b),
            "adjudication_status": "pending",
        })
    return queue, dict(sorted(differing_counts.items()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-a", type=Path, default=DEFAULT_ROOT / "pass_a/annotations_v1.jsonl")
    parser.add_argument("--pass-b", type=Path, default=DEFAULT_ROOT / "pass_b/annotations_v1.jsonl")
    parser.add_argument("--output", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    pass_a = read_jsonl(args.pass_a)
    pass_b = read_jsonl(args.pass_b)
    av = validator(ANNOTATION_SCHEMA)
    validate_rows(pass_a, av, "pass_a")
    validate_rows(pass_b, av, "pass_b")
    queue, field_counts = build(pass_a, pass_b)
    validate_rows(queue, validator(DISAGREEMENT_SCHEMA), "disagreement")

    queue_bytes = canonical_jsonl_bytes(queue)
    write_bytes_idempotent(args.output, queue_bytes)
    manifest = {
        "schema_version": "outcome_gt_disagreement_manifest.v1",
        "pass_a_sha256": sha256_file(args.pass_a),
        "pass_b_sha256": sha256_file(args.pass_b),
        "population_rows": EXPECTED_ROWS,
        "agreement_rows": EXPECTED_ROWS - len(queue),
        "disagreement_rows": len(queue),
        "differing_field_counts": field_counts,
        "queue_sha256": sha256_bytes(queue_bytes),
        "status": "READY_FOR_FINAL_ADJUDICATION" if queue else "NO_DISAGREEMENTS",
    }
    write_json_idempotent(args.manifest, manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
