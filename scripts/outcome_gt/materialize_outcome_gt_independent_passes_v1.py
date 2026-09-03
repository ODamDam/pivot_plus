#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from outcome_gt_annotation_common_v1 import (
    EXPECTED_INPUT_SHA256,
    PASS_SEEDS,
    ROOT,
    assignment_item_id,
    canonical_json,
    canonical_jsonl_bytes,
    read_jsonl,
    require_input_hash,
    review_rule,
    sha256_bytes,
    validate_adjudication_population,
    write_bytes_idempotent,
    write_json_idempotent,
)

DEFAULT_INPUT = ROOT / "data/outcome_gt/adjudication_v1/input/outcome_gt_adjudication_input_1746_v1.jsonl"
DEFAULT_ROOT = ROOT / "data/outcome_gt/adjudication_v1/passes"


def source_item_sha(row: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(row).encode("utf-8")).hexdigest()


def build_assignment(row: dict[str, Any], pass_id: str) -> dict[str, Any]:
    return {
        "schema_version": "outcome_gt_annotation_assignment.v1",
        "assignment_item_id": assignment_item_id(pass_id, row["generation_id"]),
        "pass_id": pass_id,
        "response_text": row["response_text"],
        "response_sha256": row["response_sha256"],
        "request_context": row["request_context"],
        "rule": review_rule(row["rule"]),
        "view_guarantees": {
            "lineage_ids_exposed": False,
            "rule_id_exposed": False,
            "replicate_index_exposed": False,
            "case_gt_labels_included": False,
            "scanner_results_included": False,
            "sibling_responses_included": False,
            "existing_outcome_gt_included": False,
            "other_annotator_decisions_included": False,
        },
    }


def build_key(row: dict[str, Any], pass_id: str) -> dict[str, Any]:
    return {
        "schema_version": "outcome_gt_assignment_key.v1",
        "assignment_item_id": assignment_item_id(pass_id, row["generation_id"]),
        "pass_id": pass_id,
        "adjudication_item_id": row["adjudication_item_id"],
        "generation_id": row["generation_id"],
        "production_case_id": row["production_case_id"],
        "source_case_id": row["source_case_id"],
        "replicate_index": row["replicate_index"],
        "rule_id": row["rule"]["rule_id"],
        "response_sha256": row["response_sha256"],
        "source_item_sha256": source_item_sha(row),
        "adjudication_input_sha256": EXPECTED_INPUT_SHA256,
    }


def order_key(pass_id: str, row: dict[str, Any]) -> str:
    return hashlib.sha256(f"{PASS_SEEDS[pass_id]}:order:{row['generation_id']}".encode()).hexdigest()


def materialize_one(rows: list[dict[str, Any]], pass_id: str, output_root: Path) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: order_key(pass_id, row))
    assignments = [build_assignment(row, pass_id) for row in ordered]
    keys = [build_key(row, pass_id) for row in ordered]

    forbidden = {
        "generation_id", "production_case_id", "source_case_id", "replicate_index",
        "adjudication_item_id", "rule_id", "binding_provenance", "provenance",
    }
    leaked: list[str] = []
    for row in assignments:
        text = canonical_json(row)
        for key in forbidden:
            if f'"{key}"' in text:
                leaked.append(key)
    if leaked:
        raise ValueError(f"review assignment exposes hidden lineage keys: {sorted(set(leaked))}")

    pass_dir = output_root / pass_id
    assignment_path = pass_dir / "assignment_1746_v1.jsonl"
    key_path = pass_dir / "private_key_1746_v1.jsonl"
    manifest_path = pass_dir / "assignment_1746_v1_manifest.json"

    assignment_bytes = canonical_jsonl_bytes(assignments)
    key_bytes = canonical_jsonl_bytes(keys)
    manifest = {
        "schema_version": "outcome_gt_annotation_assignment_manifest.v1",
        "pass_id": pass_id,
        "source_adjudication_input_sha256": EXPECTED_INPUT_SHA256,
        "assignment_path": str(assignment_path.relative_to(ROOT)).replace("\\", "/"),
        "assignment_sha256": sha256_bytes(assignment_bytes),
        "private_key_path": str(key_path.relative_to(ROOT)).replace("\\", "/"),
        "private_key_sha256": sha256_bytes(key_bytes),
        "rows": len(assignments),
        "lineage_hidden_from_assignment": True,
        "rule_id_hidden_from_assignment": True,
        "replicate_index_hidden_from_assignment": True,
        "scanner_results_included": False,
        "case_gt_labels_included": False,
        "sibling_responses_included_per_item": False,
        "other_pass_decisions_included": False,
        "status": "READY_FOR_INDEPENDENT_ANNOTATION",
    }
    write_bytes_idempotent(assignment_path, assignment_bytes)
    write_bytes_idempotent(key_path, key_bytes)
    write_json_idempotent(manifest_path, manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()

    require_input_hash(args.input)
    rows = read_jsonl(args.input)
    audit = validate_adjudication_population(rows)
    manifests = [materialize_one(rows, pass_id, args.output_root) for pass_id in ("pass_a", "pass_b")]
    print(json.dumps({"status": "INDEPENDENT_PASSES_READY", "source_audit": audit, "passes": manifests}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
