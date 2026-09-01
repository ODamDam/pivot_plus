#!/usr/bin/env python3
"""Build the GT-field-only final adjudication queue without replacing v1 artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FIRST_ROOT = ROOT / "data/dataset_a/adjudication/case_gt_v1/first_pass"
SECOND = ROOT / "data/dataset_a/adjudication/case_gt_v1/second_pass/second_pass_ai_review_v1.jsonl"
PRIVATE = ROOT / "data/dataset_a/adjudication/case_gt_v1/second_pass/second_pass_private_map_v1.jsonl"
BLIND = ROOT / "data/dataset_a/adjudication/case_gt_v1/second_pass/second_pass_blind_input_v1.jsonl"
ELIGIBILITY = ROOT / "data/dataset_a/adjudication/case_gt_v1/case_gt_eligibility_snapshot_v1.jsonl"
OUTPUT = ROOT / "data/dataset_a/adjudication/case_gt_v1/final_adjudication/disagreement_queue_v1_1.jsonl"
SUMMARY = ROOT / "reports/dataset_a/case_gt_second_pass_v1/disagreement_queue_validation_v1_1.json"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_rows() -> list[dict[str, Any]]:
    first: dict[str, dict[str, Any]] = {}
    for number in range(1, 20):
        for row in read_jsonl(FIRST_ROOT / f"batch_{number:02d}_ai_first_pass_v1.jsonl"):
            first[row["adjudication_id"]] = row
    second = {row["adjudication_id"]: row for row in read_jsonl(SECOND)}
    private = {row["adjudication_id"]: row for row in read_jsonl(PRIVATE)}
    blind = {row["adjudication_id"]: row for row in read_jsonl(BLIND)}
    eligibility = {row["candidate_id"]: row for row in read_jsonl(ELIGIBILITY)}
    if len(first) != 902 or len(second) != len(private) != len(blind) != 197:
        raise ValueError("Input cardinality invariant failed")
    if set(second) != set(private) or set(second) != set(blind) or not set(second) <= set(first):
        raise ValueError("Input ID-set invariant failed")

    rows = []
    for adjudication_id in sorted(second):
        first_row, second_row = first[adjudication_id], second[adjudication_id]
        first_gt, second_gt = first_row["case_gt"], second_row["case_gt"]
        fields = [
            field for field in ("pi_status", "maliciousness", "derived_class")
            if first_gt[field] != second_gt[field]
        ]
        if not fields:
            continue
        blind_row = blind[adjudication_id]
        source_row = eligibility[first_row["candidate_id"]]
        rows.append({
            "schema_version": "case_gt_final_adjudication_queue.v1.1",
            "candidate_id": first_row["candidate_id"],
            "adjudication_id": adjudication_id,
            "second_pass_id": second_row["second_pass_id"],
            "source": {
                "source_id": source_row.get("source_id"),
                "source_name": source_row.get("source_name"),
                "source_revision": source_row.get("source_revision"),
                "raw_row_locator": source_row.get("raw_row_locator"),
                "normalized_text_hash": source_row.get("normalized_text_hash"),
            },
            "scenario": blind_row.get("scenario"),
            "original_adjudication_input": {
                key: value for key, value in blind_row.items()
                if key not in {"schema_version", "second_pass_id", "adjudication_id", "candidate_id"}
            },
            "first_pass": {
                "pi_status": first_gt["pi_status"],
                "maliciousness": first_gt["maliciousness"],
                "derived_class": first_gt["derived_class"],
                "rationale": first_row["rationale"],
                "confidence": first_row["reviewer_confidence"],
            },
            "second_pass": {
                "pi_status": second_gt["pi_status"],
                "maliciousness": second_gt["maliciousness"],
                "derived_class": second_gt["derived_class"],
                "rationale": second_row["rationale"],
                "confidence": second_row["reviewer_confidence"],
            },
            "disagreement_fields": fields,
            "selection_provenance": {
                "selection_group": private[adjudication_id]["selection_group"],
                "selection_reasons": private[adjudication_id]["selection_reasons"],
            },
        })
    if len(rows) != 49 or len({row["candidate_id"] for row in rows}) != 49:
        raise ValueError("Expected 49 unique GT-field disagreements")
    return rows


def run() -> dict[str, Any]:
    if OUTPUT.exists() or SUMMARY.exists():
        raise FileExistsError("Refusing to overwrite v1.1 disagreement artifacts")
    rows = build_rows()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = {
        "schema_version": "case_gt_disagreement_queue_validation_v1.1",
        "artifact_status": "PENDING_FINAL_ADJUDICATION_NOT_FINAL_GT",
        "queue_count": len(rows),
        "unique_candidate_id_count": len({row["candidate_id"] for row in rows}),
        "empty_disagreement_fields": sum(not row["disagreement_fields"] for row in rows),
        "missing_original_adjudication_input": sum("original_adjudication_input" not in row for row in rows),
        "missing_source_or_scenario": sum("source" not in row or "scenario" not in row for row in rows),
        "queue_sha256": hash_file(OUTPUT),
        "source_artifacts": {
            "second_pass_sha256": hash_file(SECOND),
            "private_map_sha256": hash_file(PRIVATE),
            "blind_input_sha256": hash_file(BLIND),
            "eligibility_snapshot_sha256": hash_file(ELIGIBILITY),
        },
    }
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
