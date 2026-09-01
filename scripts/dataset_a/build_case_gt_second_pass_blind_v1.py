#!/usr/bin/env python3
"""Build the 197-record blind independent Case GT second-pass projection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SELECTION = ROOT / "data/dataset_a/adjudication/case_gt_v1/second_pass/second_pass_candidate_manifest_v1.jsonl"
BLIND_SOURCE = ROOT / "data/dataset_a/adjudication/case_gt_v1/case_gt_blind_input_v1.jsonl"
OUTPUT = ROOT / "data/dataset_a/adjudication/case_gt_v1/second_pass/second_pass_blind_input_v1.jsonl"
PRIVATE = ROOT / "data/dataset_a/adjudication/case_gt_v1/second_pass/second_pass_private_map_v1.jsonl"
FORBIDDEN_KEYS = {"first_pass", "needs_second_pass", "qc_random_sample", "edge_case", "selection_reason", "selection_reasons", "first_pass_confidence", "first_pass_rationale", "first_pass_label", "source_id", "source_name", "original_label", "provisional_gt", "scanner_result", "target_llm_response", "target_llm_outcome", "evaluator_output"}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def second_pass_id(adjudication_id: str) -> str:
    return "CGT-SP-" + hashlib.sha256(("case-gt-second-pass-v1:" + adjudication_id).encode()).hexdigest()[:16].upper()


def leaked_keys(value: Any) -> set[str]:
    found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN_KEYS: found.add(key.lower())
            found |= leaked_keys(item)
    elif isinstance(value, list):
        for item in value: found |= leaked_keys(item)
    return found


def build() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if OUTPUT.exists() or PRIVATE.exists():
        raise FileExistsError("Refusing to overwrite existing second-pass projection")
    selections = read_jsonl(SELECTION)
    source = {row["adjudication_id"]: row for row in read_jsonl(BLIND_SOURCE)}
    if len(selections) != 197 or len({r["adjudication_id"] for r in selections}) != 197:
        raise ValueError("Selection manifest must contain 197 unique adjudication IDs")
    blind, private = [], []
    for selected in sorted(selections, key=lambda row: row["adjudication_id"]):
        original = source[selected["adjudication_id"]]
        case = original["case_input"]
        sid = second_pass_id(original["adjudication_id"])
        blind_row = {
            "schema_version": "case_gt_second_pass_blind_v1",
            "second_pass_id": sid,
            "adjudication_id": original["adjudication_id"],
            "candidate_id": original["candidate_id"],
            "trusted_instruction": case.get("trusted_instruction"),
            "normal_task": case.get("normal_task"),
            "trust_boundary": case.get("trust_boundary"),
            "trusted_context": case.get("trusted_context"),
            "untrusted_input": case.get("untrusted_input"),
            "scenario": {"scenario_id": case.get("scenario_id"), "scenario_text": case.get("scenario_text")},
            "representation": {"representation_context": case.get("representation_context"), "structural_metadata": case.get("structural_metadata")},
            "delivery_context": {"delivery_context": case.get("delivery_context"), "interpretation_mode": case.get("interpretation_mode")},
        }
        leaks = leaked_keys(blind_row)
        if leaks: raise ValueError(f"Blind projection leaked metadata keys: {leaks}")
        blind.append(blind_row)
        private.append({
            "schema_version": "case_gt_second_pass_private_map_v1",
            "second_pass_id": sid,
            "adjudication_id": original["adjudication_id"],
            "candidate_id": original["candidate_id"],
            "selection_group": selected["selection_group"],
            "selection_reasons": selected["selection_reasons"],
        })
    if len({r["second_pass_id"] for r in blind}) != len(blind): raise ValueError("Duplicate second_pass_id")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    for path, rows in ((OUTPUT, blind), (PRIVATE, private)):
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows: handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return blind, private


if __name__ == "__main__":
    blind, private = build()
    print(json.dumps({"blind": len(blind), "private": len(private), "leaks": 0}, indent=2))
