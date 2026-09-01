#!/usr/bin/env python3
"""Build and validate a leakage-free blind projection for supplemental second pass."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POOL = ROOT / "data/non_pi_supplemental/candidate_pool/non_pi_supplemental_candidates_v1_1.jsonl"
FIRST = ROOT / "data/non_pi_supplemental/adjudication/first_pass/non_pi_supplemental_first_pass_305_v1.jsonl"
MANIFEST = ROOT / "data/non_pi_supplemental/adjudication/second_pass/second_pass_candidate_manifest_v1.jsonl"
OUTPUT = ROOT / "data/non_pi_supplemental/adjudication/second_pass/blind_second_pass_input_34_v1.jsonl"
REPORT = ROOT / "reports/non_pi_supplemental/second_pass/blind_input_validation_v1.json"
POOL_SHA = "8123cc5f88cc043a1b58814307644369fd6f4f6a1ad7d794905f151afaf3f050"
FIRST_SHA = "51191e9fbc982c60b5a606dc062ff65481aebcde548892c8de716ee12f71f822"
MANIFEST_SHA = "61360b75aaef3f1931c03b90ffae2b837c757e394b8302f6aa25ff3779ada876"
FORBIDDEN_FIELDS = {
    "pi_status", "maliciousness", "derived_class", "rationale", "confidence",
    "adjudicator", "adjudicated_at", "contract_version", "review_required", "review_reasons",
    "supplemental_track", "candidate_selection_reason", "original_source_label_category",
    "source_id", "source_name", "source_repo", "source_file", "source_record_id",
    "selection_group", "selection_reasons", "selection_seed", "expected_class", "provisional_direction",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def project(source: dict[str, Any]) -> dict[str, Any]:
    return {"supplemental_candidate_id": source["supplemental_candidate_id"], "original_text": source["original_text"],
            "case_context": {"delivery_context": "standalone_candidate", "interpretation_mode": "standalone"}}


def walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items(): keys.add(key); keys |= walk_keys(item)
    elif isinstance(value, list):
        for item in value: keys |= walk_keys(item)
    return keys


def run() -> dict[str, Any]:
    if sha(POOL) != POOL_SHA or sha(FIRST) != FIRST_SHA or sha(MANIFEST) != MANIFEST_SHA:
        raise ValueError("Canonical supplemental artifact hash mismatch")
    pool, first, manifest = read_jsonl(POOL), read_jsonl(FIRST), read_jsonl(MANIFEST)
    ids = [row["supplemental_candidate_id"] for row in manifest]
    if len(ids) != 34 or len(set(ids)) != 34: raise ValueError("Manifest must contain 34 unique IDs")
    by_id = {row["supplemental_candidate_id"]: row for row in pool}
    blind = [project(by_id[identifier]) for identifier in ids]
    forbidden_key_count = sum(bool(walk_keys(row) & FORBIDDEN_FIELDS) for row in blind)
    first_rationales = {row["rationale"] for row in first}
    first_text_leakage = sum(any(isinstance(value, str) and value in first_rationales for value in row.values()) for row in blind)
    output_ids = [row["supplemental_candidate_id"] for row in blind]
    validation = {"schema_version": "supplemental_blind_second_pass_validation.v1", "manifest_count": len(ids),
                  "blind_count": len(blind), "unique_id_count": len(set(output_ids)),
                  "missing_id_count": len(set(ids)-set(output_ids)), "extra_id_count": len(set(output_ids)-set(ids)),
                  "forbidden_field_rows": forbidden_key_count, "first_pass_output_text_leakage": first_text_leakage,
                  "schema_violations": sum(set(row) != {"supplemental_candidate_id", "original_text", "case_context"} for row in blind),
                  "passed": False}
    validation["passed"] = all((len(blind)==34, len(set(output_ids))==34, not validation["missing_id_count"],
                                not validation["extra_id_count"], not forbidden_key_count, not first_text_leakage,
                                not validation["schema_violations"]))
    if not validation["passed"]: raise ValueError(json.dumps(validation, indent=2))
    OUTPUT.parent.mkdir(parents=True, exist_ok=True); REPORT.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT.exists() or REPORT.exists(): raise FileExistsError("Refusing to overwrite blind artifacts")
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as handle:
        for row in blind: handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True)+"\n")
    REPORT.write_text(json.dumps(validation, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
    return validation


if __name__ == "__main__": print(json.dumps(run(), ensure_ascii=False, indent=2))
