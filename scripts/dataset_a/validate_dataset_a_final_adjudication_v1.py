#!/usr/bin/env python3
"""Validate Dataset A's 49 human final-adjudication decisions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
QUEUE = ROOT / "data/dataset_a/adjudication/case_gt_v1/final_adjudication/disagreement_queue_v1_1.jsonl"
DEFAULT_INPUT = ROOT / "data/dataset_a/adjudication/case_gt_v1/final_adjudication/final_adjudication_49_completed_v1.jsonl"
PI = {"clear_pi", "context_dependent_pi", "not_pi", "ambiguous", "out_of_scope"}
MAL = {"malicious", "non_malicious", "ambiguous", "not_applicable"}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def derive(pi: str, mal: str) -> str:
    if pi == "out_of_scope": return "out_of_scope"
    if pi == "ambiguous" or mal in {"ambiguous", "not_applicable"}: return "boundary_ambiguous"
    if pi in {"clear_pi", "context_dependent_pi"}: return "pi_malicious" if mal == "malicious" else "pi_non_malicious"
    return "non_pi_malicious" if mal == "malicious" else "non_pi_non_malicious"


def validate(queue: list[dict[str, Any]], decisions: list[dict[str, Any]], require_complete: bool = True) -> dict[str, Any]:
    queue_ids = [row["candidate_id"] for row in queue]
    decision_ids = [row.get("candidate_id") for row in decisions]
    errors = []
    if len(decisions) != 49: errors.append(f"row_count={len(decisions)}")
    if len(decision_ids) != len(set(decision_ids)): errors.append("duplicate_candidate_id")
    missing, extra = sorted(set(queue_ids) - set(decision_ids)), sorted(set(decision_ids) - set(queue_ids))
    if missing: errors.append(f"missing_ids={len(missing)}")
    if extra: errors.append(f"extra_ids={len(extra)}")
    complete = 0
    enum_violations = derived_violations = rationale_missing = 0
    for row in decisions:
        pi, mal = row.get("final_pi_status"), row.get("final_maliciousness")
        required = (pi, mal, row.get("final_rationale"), row.get("adjudicator"), row.get("adjudicated_at"))
        if not all(value is not None and str(value).strip() for value in required):
            if require_complete: errors.append(f"{row.get('candidate_id')}:incomplete")
            if pi in PI or mal in MAL:
                enum_violations += int(pi not in PI) + int(mal not in MAL)
            continue
        complete += 1
        if pi not in PI or mal not in MAL:
            enum_violations += 1; errors.append(f"{row.get('candidate_id')}:enum")
            continue
        expected = derive(pi, mal)
        if row.get("derived_class") is not None and row.get("derived_class") != expected:
            derived_violations += 1; errors.append(f"{row.get('candidate_id')}:derived_class")
        if not str(row.get("final_rationale", "")).strip():
            rationale_missing += 1; errors.append(f"{row.get('candidate_id')}:rationale")
    return {
        "schema_version": "dataset_a_final_adjudication_validation.v1",
        "passed": not errors,
        "row_count": len(decisions),
        "unique_candidate_id_count": len(set(decision_ids)),
        "missing_id_count": len(missing),
        "extra_id_count": len(extra),
        "complete_count": complete,
        "unresolved": 49 - complete,
        "enum_violations": enum_violations,
        "derived_class_inconsistencies": derived_violations,
        "required_rationale_missing": rationale_missing,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    result = validate(read_jsonl(QUEUE), read_jsonl(args.input), not args.allow_incomplete)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
