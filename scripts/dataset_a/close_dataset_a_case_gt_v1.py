#!/usr/bin/env python3
"""Merge completed human decisions and freeze the 902-record Dataset A Case GT."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.dataset_a.validate_dataset_a_final_adjudication_v1 import derive, read_jsonl, validate
except ModuleNotFoundError:
    from validate_dataset_a_final_adjudication_v1 import derive, read_jsonl, validate


ROOT = Path(__file__).resolve().parents[2]
ELIGIBILITY = ROOT / "data/dataset_a/adjudication/case_gt_v1/case_gt_eligibility_snapshot_v1.jsonl"
BLIND = ROOT / "data/dataset_a/adjudication/case_gt_v1/case_gt_blind_input_v1.jsonl"
FIRST_ROOT = ROOT / "data/dataset_a/adjudication/case_gt_v1/first_pass"
SECOND = ROOT / "data/dataset_a/adjudication/case_gt_v1/second_pass/second_pass_ai_review_v1.jsonl"
QUEUE = ROOT / "data/dataset_a/adjudication/case_gt_v1/final_adjudication/disagreement_queue_v1_1.jsonl"
DEFAULT_DECISIONS = ROOT / "data/dataset_a/adjudication/case_gt_v1/final_adjudication/final_adjudication_49_completed_v1.jsonl"
FINAL = ROOT / "data/dataset_a/final/dataset_a_case_gt_902_v1.jsonl"
VALIDATION = ROOT / "reports/dataset_a/final_closure_v1/dataset_a_case_gt_902_validation_v1.json"
FREEZE = ROOT / "data/dataset_a/freeze/dataset_a_freeze_v1.json"
REPORT = ROOT / "reports/dataset_a/final_closure_v1/DATASET_A_CLOSURE_REPORT_v1.md"
ALLOWED_LICENSE = {"APPROVED_WITH_CONDITIONS", "CONDITIONALLY_APPROVED"}
ALLOWED_PI = {"clear_pi", "context_dependent_pi", "not_pi", "ambiguous", "out_of_scope"}
ALLOWED_MAL = {"malicious", "non_malicious", "ambiguous", "not_applicable"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_text_lf(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)


def git_head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def load_first() -> dict[str, dict[str, Any]]:
    rows = []
    for number in range(1, 20):
        rows += read_jsonl(FIRST_ROOT / f"batch_{number:02d}_ai_first_pass_v1.jsonl")
    result = {row["candidate_id"]: row for row in rows}
    if len(rows) != 902 or len(result) != 902:
        raise ValueError("First-pass cardinality invariant failed")
    return result


def normalized_decisions(path: Path) -> list[dict[str, Any]]:
    rows = read_jsonl(path)
    for row in rows:
        pi, mal = row.get("final_pi_status"), row.get("final_maliciousness")
        if pi in ALLOWED_PI and mal in ALLOWED_MAL:
            row["derived_class"] = derive(pi, mal)
    return rows


def preflight(path: Path) -> dict[str, Any]:
    return validate(read_jsonl(QUEUE), normalized_decisions(path), require_complete=True)


def build_final(decisions_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    eligibility_rows, blind_rows = read_jsonl(ELIGIBILITY), read_jsonl(BLIND)
    eligibility = {row["candidate_id"]: row for row in eligibility_rows}
    blind = {row["candidate_id"]: row for row in blind_rows}
    first = load_first()
    second = {row["candidate_id"]: row for row in read_jsonl(SECOND)}
    queue_ids = {row["candidate_id"] for row in read_jsonl(QUEUE)}
    decisions_list = normalized_decisions(decisions_path)
    decision_validation = validate(read_jsonl(QUEUE), decisions_list, require_complete=True)
    if not decision_validation["passed"]:
        raise ValueError(json.dumps(decision_validation, ensure_ascii=False))
    decisions = {row["candidate_id"]: row for row in decisions_list}
    if not (len(eligibility) == len(blind) == len(first) == 902 and set(eligibility) == set(blind) == set(first)):
        raise ValueError("Eligible/blind/first-pass ID-set invariant failed")

    final = []
    for candidate_id in sorted(eligibility):
        first_row = first[candidate_id]
        if candidate_id in queue_ids:
            decision = decisions[candidate_id]
            pi, mal = decision["final_pi_status"], decision["final_maliciousness"]
            rationale = decision["final_rationale"]
            resolution = "human_final_adjudication"
            adjudicator = decision["adjudicator"]
            adjudicated_at = decision["adjudicated_at"]
        else:
            gt = first_row["case_gt"]
            pi, mal, rationale = gt["pi_status"], gt["maliciousness"], first_row["rationale"]
            if candidate_id in second:
                sgt = second[candidate_id]["case_gt"]
                if (pi, mal) != (sgt["pi_status"], sgt["maliciousness"]):
                    raise ValueError(f"Unqueued GT disagreement: {candidate_id}")
                resolution = "independent_first_second_agreement"
            else:
                resolution = "first_pass_not_selected_for_second_pass"
            adjudicator = None
            adjudicated_at = None
        e = eligibility[candidate_id]
        final.append({
            "schema_version": "dataset_a_case_gt_final.v1",
            "candidate_id": candidate_id,
            "adjudication_id": first_row["adjudication_id"],
            "case_input": blind[candidate_id]["case_input"],
            "case_gt": {
                "pi_status": pi,
                "maliciousness": mal,
                "derived_class": derive(pi, mal),
                "rationale": rationale,
            },
            "adjudication_provenance": {
                "resolution": resolution,
                "first_pass_reviewer_id": first_row.get("reviewer_id"),
                "second_pass_id": second.get(candidate_id, {}).get("second_pass_id"),
                "adjudicator": adjudicator,
                "adjudicated_at": adjudicated_at,
                "contract_version": "GT Adjudication Contract v2",
            },
            "source_provenance": {
                key: e.get(key) for key in (
                    "source_id", "source_name", "source_revision", "raw_file_path", "raw_file_sha256",
                    "raw_row_locator", "raw_text_hash", "normalized_text_hash", "normalization_method", "provenance_status"
                )
            },
            "license": {
                "eligibility_status": e.get("license_eligibility_status"),
                "official_license": e.get("official_license"),
                "evidence_ref": e.get("license_evidence_ref"),
                "required_obligations": e.get("required_obligations"),
            },
        })
    return final, decision_validation


def validate_final(rows: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = read_jsonl(ELIGIBILITY)
    eligible_ids = {row["candidate_id"] for row in eligible}
    ids = [row.get("candidate_id") for row in rows]
    missing, extra = eligible_ids - set(ids), set(ids) - eligible_ids
    enum = derived_bad = provenance_missing = license_missing = blocked = required_missing = 0
    for row in rows:
        gt = row.get("case_gt") or {}; pi, mal = gt.get("pi_status"), gt.get("maliciousness")
        required_missing += int(not all((pi, mal, gt.get("derived_class"), gt.get("rationale"))))
        enum += int(pi not in ALLOWED_PI or mal not in ALLOWED_MAL)
        if pi in ALLOWED_PI and mal in ALLOWED_MAL:
            derived_bad += int(gt.get("derived_class") != derive(pi, mal))
        provenance_missing += int(not row.get("adjudication_provenance") or not row.get("source_provenance"))
        status = (row.get("license") or {}).get("eligibility_status")
        license_missing += int(status is None)
        blocked += int(status not in ALLOWED_LICENSE)
    result = {
        "schema_version": "dataset_a_case_gt_final_validation.v1",
        "rows": len(rows),
        "unique_candidate_ids": len(set(ids)),
        "eligible_candidate_ids": len(eligible_ids),
        "missing_ids": len(missing), "extra_ids": len(extra),
        "case_gt_required_fields_coverage": len(rows) - required_missing,
        "enum_violations": enum, "derived_class_inconsistencies": derived_bad,
        "provenance_coverage": len(rows) - provenance_missing,
        "license_eligibility_coverage": len(rows) - license_missing,
        "blocked_source_contamination": blocked,
        "unresolved_gt": required_missing,
    }
    result["passed"] = all((
        len(rows) == 902, len(set(ids)) == 902, not missing, not extra, not required_missing,
        not enum, not derived_bad, not provenance_missing, not license_missing, not blocked,
    ))
    result["source_distribution"] = dict(sorted(Counter(row["source_provenance"]["source_id"] for row in rows).items()))
    result["final_case_gt_distribution"] = dict(sorted(Counter(row["case_gt"]["derived_class"] for row in rows).items()))
    return result


def run(decisions_path: Path) -> dict[str, Any]:
    for path in (FINAL, VALIDATION, FREEZE, REPORT):
        if path.exists(): raise FileExistsError(f"Refusing to overwrite {path}")
    rows, decision_validation = build_final(decisions_path)
    validation = validate_final(rows)
    if not validation["passed"]: raise ValueError(json.dumps(validation, ensure_ascii=False))
    FINAL.parent.mkdir(parents=True, exist_ok=True)
    with FINAL.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows: handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    write_text_lf(VALIDATION, json.dumps(validation, ensure_ascii=False, indent=2) + "\n")
    timestamp = datetime.now(timezone.utc).isoformat()
    parent_hashes = {
        "eligibility_snapshot": sha256(ELIGIBILITY), "blind_input": sha256(BLIND),
        "second_pass": sha256(SECOND), "disagreement_queue": sha256(QUEUE),
        "final_adjudication": sha256(decisions_path),
        "first_pass_batches": {
            f"batch_{number:02d}": sha256(FIRST_ROOT / f"batch_{number:02d}_ai_first_pass_v1.jsonl")
            for number in range(1, 20)
        },
    }
    freeze = {
        "schema_version": "dataset_a_freeze.v1", "status": "DATASET_A_FROZEN",
        "frozen_dataset_path": FINAL.relative_to(ROOT).as_posix(), "row_count": 902,
        "sha256": sha256(FINAL), "source_distribution": validation["source_distribution"],
        "final_case_gt_distribution": validation["final_case_gt_distribution"],
        "construction_version": "dataset_a_case_gt_final.v1", "adjudication_version": "final_adjudication_49_v1",
        "relevant_contract_versions": ["pivot-dataset-a-spec-v1.0", "GT Adjudication Contract v2"],
        "timestamp": timestamp, "git_commit": git_head(), "parent_artifact_hashes": parent_hashes,
        "run_id": "dataset-a-final-closure-v1", "random_seed": "not_applicable_deterministic_merge",
        "validation_path": VALIDATION.relative_to(ROOT).as_posix(), "validation_status": "PASS",
    }
    write_text_lf(FREEZE, json.dumps(freeze, ensure_ascii=False, indent=2) + "\n")
    write_text_lf(REPORT,
        "# Dataset A Closure Report v1\n\n"
        f"- Status: `DATASET_A_FROZEN`\n- Final adjudication: 49/49\n- Final Case GT: 902/902\n"
        f"- Unresolved: 0\n- Validation: PASS\n- Dataset SHA-256: `{freeze['sha256']}`\n"
        f"- Distribution: `{json.dumps(validation['final_case_gt_distribution'], sort_keys=True)}`\n",
    )
    return {"decision_validation": decision_validation, "final_validation": validation, "freeze": freeze}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    if args.preflight_only:
        result = preflight(args.decisions); print(json.dumps(result, ensure_ascii=False, indent=2)); return 0 if result["passed"] else 1
    print(json.dumps(run(args.decisions), ensure_ascii=False, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
