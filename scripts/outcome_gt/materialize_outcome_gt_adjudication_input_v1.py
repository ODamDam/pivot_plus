#!/usr/bin/env python3
"""Materialize the 1,746 response-level Outcome GT adjudication population.

Joins the frozen 582-rule catalog to the canonical Target LLM production
attack results using generation_id and production_case_id. The output is an
annotation-view artifact; it intentionally omits Case GT labels, scanner
results, sibling responses, prior Outcome GT, and other annotator decisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

PLAN = ROOT / "experiments/target_llm_production_v1/inputs/production_main_execution_plan_2661_v1_1.jsonl"
DEFAULT_RESULTS = ROOT / "experiments/target_llm_production_v1/runs/target-llm-production-v1/results.jsonl"
RULES = ROOT / "data/outcome_gt/rule_catalog_v1/final/outcome_rules_582_v1.jsonl"
RULE_FREEZE = ROOT / "data/outcome_gt/rule_catalog_v1/final/outcome_rule_catalog_v1_freeze_manifest.json"

DEFAULT_OUTPUT = ROOT / "data/outcome_gt/adjudication_v1/input/outcome_gt_adjudication_input_1746_v1.jsonl"
DEFAULT_MANIFEST = ROOT / "data/outcome_gt/adjudication_v1/input/outcome_gt_adjudication_input_1746_v1_manifest.json"

EXPECTED_PLAN_SHA256 = "ff933826597e5d4107c011fc2507754e7cf675ef16617c15f3226737eaf79101"
EXPECTED_RESULTS_SHA256 = "350345bc370265943f36291558686888682bcbcbff6549a2c8db4babad88fe75"
EXPECTED_RULES_SHA256 = "c85f277f897d29b53445f7e292ae32babac277b564f37945a3dc99c5c90248a8"
EXPECTED_DATASET_A_SHA256 = "6cf89b6746491fadc404982f85118fbcc99bcefbc0219a5406c1d800967bcf9b"
RULE_CATALOG_CLOSURE_COMMIT = "09a57a03a1b61740f45be34e0720b74be75573ff"

EXPECTED_TOTAL_RESULTS = 2661
EXPECTED_ATTACK_GENERATIONS = 1746
EXPECTED_CASES = 582
EXPECTED_REPLICATES = {"r1", "r2", "r3"}
REPLICATE_ORDER = {"r1": 1, "r2": 2, "r3": 3}

FORBIDDEN_OUTPUT_KEYS = {
    "case_gt", "source_case_gt", "pi_status", "maliciousness", "derived_class",
    "scanner", "scanner_result", "evaluator", "evaluator_output", "evaluator_verdict",
    "outcome_gt", "outcome_label", "boundary_violated", "attacker_goal_achieved",
    "normal_task_completed", "refusal", "final_adjudication", "annotation",
    "ground_truth_decision", "sibling_response", "sibling_outcome",
    "other_annotator_decision",
}

RULE_VIEW_FIELDS = (
    "rule_id",
    "rule_catalog_version",
    "policy_version",
    "goal_types",
    "normal_task_completion_criterion",
    "boundary_violation_criterion",
    "attacker_goal",
    "attacker_goal_success_criterion",
    "edge_case_policy",
    "rule_status",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: invalid JSON at line {line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}: line {line_number} is not a JSON object")
            rows.append(value)
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        for row in rows
    )


def adjudication_item_id(generation_id: str) -> str:
    suffix = hashlib.sha256(f"outcome-gt-adjudication-input-v1:{generation_id}".encode()).hexdigest()[:16].upper()
    return f"OGTAI-V1-{suffix}"


def _require_hash(path: Path, expected: str, label: str) -> str:
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")
    return actual


def _find_forbidden_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower()
            if normalized in FORBIDDEN_OUTPUT_KEYS:
                found.add(normalized)
            found.update(_find_forbidden_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_find_forbidden_keys(item))
    return found


def validate_static_inputs(plan_rows: list[dict[str, Any]], rule_rows: list[dict[str, Any]]) -> dict[str, Any]:
    attack_plan = [row for row in plan_rows if row.get("mode") == "attack"]
    if len(plan_rows) != EXPECTED_TOTAL_RESULTS:
        raise ValueError(f"production plan must contain {EXPECTED_TOTAL_RESULTS} rows")
    if len({row.get("generation_id") for row in plan_rows}) != EXPECTED_TOTAL_RESULTS:
        raise ValueError("production plan generation_id values are not unique")
    if len(attack_plan) != EXPECTED_ATTACK_GENERATIONS:
        raise ValueError(f"attack plan must contain {EXPECTED_ATTACK_GENERATIONS} rows")

    case_to_reps: dict[str, set[str]] = defaultdict(set)
    attack_case_ids: set[str] = set()
    for row in attack_plan:
        gid = row.get("generation_id")
        case_id = row.get("production_case_id")
        replicate = row.get("replicate_index")
        if row.get("source_pool") != "dataset_a":
            raise ValueError(f"{gid}: attack source_pool must be dataset_a")
        if replicate not in EXPECTED_REPLICATES:
            raise ValueError(f"{gid}: invalid replicate_index {replicate!r}")
        materialized = row.get("materialized_request") or {}
        canonical = materialized.get("canonical_request") or {}
        if canonical.get("generation_id") != gid:
            raise ValueError(f"{gid}: canonical request generation_id mismatch")
        if canonical.get("case_id") != case_id:
            raise ValueError(f"{gid}: canonical request case_id mismatch")
        for field in ("trusted_instruction", "normal_task", "trust_boundary", "untrusted_input", "injection_location"):
            if not isinstance(canonical.get(field), str) or not canonical[field].strip():
                raise ValueError(f"{gid}: canonical request missing {field}")
        attack_case_ids.add(case_id)
        case_to_reps[case_id].add(replicate)

    if len(attack_case_ids) != EXPECTED_CASES:
        raise ValueError(f"attack plan must contain {EXPECTED_CASES} unique production cases")
    bad_reps = {case_id: sorted(reps) for case_id, reps in case_to_reps.items() if reps != EXPECTED_REPLICATES}
    if bad_reps:
        raise ValueError(f"attack replicate coverage failure: {list(bad_reps.items())[:5]}")

    if len(rule_rows) != EXPECTED_CASES:
        raise ValueError(f"rule catalog must contain {EXPECTED_CASES} rows")
    rule_case_ids = [row.get("production_case_id") for row in rule_rows]
    if len(set(rule_case_ids)) != EXPECTED_CASES:
        raise ValueError("rule catalog production_case_id values are not unique")
    if set(rule_case_ids) != attack_case_ids:
        raise ValueError("rule catalog and attack-plan production_case_id sets differ")
    if any(row.get("rule_status") != "approved" for row in rule_rows):
        raise ValueError("all frozen rules must have rule_status=approved")

    return {
        "plan_rows": len(plan_rows),
        "attack_plan_rows": len(attack_plan),
        "rule_rows": len(rule_rows),
        "production_cases": len(attack_case_ids),
        "replicate_coverage": "r1_r2_r3_exact",
    }


def validate_results(result_rows: list[dict[str, Any]], attack_plan_by_gid: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if len(result_rows) != EXPECTED_TOTAL_RESULTS:
        raise ValueError(f"production results must contain {EXPECTED_TOTAL_RESULTS} rows")
    gids = [row.get("generation_id") for row in result_rows]
    if len(set(gids)) != EXPECTED_TOTAL_RESULTS:
        raise ValueError("production result generation_id values are not unique")
    if any(row.get("execution_status") != "completed" for row in result_rows):
        raise ValueError("production results contain non-completed execution")

    attack_results = [row for row in result_rows if row.get("mode") == "attack"]
    if len(attack_results) != EXPECTED_ATTACK_GENERATIONS:
        raise ValueError(f"attack results must contain {EXPECTED_ATTACK_GENERATIONS} rows")

    attack_result_ids = {row["generation_id"] for row in attack_results}
    if attack_result_ids != set(attack_plan_by_gid):
        missing = sorted(set(attack_plan_by_gid) - attack_result_ids)
        extra = sorted(attack_result_ids - set(attack_plan_by_gid))
        raise ValueError(f"attack plan/result generation_id mismatch; missing={missing[:5]}, extra={extra[:5]}")

    for result in attack_results:
        gid = result["generation_id"]
        plan = attack_plan_by_gid[gid]
        if result.get("production_case_id") != plan.get("production_case_id"):
            raise ValueError(f"{gid}: production_case_id mismatch")
        if result.get("replicate_index") != plan.get("replicate_index"):
            raise ValueError(f"{gid}: replicate_index mismatch")
        if result.get("source_pool") != "dataset_a":
            raise ValueError(f"{gid}: result source_pool must be dataset_a")
        text = result.get("response_text")
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"{gid}: empty response_text")
        actual_response_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if result.get("response_sha256") != actual_response_sha:
            raise ValueError(f"{gid}: response_sha256 mismatch")
    return attack_results


def build_item(
    plan: dict[str, Any],
    result: dict[str, Any],
    rule: dict[str, Any],
    *,
    plan_sha256: str,
    results_sha256: str,
    rules_sha256: str,
    results_path: Path,
) -> dict[str, Any]:
    gid = result["generation_id"]
    canonical = plan["materialized_request"]["canonical_request"]

    if rule.get("production_case_id") != result.get("production_case_id"):
        raise ValueError(f"{gid}: rule production_case_id mismatch")
    if "source_case_id" in result and rule.get("source_case_id") != result.get("source_case_id"):
        raise ValueError(f"{gid}: source_case_id mismatch")

    rule_view = {field: rule[field] for field in RULE_VIEW_FIELDS}
    item = {
        "schema_version": "outcome_gt_adjudication_input.v1",
        "adjudication_item_id": adjudication_item_id(gid),
        "generation_id": gid,
        "production_case_id": result["production_case_id"],
        "source_case_id": rule["source_case_id"],
        "replicate_index": result["replicate_index"],
        "outcome_applicability": "applicable",
        "response_text": result["response_text"],
        "response_sha256": result["response_sha256"],
        "request_context": {
            "trusted_instruction": canonical["trusted_instruction"],
            "normal_task": canonical["normal_task"],
            "trust_boundary": canonical["trust_boundary"],
            "trusted_context": canonical.get("trusted_context"),
            "untrusted_input": canonical["untrusted_input"],
            "injection_location": canonical["injection_location"],
        },
        "rule": rule_view,
        "provenance": {
            "production_plan_path": str(PLAN.relative_to(ROOT)).replace("\\", "/"),
            "production_plan_sha256": plan_sha256,
            "production_results_path": (
                str(results_path.relative_to(ROOT)).replace("\\", "/")
                if results_path.is_relative_to(ROOT)
                else str(results_path)
            ),
            "production_results_sha256": results_sha256,
            "rule_catalog_path": str(RULES.relative_to(ROOT)).replace("\\", "/"),
            "rule_catalog_sha256": rules_sha256,
            "rule_catalog_closure_commit": RULE_CATALOG_CLOSURE_COMMIT,
            "source_dataset_sha256": EXPECTED_DATASET_A_SHA256,
        },
        "view_guarantees": {
            "scanner_results_included": False,
            "case_gt_labels_included": False,
            "sibling_responses_included": False,
            "existing_outcome_gt_included": False,
            "other_annotator_decisions_included": False,
        },
    }
    forbidden = _find_forbidden_keys(item)
    if forbidden:
        raise ValueError(f"{gid}: forbidden annotation-view keys: {sorted(forbidden)}")
    return item


def materialize(results_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not results_path.exists():
        raise FileNotFoundError(
            f"canonical production results not found: {results_path}. "
            "Run this materializer in the retained production-results working copy."
        )

    plan_sha = _require_hash(PLAN, EXPECTED_PLAN_SHA256, "production plan")
    results_sha = _require_hash(results_path, EXPECTED_RESULTS_SHA256, "production results")
    rules_sha = _require_hash(RULES, EXPECTED_RULES_SHA256, "frozen rule catalog")

    freeze = json.loads(RULE_FREEZE.read_text(encoding="utf-8"))
    if freeze.get("status") != "FROZEN_APPROVED_CLOSED":
        raise ValueError("Outcome Rule Catalog v1 is not frozen/closed")
    if freeze.get("rules", {}).get("sha256") != rules_sha:
        raise ValueError("rule freeze manifest hash does not match frozen catalog")

    plan_rows = read_jsonl(PLAN)
    rule_rows = read_jsonl(RULES)
    static_audit = validate_static_inputs(plan_rows, rule_rows)

    attack_plan = [row for row in plan_rows if row["mode"] == "attack"]
    attack_plan_by_gid = {row["generation_id"]: row for row in attack_plan}
    rule_by_case = {row["production_case_id"]: row for row in rule_rows}

    result_rows = read_jsonl(results_path)
    attack_results = validate_results(result_rows, attack_plan_by_gid)

    items = [
        build_item(
            attack_plan_by_gid[result["generation_id"]],
            result,
            rule_by_case[result["production_case_id"]],
            plan_sha256=plan_sha,
            results_sha256=results_sha,
            rules_sha256=rules_sha,
            results_path=results_path,
        )
        for result in attack_results
    ]
    items.sort(key=lambda row: (row["production_case_id"], REPLICATE_ORDER[row["replicate_index"]]))

    if len(items) != EXPECTED_ATTACK_GENERATIONS:
        raise ValueError("materialized adjudication population count mismatch")
    if len({row["generation_id"] for row in items}) != EXPECTED_ATTACK_GENERATIONS:
        raise ValueError("materialized generation_id values are not unique")
    if len({row["adjudication_item_id"] for row in items}) != EXPECTED_ATTACK_GENERATIONS:
        raise ValueError("materialized adjudication_item_id values are not unique")

    output_bytes = canonical_jsonl_bytes(items)
    audit = {
        "schema_version": "outcome_gt_adjudication_input_manifest.v1",
        "status": "READY_FOR_OUTCOME_GT_ADJUDICATION",
        "outcome_gt_contract": "outcome-gt-contract-v1",
        "rule_catalog_version": "outcome-rule-catalog-v1",
        "rule_catalog_closure_commit": RULE_CATALOG_CLOSURE_COMMIT,
        "population": {
            "production_cases": EXPECTED_CASES,
            "generations": EXPECTED_ATTACK_GENERATIONS,
            "replicates_per_case": 3,
            "replicate_ids": ["r1", "r2", "r3"],
        },
        "inputs": {
            "production_plan": {"path": str(PLAN.relative_to(ROOT)).replace("\\", "/"), "sha256": plan_sha},
            "production_results": {
                "path": (
                    str(results_path.relative_to(ROOT)).replace("\\", "/")
                    if results_path.is_relative_to(ROOT)
                    else str(results_path)
                ),
                "sha256": results_sha,
            },
            "rule_catalog": {"path": str(RULES.relative_to(ROOT)).replace("\\", "/"), "sha256": rules_sha},
            "source_dataset_sha256": EXPECTED_DATASET_A_SHA256,
        },
        "static_join_audit": static_audit,
        "join_invariants": {
            "attack_plan_result_generation_id_set_equal": True,
            "rule_case_set_equals_attack_case_set": True,
            "each_case_has_exact_r1_r2_r3": True,
            "response_hashes_verified": True,
            "scanner_results_included": False,
            "case_gt_labels_included": False,
            "sibling_responses_included_per_item": False,
            "existing_outcome_gt_included": False,
        },
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
    }
    return items, audit


def _exclusive_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)


def static_preflight() -> dict[str, Any]:
    plan_sha = _require_hash(PLAN, EXPECTED_PLAN_SHA256, "production plan")
    rules_sha = _require_hash(RULES, EXPECTED_RULES_SHA256, "frozen rule catalog")
    freeze = json.loads(RULE_FREEZE.read_text(encoding="utf-8"))
    if freeze.get("status") != "FROZEN_APPROVED_CLOSED":
        raise ValueError("Outcome Rule Catalog v1 is not frozen/closed")
    audit = validate_static_inputs(read_jsonl(PLAN), read_jsonl(RULES))
    return {
        "status": "STATIC_INPUTS_READY",
        "plan_sha256": plan_sha,
        "rule_catalog_sha256": rules_sha,
        **audit,
        "canonical_results_required_sha256": EXPECTED_RESULTS_SHA256,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--static-preflight", action="store_true")
    args = parser.parse_args()

    if args.static_preflight:
        print(json.dumps(static_preflight(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    items, manifest = materialize(args.results)
    payload = canonical_jsonl_bytes(items)
    _exclusive_write(args.output, payload)
    manifest["output_path"] = (
        str(args.output.relative_to(ROOT)).replace("\\", "/")
        if args.output.is_relative_to(ROOT)
        else str(args.output)
    )
    _exclusive_write(
        args.manifest,
        (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
