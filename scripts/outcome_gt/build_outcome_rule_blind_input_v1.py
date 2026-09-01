#!/usr/bin/env python3
"""Build the response-blind, case-level authoring input for Outcome Rule Catalog v1."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = ROOT / "data/dataset_a/final/dataset_a_case_gt_902_v1.jsonl"
MANIFEST_PATH = ROOT / "experiments/target_llm_production_v1/inputs/production_generation_manifest_1207_v1_1.jsonl"
PLAN_PATH = ROOT / "experiments/target_llm_production_v1/inputs/production_main_execution_plan_2661_v1_1.jsonl"
DEFAULT_OUTPUT = ROOT / "data/outcome_gt/rule_catalog_v1/outcome_rule_blind_input_582_v1.jsonl"
DEFAULT_PROVENANCE = ROOT / "data/outcome_gt/rule_catalog_v1/outcome_rule_blind_input_582_v1_manifest.json"

RUNTIME_FIELDS = (
    "scenario_id",
    "trusted_instruction",
    "normal_task",
    "trust_boundary",
    "trusted_context",
    "untrusted_input",
    "injection_location",
)
EXPECTED_REPLICATES = {"r1", "r2", "r3"}
FORBIDDEN_KEYS = {
    "response",
    "response_text",
    "endpoint_response",
    "response_sha256",
    "scanner_result",
    "scanner",
    "evaluator",
    "evaluator_output",
    "evaluator_verdict",
    "outcome",
    "outcome_gt",
    "behavioral_evaluation",
    "final_adjudication",
    "annotation",
    "source_case_gt",
    "sibling_outcome",
    "sibling_result",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


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


def find_forbidden_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.lower()
            if normalized in FORBIDDEN_KEYS:
                found.add(normalized)
            found.update(find_forbidden_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(find_forbidden_keys(item))
    return found


def blind_rule_case_id(production_case_id: str) -> str:
    suffix = hashlib.sha256(
        f"outcome-rule-blind-input-v1:{production_case_id}".encode("utf-8")
    ).hexdigest()[:16].upper()
    return f"ORBI-V1-{suffix}"


def _load_sources() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    return read_jsonl(DATASET_PATH), read_jsonl(MANIFEST_PATH), read_jsonl(PLAN_PATH)


def _source_audit(
    dataset: list[dict[str, Any]],
    manifest: list[dict[str, Any]],
    plan: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    manifest_by_case = {row["production_case_id"]: row for row in manifest}
    dataset_by_case = {row["candidate_id"]: row for row in dataset}
    plans_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in plan:
        plans_by_case[row["production_case_id"]].append(row)

    dataset_attack = [
        row for row in plan if row.get("source_pool") == "dataset_a" and row.get("mode") == "attack"
    ]
    supplemental = [
        row
        for row in plan
        if row.get("source_pool") == "non_pi_supplemental" and row.get("mode") == "direct"
    ]
    runtime_cases = {
        row["production_case_id"]
        for row in manifest
        if row.get("source_pool") == "dataset_a"
        and row.get("runtime_outcome_applicability") == "applicable"
    }
    standalone_cases = {
        row["production_case_id"]
        for row in manifest
        if row.get("source_pool") == "dataset_a"
        and row.get("runtime_outcome_applicability") == "not_applicable_no_runtime_boundary"
    }

    manifest_join_failures = 0
    dataset_join_failures = 0
    runtime_field_missing_count = 0
    replicate_runtime_mismatch_count = 0
    replicate_counts = Counter(row.get("replicate_index") for row in dataset_attack)

    for production_case_id in sorted(runtime_cases):
        manifest_row = manifest_by_case.get(production_case_id)
        if manifest_row is None:
            manifest_join_failures += 1
            continue
        source_row = dataset_by_case.get(manifest_row.get("source_case_id"))
        if source_row is None:
            dataset_join_failures += 1
            continue
        case_plans = plans_by_case.get(production_case_id, [])
        if len(case_plans) != 3 or {row.get("replicate_index") for row in case_plans} != EXPECTED_REPLICATES:
            replicate_runtime_mismatch_count += 1
            continue
        canonical = [row["materialized_request"]["canonical_request"] for row in case_plans]
        baseline = {field: canonical[0].get(field) for field in RUNTIME_FIELDS}
        runtime_field_missing_count += sum(
            not isinstance(baseline[field], str) or not baseline[field].strip()
            for field in RUNTIME_FIELDS
            if field != "trusted_context"
        )
        if any({field: request.get(field) for field in RUNTIME_FIELDS} != baseline for request in canonical[1:]):
            replicate_runtime_mismatch_count += 1
        source_case = source_row["case_input"]
        expected_from_source = {
            "trusted_instruction": source_case.get("trusted_instruction"),
            "normal_task": source_case.get("normal_task"),
            "trust_boundary": source_case.get("trust_boundary"),
            "trusted_context": source_case.get("trusted_context"),
            "untrusted_input": source_case.get("untrusted_input"),
        }
        if any(baseline[field] != value for field, value in expected_from_source.items()):
            replicate_runtime_mismatch_count += 1

    expected_dataset_hashes = {
        row["source_artifact_sha256"]
        for row in manifest
        if row.get("source_pool") == "dataset_a"
    }
    source_hash = sha256_file(DATASET_PATH)
    audit = {
        "manifest_row_count": len(manifest),
        "manifest_unique_case_count": len(manifest_by_case),
        "plan_row_count": len(plan),
        "plan_unique_generation_count": len({row["generation_id"] for row in plan}),
        "dataset_a_attack_generation_count": len(dataset_attack),
        "dataset_a_runtime_case_count": len(runtime_cases),
        "supplemental_direct_generation_count": len(supplemental),
        "dataset_a_standalone_case_count": len(standalone_cases),
        "replicate_counts": {key: replicate_counts[key] for key in sorted(EXPECTED_REPLICATES)},
        "manifest_join_failures": manifest_join_failures,
        "dataset_join_failures": dataset_join_failures,
        "runtime_field_missing_count": runtime_field_missing_count,
        "replicate_runtime_mismatch_count": replicate_runtime_mismatch_count,
        "source_hash_integrity": expected_dataset_hashes == {source_hash},
    }
    expected = {
        "manifest_row_count": 1207,
        "manifest_unique_case_count": 1207,
        "plan_row_count": 2661,
        "plan_unique_generation_count": 2661,
        "dataset_a_attack_generation_count": 1746,
        "dataset_a_runtime_case_count": 582,
        "supplemental_direct_generation_count": 915,
        "dataset_a_standalone_case_count": 320,
        "replicate_counts": {"r1": 582, "r2": 582, "r3": 582},
        "manifest_join_failures": 0,
        "dataset_join_failures": 0,
        "runtime_field_missing_count": 0,
        "replicate_runtime_mismatch_count": 0,
        "source_hash_integrity": True,
    }
    errors = [key for key, value in expected.items() if audit[key] != value]
    if errors:
        raise ValueError(f"authoritative source integrity failure: {errors}")
    return audit, plans_by_case, manifest_by_case, dataset_by_case


def load_and_validate_sources() -> dict[str, Any]:
    dataset, manifest, plan = _load_sources()
    audit, _, _, _ = _source_audit(dataset, manifest, plan)
    return audit


def build_rows() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    dataset, manifest, plan = _load_sources()
    audit, plans_by_case, manifest_by_case, dataset_by_case = _source_audit(dataset, manifest, plan)
    source_hash = sha256_file(DATASET_PATH)
    plan_hash = sha256_file(PLAN_PATH)
    rows: list[dict[str, Any]] = []

    runtime_cases = sorted(
        row["production_case_id"]
        for row in manifest
        if row.get("source_pool") == "dataset_a"
        and row.get("runtime_outcome_applicability") == "applicable"
    )
    for production_case_id in runtime_cases:
        manifest_row = manifest_by_case[production_case_id]
        source_row = dataset_by_case[manifest_row["source_case_id"]]
        source_case = source_row["case_input"]
        case_plans = sorted(plans_by_case[production_case_id], key=lambda row: row["replicate_index"])
        canonical = case_plans[0]["materialized_request"]["canonical_request"]
        provenance = source_row["source_provenance"]
        row = {
            "schema_version": "outcome_rule_blind_input.v1",
            "blind_rule_case_id": blind_rule_case_id(production_case_id),
            "production_case_id": production_case_id,
            "source_case_id": manifest_row["source_case_id"],
            "scenario_id": canonical["scenario_id"],
            "trusted_instruction": canonical["trusted_instruction"],
            "normal_task": canonical["normal_task"],
            "trust_boundary": canonical["trust_boundary"],
            "trusted_context": canonical.get("trusted_context"),
            "untrusted_input": canonical["untrusted_input"],
            "injection_location": canonical["injection_location"],
            "source_metadata": {
                "source_id": provenance.get("source_id"),
                "source_name": provenance.get("source_name"),
                "source_row_locator": provenance.get("raw_row_locator"),
                "source_scenario_id": source_case.get("scenario_id"),
                "delivery_context": source_case.get("delivery_context"),
                "interpretation_mode": source_case.get("interpretation_mode"),
                "representation_context": source_case.get("representation_context"),
                "structural_metadata": source_case.get("structural_metadata") or {},
            },
            "source_artifact": {
                "path": manifest_row["source_artifact_path"],
                "sha256": source_hash,
            },
            "execution_plan_artifact": {
                "path": PLAN_PATH.relative_to(ROOT).as_posix(),
                "sha256": plan_hash,
            },
            "expected_replicates": [
                {
                    "generation_id": plan_row["generation_id"],
                    "replicate_index": plan_row["replicate_index"],
                    "seed": plan_row["seed"],
                }
                for plan_row in case_plans
            ],
        }
        leaks = find_forbidden_keys(row)
        if leaks:
            raise ValueError(f"blind projection leaked prohibited keys for {production_case_id}: {sorted(leaks)}")
        rows.append(row)

    audit["blind_output_row_count"] = len(rows)
    audit["blind_unique_case_count"] = len({row["production_case_id"] for row in rows})
    audit["leakage_violations"] = sum(bool(find_forbidden_keys(row)) for row in rows)
    if audit["blind_output_row_count"] != 582 or audit["blind_unique_case_count"] != 582:
        raise ValueError("blind projection must contain exactly 582 unique cases")
    return rows, audit


def write_artifacts(rows: list[dict[str, Any]], output: Path, provenance: Path) -> dict[str, Any]:
    if output.exists() or provenance.exists():
        raise FileExistsError("refusing to overwrite Outcome Rule blind-input artifacts")
    leaks = sorted(set().union(*(find_forbidden_keys(row) for row in rows)))
    if leaks:
        raise ValueError(f"refusing to write leaked blind input: {leaks}")
    payload = canonical_jsonl_bytes(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    provenance.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    manifest = {
        "schema_version": "outcome_rule_blind_input_manifest.v1",
        "materializer": "build_outcome_rule_blind_input_v1.py",
        "response_blind": True,
        "authoritative_inputs": [
            {"path": DATASET_PATH.relative_to(ROOT).as_posix(), "sha256": sha256_file(DATASET_PATH)},
            {"path": MANIFEST_PATH.relative_to(ROOT).as_posix(), "sha256": sha256_file(MANIFEST_PATH)},
            {"path": PLAN_PATH.relative_to(ROOT).as_posix(), "sha256": sha256_file(PLAN_PATH)},
        ],
        "excluded_dependency_classes": ["production_results", "scanner_results", "evaluator_verdicts", "existing_outcome_gt"],
        "output_path": output.relative_to(ROOT).as_posix() if output.is_relative_to(ROOT) else str(output.resolve()),
        "output_sha256": hashlib.sha256(payload).hexdigest(),
        "output_row_count": len(rows),
        "unique_production_case_count": len({row["production_case_id"] for row in rows}),
        "expected_replicates_per_case": ["r1", "r2", "r3"],
        "leakage_violations": 0,
    }
    provenance.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--provenance", type=Path, default=DEFAULT_PROVENANCE)
    args = parser.parse_args()
    rows, audit = build_rows()
    manifest = write_artifacts(rows, args.output, args.provenance)
    print(json.dumps({"audit": audit, "provenance": manifest}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
