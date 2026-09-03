#!/usr/bin/env python3
"""Validate complete Outcome Rule Catalog v1 bindings and flat rules for 582 cases."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
BLIND = ROOT / "data/outcome_gt/rule_catalog_v1/outcome_rule_blind_input_582_v1.jsonl"
DEFAULT_BINDINGS = ROOT / "data/outcome_gt/rule_catalog_v1/bindings/outcome_rule_bindings_582_v1.jsonl"
DEFAULT_EXCEPTIONS = ROOT / "data/outcome_gt/rule_catalog_v1/bindings/outcome_rule_binding_exceptions_v1.jsonl"
DEFAULT_RULES = ROOT / "data/outcome_gt/rule_catalog_v1/final/outcome_rules_582_v1.jsonl"
BINDING_SCHEMA = ROOT / "schemas/outcome_rule_binding_v1.schema.json"
EXCEPTION_SCHEMA = ROOT / "schemas/outcome_rule_binding_exception_v1.schema.json"
RULE_SCHEMA = ROOT / "schemas/outcome_rule_v1.schema.json"
EXPECTED_COUNT = 582
EXPECTED_REPLICATES = {"r1", "r2", "r3"}
TEMPLATE_PARENTS = {
    "S1": {"T1_document", "T2_plain_text", "T3_code"}, "S2": {"T1_document", "T2_plain_text", "T3_code"},
    "S3": {"T1_document", "T2_plain_text", "T4_structured"}, "S4": {"T1_document", "T2_plain_text", "T3_code", "T4_structured"},
    "S5": {"T1_document", "T3_code", "T5_tool_action"}, "S6": {"T1_document", "T2_plain_text", "T3_code"},
    "S7": {"T1_document", "T2_plain_text", "T3_code"}, "S8": {"T4_structured"}, "S9": {"T5_tool_action"},
    "S10": {"T5_tool_action"}, "S11": {"T5_tool_action"},
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_schema(rows: list[dict[str, Any]], schema_path: Path, label: str) -> None:
    validator = Draft202012Validator(_load_schema(schema_path), format_checker=FormatChecker())
    failures = []
    for index, row in enumerate(rows):
        errors = sorted(validator.iter_errors(row), key=lambda error: list(error.path))
        if errors:
            failures.append((index, errors[0].message))
    if failures:
        raise ValueError(f"{label} schema failures: {failures[:5]}")


def _structural_family(row: dict[str, Any]) -> str:
    scenario = row["scenario_id"]
    if scenario == "SCN-REMAIN-DOC-001": return "T1_document"
    if scenario == "SCN-REMAIN-TEXT-001": return "T2_plain_text"
    if scenario == "SCN-REMAIN-CODE-001": return "T3_code"
    if scenario == "SCN-REMAIN-STRUCT-001": return "T4_structured"
    if row["source_metadata"].get("interpretation_mode") == "reconstructed_from_official_raw_row": return "T5_tool_action"
    raise ValueError(f"unrecognized structural family: {row['production_case_id']}")


def expected_binding_id(production_case_id: str) -> str:
    suffix = hashlib.sha256(f"outcome-rule-binding-v1:{production_case_id}".encode()).hexdigest()[:16].upper()
    return f"ORB-V1-{suffix}"


def expected_rule_id(production_case_id: str) -> str:
    suffix = hashlib.sha256(f"outcome-rule-v1:{production_case_id}".encode()).hexdigest()[:16].upper()
    return f"ORULE-V1-{suffix}"


def validate_catalog(binding_path: Path, exception_path: Path, rule_path: Path) -> dict[str, Any]:
    blind = read_jsonl(BLIND); bindings = read_jsonl(binding_path)
    exceptions = read_jsonl(exception_path) if exception_path.exists() else []; rules = read_jsonl(rule_path)
    _validate_schema(bindings, BINDING_SCHEMA, "binding"); _validate_schema(exceptions, EXCEPTION_SCHEMA, "exception"); _validate_schema(rules, RULE_SCHEMA, "rule")

    blind_ids = [row["production_case_id"] for row in blind]
    binding_ids = [row["production_case_id"] for row in bindings]
    rule_case_ids = [row["production_case_id"] for row in rules]
    if len(blind) != EXPECTED_COUNT or len(set(blind_ids)) != EXPECTED_COUNT: raise ValueError("blind population is not 582 unique cases")
    if exceptions: raise ValueError(f"unresolved exception queue is non-empty: {len(exceptions)}")
    if len(bindings) != EXPECTED_COUNT or len(set(binding_ids)) != EXPECTED_COUNT: raise ValueError("binding population is not 582 unique cases")
    if len(rules) != EXPECTED_COUNT or len(set(rule_case_ids)) != EXPECTED_COUNT: raise ValueError("rule population is not 582 unique cases")
    if set(blind_ids) != set(binding_ids) or set(blind_ids) != set(rule_case_ids): raise ValueError("blind/binding/rule production case sets are not exactly equal")
    if binding_ids != sorted(binding_ids) or rule_case_ids != sorted(rule_case_ids): raise ValueError("bindings and rules must be sorted by production_case_id")

    blind_by_case = {row["production_case_id"]: row for row in blind}
    binding_by_case = {row["production_case_id"]: row for row in bindings}
    rule_by_case = {row["production_case_id"]: row for row in rules}
    failures = {key: [] for key in ("lineage", "template_parent", "composition", "goal_projection", "provenance", "criteria")}

    for production_case_id in sorted(blind_by_case):
        source = blind_by_case[production_case_id]; binding = binding_by_case[production_case_id]; rule = rule_by_case[production_case_id]
        family = _structural_family(source); replicates = source["expected_replicates"]
        if len(replicates) != 3 or {row["replicate_index"] for row in replicates} != EXPECTED_REPLICATES: failures["lineage"].append(production_case_id)
        if binding["binding_id"] != expected_binding_id(production_case_id) or rule["rule_id"] != expected_rule_id(production_case_id): failures["lineage"].append(production_case_id)
        if binding["blind_rule_case_id"] != source["blind_rule_case_id"] or binding["source_case_id"] != source["source_case_id"] or rule["source_case_id"] != source["source_case_id"]: failures["lineage"].append(production_case_id)
        if binding["structural_family"] != family or family not in TEMPLATE_PARENTS[binding["template_id"]]: failures["template_parent"].append(production_case_id)
        if binding["primary_goal"] in binding["supporting_or_causal_goals"]: failures["composition"].append(production_case_id)
        if binding["success_composition"] == "all" and binding["template_id"] not in {"S5", "S11"}: failures["composition"].append(production_case_id)
        if binding["exceptional_overrides"]: failures["composition"].append(production_case_id)
        expected_goals = list(dict.fromkeys([binding["primary_goal"], *binding["supporting_or_causal_goals"]]))
        if rule["goal_types"] != expected_goals: failures["goal_projection"].append(production_case_id)
        provenance = rule["binding_provenance"]
        if (provenance["blind_rule_case_id"] != source["blind_rule_case_id"] or provenance["source_artifact_path"] != source["source_artifact"]["path"] or provenance["source_artifact_sha256"] != source["source_artifact"]["sha256"] or provenance["execution_plan_path"] != source["execution_plan_artifact"]["path"] or provenance["execution_plan_sha256"] != source["execution_plan_artifact"]["sha256"] or provenance["response_blind"] is not True): failures["provenance"].append(production_case_id)
        required_text = [rule["normal_task_completion_criterion"], rule["boundary_violation_criterion"], rule["attacker_goal"], rule["attacker_goal_success_criterion"], *rule["edge_case_policy"].values()]
        if any(not isinstance(value, str) or not value.strip() for value in required_text): failures["criteria"].append(production_case_id)

    nonempty = {key: sorted(set(value)) for key, value in failures.items() if value}
    if nonempty: raise ValueError(f"catalog invariant failures: { {key: value[:10] for key, value in nonempty.items()} }")
    return {
        "status": "PASS", "blind_case_count": len(blind), "binding_count": len(bindings), "exception_count": len(exceptions),
        "flat_rule_count": len(rules), "unique_production_case_count": len(set(rule_case_ids)),
        "template_counts": dict(sorted(Counter(row["template_id"] for row in bindings).items())),
        "family_counts": dict(sorted(Counter(row["structural_family"] for row in bindings).items())),
        "binding_sha256": sha256_file(binding_path), "exception_sha256": sha256_file(exception_path), "rule_sha256": sha256_file(rule_path), "blind_sha256": sha256_file(BLIND),
        "response_blind": True, "unbound_count": 0, "duplicate_binding_count": 0, "duplicate_rule_count": 0,
        "invalid_composition_count": 0, "provenance_mismatch_count": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--bindings", type=Path, default=DEFAULT_BINDINGS); parser.add_argument("--exceptions", type=Path, default=DEFAULT_EXCEPTIONS); parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    args = parser.parse_args(); report = validate_catalog(args.bindings, args.exceptions, args.rules)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
