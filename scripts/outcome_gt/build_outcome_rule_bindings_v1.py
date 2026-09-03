#!/usr/bin/env python3
"""Materialize deterministic, response-blind Outcome Rule Template bindings for 582 production cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from outcome_rule_binding_common_v1 import (
    BINDING_METHOD, DEFAULT_BINDINGS, DEFAULT_EXCEPTIONS, DEFAULT_MANIFEST,
    EXPECTED_COUNT, EXPECTED_REPLICATES, ROOT, SOURCE, TEMPLATE_DESIGN,
    TEMPLATE_DESIGN_ID, TEMPLATE_MANIFEST, TEMPLATE_PARENTS, Decision,
    ExceptionDecision, binding_id, canonical_jsonl_bytes, exception_id,
    find_forbidden_keys, read_jsonl, sha256_file, structural_family,
)
from outcome_rule_binding_classifiers_v1 import classify

def _validate_source(rows: list[dict[str, Any]]) -> None:
    if len(rows) != EXPECTED_COUNT or len({row["production_case_id"] for row in rows}) != EXPECTED_COUNT:
        raise ValueError("blind source must contain exactly 582 unique production cases")
    if rows != sorted(rows, key=lambda row: row["production_case_id"]):
        raise ValueError("blind source must be sorted by production_case_id")
    for row in rows:
        leaks = find_forbidden_keys(row)
        if leaks:
            raise ValueError(f"blind source leakage keys for {row['production_case_id']}: {sorted(leaks)}")
        replicates = row.get("expected_replicates") or []
        if len(replicates) != 3 or {item.get("replicate_index") for item in replicates} != EXPECTED_REPLICATES:
            raise ValueError(f"replicate identity failure: {row['production_case_id']}")


def _validate_template_freeze() -> dict[str, Any]:
    manifest = json.loads(TEMPLATE_MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("template_design_id") != TEMPLATE_DESIGN_ID or manifest.get("status") != "FROZEN_APPROVED":
        raise ValueError("template manifest is not frozen/approved")
    actual = sha256_file(TEMPLATE_DESIGN)
    if manifest.get("sha256") != actual:
        raise ValueError("template design SHA-256 does not match freeze manifest")
    return manifest


def make_binding(row: dict[str, Any], decision: Decision) -> dict[str, Any]:
    family = structural_family(row)
    if family not in TEMPLATE_PARENTS[decision.template_id]:
        raise ValueError(f"template-parent mismatch: {row['production_case_id']} {family} {decision.template_id}")
    return {
        "schema_version": "outcome_rule_binding.v1",
        "binding_id": binding_id(row["production_case_id"]),
        "blind_rule_case_id": row["blind_rule_case_id"],
        "production_case_id": row["production_case_id"],
        "source_case_id": row["source_case_id"],
        "template_design_id": TEMPLATE_DESIGN_ID,
        "template_id": decision.template_id,
        "structural_family": family,
        "parameters": decision.parameters,
        "exception_flags": list(decision.flags),
        "exceptional_overrides": [],
        "primary_goal": decision.primary_goal,
        "supporting_or_causal_goals": list(decision.supporting_goals),
        "success_composition": decision.success_composition,
        "binding_method": BINDING_METHOD,
        "binding_reason": decision.reason,
        "response_blind": True,
        "binding_status": "bound",
    }


def make_exception(row: dict[str, Any], decision: ExceptionDecision) -> dict[str, Any]:
    return {
        "schema_version": "outcome_rule_binding_exception.v1",
        "exception_id": exception_id(row["production_case_id"]),
        "blind_rule_case_id": row["blind_rule_case_id"],
        "production_case_id": row["production_case_id"],
        "source_case_id": row["source_case_id"],
        "structural_family": structural_family(row),
        "candidate_template_ids": list(decision.candidates),
        "reason_code": decision.reason_code,
        "reason": decision.reason,
        "review_context": {
            "trusted_instruction": row["trusted_instruction"],
            "normal_task": row["normal_task"],
            "trust_boundary": row["trust_boundary"],
            "untrusted_input": row["untrusted_input"],
            "injection_location": row["injection_location"],
            "source_metadata": row["source_metadata"],
        },
        "response_blind": True,
        "resolution_status": "pending_human_review",
    }


def build_rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    source_rows = read_jsonl(SOURCE)
    _validate_source(source_rows)
    freeze = _validate_template_freeze()

    bindings: list[dict[str, Any]] = []
    exceptions: list[dict[str, Any]] = []
    for row in source_rows:
        decision = classify(row)
        if isinstance(decision, ExceptionDecision):
            exceptions.append(make_exception(row, decision))
        else:
            bindings.append(make_binding(row, decision))

    bindings.sort(key=lambda row: row["production_case_id"])
    exceptions.sort(key=lambda row: row["production_case_id"])
    audit = {
        "source_row_count": len(source_rows),
        "bound_row_count": len(bindings),
        "exception_row_count": len(exceptions),
        "accounted_case_count": len(bindings) + len(exceptions),
        "unique_accounted_case_count": len({row["production_case_id"] for row in bindings + exceptions}),
        "family_counts": dict(sorted(Counter(structural_family(row) for row in source_rows).items())),
        "template_counts": dict(sorted(Counter(row["template_id"] for row in bindings).items())),
        "exception_reason_counts": dict(sorted(Counter(row["reason_code"] for row in exceptions).items())),
        "source_sha256": sha256_file(SOURCE),
        "template_design_sha256": sha256_file(TEMPLATE_DESIGN),
        "template_freeze_commit": freeze.get("freeze_commit"),
        "response_blind": True,
    }
    if audit["accounted_case_count"] != EXPECTED_COUNT or audit["unique_accounted_case_count"] != EXPECTED_COUNT:
        raise ValueError(f"binding accounting failure: {audit}")
    return bindings, exceptions, audit


def _exclusive_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)


def write_artifacts(
    bindings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
    audit: dict[str, Any],
    binding_path: Path,
    exception_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    binding_bytes = canonical_jsonl_bytes(bindings)
    exception_bytes = canonical_jsonl_bytes(exceptions)
    _exclusive_write(binding_path, binding_bytes)
    _exclusive_write(exception_path, exception_bytes)
    manifest = {
        "schema_version": "outcome_rule_binding_manifest.v1",
        "template_design_id": TEMPLATE_DESIGN_ID,
        "binding_method": BINDING_METHOD,
        "source_path": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "source_sha256": audit["source_sha256"],
        "template_design_path": str(TEMPLATE_DESIGN.relative_to(ROOT)).replace("\\", "/"),
        "template_design_sha256": audit["template_design_sha256"],
        "template_freeze_commit": audit["template_freeze_commit"],
        "binding_path": str(binding_path.relative_to(ROOT)).replace("\\", "/") if binding_path.is_relative_to(ROOT) else str(binding_path),
        "binding_sha256": hashlib.sha256(binding_bytes).hexdigest(),
        "exception_path": str(exception_path.relative_to(ROOT)).replace("\\", "/") if exception_path.is_relative_to(ROOT) else str(exception_path),
        "exception_sha256": hashlib.sha256(exception_bytes).hexdigest(),
        "audit": audit,
        "contains_responses": False,
        "contains_scanner_results": False,
        "response_blind": True,
    }
    _exclusive_write(manifest_path, (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bindings", type=Path, default=DEFAULT_BINDINGS)
    parser.add_argument("--exceptions", type=Path, default=DEFAULT_EXCEPTIONS)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()

    bindings, exceptions, audit = build_rows()
    if args.summary_only:
        print(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    manifest = write_artifacts(bindings, exceptions, audit, args.bindings, args.exceptions, args.manifest)
    print(json.dumps(manifest["audit"], ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
