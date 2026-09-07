#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from outcome_gt_annotation_common_v1 import (
    EXPECTED_INPUT_SHA256,
    EXPECTED_ROWS,
    ROOT,
    read_jsonl,
    sha256_file,
    write_json_idempotent,
)

SELECTION_NAMESPACE = "OUTCOME_GT_COMMON_CANARY_V1"
SELECTION_VERSION = "outcome-gt-common-canary-v1"
SELECTION_ALGORITHM = "sha256-rank-ascending-v1"
SELECTED_COUNT = 10
INPUT_PATH = ROOT / "data/outcome_gt/adjudication_v1/input/outcome_gt_adjudication_input_1746_v1.jsonl"
PASS_ROOT = ROOT / "data/outcome_gt/adjudication_v1/passes"
REQUEST_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_requests"
DEFAULT_OUTPUT = ROOT / "data/outcome_gt/adjudication_v1/canary/common_canary_selection_v1.json"


def rank_generation_ids(generation_ids: Iterable[str], count: int = SELECTED_COUNT) -> list[str]:
    values = list(generation_ids)
    if len(values) != len(set(values)):
        raise ValueError("generation_id values must be unique")
    ranked = sorted(
        values,
        key=lambda generation_id: (
            hashlib.sha256(f"{SELECTION_NAMESPACE}|{generation_id}".encode("utf-8")).hexdigest(),
            generation_id,
        ),
    )
    if not 1 <= count <= len(ranked):
        raise ValueError("selection count is outside the source population")
    return ranked[:count]


def canonical_selection_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def validate_selection_document(
    value: dict[str, Any],
    *,
    source_generation_ids: Iterable[str],
    source_population_sha256: str,
    pass_generation_ids: dict[str, Iterable[str]],
    request_sha256_by_pass: dict[str, str],
) -> None:
    expected_top_level = {
        "schema_version", "selection_version", "selection_algorithm", "selection_namespace",
        "source_population", "source_requests", "selected_count", "ordered_generation_ids",
        "creation_provenance",
    }
    if set(value) != expected_top_level:
        raise ValueError("selection document fields do not match the frozen metadata contract")
    if value.get("schema_version") != "outcome_gt_common_canary_selection.v1":
        raise ValueError("selection schema version mismatch")
    if value.get("selection_version") != SELECTION_VERSION:
        raise ValueError("selection version mismatch")
    if value.get("selection_algorithm") != SELECTION_ALGORITHM:
        raise ValueError("selection algorithm mismatch")
    if value.get("selection_namespace") != SELECTION_NAMESPACE:
        raise ValueError("selection namespace mismatch")

    source_ids = list(source_generation_ids)
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("canonical population generation_id values are not unique")
    source = value.get("source_population", {})
    if set(source) != {"path", "sha256", "count"}:
        raise ValueError("source population metadata fields mismatch")
    if source.get("sha256") != source_population_sha256:
        raise ValueError("source population SHA-256 mismatch")
    if source.get("count") != len(source_ids):
        raise ValueError("source population count mismatch")

    selected = value.get("ordered_generation_ids")
    if not isinstance(selected, list) or len(selected) != value.get("selected_count"):
        raise ValueError("selected count mismatch")
    if len(selected) != len(set(selected)):
        raise ValueError("selected generation_id values must be unique")
    if not set(selected).issubset(set(source_ids)):
        raise ValueError("selected generation_id is not in canonical population")
    if selected != rank_generation_ids(source_ids, count=len(selected)):
        raise ValueError("selection does not match deterministic SHA-256 ranking")

    source_requests = value.get("source_requests", {})
    if set(source_requests) != {"pass_a", "pass_b"}:
        raise ValueError("source request pass metadata mismatch")
    for pass_id in ("pass_a", "pass_b"):
        pass_ids = list(pass_generation_ids.get(pass_id, []))
        if len(pass_ids) != len(set(pass_ids)):
            raise ValueError(f"{pass_id}: generation_id values are not unique")
        if set(pass_ids) != set(source_ids):
            raise ValueError(f"{pass_id}: source population mismatch")
        if not set(selected).issubset(set(pass_ids)):
            raise ValueError(f"{pass_id}: selected generation coverage mismatch")
        request = source_requests.get(pass_id, {})
        if set(request) != {"path", "sha256", "count"}:
            raise ValueError(f"{pass_id}: source request metadata fields mismatch")
        if request.get("sha256") != request_sha256_by_pass.get(pass_id):
            raise ValueError(f"{pass_id}: request SHA-256 mismatch")
        if request.get("count") != len(pass_ids):
            raise ValueError(f"{pass_id}: request population count mismatch")

    provenance = value.get("creation_provenance", {})
    if set(provenance) != {
        "generator", "identifier", "response_content_used", "ground_truth_used",
        "judge_result_used", "judge_model_used",
    }:
        raise ValueError("creation provenance fields mismatch")
    expected_flags = {
        "response_content_used": False,
        "ground_truth_used": False,
        "judge_result_used": False,
        "judge_model_used": False,
    }
    if provenance.get("identifier") != "generation_id":
        raise ValueError("selection identifier must be generation_id")
    if any(provenance.get(key) is not expected for key, expected in expected_flags.items()):
        raise ValueError("selection provenance permits response, GT, judge result, or model leakage")


def _pass_generation_ids(pass_id: str) -> list[str]:
    keys = read_jsonl(PASS_ROOT / pass_id / "private_key_1746_v1.jsonl")
    requests = read_jsonl(REQUEST_ROOT / pass_id / "judge_requests_1746_v2.jsonl")
    if len(keys) != EXPECTED_ROWS or len(requests) != EXPECTED_ROWS:
        raise ValueError(f"{pass_id}: expected {EXPECTED_ROWS} key and request rows")
    key_by_assignment = {row["assignment_item_id"]: row for row in keys}
    if len(key_by_assignment) != EXPECTED_ROWS:
        raise ValueError(f"{pass_id}: private-key assignment lineage is not unique")
    generation_ids: list[str] = []
    for request in requests:
        key = key_by_assignment.get(request.get("assignment_item_id"))
        if key is None:
            raise ValueError(f"{pass_id}: request has no private-key lineage")
        generation_ids.append(key["generation_id"])
    return generation_ids


def build_selection_document() -> dict[str, Any]:
    source_rows = read_jsonl(INPUT_PATH)
    if len(source_rows) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} canonical source rows")
    if sha256_file(INPUT_PATH) != EXPECTED_INPUT_SHA256:
        raise ValueError("canonical adjudication input SHA-256 mismatch")
    source_generation_ids = [row["generation_id"] for row in source_rows]
    pass_generation_ids = {pass_id: _pass_generation_ids(pass_id) for pass_id in ("pass_a", "pass_b")}
    request_manifests = {
        pass_id: json.loads(
            (REQUEST_ROOT / pass_id / "judge_requests_1746_v2_manifest.json").read_text(encoding="utf-8")
        )
        for pass_id in ("pass_a", "pass_b")
    }
    request_sha256_by_pass = {
        pass_id: request_manifests[pass_id]["request_sha256"] for pass_id in ("pass_a", "pass_b")
    }
    for pass_id in ("pass_a", "pass_b"):
        request_path = ROOT / request_manifests[pass_id]["request_path"]
        if sha256_file(request_path) != request_sha256_by_pass[pass_id]:
            raise ValueError(f"{pass_id}: request manifest SHA-256 mismatch")
    value = {
        "schema_version": "outcome_gt_common_canary_selection.v1",
        "selection_version": SELECTION_VERSION,
        "selection_algorithm": SELECTION_ALGORITHM,
        "selection_namespace": SELECTION_NAMESPACE,
        "source_population": {
            "path": str(INPUT_PATH.relative_to(ROOT)).replace("\\", "/"),
            "sha256": sha256_file(INPUT_PATH),
            "count": len(source_generation_ids),
        },
        "source_requests": {
            pass_id: {
                "path": request_manifests[pass_id]["request_path"],
                "sha256": request_sha256_by_pass[pass_id],
                "count": request_manifests[pass_id]["rows"],
            }
            for pass_id in ("pass_a", "pass_b")
        },
        "selected_count": SELECTED_COUNT,
        "ordered_generation_ids": rank_generation_ids(source_generation_ids),
        "creation_provenance": {
            "generator": "scripts/outcome_gt/materialize_outcome_gt_common_canary_v1.py",
            "identifier": "generation_id",
            "response_content_used": False,
            "ground_truth_used": False,
            "judge_result_used": False,
            "judge_model_used": False,
        },
    }
    validate_selection_document(
        value,
        source_generation_ids=source_generation_ids,
        source_population_sha256=EXPECTED_INPUT_SHA256,
        pass_generation_ids=pass_generation_ids,
        request_sha256_by_pass=request_sha256_by_pass,
    )
    return value


def load_validated_selection(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    canonical = build_selection_document()
    source_generation_ids = [row["generation_id"] for row in read_jsonl(INPUT_PATH)]
    validate_selection_document(
        value,
        source_generation_ids=source_generation_ids,
        source_population_sha256=sha256_file(INPUT_PATH),
        pass_generation_ids={pass_id: _pass_generation_ids(pass_id) for pass_id in ("pass_a", "pass_b")},
        request_sha256_by_pass={
            pass_id: canonical["source_requests"][pass_id]["sha256"] for pass_id in ("pass_a", "pass_b")
        },
    )
    if path.read_bytes() != canonical_selection_bytes(canonical):
        raise ValueError("selection artifact is not byte-for-byte equal to deterministic regeneration")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    value = build_selection_document()
    if args.validate_only:
        if not args.output.exists():
            raise FileNotFoundError(f"missing selection artifact: {args.output}")
        if args.output.read_bytes() != canonical_selection_bytes(value):
            raise ValueError("selection artifact differs byte-for-byte from deterministic regeneration")
    else:
        write_json_idempotent(args.output, value)
    print(json.dumps({
        "status": "COMMON_CANARY_SELECTION_READY",
        "selection_path": str(args.output),
        "selected_count": value["selected_count"],
        "ordered_generation_ids": value["ordered_generation_ids"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
