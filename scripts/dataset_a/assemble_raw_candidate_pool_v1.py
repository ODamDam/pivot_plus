#!/usr/bin/env python3
"""Assemble a deterministic, unlabeled Dataset A raw candidate pool.

This script intentionally does not assign Case GT labels or final Dataset A IDs.
It consolidates preserved local candidate exports, applies Source Catalog gates,
deduplicates exact text, and records unresolved provenance work for later review.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_OUTPUT = Path(
    "data/dataset_a/candidate_pool/dataset_a_raw_candidate_pool_1500_v1.jsonl"
)
DEFAULT_REPORT = Path(
    "reports/dataset_a/dataset_a_raw_candidate_pool_1500_v1_validation.json"
)
DEFAULT_MINIMUM_SIZE = 1000

DEFAULT_INPUTS = [
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/01_seed_review/benign/manual_review_seed_malicious_schema_v1.csv"),
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/01_seed_review/context_eval/manual_review_context_eval_schema_v1.csv"),
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/01_seed_review/bypass/manual_review_bypass_candidate_schema_v1.csv"),
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/01_seed_review/hard_negative/manual_review_hard_negative_schema_v1.csv"),
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/01_seed_review/benign/manual_review_benign_schema_v1.csv"),
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/04_structure_intact/structure_intact_candidates_v1/structure_intact_candidates_all_v1.csv"),
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/04_structure_intact/external_structure_candidates/src10_scout450_v1/src10_scout450_structure_candidates_all_v1.csv"),
    Path("data/archive/pre_monorepo_data_pipeline_20260730/review/04_structure_intact/external_structure_candidates/src11_bipia_v1/src11_bipia_code_candidates_all_v1.csv"),
]


@dataclass(frozen=True)
class SourcePolicy:
    canonical_id: str
    quota: int
    eligibility_tier: str
    license_status: str
    generated_only: bool = False


SOURCE_POLICIES = {
    "SRC-01_lakera_gandalf": SourcePolicy(
        "SRC-01", 32, "immediate", "verified_permissive"
    ),
    "SRC-07_prodnull_prompt_injection_repo_dataset": SourcePolicy(
        "SRC-07", 380, "immediate", "verified_permissive_with_provenance_review"
    ),
    "SRC-10_SCOUT_450": SourcePolicy(
        "SRC-10", 56, "immediate", "verified_permissive_subset_mixed", True
    ),
    "SRC-03_spml_chatbot_prompt_injection": SourcePolicy(
        "SRC-03", 300, "conditional", "upstream_review_required"
    ),
    "SRC-05_rogue_security_prompt_injections_benchmark": SourcePolicy(
        "SRC-05", 200, "conditional", "verified_conditional"
    ),
    "SRC-06_jailbreak_llms": SourcePolicy(
        "SRC-06", 120, "conditional", "upstream_review_required"
    ),
    "SRC-09_neuralchemy_prompt_injection_dataset": SourcePolicy(
        "SRC-09", 200, "conditional", "upstream_review_required"
    ),
    "SRC-11_microsoft_BIPIA": SourcePolicy(
        "SRC-11", 212, "conditional", "mixed_license_upstream_review"
    ),
}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _eligible_row(row: dict[str, str], policy: SourcePolicy) -> bool:
    text = (row.get("scanner_input") or "").strip()
    if not text or len(text) < 8 or len(text) > 20_000:
        return False
    if policy.generated_only:
        return (
            row.get("generation_method") == "gpt_generated"
            and row.get("source_dataset") == "generated"
        )
    return True


def _candidate_from_row(
    row: dict[str, str],
    source_file: Path,
    source_file_hash: str,
    row_number: int,
    policy: SourcePolicy,
) -> dict[str, Any]:
    text = (row.get("scanner_input") or "").strip()
    text_hash = sha256_text(text)
    source_record_id = (row.get("source_record_id") or "").strip() or None
    return {
        "schema_version": "dataset_a_raw_candidate_v1.0",
        "candidate_id": None,
        "family_id": None,
        "source": {
            "source_id": policy.canonical_id,
            "source_record_id": source_record_id,
            "source_revision": None,
            "license_status": policy.license_status,
            "language": (row.get("language") or "").strip() or None,
        },
        "provenance": {
            "raw_source_id": (row.get("source_id") or "").strip(),
            "local_source_file": source_file.as_posix(),
            "local_source_file_sha256": source_file_hash,
            "local_row_number": row_number,
            "normalized_record_id": (row.get("normalized_record_id") or "").strip() or None,
            "source_split": (row.get("source_split") or "").strip() or None,
            "generation_method": (row.get("generation_method") or "").strip() or None,
            "source_dataset": (row.get("source_dataset") or "").strip() or None,
            "provenance_status_observed": (row.get("provenance_status") or "").strip() or None,
        },
        "content": {
            "raw_text": text,
            "text_sha256": text_hash,
            "input_format_observed": (
                row.get("candidate_structure_format")
                or row.get("input_format")
                or ""
            ).strip() or None,
        },
        "collection": {
            "status": "raw_candidate",
            "eligibility_tier": policy.eligibility_tier,
            "source_gate_status": "pending_revision_and_record_review",
            "selected_for_adjudication": False,
        },
        "prior_metadata": {
            "original_label": (row.get("original_label") or "").strip() or None,
            "original_subset": (row.get("subset") or "").strip() or None,
            "original_attack_type": (
                row.get("attack_type") or row.get("attack_type_original") or ""
            ).strip() or None,
            "legacy_review_decision": (row.get("review_decision") or "").strip() or None,
        },
        "case_gt": None,
    }


def collect_candidates(
    source_files: Iterable[Path],
    policies: dict[str, SourcePolicy] = SOURCE_POLICIES,
) -> list[dict[str, Any]]:
    by_hash: dict[str, dict[str, Any]] = {}
    file_hash_cache: dict[Path, str] = {}
    for source_file in source_files:
        with source_file.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for row_number, row in enumerate(reader, start=2):
                raw_source_id = (row.get("source_id") or "").strip()
                policy = policies.get(raw_source_id)
                if policy is None or not _eligible_row(row, policy):
                    continue
                text = (row.get("scanner_input") or "").strip()
                text_hash = sha256_text(text)
                if text_hash in by_hash:
                    continue
                if source_file not in file_hash_cache:
                    file_hash_cache[source_file] = sha256_file(source_file)
                candidate = _candidate_from_row(
                    row,
                    source_file,
                    file_hash_cache[source_file],
                    row_number,
                    policy,
                )
                by_hash[text_hash] = candidate
    return list(by_hash.values())


def _selection_key(record: dict[str, Any]) -> tuple[int, int, str, str]:
    provenance = record["provenance"]
    source = record["source"]
    return (
        0 if source.get("source_record_id") else 1,
        0 if provenance.get("provenance_status_observed") == "traceable" else 1,
        source.get("source_record_id") or "",
        record["content"]["text_sha256"],
    )


def select_candidates(
    candidates: list[dict[str, Any]],
    policies: dict[str, SourcePolicy] = SOURCE_POLICIES,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        grouped[candidate["source"]["source_id"]].append(candidate)

    selected: list[dict[str, Any]] = []
    for raw_source_id, policy in policies.items():
        del raw_source_id
        selected.extend(sorted(grouped[policy.canonical_id], key=_selection_key)[: policy.quota])

    for index, candidate in enumerate(selected, start=1):
        candidate["candidate_id"] = f"DA-RAW-{index:06d}"
        source_key = candidate["source"].get("source_record_id") or candidate["content"]["text_sha256"]
        candidate["family_id"] = "FAM-RAW-" + sha256_text(
            f'{candidate["source"]["source_id"]}:{source_key}'
        )[:16].upper()
    return selected


def validate_pool(records: list[dict[str, Any]], minimum_size: int) -> dict[str, Any]:
    ids = [record["candidate_id"] for record in records]
    hashes = [record["content"]["text_sha256"] for record in records]
    source_counts = Counter(record["source"]["source_id"] for record in records)
    tier_counts = Counter(record["collection"]["eligibility_tier"] for record in records)
    revision_missing_count = sum(
        not record["source"].get("source_revision") for record in records
    )
    checks = {
        "minimum_pool_size_met": len(records) >= minimum_size,
        "candidate_ids_unique": len(ids) == len(set(ids)),
        "exact_text_hashes_unique": len(hashes) == len(set(hashes)),
        "all_records_raw_candidates": all(
            record["collection"]["status"] == "raw_candidate" for record in records
        ),
        "no_case_gt_assigned": all(record.get("case_gt") is None for record in records),
        "all_have_local_source_hash": all(
            bool(record["provenance"].get("local_source_file_sha256")) for record in records
        ),
    }
    return {
        "validation_version": "dataset_a_raw_candidate_pool_validation_v1.0",
        "validated_at": datetime.now(timezone.utc).isoformat(),
        "passed": all(checks.values()),
        "checks": checks,
        "record_count": len(records),
        "minimum_size": minimum_size,
        "source_counts": dict(sorted(source_counts.items())),
        "eligibility_tier_counts": dict(sorted(tier_counts.items())),
        "revision_missing_count": revision_missing_count,
        "final_dataset_ready": False,
        "blocking_gates": [
            "immutable source revisions are not recorded in the preserved local exports",
            "record-level license and provenance review is incomplete",
            "independent PI and maliciousness adjudication has not run",
            "scenario binding has not run",
        ],
    }


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--minimum-size", type=int, default=DEFAULT_MINIMUM_SIZE)
    parser.add_argument("inputs", nargs="*", type=Path, default=DEFAULT_INPUTS)
    args = parser.parse_args()

    missing = [path.as_posix() for path in args.inputs if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing candidate inputs: {missing}")

    candidates = collect_candidates(args.inputs)
    selected = select_candidates(candidates)
    report = validate_pool(selected, args.minimum_size)
    report["input_files"] = [
        {"path": path.as_posix(), "sha256": sha256_file(path)} for path in args.inputs
    ]
    report["source_quotas"] = {
        policy.canonical_id: policy.quota for policy in SOURCE_POLICIES.values()
    }
    report["quota_shortfalls"] = {
        policy.canonical_id: policy.quota - report["source_counts"].get(policy.canonical_id, 0)
        for policy in SOURCE_POLICIES.values()
        if report["source_counts"].get(policy.canonical_id, 0) < policy.quota
    }
    if report["quota_shortfalls"]:
        report["passed"] = False
    if not report["passed"]:
        raise ValueError(f"Raw candidate pool validation failed: {report}")

    write_jsonl(args.output, selected)
    report["output_file"] = args.output.as_posix()
    report["output_sha256"] = sha256_file(args.output)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
