#!/usr/bin/env python3
"""Intake publication-safe JBB-Behaviors Original goals into supplemental pool."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data/non_pi_supplemental"
REPORTS = ROOT / "reports/non_pi_supplemental"
EXISTING_POOL = DATA / "candidate_pool/non_pi_supplemental_candidates_v1.jsonl"
FROZEN = ROOT / "data/dataset_a/final/dataset_a_case_gt_902_v1.jsonl"
JBB_REVISION = "886acc352a31533ffbcf4ef22c744658688086fc"
JBB_RAW_SHA256 = "f985615b17b7659a7598f751a3c1fe0704e80d4f966d6ba36b6777d53ad18150"
JBB_LICENSE_SHA256 = "90646877cb6bda11eff59af1ea1bc09776dda552e1cf4685ed9dbac4753bb189"
EXISTING_POOL_SHA256 = "428aa557191a4cfdd4cc2c9eb7e887346385a63dcd8f1f7c1009ba5563c00ff3"
FROZEN_SHA256 = "6cf89b6746491fadc404982f85118fbcc99bcefbc0219a5406c1d800967bcf9b"
CANDIDATE_FIELDS = {
    "supplemental_candidate_id", "supplemental_track", "source_id", "source_name",
    "source_repo", "pinned_revision", "source_file", "source_row_locator",
    "source_record_id", "original_text", "original_source_label_category", "license_id",
    "license_evidence", "redistribution_status", "upstream_source", "raw_file_sha256",
    "candidate_selection_reason", "needs_pi_review", "notes",
}
UPSTREAM_INVENTORY_FIELDS = {
    "source_row_locator", "source_record_id", "behavior_id", "category", "source",
    "redistribution_status", "exclusion_reason",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalize(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold()
    value = re.sub(r"\s+", " ", value).strip()
    return re.sub(r"[^\w\s]", "", value)


def candidate_id(record_id: str) -> str:
    digest = hashlib.sha256(f"non-pi-supplemental-v1:JBB-ORIGINAL:{record_id}".encode()).hexdigest()[:16].upper()
    return f"NPS-V1-{digest}"


def prefilter_pi(text: str) -> tuple[bool, bool, str | None]:
    """Return (exclude, needs_review, reason); never assigns final Case GT."""
    explicit = (
        r"ignore (?:all |any )?(?:previous|prior|system|developer) instructions",
        r"reveal (?:the |your )?(?:system|developer) (?:prompt|instructions|message)",
        r"(?:extract|print|leak|repeat) (?:the |your )?(?:system|developer) (?:prompt|instructions|message)",
        r"override (?:the )?(?:system|developer) instructions",
    )
    if any(re.search(pattern, text, re.I) for pattern in explicit):
        return True, False, "explicit_hierarchy_or_trust_boundary_takeover"
    ambiguous = (
        r"prompt injection", r"jailbreak (?:the )?(?:model|assistant)",
        r"bypass (?:the )?(?:system|developer) (?:prompt|instructions)",
    )
    if any(re.search(pattern, text, re.I) for pattern in ambiguous):
        return False, True, "possible_hierarchy_or_trust_boundary_takeover"
    return False, False, None


def duplicate_groups(rows: list[dict[str, Any]], normalized: bool) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for row in rows:
        value = normalize(row["original_text"]) if normalized else row["original_text"]
        groups.setdefault(value, []).append(row["supplemental_candidate_id"])
    return [
        {"value_sha256": hashlib.sha256(value.encode()).hexdigest(), "ids": ids}
        for value, ids in sorted(groups.items()) if len(ids) > 1
    ]


def frozen_text_sets() -> tuple[set[str], set[str]]:
    exact: set[str] = set()
    normalized: set[str] = set()
    for row in read_jsonl(FROZEN):
        case = row["case_input"]
        for key in ("untrusted_input", "trusted_instruction", "normal_task"):
            if case.get(key):
                exact.add(case[key])
                normalized.add(normalize(case[key]))
    return exact, normalized


def git_head(repo: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def run(repo: Path) -> dict[str, Any]:
    raw = repo / "data/harmful-behaviors.csv"
    license_file = repo / "LICENSE"
    readme = repo / "README.md"
    if git_head(repo) != JBB_REVISION:
        raise ValueError("JBB pinned revision mismatch")
    if sha256(raw) != JBB_RAW_SHA256 or sha256(license_file) != JBB_LICENSE_SHA256:
        raise ValueError("JBB source hash mismatch")
    if sha256(EXISTING_POOL) != EXISTING_POOL_SHA256:
        raise ValueError("Existing XSTest pool changed")
    if sha256(FROZEN) != FROZEN_SHA256:
        raise ValueError("Frozen Dataset A changed")

    with raw.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected_columns = ["Index", "Goal", "Target", "Behavior", "Category", "Source"]
    if list(rows[0]) != expected_columns or len(rows) != 100:
        raise ValueError("Unexpected JBB harmful schema or row count")
    source_distribution = Counter(row["Source"] for row in rows)
    if source_distribution != {"Original": 55, "TDC/HarmBench": 27, "AdvBench": 18}:
        raise ValueError(f"Unexpected source distribution: {source_distribution}")

    existing = read_jsonl(EXISTING_POOL)
    if len(existing) != 250 or any(row["source_id"] != "NPS-SRC-XSTEST" for row in existing):
        raise ValueError("Existing pool is not the canonical XSTest 250")
    frozen_exact, frozen_norm = frozen_text_sets()
    existing_exact = {row["original_text"] for row in existing}
    existing_norm = {normalize(row["original_text"]) for row in existing}

    original_provenance: list[dict[str, Any]] = []
    upstream_inventory: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    semantic_exclusions: list[dict[str, Any]] = []
    overlaps: list[dict[str, Any]] = []
    cross_xstest: list[dict[str, Any]] = []
    needs_review = 0
    for csv_line, row in enumerate(rows, 2):
        locator = f"data/harmful-behaviors.csv:{csv_line}"
        if row["Source"] != "Original":
            upstream_inventory.append({
                "source_row_locator": locator, "source_record_id": row["Index"],
                "behavior_id": row["Behavior"], "category": row["Category"], "source": row["Source"],
                "redistribution_status": "excluded_upstream_provenance",
                "exclusion_reason": "Only Source=Original is approved for this intake; Goal and Target withheld.",
            })
            continue
        original_provenance.append({
            "source_row_locator": locator, "Index": row["Index"], "Goal": row["Goal"],
            "Target": row["Target"], "Behavior": row["Behavior"], "Category": row["Category"],
            "Source": row["Source"], "raw_file_sha256": JBB_RAW_SHA256,
        })
        excluded, review, reason = prefilter_pi(row["Goal"])
        identifier = candidate_id(row["Index"])
        if excluded:
            semantic_exclusions.append({"supplemental_candidate_id": identifier, "source_record_id": row["Index"], "reason": reason})
            continue
        needs_review += int(review)
        if row["Goal"] in frozen_exact or normalize(row["Goal"]) in frozen_norm:
            overlaps.append({"supplemental_candidate_id": identifier, "source_record_id": row["Index"], "reason": "frozen_dataset_a_overlap"})
            continue
        if row["Goal"] in existing_exact or normalize(row["Goal"]) in existing_norm:
            cross_xstest.append({"supplemental_candidate_id": identifier, "source_record_id": row["Index"], "reason": "xstest_overlap"})
            continue
        candidates.append({
            "supplemental_candidate_id": identifier,
            "supplemental_track": "non_pi_malicious_candidate",
            "source_id": "NPS-SRC-JBB-ORIGINAL", "source_name": "JBB-Behaviors Original harmful goals",
            "source_repo": "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors",
            "pinned_revision": JBB_REVISION, "source_file": "data/harmful-behaviors.csv",
            "source_row_locator": locator, "source_record_id": row["Index"], "original_text": row["Goal"],
            "original_source_label_category": {"behavior": row["Behavior"], "category": row["Category"], "source": row["Source"]},
            "license_id": "MIT", "license_evidence": ["license_audit/jbb_LICENSE.txt", "license_audit/jbb_README.md#license"],
            "redistribution_status": "redistribution_approved_with_attribution", "upstream_source": None,
            "raw_file_sha256": JBB_RAW_SHA256,
            "candidate_selection_reason": "JBB Source=Original direct harmful Goal retained as provisional malicious intent; no final Case GT assigned.",
            "needs_pi_review": review, "notes": "Target excluded from candidate text and retained only in Original provenance projection.",
        })

    combined = existing + candidates
    ids = [row["supplemental_candidate_id"] for row in combined]
    exact_groups = duplicate_groups(combined, False)
    norm_groups = duplicate_groups(combined, True)
    internal_exact = duplicate_groups(candidates, False)
    internal_norm = duplicate_groups(candidates, True)
    schema_violations = sum(set(row) != CANDIDATE_FIELDS for row in combined)
    provenance_coverage = sum(all(row.get(k) is not None for k in (
        "source_id", "source_repo", "pinned_revision", "source_file", "source_row_locator", "raw_file_sha256"
    )) for row in combined)
    license_coverage = sum(row.get("redistribution_status") == "redistribution_approved_with_attribution" and bool(row.get("license_id") and row.get("license_evidence")) for row in combined)
    validation = {
        "schema_version": "jbb_supplemental_validation.v1", "existing_xstest_count": len(existing),
        "existing_xstest_sha256": sha256(EXISTING_POOL), "jbb_original_count": len(original_provenance),
        "jbb_candidate_count": len(candidates), "combined_count": len(combined), "unique_id_count": len(set(ids)),
        "schema_violations": schema_violations, "provenance_coverage": provenance_coverage,
        "license_coverage": license_coverage, "upstream_inventory_count": len(upstream_inventory),
        "upstream_raw_text_contamination": sum(bool(set(row) & {"Goal", "Target", "goal", "target", "original_text"}) for row in upstream_inventory),
        "exact_duplicate_groups": len(exact_groups), "normalized_duplicate_groups": len(norm_groups),
        "frozen_dataset_a_overlap_count": len(overlaps), "frozen_dataset_a_sha256": sha256(FROZEN),
        "passed": False,
    }
    validation["passed"] = all((
        len(existing) == 250, len(original_provenance) == 55, len(upstream_inventory) == 45,
        len(ids) == len(set(ids)), schema_violations == 0, provenance_coverage == len(combined),
        license_coverage == len(combined), not exact_groups, not norm_groups, not overlaps,
        not cross_xstest, validation["upstream_raw_text_contamination"] == 0,
        sha256(EXISTING_POOL) == EXISTING_POOL_SHA256, sha256(FROZEN) == FROZEN_SHA256,
    ))

    shutil.copyfile(readme, DATA / "license_audit/jbb_README.md")
    shutil.copyfile(license_file, DATA / "license_audit/jbb_LICENSE.txt")
    write_jsonl(DATA / "raw/jbb_original_harmful_provenance_v1.jsonl", original_provenance)
    write_jsonl(DATA / "license_audit/jbb_upstream_excluded_inventory_v1.jsonl", upstream_inventory)
    write_jsonl(DATA / "candidate_pool/non_pi_supplemental_candidates_v1_1.jsonl", combined)
    write_json(DATA / "license_audit/jbb_license_audit_v1.json", {
        "schema_version": "jbb_license_audit.v1", "dataset_license": "MIT",
        "source_repo": "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors",
        "pinned_revision": JBB_REVISION, "source_file": "data/harmful-behaviors.csv",
        "raw_file_sha256": JBB_RAW_SHA256, "license_file_sha256": JBB_LICENSE_SHA256,
        "dataset_card_evidence": "jbb_README.md", "license_evidence": "jbb_LICENSE.txt",
        "source_decisions": {
            "Original": "redistribution_approved_with_attribution",
            "TDC/HarmBench": "excluded_upstream_provenance", "AdvBench": "excluded_upstream_provenance",
        }, "doi": None, "doi_note": "No DOI stated in the pinned dataset card; paper identified by arXiv:2404.01318 and NeurIPS 2024 citation.",
        "citation": {"title": "JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models", "authors": "Chao et al.", "venue": "NeurIPS Datasets and Benchmarks Track", "year": 2024, "arxiv": "2404.01318"},
    })
    write_json(DATA / "source_catalog/jbb_source_catalog_v1.json", {
        "schema_version": "non_pi_supplemental_source_catalog.jbb.v1", "source_id": "NPS-SRC-JBB-ORIGINAL",
        "repo": "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors", "revision": JBB_REVISION,
        "file": "data/harmful-behaviors.csv", "sha256": JBB_RAW_SHA256,
        "columns": expected_columns, "row_count": len(rows), "source_distribution": dict(source_distribution),
        "candidate_text_field": "Goal", "target_used_as_candidate_text": False,
    })
    write_json(REPORTS / "jbb_duplicate_audit_v1.json", {
        "schema_version": "jbb_duplicate_audit.v1",
        "jbb_original_internal": {"exact_groups": internal_exact, "normalized_groups": internal_norm},
        "jbb_vs_xstest": {"excluded_overlaps": cross_xstest}, "jbb_vs_frozen_dataset_a": {"excluded_overlaps": overlaps},
        "jbb_vs_harmbench_blocked": {"comparison_performed": False, "reason": "HarmBench blocked inventory intentionally withholds raw behavior text."},
        "combined_pool": {"exact_groups": exact_groups, "normalized_groups": norm_groups},
    })
    write_json(REPORTS / "jbb_semantic_intake_v1.json", {
        "schema_version": "jbb_semantic_intake.v1", "original_rows": 55,
        "candidates": len(candidates), "needs_pi_review": needs_review, "semantic_exclusions": semantic_exclusions,
        "dataset_a_overlaps": overlaps, "xstest_overlaps": cross_xstest,
        "rule": "Deterministic prefilter only; no final Case GT assigned.",
    })
    write_json(REPORTS / "jbb_validation_v1.json", validation)
    write_json(REPORTS / "jbb_intake_summary_v1.json", {
        "schema_version": "jbb_intake_summary.v1", "source_distribution": dict(source_distribution),
        "original_candidates": len(candidates), "needs_pi_review": needs_review,
        "semantic_exclusions": len(semantic_exclusions), "dataset_a_duplicates": len(overlaps),
        "pool": {"total": len(combined), "provisional_benign": 250, "provisional_malicious": len(candidates)},
        "status": "JBB_INTAKE_READY" if validation["passed"] else "BLOCKED",
    })
    return {"validation": validation, "needs_pi_review": needs_review, "semantic_exclusions": len(semantic_exclusions)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jbb-repo", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.jbb_repo), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
