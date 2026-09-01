#!/usr/bin/env python3
"""Build Non-PI Supplemental Pool v1 source preflight and raw intake only."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "data/non_pi_supplemental"
REPORTS = ROOT / "reports/non_pi_supplemental"
FROZEN = ROOT / "data/dataset_a/final/dataset_a_case_gt_902_v1.jsonl"
X_REVISION = "d7bb5bd738c1fcbc36edd83d5e7d1b71a3e2d84d"
H_REVISION = "8e1604d1171fe8a48d8febecd22f600e462bdcdd"
X_SHA256 = "073e0b0fcc056dc053e4bd473bcf25c02e50f7771ffb261a1b047901d7de286e"
H_SHA256 = "8d81accedd38eaaf8b760618622bb888417d1fd0c86eba65c427a16f1cbb4afc"
CANDIDATE_FIELDS = {
    "supplemental_candidate_id", "supplemental_track", "source_id", "source_name",
    "source_repo", "pinned_revision", "source_file", "source_row_locator",
    "source_record_id", "original_text", "original_source_label_category", "license_id",
    "license_evidence", "redistribution_status", "upstream_source", "raw_file_sha256",
    "candidate_selection_reason", "needs_pi_review", "notes",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def candidate_id(source_id: str, record_id: str) -> str:
    digest = hashlib.sha256(f"non-pi-supplemental-v1:{source_id}:{record_id}".encode()).hexdigest()[:16].upper()
    return f"NPS-V1-{digest}"


def normalize(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).casefold()
    value = re.sub(r"\s+", " ", value).strip()
    return re.sub(r"[^\w\s]", "", value)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def duplicate_groups(values: list[tuple[str, str]]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for identifier, value in values:
        groups.setdefault(value, []).append(identifier)
    return [{"value_sha256": hashlib.sha256(value.encode()).hexdigest(), "ids": ids}
            for value, ids in sorted(groups.items()) if len(ids) > 1]


def run(xrepo: Path, hrepo: Path) -> dict[str, Any]:
    if OUT.exists() or REPORTS.exists():
        raise FileExistsError("Refusing to overwrite supplemental workspace")
    xfile = xrepo / "xstest_prompts.csv"
    hfile = hrepo / "data/behavior_datasets/harmbench_behaviors_text_all.csv"
    if sha256(xfile) != X_SHA256 or sha256(hfile) != H_SHA256:
        raise ValueError("Pinned raw file hash mismatch")
    if subprocess_head(xrepo) != X_REVISION or subprocess_head(hrepo) != H_REVISION:
        raise ValueError("Pinned repository revision mismatch")

    for directory in ("source_catalog", "license_audit", "raw", "candidate_pool", "adjudication"):
        (OUT / directory).mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(xfile, OUT / "raw/xstest_prompts.csv")
    shutil.copyfile(xrepo / "README.md", OUT / "license_audit/xstest_README.md")
    shutil.copyfile(xrepo / "LICENSE", OUT / "license_audit/xstest_LICENSE.txt")
    shutil.copyfile(hrepo / "README.md", OUT / "license_audit/harmbench_README.md")
    shutil.copyfile(hrepo / "LICENSE", OUT / "license_audit/harmbench_LICENSE.txt")

    with xfile.open(encoding="utf-8-sig", newline="") as handle:
        xrows = list(csv.DictReader(handle))
    with hfile.open(encoding="utf-8-sig", newline="") as handle:
        hrows = list(csv.DictReader(handle))
    if len(xrows) != 450 or Counter(row["label"] for row in xrows) != {"safe": 250, "unsafe": 200}:
        raise ValueError("Unexpected XSTest distribution")
    if len(hrows) != 400:
        raise ValueError("Unexpected HarmBench row count")

    frozen_texts = []
    for row in read_jsonl(FROZEN):
        case = row["case_input"]
        for key in ("untrusted_input", "trusted_instruction", "normal_task"):
            if case.get(key): frozen_texts.append((row["candidate_id"], case[key]))
    frozen_exact = {text for _, text in frozen_texts}
    frozen_normalized = {normalize(text) for _, text in frozen_texts}

    candidates = []
    x_overlap = []
    for index, row in enumerate(xrows, 2):
        if row["label"] != "safe":
            continue
        identifier = candidate_id("XSTEST", row["id"])
        reason = "XSTest prompt source label is safe; retained only as provisional intent pending independent Contract v2 adjudication."
        candidate = {
            "supplemental_candidate_id": identifier,
            "supplemental_track": "non_pi_non_malicious_candidate",
            "source_id": "NPS-SRC-XSTEST", "source_name": "XSTest prompts",
            "source_repo": "https://github.com/paul-rottger/xstest", "pinned_revision": X_REVISION,
            "source_file": "xstest_prompts.csv", "source_row_locator": f"xstest_prompts.csv:{index}",
            "source_record_id": row["id"], "original_text": row["prompt"],
            "original_source_label_category": {"label": row["label"], "type": row["type"], "focus": row["focus"], "note": row["note"]},
            "license_id": "CC-BY-4.0",
            "license_evidence": ["license_audit/xstest_README.md#license", "license_audit/xstest_LICENSE.txt"],
            "redistribution_status": "redistribution_approved_with_attribution", "upstream_source": None,
            "raw_file_sha256": X_SHA256, "candidate_selection_reason": reason,
            "needs_pi_review": False, "notes": "Source label is not final Case GT.",
        }
        if row["prompt"] in frozen_exact or normalize(row["prompt"]) in frozen_normalized:
            x_overlap.append({"supplemental_candidate_id": identifier, "source_record_id": row["id"], "reason": "frozen_dataset_a_overlap"})
        else:
            candidates.append(candidate)

    pi_pattern = re.compile(r"ignore (?:all |any )?(?:previous|prior|system|developer) instructions|system prompt|developer message|reveal .*instructions|prompt injection|jailbreak", re.I)
    blocked = []
    semantic_potential = 0
    pi_review = 0
    for index, row in enumerate(hrows, 2):
        potential = row["SemanticCategory"] != "copyright"
        flagged = bool(pi_pattern.search(row["Behavior"]))
        semantic_potential += int(potential)
        pi_review += int(flagged)
        blocked.append({
            "source_row_locator": f"harmbench_behaviors_text_all.csv:{index}",
            "source_record_id": row["BehaviorID"], "functional_category": row["FunctionalCategory"],
            "semantic_category": row["SemanticCategory"], "tags": row["Tags"],
            "redistribution_status": "blocked_pending_upstream_license",
            "upstream_source": "unresolved_no_row_level_source_metadata",
            "semantic_candidate_if_licensed": potential, "needs_pi_review": flagged,
            "excluded_attack_generated_test_case": False,
            "notes": "Raw behavior objective inspected; original text withheld from supplemental materialization pending upstream license resolution.",
        })

    ids = [row["supplemental_candidate_id"] for row in candidates]
    exact_groups = duplicate_groups([(row["supplemental_candidate_id"], row["original_text"]) for row in candidates])
    normalized_groups = duplicate_groups([(row["supplemental_candidate_id"], normalize(row["original_text"])) for row in candidates])
    validation = {
        "schema_version": "non_pi_supplemental_validation.v1", "candidate_count": len(candidates),
        "unique_id_count": len(set(ids)), "schema_violations": sum(set(row) != CANDIDATE_FIELDS for row in candidates),
        "provenance_coverage": sum(all(row.get(k) is not None for k in ("source_id", "source_repo", "pinned_revision", "source_file", "source_row_locator", "raw_file_sha256")) for row in candidates),
        "license_coverage": sum(bool(row["license_id"] and row["license_evidence"] and row["redistribution_status"]) for row in candidates),
        "exact_duplicate_groups": len(exact_groups), "normalized_duplicate_groups": len(normalized_groups),
        "frozen_dataset_a_overlap_count": len(x_overlap), "passed": False,
    }
    validation["passed"] = all((len(candidates) == 250 - len(x_overlap), len(ids) == len(set(ids)), validation["schema_violations"] == 0,
                                validation["provenance_coverage"] == len(candidates), validation["license_coverage"] == len(candidates),
                                not exact_groups, not normalized_groups, not x_overlap))
    source_catalog = {
        "schema_version": "non_pi_supplemental_source_catalog.v1",
        "sources": [
            {"source_id": "NPS-SRC-XSTEST", "repo": "https://github.com/paul-rottger/xstest", "revision": X_REVISION, "file": "xstest_prompts.csv", "sha256": X_SHA256, "license": "CC-BY-4.0", "redistribution_status": "redistribution_approved_with_attribution", "prompt_rows": 450, "safe_rows": 250, "unsafe_rows_excluded": 200, "citation": {"title": "XSTest: A Test Suite for Identifying Exaggerated Safety Behaviours in Large Language Models", "authors": "Rottger et al.", "venue": "NAACL 2024", "url": "https://aclanthology.org/2024.naacl-long.301/", "doi": "10.18653/v1/2024.naacl-long.301"}, "attribution_requirements": ["identify creators", "retain CC-BY-4.0 notice", "link license", "indicate changes"]},
            {"source_id": "NPS-SRC-HARMBENCH", "repo": "https://github.com/centerforaisafety/HarmBench", "revision": H_REVISION, "file": "data/behavior_datasets/harmbench_behaviors_text_all.csv", "sha256": H_SHA256, "repository_license": "MIT", "redistribution_status": "blocked_pending_upstream_license", "row_count": 400, "reason": "No row-level or source-family provenance field maps behavior text to upstream copyright/license."},
        ],
    }
    h_exact = {row["Behavior"] for row in hrows}
    h_normalized = {normalize(row["Behavior"]) for row in hrows}
    harmbench_exact_groups = duplicate_groups([(row["BehaviorID"], row["Behavior"]) for row in hrows])
    harmbench_normalized_groups = duplicate_groups([(row["BehaviorID"], normalize(row["Behavior"])) for row in hrows])
    duplicate_audit = {"schema_version": "non_pi_supplemental_duplicate_audit.v1", "exact_duplicate_groups": exact_groups, "normalized_duplicate_groups": normalized_groups, "harmbench_blocked_internal_duplicates": {"exact_group_count": len(harmbench_exact_groups), "normalized_group_count": len(harmbench_normalized_groups), "groups": harmbench_exact_groups}, "xstest_harmbench_comparison": {"exact_overlap_count": sum(row["original_text"] in h_exact for row in candidates), "normalized_overlap_count": sum(normalize(row["original_text"]) in h_normalized for row in candidates), "note": "Compared in-memory against pinned HarmBench raw behaviors; HarmBench text was not materialized because redistribution is blocked."}, "frozen_dataset_a_overlaps": x_overlap}
    write_json(OUT / "source_catalog/source_catalog_v1.json", source_catalog)
    write_jsonl(OUT / "raw/xstest_safe_candidates_v1.jsonl", candidates)
    write_jsonl(OUT / "candidate_pool/non_pi_supplemental_candidates_v1.jsonl", candidates)
    write_jsonl(OUT / "license_audit/harmbench_blocked_inventory_v1.jsonl", blocked)
    write_json(OUT / "license_audit/xstest_license_audit_v1.json", {"schema_version": "xstest_license_audit.v1", "source_repo": "https://github.com/paul-rottger/xstest", "pinned_revision": X_REVISION, "source_file": "xstest_prompts.csv", "raw_file_sha256": X_SHA256, "prompt_license": "CC-BY-4.0", "prompt_redistribution_status": "redistribution_approved_with_attribution", "model_completions_ingested": False, "model_completions_license_scope": "original model-provider licenses; excluded", "license_evidence": ["xstest_README.md", "xstest_LICENSE.txt"], "citation": {"title": "XSTest: A Test Suite for Identifying Exaggerated Safety Behaviours in Large Language Models", "authors": "Rottger et al.", "venue": "NAACL 2024", "url": "https://aclanthology.org/2024.naacl-long.301/", "doi": "10.18653/v1/2024.naacl-long.301"}})
    write_json(OUT / "license_audit/harmbench_license_audit_v1.json", {"schema_version": "harmbench_license_audit.v1", "repository_license": "MIT", "raw_rows": 400, "source_family_metadata_available": False, "approved_rows": 0, "blocked_rows": 400, "semantic_non_copyright_potential": semantic_potential, "needs_pi_review": pi_review, "attack_generated_test_cases_ingested": 0, "decision": "LICENSE_REVIEW_REQUIRED"})
    write_json(REPORTS / "duplicate_audit_v1.json", duplicate_audit)
    write_json(REPORTS / "validation_v1.json", validation)
    write_json(REPORTS / "preflight_summary_v1.json", {"schema_version": "non_pi_supplemental_preflight_summary.v1", "xstest": {"total": 450, "safe": 250, "unsafe_excluded": 200, "dataset_a_overlap": len(x_overlap)}, "harmbench": {"total": 400, "approved": 0, "blocked": 400, "semantic_potential": semantic_potential, "needs_pi_review": pi_review}, "candidate_pool": {"total": len(candidates), "benign": len(candidates), "malicious": 0}, "status": "LICENSE_REVIEW_REQUIRED" if validation["passed"] else "BLOCKED"})
    return {"validation": validation, "semantic_potential": semantic_potential, "blocked": len(blocked)}


def subprocess_head(repo: Path) -> str:
    import subprocess
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xstest-repo", type=Path, required=True)
    parser.add_argument("--harmbench-repo", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.xstest_repo, args.harmbench_repo), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
