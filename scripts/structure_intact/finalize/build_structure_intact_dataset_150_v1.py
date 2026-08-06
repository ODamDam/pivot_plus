from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any


def find_project_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "data").is_dir() and (candidate / "scripts").is_dir():
            return candidate
    raise FileNotFoundError("Could not find project root containing data/ and scripts/.")


PROJECT_ROOT = find_project_root(Path(__file__).parent)
REVIEW_ROOT = PROJECT_ROOT / "data" / "review" / "04_structure_intact"
AUDIT_ROOT = REVIEW_ROOT / "structure_intact_audit_v1"
EXTERNAL_ROOT = REVIEW_ROOT / "external_structure_candidates"
MARKDOWN_RESCAN_ROOT = REVIEW_ROOT / "structure_intact_markdown_rescan_v2"
YAML_RESCAN_ROOT = REVIEW_ROOT / "yaml_rescan_v2"
FINAL_ROOT = REVIEW_ROOT / "final"
FINAL_ROOT.mkdir(parents=True, exist_ok=True)


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"No rows to write: {path}")
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def first_nonempty(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(row.get(key, "") or "").strip()
        if value:
            return value
    return ""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def keep_rows(path: Path) -> list[dict[str, Any]]:
    rows = read_csv(path)
    if rows and "review_decision" in rows[0]:
        return [row for row in rows if row.get("review_decision", "").strip().lower() == "keep"]
    return rows


def resolve(*candidates: Path) -> Path:
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError("None of the candidate paths exists:\n" + "\n".join(map(str, candidates)))


def normalize(row: dict[str, Any], fmt: str, index: int) -> dict[str, Any]:
    text = first_nonempty(row, "scanner_input", "eval_content", "context_with_attack", "text", "content")
    if not text:
        raise ValueError(f"No scanner_input for {fmt}: {row.get('candidate_id')}")

    source_id = first_nonempty(row, "source_id")
    structure_origin = first_nonempty(row, "structure_origin")
    if not structure_origin:
        structure_origin = (
            "synthetic_source_original"
            if source_id in {"SRC-10_scout450", "SRC-11_microsoft_bipia", "SRC-12_bordair_multimodal"}
            else "source_original"
        )

    generation_method = first_nonempty(row, "generation_method")
    if not generation_method:
        generation_method = (
            "public_source_generator"
            if structure_origin == "synthetic_source_original"
            else "source_original"
        )

    return {
        "dataset_id": f"STRUCT-INTACT-{index:04d}",
        "candidate_id": first_nonempty(row, "candidate_id"),
        "source_id": source_id,
        "source_record_id": first_nonempty(row, "source_record_id", "record_id", "id"),
        "text_sha256": first_nonempty(row, "text_sha256") or sha256_text(text),
        "scanner_input": text,
        "ground_truth_decision": "malicious",
        "dataset_subset": "structure_intact_malicious",
        "structure_format": fmt,
        "structure_origin": structure_origin,
        "generation_method": generation_method,
        "provenance_status": first_nonempty(row, "provenance_status") or "traceable",
        "review_decision": "keep",
        "quota_selection": "yes",
        "attack_type": first_nonempty(row, "attack_type", "attack_category", "category"),
        "attack_goal": first_nonempty(row, "attack_goal", "attack_name"),
        "attack_surface": first_nonempty(row, "attack_surface"),
        "review_note": first_nonempty(row, "review_note"),
    }


def main() -> None:
    additions_root = REVIEW_ROOT / "final_selection"

    markdown_rows = (
        keep_rows(resolve(AUDIT_ROOT / "structure_audit_markdown_v1_completed.csv",
                          REVIEW_ROOT / "audit" / "structure_audit_markdown_v1_completed.csv"))
        + keep_rows(EXTERNAL_ROOT / "src10_scout450_v1" / "src10_scout450_markdown_candidates_v1_completed.csv")
        + read_csv(MARKDOWN_RESCAN_ROOT / "markdown_rescan_selected_4_v2.csv")
        + read_csv(additions_root / "structure_intact_markdown_additional_4_v1.csv")
    )

    json_rows = (
        keep_rows(resolve(AUDIT_ROOT / "structure_audit_json_v1_completed.csv",
                          REVIEW_ROOT / "audit" / "structure_audit_json_v1_completed.csv"))
        + keep_rows(EXTERNAL_ROOT / "src10_scout450_v1" / "src10_scout450_json_candidates_v1_completed.csv")
        + [row for row in read_csv(additions_root / "structure_intact_bordair_selected_2_v1.csv")
           if row.get("candidate_structure_format") == "json"]
    )

    code_rows = (
        keep_rows(resolve(AUDIT_ROOT / "structure_audit_code_block_v1_completed.csv",
                          REVIEW_ROOT / "audit" / "structure_audit_code_block_v1_completed.csv"))
        + keep_rows(EXTERNAL_ROOT / "src10_scout450_v1" / "src10_scout450_code_block_candidates_v1_completed.csv")
        + read_csv(EXTERNAL_ROOT / "src11_bipia_v1" / "src11_bipia_code_selected_10_v1.csv")
        + read_csv(additions_root / "structure_intact_bipia_code_additional_8_v1.csv")
    )

    repository_rows = read_csv(
        resolve(
            REVIEW_ROOT / "audit" / "structure_intact_repository_file_selected_30_v1.csv",
            AUDIT_ROOT / "structure_intact_repository_file_selected_30_v1.csv",
        )
    )

    yaml_rows = (
        read_csv(resolve(REVIEW_ROOT / "audit" / "structure_intact_yaml_selected_2_v1.csv",
                         AUDIT_ROOT / "structure_intact_yaml_selected_2_v1.csv"))
        + read_csv(resolve(YAML_RESCAN_ROOT / "yaml_rescan_selected_strict_v2.csv",
                           REVIEW_ROOT / "audit" / "yaml_rescan_selected_strict_v2.csv"))
        + [row for row in read_csv(additions_root / "structure_intact_bordair_selected_2_v1.csv")
           if row.get("candidate_structure_format") == "yaml"]
    )

    groups = {
        "markdown": markdown_rows,
        "json": json_rows,
        "yaml": yaml_rows,
        "code_block": code_rows,
        "repository_file": repository_rows,
    }
    expected = {
        "markdown": 34,
        "json": 34,
        "yaml": 14,
        "code_block": 38,
        "repository_file": 30,
    }

    for fmt, rows in groups.items():
        if len(rows) != expected[fmt]:
            raise ValueError(f"{fmt}: expected {expected[fmt]}, got {len(rows)}")

    final_rows: list[dict[str, Any]] = []
    index = 1
    for fmt in ["markdown", "json", "yaml", "code_block", "repository_file"]:
        for row in groups[fmt]:
            final_rows.append(normalize(row, fmt, index))
            index += 1

    hashes = [row["text_sha256"] for row in final_rows]
    duplicate_hashes = sorted({h for h in hashes if hashes.count(h) > 1})
    if duplicate_hashes:
        raise ValueError(f"Duplicate text hashes: {duplicate_hashes[:10]}")

    final_csv = FINAL_ROOT / "structure_intact_dataset_150_v1.csv"
    final_jsonl = FINAL_ROOT / "structure_intact_dataset_150_v1.jsonl"
    manifest_csv = FINAL_ROOT / "structure_intact_dataset_150_manifest_v1.csv"
    summary_json = PROJECT_ROOT / "reports" / "structure_intact_dataset_150_summary_v1.json"

    write_csv(final_csv, final_rows)
    with final_jsonl.open("w", encoding="utf-8") as f:
        for row in final_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    manifest_rows = []
    for fmt, rows in groups.items():
        source_counts: dict[str, int] = {}
        for row in rows:
            sid = first_nonempty(row, "source_id") or "UNKNOWN"
            source_counts[sid] = source_counts.get(sid, 0) + 1
        manifest_rows.append({
            "structure_format": fmt,
            "target_count": expected[fmt],
            "actual_count": len(rows),
            "source_distribution": json.dumps(source_counts, ensure_ascii=False, sort_keys=True),
            "status": "complete",
        })
    write_csv(manifest_csv, manifest_rows)

    summary = {
        "dataset_name": "structure_intact_dataset_150_v1",
        "total_rows": len(final_rows),
        "format_counts": {fmt: len(rows) for fmt, rows in groups.items()},
        "format_targets": expected,
        "duplicate_text_hash_count": 0,
        "all_ground_truth_malicious": True,
        "all_reviewed_keep": True,
        "all_quota_selected": True,
        "output_csv": str(final_csv.relative_to(PROJECT_ROOT)),
        "output_jsonl": str(final_jsonl.relative_to(PROJECT_ROOT)),
        "manifest_csv": str(manifest_csv.relative_to(PROJECT_ROOT)),
    }
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 72)
    print("[done] structure-intact dataset 150 v1")
    print(f"total rows      : {len(final_rows)}")
    for fmt, count in summary["format_counts"].items():
        print(f"  {fmt:<20}: {count}")
    print(f"duplicate hashes: {summary['duplicate_text_hash_count']}")
    print(f"csv             : {final_csv}")
    print(f"jsonl           : {final_jsonl}")
    print(f"manifest        : {manifest_csv}")
    print(f"summary         : {summary_json}")
    print("=" * 72)


if __name__ == "__main__":
    main()
