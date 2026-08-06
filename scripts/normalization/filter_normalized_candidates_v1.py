from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


INPUT_JSONL = Path("data/normalized/all_sources_normalized_v1.jsonl")

OUT_DIR = Path("data/normalized")
REVIEW_DIR = Path("data/review")
REPORT_DIR = Path("reports")

OUT_DIR.mkdir(parents=True, exist_ok=True)
REVIEW_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

ELIGIBLE_JSONL = OUT_DIR / "eligible_pool_v1.jsonl"
EXCLUDED_CSV = REVIEW_DIR / "auto_filter_excluded_v1.csv"
LENGTH_REVIEW_CSV = REVIEW_DIR / "auto_filter_length_review_v1.csv"

SUMMARY_CSV = REPORT_DIR / "auto_filter_summary_v1.csv"
SUMMARY_MD = REPORT_DIR / "auto_filter_summary_v1.md"


GENERAL_MAX_LEN = 6000
STRUCTURE_MAX_LEN = 20000
MIN_LEN = 20


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def bool_str(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def add_filter_fields(row: dict[str, Any]) -> dict[str, Any]:
    row = dict(row)
    row["auto_filter_status"] = ""
    row["auto_filter_reasons"] = ""
    row["duplicate_of_record_id"] = ""
    return row


def compact_row(row: dict[str, Any]) -> dict[str, Any]:
    """
    Review CSV가 너무 무거워지는 것을 막기 위한 축약 row.
    """
    scanner_input = row.get("scanner_input", "") or ""

    return {
        "normalized_record_id": row.get("normalized_record_id", ""),
        "source_id": row.get("source_id", ""),
        "source_split": row.get("source_split", ""),
        "source_record_id": row.get("source_record_id", ""),
        "normalized_label": row.get("normalized_label", ""),
        "candidate_use": row.get("candidate_use", ""),
        "attack_type": row.get("attack_type", ""),
        "is_structure_intact": row.get("is_structure_intact", ""),
        "is_context_eval": row.get("is_context_eval", ""),
        "is_augmented": row.get("is_augmented", ""),
        "group_id": row.get("group_id", ""),
        "text_length": row.get("text_length", ""),
        "text_sha256": row.get("text_sha256", ""),
        "keep_or_drop": row.get("keep_or_drop", ""),
        "drop_reason": row.get("drop_reason", ""),
        "auto_filter_status": row.get("auto_filter_status", ""),
        "auto_filter_reasons": row.get("auto_filter_reasons", ""),
        "duplicate_of_record_id": row.get("duplicate_of_record_id", ""),
        "scanner_input_preview": scanner_input[:500].replace("\n", "\\n"),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            f.write("")
        return

    fieldnames = list(rows[0].keys())

    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    rows = [add_filter_fields(r) for r in read_jsonl(INPUT_JSONL)]

    seen_hash: dict[str, str] = {}

    eligible: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    length_review: list[dict[str, Any]] = []

    status_counter = Counter()
    reason_counter = Counter()

    for row in rows:
        reasons = []

        record_id = row.get("normalized_record_id", "")
        text_hash = row.get("text_sha256", "")
        text_length = int(row.get("text_length") or 0)
        is_structure = bool_str(row.get("is_structure_intact"))

        if row.get("keep_or_drop") == "drop":
            reasons.append(f"pre_marked_drop:{row.get('drop_reason', '')}")

        if text_length < MIN_LEN:
            reasons.append("too_short")

        if text_hash:
            if text_hash in seen_hash:
                reasons.append("exact_duplicate")
                row["duplicate_of_record_id"] = seen_hash[text_hash]
            else:
                seen_hash[text_hash] = record_id

        max_len = STRUCTURE_MAX_LEN if is_structure else GENERAL_MAX_LEN
        is_too_long = text_length > max_len

        if reasons:
            row["auto_filter_status"] = "excluded"
            row["auto_filter_reasons"] = ";".join(reasons)
            excluded.append(compact_row(row))
            status_counter["excluded"] += 1
            for reason in reasons:
                reason_counter[reason.split(":")[0]] += 1
            continue

        if is_too_long:
            row["auto_filter_status"] = "length_review"
            row["auto_filter_reasons"] = f"too_long>{max_len}"
            length_review.append(compact_row(row))
            status_counter["length_review"] += 1
            reason_counter["too_long"] += 1
            continue

        row["auto_filter_status"] = "eligible"
        row["auto_filter_reasons"] = ""
        eligible.append(row)
        status_counter["eligible"] += 1

    with ELIGIBLE_JSONL.open("w", encoding="utf-8") as f:
        for row in eligible:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    write_csv(EXCLUDED_CSV, excluded)
    write_csv(LENGTH_REVIEW_CSV, length_review)

    # Summary
    summary_rows = []
    grouped = defaultdict(list)

    for row in eligible:
        grouped[row["source_id"]].append(row)

    for source_id, group in sorted(grouped.items()):
        summary_rows.append({
            "source_id": source_id,
            "eligible_total": len(group),
            "label_counts": json.dumps(dict(Counter(r["normalized_label"] for r in group)), ensure_ascii=False, sort_keys=True),
            "candidate_use_counts": json.dumps(dict(Counter(r["candidate_use"] for r in group)), ensure_ascii=False, sort_keys=True),
            "attack_type_counts": json.dumps(dict(Counter(r["attack_type"] for r in group)), ensure_ascii=False, sort_keys=True),
            "structure_counts": json.dumps(dict(Counter(r["is_structure_intact"] for r in group)), ensure_ascii=False, sort_keys=True),
            "augmented_counts": json.dumps(dict(Counter(r["is_augmented"] for r in group)), ensure_ascii=False, sort_keys=True),
        })

    write_csv(SUMMARY_CSV, summary_rows)

    with SUMMARY_MD.open("w", encoding="utf-8") as f:
        f.write("# Auto Filter Summary v1\n\n")
        f.write(f"- input rows: {len(rows)}\n")
        f.write(f"- eligible rows: {len(eligible)}\n")
        f.write(f"- excluded rows: {len(excluded)}\n")
        f.write(f"- length review rows: {len(length_review)}\n\n")

        f.write("## Status Counts\n\n")
        for k, v in status_counter.most_common():
            f.write(f"- {k}: {v}\n")

        f.write("\n## Reason Counts\n\n")
        for k, v in reason_counter.most_common():
            f.write(f"- {k}: {v}\n")

        f.write("\n## Eligible by Source\n\n")
        f.write("| source_id | eligible_total | labels | candidate_use | attack_type |\n")
        f.write("| --- | ---: | --- | --- | --- |\n")

        for r in summary_rows:
            f.write(
                f"| {r['source_id']} "
                f"| {r['eligible_total']} "
                f"| `{r['label_counts']}` "
                f"| `{r['candidate_use_counts']}` "
                f"| `{r['attack_type_counts']}` |\n"
            )

        f.write("\n## Output Files\n\n")
        f.write(f"- eligible jsonl: `{ELIGIBLE_JSONL.as_posix()}`\n")
        f.write(f"- excluded csv: `{EXCLUDED_CSV.as_posix()}`\n")
        f.write(f"- length review csv: `{LENGTH_REVIEW_CSV.as_posix()}`\n")
        f.write(f"- summary csv: `{SUMMARY_CSV.as_posix()}`\n")

    print(f"[OK] input rows: {len(rows)}")
    print(f"[OK] eligible rows: {len(eligible)}")
    print(f"[OK] excluded rows: {len(excluded)}")
    print(f"[OK] length review rows: {len(length_review)}")
    print(f"[OK] wrote {ELIGIBLE_JSONL}")
    print(f"[OK] wrote {EXCLUDED_CSV}")
    print(f"[OK] wrote {LENGTH_REVIEW_CSV}")
    print(f"[OK] wrote {SUMMARY_MD}")


if __name__ == "__main__":
    main()
