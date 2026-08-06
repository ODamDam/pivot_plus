from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_INPUT = Path("data/final/mutation_smoke_output_v1.jsonl")
DEFAULT_VALID = Path("data/final/mutation_smoke_valid_v1.jsonl")
DEFAULT_REVIEW = Path("data/final/mutation_smoke_review_v1.jsonl")
DEFAULT_DROPPED = Path("data/final/mutation_smoke_dropped_v1.jsonl")
DEFAULT_SUMMARY = Path("reports/mutation_smoke_validation_summary_v1.md")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def length_ratio(original: str, mutated: str) -> float:
    if not original:
        return 0.0
    return len(mutated) / max(len(original), 1)


def classify(row: dict[str, Any], *, review_ratio: float, drop_ratio: float) -> tuple[str, str]:
    original = str(row.get("original_text", "") or "")
    mutated = str(row.get("mutated_text", "") or "")
    operator = str(row.get("mutation_operator", "") or "")
    family = str(row.get("mutation_family", "") or "")
    status = str(row.get("status", "") or "")

    if status and status != "OK":
        return "drop", f"non_ok_status:{status}"

    if not operator:
        return "drop", "missing_operator"

    if not family:
        return "drop", "missing_family"

    if not mutated.strip():
        return "drop", "empty_mutated_text"

    if mutated == original:
        return "drop", "unchanged"

    ratio = length_ratio(original, mutated)

    if ratio >= drop_ratio:
        return "review", f"excessive_length_growth_ratio:{ratio:.2f}"

    if ratio >= review_ratio:
        return "review", f"large_length_growth_ratio:{ratio:.2f}"

    if operator == "op_comp_expand_context":
        return "review", "context_expansion_requires_review"

    if operator == "op_lex_homoglyph_injection":
        return "review", "encoding_obfuscation_requires_review"

    return "valid", "passed"


def write_summary(
    path: Path,
    *,
    valid: list[dict[str, Any]],
    review: list[dict[str, Any]],
    dropped: list[dict[str, Any]],
    input_path: Path,
    valid_path: Path,
    review_path: Path,
    dropped_path: Path,
) -> None:
    all_rows = valid + review + dropped

    class_counts = Counter(row.get("validation_status", "") for row in all_rows)
    reason_counts = Counter(row.get("validation_reason", "") for row in all_rows)
    operator_counts = Counter(row.get("mutation_operator", "") for row in all_rows)
    valid_operator_counts = Counter(row.get("mutation_operator", "") for row in valid)
    review_reason_counts = Counter(row.get("validation_reason", "") for row in review)
    dropped_reason_counts = Counter(row.get("validation_reason", "") for row in dropped)

    def table(title: str, data: Counter[str]) -> list[str]:
        lines = ["", f"## {title}", "", "| key | count |", "| --- | ---: |"]
        for key, value in sorted(data.items(), key=lambda item: str(item[0])):
            shown = key if key else "<blank>"
            lines.append(f"| `{shown}` | {value} |")
        return lines

    lines = [
        "# Mutation Smoke Validation Summary v1",
        "",
        f"- input: `{input_path.as_posix()}`",
        f"- valid_output: `{valid_path.as_posix()}`",
        f"- review_output: `{review_path.as_posix()}`",
        f"- dropped_output: `{dropped_path.as_posix()}`",
        f"- total_rows: {len(all_rows)}",
        f"- valid_rows: {len(valid)}",
        f"- review_rows: {len(review)}",
        f"- dropped_rows: {len(dropped)}",
    ]

    lines += table("Validation Class Counts", class_counts)
    lines += table("Validation Reason Counts", reason_counts)
    lines += table("All Operator Counts", operator_counts)
    lines += table("Valid Operator Counts", valid_operator_counts)
    lines += table("Review Reason Counts", review_reason_counts)
    lines += table("Dropped Reason Counts", dropped_reason_counts)

    lines += [
        "",
        "## Dropped Rows",
        "",
        "| mutation_id | operator | family | attack_type | reason |",
        "| --- | --- | --- | --- | --- |",
    ]

    for row in dropped:
        lines.append(
            f"| `{row.get('mutation_id', '')}` "
            f"| `{row.get('mutation_operator', '')}` "
            f"| `{row.get('mutation_family', '')}` "
            f"| `{row.get('attack_type', '')}` "
            f"| `{row.get('validation_reason', '')}` |"
        )

    lines += [
        "",
        "## Review Rows",
        "",
        "| mutation_id | operator | family | attack_type | reason |",
        "| --- | --- | --- | --- | --- |",
    ]

    for row in review:
        lines.append(
            f"| `{row.get('mutation_id', '')}` "
            f"| `{row.get('mutation_operator', '')}` "
            f"| `{row.get('mutation_family', '')}` "
            f"| `{row.get('attack_type', '')}` "
            f"| `{row.get('validation_reason', '')}` |"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--valid-output", default=str(DEFAULT_VALID))
    parser.add_argument("--review-output", default=str(DEFAULT_REVIEW))
    parser.add_argument("--dropped-output", default=str(DEFAULT_DROPPED))
    parser.add_argument("--summary-output", default=str(DEFAULT_SUMMARY))
    parser.add_argument("--review-ratio", type=float, default=3.0)
    parser.add_argument("--drop-ratio", type=float, default=10.0)
    args = parser.parse_args()

    input_path = Path(args.input)
    valid_path = Path(args.valid_output)
    review_path = Path(args.review_output)
    dropped_path = Path(args.dropped_output)
    summary_path = Path(args.summary_output)

    rows = read_jsonl(input_path)

    valid: list[dict[str, Any]] = []
    review: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []

    for row in rows:
        status, reason = classify(row, review_ratio=args.review_ratio, drop_ratio=args.drop_ratio)
        row = dict(row)
        row["validation_status"] = status
        row["validation_reason"] = reason

        if status == "valid":
            valid.append(row)
        elif status == "review":
            review.append(row)
        else:
            dropped.append(row)

    write_jsonl(valid_path, valid)
    write_jsonl(review_path, review)
    write_jsonl(dropped_path, dropped)

    write_summary(
        summary_path,
        valid=valid,
        review=review,
        dropped=dropped,
        input_path=input_path,
        valid_path=valid_path,
        review_path=review_path,
        dropped_path=dropped_path,
    )

    print(f"[OK] total rows: {len(rows)}")
    print(f"[OK] valid rows: {len(valid)}")
    print(f"[OK] review rows: {len(review)}")
    print(f"[OK] dropped rows: {len(dropped)}")
    print(f"[OK] valid output: {valid_path}")
    print(f"[OK] review output: {review_path}")
    print(f"[OK] dropped output: {dropped_path}")
    print(f"[OK] summary: {summary_path}")


if __name__ == "__main__":
    main()
