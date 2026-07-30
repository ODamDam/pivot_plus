from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.operator_assignment_policy import (  # noqa: E402
    is_main_malicious_mutation_candidate,
    is_smoke_test_candidate,
    to_engine_input,
)


DEFAULT_REVIEW_FILES = [
    PROJECT_ROOT / "data" / "review" / "manual_review_seed_malicious_schema_v1.csv",
    PROJECT_ROOT / "data" / "review" / "manual_review_bypass_candidate_schema_v1.csv",
]


def read_csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            f.write("")
        return

    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def norm(value: Any) -> str:
    return str(value or "").strip()


def lower(value: Any) -> str:
    return norm(value).lower()


def is_kept_by_review(row: dict[str, Any], *, allow_unreviewed: bool) -> bool:
    review_decision = lower(row.get("review_decision"))
    keep_or_drop = lower(row.get("keep_or_drop"))
    review_status = lower(row.get("review_status") or row.get("manual_review_status"))

    if review_decision == "keep":
        return True

    if keep_or_drop == "keep":
        return True

    if allow_unreviewed:
        if review_decision in {"", "pending"} and keep_or_drop in {"", "pending", "none"}:
            if review_status in {"", "auto", "pending", "reviewed", "manual_reviewed"}:
                return True

    return False


def row_key(row: dict[str, Any]) -> str:
    review_file = norm(row.get("_review_file"))

    normalized_record_id = norm(row.get("normalized_record_id"))
    if normalized_record_id:
        return f"normalized_record_id:{normalized_record_id}"

    text_sha256 = norm(row.get("text_sha256"))
    if text_sha256:
        return f"text_sha256:{text_sha256}"

    sample_id = norm(row.get("sample_id"))
    if sample_id:
        return f"review_file:{review_file}|sample_id:{sample_id}"

    source_id = norm(row.get("source_id"))
    source_record_id = norm(row.get("source_record_id"))
    if source_id or source_record_id:
        return f"source:{source_id}|record:{source_record_id}|review_file:{review_file}"

    return "text:" + norm(row.get("scanner_input") or row.get("text"))[:200]


def load_review_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for path in paths:
        for row in read_csv_rows(path):
            row["_review_file"] = str(path.relative_to(PROJECT_ROOT))
            rows.append(row)

    return rows


def build_mutation_inputs(
    rows: list[dict[str, Any]],
    *,
    smoke_test: bool,
    allow_unreviewed: bool,
    limit: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    seen: set[str] = set()

    for row in rows:
        key = row_key(row)

        if key in seen:
            excluded.append({
                "sample_id": row.get("sample_id", ""),
                "reason": "duplicate",
                "review_file": row.get("_review_file", ""),
                "attack_type": row.get("attack_type", ""),
                "source_id": row.get("source_id", ""),
            })
            continue

        if not is_kept_by_review(row, allow_unreviewed=allow_unreviewed):
            excluded.append({
                "sample_id": row.get("sample_id", ""),
                "reason": "not_kept_by_review",
                "review_file": row.get("_review_file", ""),
                "review_decision": row.get("review_decision", ""),
                "keep_or_drop": row.get("keep_or_drop", ""),
                "attack_type": row.get("attack_type", ""),
                "source_id": row.get("source_id", ""),
            })
            continue

        if smoke_test:
            candidate_ok = is_smoke_test_candidate(row)
            reason = "not_smoke_test_candidate"
        else:
            candidate_ok = is_main_malicious_mutation_candidate(row)
            reason = "not_main_malicious_mutation_candidate"

        if not candidate_ok:
            excluded.append({
                "sample_id": row.get("sample_id", ""),
                "reason": reason,
                "review_file": row.get("_review_file", ""),
                "subset": row.get("subset", ""),
                "ground_truth_decision": row.get("ground_truth_decision", ""),
                "attack_type": row.get("attack_type", ""),
                "attack_surface": row.get("attack_surface", ""),
                "input_format": row.get("input_format", ""),
                "source_id": row.get("source_id", ""),
            })
            continue

        mutation_seed_id = f"MSEED-{len(selected) + 1:06d}"
        engine_row = to_engine_input(row, mutation_seed_id=mutation_seed_id, smoke_test=smoke_test)

        if int(engine_row.get("mutation_budget", 0)) <= 0:
            excluded.append({
                "sample_id": row.get("sample_id", ""),
                "reason": "zero_mutation_budget",
                "review_file": row.get("_review_file", ""),
                "attack_type": row.get("attack_type", ""),
                "attack_surface": row.get("attack_surface", ""),
                "input_format": row.get("input_format", ""),
                "source_id": row.get("source_id", ""),
            })
            continue

        engine_row["metadata"]["review_file"] = row.get("_review_file", "")
        engine_row["metadata"]["adapter_mode"] = "smoke_test" if smoke_test else "main"

        selected.append(engine_row)
        seen.add(key)

        if limit > 0 and len(selected) >= limit:
            break

    return selected, excluded


def summarize(rows: list[dict[str, Any]], excluded: list[dict[str, Any]]) -> dict[str, Any]:
    source_counts = Counter(row.get("source_id", "") for row in rows)
    attack_counts = Counter(row.get("attack_type", "") for row in rows)
    surface_counts = Counter(row.get("engine_surface", "") for row in rows)

    family_counts: Counter[str] = Counter()
    weakness_counts: Counter[str] = Counter()

    for row in rows:
        family_counts.update(row.get("allowed_operator_families", []))
        weakness_counts.update(row.get("target_evaluator_weaknesses", []))

    excluded_reasons = Counter(row.get("reason", "") for row in excluded)

    return {
        "selected_total": len(rows),
        "excluded_total": len(excluded),
        "source_counts": dict(source_counts),
        "attack_type_counts": dict(attack_counts),
        "engine_surface_counts": dict(surface_counts),
        "allowed_family_counts": dict(family_counts),
        "target_weakness_counts": dict(weakness_counts),
        "excluded_reason_counts": dict(excluded_reasons),
    }


def write_summary_md(path: Path, summary: dict[str, Any], output_jsonl: Path, excluded_csv: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    def table_from_dict(title: str, data: dict[str, Any]) -> str:
        lines = [f"## {title}", "", "| key | count |", "| --- | ---: |"]
        for key, value in sorted(data.items(), key=lambda item: str(item[0])):
            lines.append(f"| `{key}` | {value} |")
        lines.append("")
        return "\n".join(lines)

    content = [
        "# Mutation Input Build Summary v1",
        "",
        f"- output_jsonl: `{output_jsonl.relative_to(PROJECT_ROOT).as_posix()}`",
        f"- excluded_csv: `{excluded_csv.relative_to(PROJECT_ROOT).as_posix()}`",
        f"- selected_total: {summary['selected_total']}",
        f"- excluded_total: {summary['excluded_total']}",
        "",
        table_from_dict("Source Counts", summary["source_counts"]),
        table_from_dict("Attack Type Counts", summary["attack_type_counts"]),
        table_from_dict("Engine Surface Counts", summary["engine_surface_counts"]),
        table_from_dict("Allowed Family Counts", summary["allowed_family_counts"]),
        table_from_dict("Target Weakness Counts", summary["target_weakness_counts"]),
        table_from_dict("Excluded Reason Counts", summary["excluded_reason_counts"]),
    ]

    path.write_text("\n".join(content), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        nargs="*",
        default=[str(p) for p in DEFAULT_REVIEW_FILES],
        help="Manual review CSV files.",
    )
    parser.add_argument(
        "--output",
        default=str(PROJECT_ROOT / "data" / "final" / "mutation_input_smoke_v1.jsonl"),
        help="Output engine-compatible JSONL path.",
    )
    parser.add_argument(
        "--excluded-output",
        default=str(PROJECT_ROOT / "data" / "final" / "mutation_input_excluded_v1.csv"),
        help="Excluded rows CSV path.",
    )
    parser.add_argument(
        "--summary-output",
        default=str(PROJECT_ROOT / "reports" / "mutation_input_build_summary_v1.md"),
        help="Summary markdown path.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Build full main mutation input instead of conservative smoke-test input.",
    )
    parser.add_argument(
        "--allow-unreviewed",
        action="store_true",
        help="Allow unreviewed rows for adapter/debug smoke testing. Do not use for final benchmark generation.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of selected rows. Use 0 for no limit.",
    )
    args = parser.parse_args()

    input_paths = [Path(p) for p in args.input]
    output_path = Path(args.output)
    excluded_path = Path(args.excluded_output)
    summary_path = Path(args.summary_output)

    rows = load_review_rows(input_paths)
    selected, excluded = build_mutation_inputs(
        rows,
        smoke_test=not args.full,
        allow_unreviewed=args.allow_unreviewed,
        limit=args.limit,
    )

    write_jsonl(output_path, selected)
    write_csv(excluded_path, excluded)

    summary = summarize(selected, excluded)
    write_summary_md(summary_path, summary, output_path, excluded_path)

    print(f"[OK] input rows: {len(rows)}")
    print(f"[OK] selected rows: {len(selected)}")
    print(f"[OK] excluded rows: {len(excluded)}")
    print(f"[OK] output: {output_path.relative_to(PROJECT_ROOT)}")
    print(f"[OK] excluded: {excluded_path.relative_to(PROJECT_ROOT)}")
    print(f"[OK] summary: {summary_path.relative_to(PROJECT_ROOT)}")

    if not selected:
        print("[WARN] No mutation input rows selected.")
        print("[WARN] If manual review is not done yet, run with --allow-unreviewed only for adapter/debug testing.")


if __name__ == "__main__":
    main()
