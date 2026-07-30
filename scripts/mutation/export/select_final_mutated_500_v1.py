from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


VALID_PATH = Path(
    "data/review/mutation_filter/"
    "mutation_candidates_1150_valid_v1.jsonl"
)

OUTPUT_JSONL_PATH = Path(
    "data/final/mutated_malicious_500_v1.jsonl"
)

OUTPUT_CSV_PATH = Path(
    "data/final/mutated_malicious_500_v1.csv"
)

SUMMARY_PATH = Path(
    "reports/mutated_malicious_500_selection_summary_v1.json"
)

CHILDREN_PER_PARENT = 2


# Lower value means higher preference.
OPERATOR_PRIORITY = {
    "op_fmt_structured_wrapper_json_yaml": 1,
    "op_fmt_markdown_wrapper": 2,
    "op_syn_boundary_delimiter_injection": 3,
    "op_fmt_punctuation_resegmentation": 4,
    "op_fmt_whitespace_noise": 5,
    "op_lex_homoglyph_injection": 6,
    "op_lex_polite_prefix": 7,
    "op_comp_expand_context": 8,
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL at {path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(row, dict):
                raise ValueError(
                    f"Expected JSON object at {path}:{line_number}"
                )

            rows.append(row)

    return rows


def save_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as file:
        for row in rows:
            file.write(
                json.dumps(row, ensure_ascii=False) + "\n"
            )


def first_nonempty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue

        text = str(value).strip()

        if text:
            return text

    return ""


def as_float(value: Any, default: float = 9999.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def candidate_sort_key(
    row: dict[str, Any],
) -> tuple[Any, ...]:
    operator_id = first_nonempty(
        row.get("selected_op_id"),
        "unknown",
    )

    priority = OPERATOR_PRIORITY.get(operator_id, 999)

    length_ratio = as_float(
        row.get("length_ratio"),
        default=9999.0,
    )

    # Prefer moderate transformations near ratio 1.0.
    length_distance = abs(length_ratio - 1.0)

    child_hash = first_nonempty(
        row.get("child_sha256"),
        row.get("text_sha256"),
    )

    candidate_index = int(
        row.get("candidate_index") or 0
    )

    return (
        priority,
        length_distance,
        child_hash,
        candidate_index,
    )


def select_two(
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ordered = sorted(
        candidates,
        key=candidate_sort_key,
    )

    if len(ordered) < CHILDREN_PER_PARENT:
        return ordered

    first = ordered[0]

    first_operator = first_nonempty(
        first.get("selected_op_id"),
        "unknown",
    )
    first_family = first_nonempty(
        first.get("operator_family"),
        "unknown",
    )

    # Best case: different operator and different family.
    second_pool = [
        row
        for row in ordered[1:]
        if first_nonempty(
            row.get("selected_op_id"),
            "unknown",
        ) != first_operator
        and first_nonempty(
            row.get("operator_family"),
            "unknown",
        ) != first_family
    ]

    # Second-best: different operator.
    if not second_pool:
        second_pool = [
            row
            for row in ordered[1:]
            if first_nonempty(
                row.get("selected_op_id"),
                "unknown",
            ) != first_operator
        ]

    # Fallback: any other valid candidate.
    if not second_pool:
        second_pool = ordered[1:]

    second = sorted(
        second_pool,
        key=candidate_sort_key,
    )[0]

    return [first, second]


def main() -> None:
    valid_rows = load_jsonl(VALID_PATH)

    by_parent: dict[str, list[dict[str, Any]]] = (
        defaultdict(list)
    )

    for row in valid_rows:
        parent_id = first_nonempty(
            row.get("parent_record_id"),
        )

        if not parent_id:
            raise RuntimeError(
                "VALID row without parent_record_id"
            )

        by_parent[parent_id].append(row)

    if len(by_parent) != 250:
        raise RuntimeError(
            "Expected 250 parent seeds, "
            f"found {len(by_parent)}"
        )

    insufficient = {
        parent_id: len(rows)
        for parent_id, rows in by_parent.items()
        if len(rows) < CHILDREN_PER_PARENT
    }

    if insufficient:
        raise RuntimeError(
            "Parents with fewer than two VALID rows: "
            f"{insufficient}"
        )

    selected_rows: list[dict[str, Any]] = []

    for parent_id in sorted(by_parent):
        selected = select_two(by_parent[parent_id])

        if len(selected) != CHILDREN_PER_PARENT:
            raise RuntimeError(
                f"Failed to select two rows for {parent_id}"
            )

        for selection_index, row in enumerate(
            selected,
            start=1,
        ):
            output_row = dict(row)

            output_row["final_dataset_role"] = (
                "mutated_malicious"
            )
            output_row["final_selection_index"] = (
                selection_index
            )
            output_row["is_selected_final_v1"] = True
            output_row["is_mutated"] = True
            output_row["label"] = "malicious"
            output_row["ground_truth_decision"] = (
                "malicious"
            )

            # Stable final sample identifier.
            output_row["final_sample_id"] = (
                f"{parent_id}::mut{selection_index:02d}"
            )

            selected_rows.append(output_row)

    if len(selected_rows) != 500:
        raise RuntimeError(
            f"Expected 500 selected rows, "
            f"found {len(selected_rows)}"
        )

    final_ids = [
        row["final_sample_id"]
        for row in selected_rows
    ]

    if len(final_ids) != len(set(final_ids)):
        raise RuntimeError(
            "Duplicate final_sample_id detected"
        )

    child_hashes = [
        first_nonempty(row.get("child_sha256"))
        for row in selected_rows
    ]

    nonempty_hashes = [
        value
        for value in child_hashes
        if value
    ]

    if len(nonempty_hashes) != len(set(nonempty_hashes)):
        raise RuntimeError(
            "Duplicate child_sha256 detected"
        )

    save_jsonl(
        OUTPUT_JSONL_PATH,
        selected_rows,
    )

    OUTPUT_CSV_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    csv_columns = [
        "final_sample_id",
        "parent_record_id",
        "final_selection_index",
        "attack_type",
        "selected_op_id",
        "operator_family",
        "input_format",
        "output_format",
        "length_ratio",
        "child_sha256",
        "filter_decision",
        "child_text",
    ]

    with OUTPUT_CSV_PATH.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=csv_columns,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in selected_rows:
            writer.writerow(row)

    attack_counts = Counter(
        first_nonempty(
            row.get("attack_type"),
            "unknown",
        )
        for row in selected_rows
    )

    operator_counts = Counter(
        first_nonempty(
            row.get("selected_op_id"),
            "unknown",
        )
        for row in selected_rows
    )

    family_counts = Counter(
        first_nonempty(
            row.get("operator_family"),
            "unknown",
        )
        for row in selected_rows
    )

    operators_by_attack: dict[str, Counter[str]] = (
        defaultdict(Counter)
    )

    same_operator_parent_count = 0

    selected_by_parent: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for row in selected_rows:
        attack_type = first_nonempty(
            row.get("attack_type"),
            "unknown",
        )
        operator_id = first_nonempty(
            row.get("selected_op_id"),
            "unknown",
        )
        parent_id = first_nonempty(
            row.get("parent_record_id"),
            "unknown",
        )

        operators_by_attack[
            attack_type
        ][operator_id] += 1

        selected_by_parent[parent_id].append(row)

    for rows in selected_by_parent.values():
        operators = {
            first_nonempty(
                row.get("selected_op_id"),
                "unknown",
            )
            for row in rows
        }

        if len(operators) == 1:
            same_operator_parent_count += 1

    summary = {
        "input_valid_candidates": len(valid_rows),
        "parent_seed_count": len(by_parent),
        "selected_count": len(selected_rows),
        "children_per_parent": CHILDREN_PER_PARENT,
        "attack_type_counts": dict(
            sorted(attack_counts.items())
        ),
        "operator_counts": dict(
            operator_counts.most_common()
        ),
        "operator_family_counts": dict(
            family_counts.most_common()
        ),
        "operators_by_attack_type": {
            attack_type: dict(counts.most_common())
            for attack_type, counts in sorted(
                operators_by_attack.items()
            )
        },
        "selection_quality": {
            "parents_with_distinct_operators": (
                250 - same_operator_parent_count
            ),
            "parents_with_same_operator": (
                same_operator_parent_count
            ),
            "duplicate_final_sample_ids": 0,
            "duplicate_child_hashes": 0,
        },
        "output_paths": {
            "jsonl": str(OUTPUT_JSONL_PATH),
            "csv": str(OUTPUT_CSV_PATH),
        },
    }

    SUMMARY_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    SUMMARY_PATH.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 72)
    print("[done] final mutated malicious selection")
    print(f"input VALID candidates : {len(valid_rows)}")
    print(f"parent seeds           : {len(by_parent)}")
    print(f"selected rows          : {len(selected_rows)}")
    print(
        "distinct-op parents    : "
        f"{250 - same_operator_parent_count}/250"
    )
    print(
        "same-op parents        : "
        f"{same_operator_parent_count}/250"
    )
    print(f"output jsonl           : {OUTPUT_JSONL_PATH}")
    print(f"output csv             : {OUTPUT_CSV_PATH}")
    print(f"summary                : {SUMMARY_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    main()