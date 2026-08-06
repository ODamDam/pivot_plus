from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


GENERAL_PATH = Path(
    "data/review/manual_review_benign_schema_v1.csv"
)

HARD_NEGATIVE_PATH = Path(
    "data/review/manual_review_hard_negative_schema_v1.csv"
)

OUTPUT_CSV_PATH = Path(
    "data/final/benign_100_v1.csv"
)

OUTPUT_JSONL_PATH = Path(
    "data/final/benign_100_v1.jsonl"
)

SUMMARY_PATH = Path(
    "reports/benign_100_selection_summary_v1.json"
)

GENERAL_TARGET = 50
HARD_REPOSITORY_TARGET = 25
HARD_OTHER_TARGET = 25


def load_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def deterministic_spread(
    rows: list[dict[str, Any]],
    count: int,
) -> list[dict[str, Any]]:
    if len(rows) < count:
        raise RuntimeError(
            f"Need {count}, but only {len(rows)} rows available"
        )

    ordered = sorted(
        rows,
        key=lambda row: (
            len(str(row.get("scanner_input") or "")),
            str(row.get("text_sha256") or ""),
        ),
    )

    if count == 1:
        return [dict(ordered[len(ordered) // 2])]

    selected: list[dict[str, Any]] = []

    for i in range(count):
        index = round(
            i * (len(ordered) - 1)
            / (count - 1)
        )
        selected.append(dict(ordered[index]))

    return selected


def valid_benign(
    row: dict[str, Any],
) -> bool:
    scanner_input = str(
        row.get("scanner_input") or ""
    ).strip()

    decision = str(
        row.get("ground_truth_decision") or ""
    ).strip().lower()

    text_hash = str(
        row.get("text_sha256") or ""
    ).strip()

    return bool(
        scanner_input
        and text_hash
        and decision == "benign"
    )


def main() -> None:
    general_rows = [
        row
        for row in load_csv(GENERAL_PATH)
        if valid_benign(row)
    ]

    hard_rows = [
        row
        for row in load_csv(HARD_NEGATIVE_PATH)
        if valid_benign(row)
    ]

    hard_repository = [
        row
        for row in hard_rows
        if str(
            row.get("input_format") or ""
        ).strip() == "repository_file"
    ]

    hard_other = [
        row
        for row in hard_rows
        if str(
            row.get("input_format") or ""
        ).strip() != "repository_file"
    ]

    selected_general = deterministic_spread(
        general_rows,
        GENERAL_TARGET,
    )

    selected_hard_repository = deterministic_spread(
        hard_repository,
        HARD_REPOSITORY_TARGET,
    )

    selected_hard_other = deterministic_spread(
        hard_other,
        HARD_OTHER_TARGET,
    )

    selected = (
        selected_general
        + selected_hard_repository
        + selected_hard_other
    )

    hashes = [
        str(row["text_sha256"])
        for row in selected
    ]

    if len(hashes) != len(set(hashes)):
        raise RuntimeError(
            "Duplicate benign text_sha256 detected"
        )

    if len(selected) != 100:
        raise RuntimeError(
            f"Expected 100 rows, found {len(selected)}"
        )

    for index, row in enumerate(selected, start=1):
        original_attack_type = str(
            row.get("attack_type") or ""
        )

        row["final_sample_id"] = (
            f"BENIGN-V1-{index:04d}"
        )
        row["final_dataset_role"] = "benign"
        row["is_selected_final_v1"] = True
        row["label"] = "benign"
        row["ground_truth_decision"] = "benign"
        row["is_malicious"] = False
        row["is_mutated"] = False
        row["original_attack_type"] = (
            original_attack_type
        )

    OUTPUT_CSV_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames: list[str] = []

    for row in selected:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)

    with OUTPUT_CSV_PATH.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(selected)

    with OUTPUT_JSONL_PATH.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        for row in selected:
            file.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    summary = {
        "selected_count": len(selected),
        "composition": {
            "general_benign": len(selected_general),
            "hard_negative_repository_file": (
                len(selected_hard_repository)
            ),
            "hard_negative_other": (
                len(selected_hard_other)
            ),
        },
        "attack_type_counts": dict(
            Counter(
                str(row.get("attack_type") or "unknown")
                for row in selected
            )
        ),
        "input_format_counts": dict(
            Counter(
                str(row.get("input_format") or "unknown")
                for row in selected
            )
        ),
        "source_counts": dict(
            Counter(
                str(row.get("source_id") or "unknown")
                for row in selected
            )
        ),
        "duplicate_hashes": 0,
        "output_paths": {
            "csv": str(OUTPUT_CSV_PATH),
            "jsonl": str(OUTPUT_JSONL_PATH),
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
    print("[done] benign 100 selection")
    print(f"general benign          : {len(selected_general)}")
    print(
        "hard negative repository: "
        f"{len(selected_hard_repository)}"
    )
    print(
        "hard negative other     : "
        f"{len(selected_hard_other)}"
    )
    print(f"selected total          : {len(selected)}")
    print(f"output csv              : {OUTPUT_CSV_PATH}")
    print(f"output jsonl            : {OUTPUT_JSONL_PATH}")
    print(f"summary                 : {SUMMARY_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    main()