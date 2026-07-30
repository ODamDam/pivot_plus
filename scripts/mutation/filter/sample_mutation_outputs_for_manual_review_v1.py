from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_INPUT = (
    PROJECT_ROOT
    / "data"
    / "final"
    / "mutation_smoke_output_v1.jsonl"
)

DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "mutation_operator_manual_review_v1.csv"
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Invalid JSONL at {path}:{line_no}: {e}"
                ) from e

    return rows


def extract_selection_info(
    trace: Any,
) -> tuple[str, int]:
    selection_reason = ""
    retry_count = 0

    if not isinstance(trace, list):
        return selection_reason, retry_count

    for item in trace:
        if not isinstance(item, dict):
            continue

        selection = item.get("selection")

        if not isinstance(selection, dict):
            continue

        reason = selection.get("reason")

        if reason:
            selection_reason = str(reason)

        retry_index = selection.get(
            "retry_index"
        )

        if isinstance(retry_index, int):
            retry_count = max(
                retry_count,
                retry_index,
            )

    return selection_reason, retry_count


def build_review_row(
    row: dict[str, Any],
) -> dict[str, Any]:
    original = str(
        row.get("original_text", "")
    )

    mutated = str(
        row.get("mutated_text", "")
    )

    selection_reason, retry_count = (
        extract_selection_info(
            row.get("mutation_trace", [])
        )
    )

    return {
        "review_id": row.get(
            "mutation_id",
            "",
        ),
        "mutation_seed_id": row.get(
            "mutation_seed_id",
            "",
        ),
        "parent_seed_id": row.get(
            "parent_seed_id",
            "",
        ),
        "attack_type": row.get(
            "attack_type",
            "",
        ),
        "input_format": row.get(
            "input_format",
            "",
        ),
        "mutation_family": row.get(
            "mutation_family",
            "",
        ),
        "mutation_operator": row.get(
            "mutation_operator",
            "",
        ),
        "mutation_strength": row.get(
            "mutation_strength",
            "",
        ),
        "status": row.get(
            "status",
            "",
        ),
        "selection_reason": (
            selection_reason
        ),
        "retry_count": retry_count,
        "original_length": len(original),
        "mutated_length": len(mutated),
        "length_delta": (
            len(mutated) - len(original)
        ),
        "original_text": original,
        "mutated_text": mutated,
        "semantic_preservation": "",
        "label_preservation": "",
        "mutation_effective": "",
        "structure_preservation": "",
        "manual_decision": "",
        "review_notes": "",
    }


def sample_by_operator(
    rows: list[dict[str, Any]],
    samples_per_operator: int,
) -> list[dict[str, Any]]:
    grouped: dict[
        str,
        list[dict[str, Any]]
    ] = defaultdict(list)

    for row in rows:
        if row.get("status") != "OK":
            continue

        op_id = str(
            row.get(
                "mutation_operator",
                "",
            )
        )

        if not op_id or op_id.startswith("__"):
            continue

        grouped[op_id].append(row)

    sampled: list[dict[str, Any]] = []

    for op_id in sorted(grouped):
        operator_rows = sorted(
            grouped[op_id],
            key=lambda item: (
                str(
                    item.get(
                        "attack_type",
                        "",
                    )
                ),
                str(
                    item.get(
                        "mutation_seed_id",
                        "",
                    )
                ),
            ),
        )

        selected: list[dict[str, Any]] = []
        used_attack_types: set[str] = set()

        # 먼저 서로 다른 attack type을 우선 선택한다.
        for row in operator_rows:
            attack_type = str(
                row.get(
                    "attack_type",
                    "",
                )
            )

            if attack_type in used_attack_types:
                continue

            selected.append(row)
            used_attack_types.add(
                attack_type
            )

            if (
                len(selected)
                >= samples_per_operator
            ):
                break

        # 표본 수가 부족하면 나머지에서 채운다.
        if (
            len(selected)
            < samples_per_operator
        ):
            selected_ids = {
                row.get("mutation_id")
                for row in selected
            }

            for row in operator_rows:
                if (
                    row.get("mutation_id")
                    in selected_ids
                ):
                    continue

                selected.append(row)

                if (
                    len(selected)
                    >= samples_per_operator
                ):
                    break

        sampled.extend(
            build_review_row(row)
            for row in selected
        )

    return sampled


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not rows:
        raise ValueError(
            "No review rows generated."
        )

    fieldnames = list(rows[0].keys())

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT),
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
    )

    parser.add_argument(
        "--samples-per-operator",
        type=int,
        default=3,
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    rows = read_jsonl(input_path)

    sampled = sample_by_operator(
        rows,
        samples_per_operator=max(
            1,
            args.samples_per_operator,
        ),
    )

    write_csv(
        output_path,
        sampled,
    )

    operator_count = len(
        {
            row["mutation_operator"]
            for row in sampled
        }
    )

    print(
        f"[OK] source rows: {len(rows)}"
    )
    print(
        f"[OK] sampled operators: "
        f"{operator_count}"
    )
    print(
        f"[OK] review rows: "
        f"{len(sampled)}"
    )
    print(
        f"[OK] output: "
        f"{output_path.relative_to(PROJECT_ROOT)}"
    )


if __name__ == "__main__":
    main()