from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ANNOTATION_FIELDS = [
    "response_harm_label",
    "attack_goal_achieved",
    "response_compliance_level",
    "response_judgability",
    "ground_truth_decision",
    "evidence_span",
    "rationale",
    "reviewer_confidence",
    "review_status",
]


PILOT_PAIR_QUOTAS = {
    "mutated_malicious": 10,
    "seed_malicious": 6,
    "structure_intact_malicious": 3,
    "benign_general": 3,
    "benign_hard_negative": 3,
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
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
                    f"Invalid JSON at {path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(row, dict):
                raise ValueError(
                    f"Expected JSON object at {path}:{line_number}"
                )

            rows.append(row)

    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as file:
        for row in rows:
            file.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
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

        for row in rows:
            writer.writerow({
                field: normalize_csv_value(row.get(field))
                for field in fieldnames
            })


def normalize_csv_value(value: Any) -> Any:
    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)

    return value


def stable_hash(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def get_context_text(row: dict[str, Any]) -> str:
    for key in (
        "context_text",
        "context",
        "system_prompt",
        "repository_content",
    ):
        value = row.get(key)

        if isinstance(value, str) and value.strip():
            return value

    return ""


def get_prompt_text(row: dict[str, Any]) -> str:
    for key in (
        "prompt_text",
        "prompt",
        "user_prompt",
        "input",
    ):
        value = row.get(key)

        if isinstance(value, str) and value.strip():
            return value

    return ""


def index_unique(
    rows: list[dict[str, Any]],
    key: str,
    source_name: str,
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}

    for row in rows:
        value = row.get(key)

        if not isinstance(value, str) or not value:
            raise ValueError(
                f"{source_name} row is missing valid {key}: {row}"
            )

        if value in indexed:
            raise ValueError(
                f"Duplicate {key}={value!r} in {source_name}"
            )

        indexed[value] = row

    return indexed


def build_annotation_row(
    dataset_row: dict[str, Any],
    generation_row: dict[str, Any],
    input_view: str,
) -> dict[str, Any]:
    server_meta = generation_row.get("server_meta") or {}

    if not isinstance(server_meta, dict):
        server_meta = {}

    done = server_meta.get("done")
    done_reason = server_meta.get("done_reason")
    response_text = str(
        generation_row.get("response_text") or ""
    )

    generation_complete = done is True
    generation_truncated = done_reason == "length"

    if done is False:
        default_judgability = (
            "unclear_due_to_generation_anomaly"
        )
    elif generation_truncated:
        default_judgability = (
            "judgable_with_caution"
        )
    else:
        default_judgability = "judgable"

    row = {
        "annotation_id": (
            f"{dataset_row['dataset_id']}::{input_view}"
        ),
        "dataset_id": dataset_row["dataset_id"],
        "input_view": input_view,
        "dataset_subset": dataset_row.get(
            "dataset_subset"
        ),
        "prompt_risk_label": dataset_row.get(
            "prompt_risk_label",
            dataset_row.get(
                "label",
                dataset_row.get("is_malicious"),
            ),
        ),
        "attack_type": dataset_row.get("attack_type"),
        "context_type": dataset_row.get(
            "context_type",
            "none",
        ),
        "mutation_operator": dataset_row.get(
            "mutation_operator"
        ),
        "mutation_family": dataset_row.get(
            "mutation_family"
        ),
        "prompt_text": get_prompt_text(dataset_row),
        "context_text": get_context_text(dataset_row),
        "response_text": response_text,
        "response_length_chars": len(response_text),
        "execution_status": generation_row.get(
            "execution_status"
        ),
        "generation_complete": generation_complete,
        "generation_truncated": generation_truncated,
        "done": done,
        "done_reason": done_reason,
        "eval_count": server_meta.get("eval_count"),
        "response_sha256": server_meta.get(
            "response_sha256"
        ),
        "source_messages_sha256": server_meta.get(
            "source_messages_sha256"
        ),
        "final_messages_sha256": server_meta.get(
            "final_messages_sha256"
        ),
        "paired_evaluation_eligible": True,
        "response_harm_label": "",
        "attack_goal_achieved": "",
        "response_compliance_level": "",
        "response_judgability": default_judgability,
        "ground_truth_decision": "",
        "evidence_span": "",
        "rationale": "",
        "reviewer_confidence": "",
        "review_status": "unreviewed",
    }

    return row


def pilot_priority(
    pair: list[dict[str, Any]],
) -> tuple[int, int, int, str]:
    prompt_row = next(
        row for row in pair
        if row["input_view"] == "prompt_only"
    )
    context_row = next(
        row for row in pair
        if row["input_view"] == "context_prompt"
    )

    has_context = (
        str(context_row.get("context_type") or "none")
        != "none"
    )
    has_truncation = any(
        row.get("generation_truncated") is True
        for row in pair
    )

    response_changed = (
        prompt_row.get("response_sha256")
        != context_row.get("response_sha256")
    )

    # 우선순위:
    # 1) truncation 포함
    # 2) 실제 context 존재
    # 3) 두 view의 응답이 다름
    # 4) 안정적인 해시 순서
    return (
        0 if has_truncation else 1,
        0 if has_context else 1,
        0 if response_changed else 1,
        stable_hash(prompt_row["dataset_id"]),
    )


def select_pilot_pairs(
    pool_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in pool_rows:
        grouped[row["dataset_id"]].append(row)

    valid_pairs: list[list[dict[str, Any]]] = []

    for dataset_id, pair in grouped.items():
        views = {
            row["input_view"]
            for row in pair
        }

        if views != {"prompt_only", "context_prompt"}:
            continue

        if len(pair) != 2:
            raise ValueError(
                f"Expected exactly two rows for {dataset_id}, "
                f"found {len(pair)}"
            )

        valid_pairs.append(pair)

    pairs_by_subset: dict[
        str,
        list[list[dict[str, Any]]],
    ] = defaultdict(list)

    for pair in valid_pairs:
        subset = str(pair[0].get("dataset_subset"))
        pairs_by_subset[subset].append(pair)

    selected_pairs: list[list[dict[str, Any]]] = []

    for subset, quota in PILOT_PAIR_QUOTAS.items():
        candidates = sorted(
            pairs_by_subset.get(subset, []),
            key=pilot_priority,
        )

        if len(candidates) < quota:
            raise ValueError(
                f"Not enough paired rows for {subset}: "
                f"needed {quota}, found {len(candidates)}"
            )

        selected_pairs.extend(candidates[:quota])

    selected_rows: list[dict[str, Any]] = []

    for pair_number, pair in enumerate(
        selected_pairs,
        start=1,
    ):
        ordered_pair = sorted(
            pair,
            key=lambda row: (
                0 if row["input_view"] == "prompt_only"
                else 1
            ),
        )

        for row in ordered_pair:
            pilot_row = dict(row)
            pilot_row["pilot_pair_number"] = pair_number
            selected_rows.append(pilot_row)

    return selected_rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build response annotation pool and paired pilot."
        )
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--prompt-results",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--context-results",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/evaluation/annotations"),
    )
    args = parser.parse_args()

    dataset_rows = read_jsonl(args.dataset)
    prompt_rows = read_jsonl(args.prompt_results)
    context_rows = read_jsonl(args.context_results)

    dataset_index = index_unique(
        dataset_rows,
        "dataset_id",
        "dataset",
    )
    prompt_index = index_unique(
        prompt_rows,
        "dataset_id",
        "prompt results",
    )
    context_index = index_unique(
        context_rows,
        "dataset_id",
        "context results",
    )

    paired_ids = sorted(
        set(prompt_index)
        & set(context_index)
    )

    pool_rows: list[dict[str, Any]] = []

    for dataset_id in paired_ids:
        dataset_row = dataset_index.get(dataset_id)

        if dataset_row is None:
            raise ValueError(
                f"Generation result not found in dataset: "
                f"{dataset_id}"
            )

        pool_rows.append(
            build_annotation_row(
                dataset_row=dataset_row,
                generation_row=prompt_index[dataset_id],
                input_view="prompt_only",
            )
        )

        pool_rows.append(
            build_annotation_row(
                dataset_row=dataset_row,
                generation_row=context_index[dataset_id],
                input_view="context_prompt",
            )
        )

    pool_rows.sort(
        key=lambda row: (
            row["dataset_id"],
            0 if row["input_view"] == "prompt_only"
            else 1,
        )
    )

    pilot_rows = select_pilot_pairs(pool_rows)

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    pool_jsonl = (
        output_dir / "response_annotation_pool_v1.jsonl"
    )
    pool_csv = (
        output_dir / "response_annotation_pool_v1.csv"
    )
    pilot_jsonl = (
        output_dir / "response_annotation_pilot_50_v1.jsonl"
    )
    pilot_csv = (
        output_dir / "response_annotation_pilot_50_v1.csv"
    )

    fieldnames = list(pool_rows[0].keys())

    # pilot에만 존재하는 컬럼을 맨 앞에 추가
    pilot_fieldnames = [
        "pilot_pair_number",
        *fieldnames,
    ]

    write_jsonl(pool_jsonl, pool_rows)
    write_csv(pool_csv, pool_rows, fieldnames)

    write_jsonl(pilot_jsonl, pilot_rows)
    write_csv(pilot_csv, pilot_rows, pilot_fieldnames)

    print("Annotation pool")
    print("  generation rows:", len(pool_rows))
    print("  paired dataset ids:", len(paired_ids))
    print(
        "  input views:",
        Counter(row["input_view"] for row in pool_rows),
    )
    print(
        "  subsets:",
        Counter(row["dataset_subset"] for row in pool_rows),
    )
    print(
        "  truncated:",
        sum(
            row["generation_truncated"]
            for row in pool_rows
        ),
    )

    print()
    print("Pilot")
    print("  rows:", len(pilot_rows))
    print(
        "  pairs:",
        len({
            row["dataset_id"]
            for row in pilot_rows
        }),
    )
    print(
        "  subsets:",
        Counter(
            row["dataset_subset"]
            for row in pilot_rows
            if row["input_view"] == "prompt_only"
        ),
    )
    print(
        "  context-present pairs:",
        sum(
            1
            for row in pilot_rows
            if (
                row["input_view"] == "context_prompt"
                and row["context_type"] != "none"
            )
        ),
    )
    print(
        "  truncated generations:",
        sum(
            row["generation_truncated"]
            for row in pilot_rows
        ),
    )

    print()
    print("Outputs")
    print(" ", pool_jsonl)
    print(" ", pool_csv)
    print(" ", pilot_jsonl)
    print(" ", pilot_csv)


if __name__ == "__main__":
    main()