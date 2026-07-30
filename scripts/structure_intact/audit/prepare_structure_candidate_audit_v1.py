from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

INPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_candidates_v1"
    / "structure_intact_candidates_all_v1.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_audit_v1"
)

SUMMARY_PATH = (
    PROJECT_ROOT
    / "reports"
    / "structure_intact_audit_batch_summary_v1.json"
)

SCARCE_FORMATS = {
    "markdown",
    "json",
    "code_block",
}

SAMPLED_FORMAT_TARGETS = {
    "yaml": 80,
    "repository_file": 80,
}


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


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
        writer.writerows(rows)


def norm(value: Any) -> str:
    return str(value or "").strip()


def numeric_length(row: dict[str, Any]) -> int:
    try:
        return int(row.get("text_length") or 0)
    except (TypeError, ValueError):
        return len(norm(row.get("scanner_input")))


def deterministic_spread(
    rows: list[dict[str, Any]],
    count: int,
) -> list[dict[str, Any]]:
    if count <= 0 or not rows:
        return []

    ordered = sorted(
        rows,
        key=lambda row: (
            numeric_length(row),
            norm(row.get("source_id")),
            norm(row.get("text_sha256")),
        ),
    )

    if len(ordered) <= count:
        return [dict(row) for row in ordered]

    if count == 1:
        middle_index = len(ordered) // 2
        return [dict(ordered[middle_index])]

    selected: list[dict[str, Any]] = []

    for index in range(count):
        position = round(
            index * (len(ordered) - 1)
            / (count - 1)
        )
        selected.append(dict(ordered[position]))

    return selected


def stratified_sample(
    rows: list[dict[str, Any]],
    target: int,
) -> list[dict[str, Any]]:
    """
    source_id와 structure_detection_reason 조합을 층으로 사용한다.
    각 층에서 최소 1개를 먼저 확보한 뒤 남은 quota를 채운다.
    """
    if len(rows) <= target:
        return [dict(row) for row in rows]

    strata: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for row in rows:
        key = (
            norm(row.get("source_id")) or "unknown",
            norm(row.get("structure_detection_reason"))
            or "unknown",
        )
        strata[key].append(row)

    selected: list[dict[str, Any]] = []
    selected_hashes: set[str] = set()

    # 각 층에서 대표 1개를 우선 확보
    for key in sorted(strata):
        representative = deterministic_spread(
            strata[key],
            1,
        )[0]

        text_hash = norm(
            representative.get("text_sha256")
        )

        if text_hash not in selected_hashes:
            selected.append(representative)
            selected_hashes.add(text_hash)

    if len(selected) > target:
        return deterministic_spread(selected, target)

    # 전체 길이 분포에서 나머지 quota 채우기
    remaining = [
        row
        for row in rows
        if norm(row.get("text_sha256"))
        not in selected_hashes
    ]

    needed = target - len(selected)

    for row in deterministic_spread(remaining, needed):
        text_hash = norm(row.get("text_sha256"))

        if text_hash in selected_hashes:
            continue

        selected.append(row)
        selected_hashes.add(text_hash)

    if len(selected) != target:
        raise RuntimeError(
            f"Expected {target} rows, "
            f"selected {len(selected)}"
        )

    return selected


def main() -> None:
    rows = read_csv(INPUT_PATH)

    by_format: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for row in rows:
        format_name = norm(
            row.get("candidate_structure_format")
        )
        by_format[format_name].append(row)

    audit_rows: list[dict[str, Any]] = []

    # 부족 형식은 전부 검토
    for format_name in sorted(SCARCE_FORMATS):
        selected = sorted(
            by_format.get(format_name, []),
            key=lambda row: (
                numeric_length(row),
                norm(row.get("source_id")),
                norm(row.get("text_sha256")),
            ),
        )

        for row in selected:
            output = dict(row)
            output["audit_batch_type"] = "all_scarce"
            audit_rows.append(output)

    # 충분한 형식은 층화 표본
    for format_name, target in sorted(
        SAMPLED_FORMAT_TARGETS.items()
    ):
        selected = stratified_sample(
            by_format.get(format_name, []),
            target,
        )

        for row in selected:
            output = dict(row)
            output["audit_batch_type"] = (
                "stratified_quality_audit"
            )
            audit_rows.append(output)

    review_columns = [
        "structure_valid",
        "attack_semantics_valid",
        "provenance_valid",
        "review_decision",
        "review_note",
    ]

    for row in audit_rows:
        for column in review_columns:
            row[column] = ""

    fieldnames = list(audit_rows[0].keys())

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    combined_path = (
        OUTPUT_DIR
        / "structure_intact_audit_192_v1.csv"
    )

    write_csv(
        combined_path,
        audit_rows,
        fieldnames,
    )

    for format_name in [
        "markdown",
        "json",
        "yaml",
        "code_block",
        "repository_file",
    ]:
        format_rows = [
            row
            for row in audit_rows
            if norm(
                row.get("candidate_structure_format")
            ) == format_name
        ]

        write_csv(
            OUTPUT_DIR
            / f"structure_audit_{format_name}_v1.csv",
            format_rows,
            fieldnames,
        )

    format_counts = Counter(
        norm(row.get("candidate_structure_format"))
        for row in audit_rows
    )

    source_counts_by_format: dict[
        str,
        Counter[str],
    ] = defaultdict(Counter)

    detection_counts_by_format: dict[
        str,
        Counter[str],
    ] = defaultdict(Counter)

    for row in audit_rows:
        format_name = norm(
            row.get("candidate_structure_format")
        )

        source_counts_by_format[format_name][
            norm(row.get("source_id")) or "unknown"
        ] += 1

        detection_counts_by_format[format_name][
            norm(
                row.get("structure_detection_reason")
            )
            or "unknown"
        ] += 1

    summary = {
        "input_candidate_rows": len(rows),
        "audit_count": len(audit_rows),
        "audit_counts_by_format": dict(
            sorted(format_counts.items())
        ),
        "source_counts_by_format": {
            format_name: dict(
                counts.most_common()
            )
            for format_name, counts in sorted(
                source_counts_by_format.items()
            )
        },
        "detection_counts_by_format": {
            format_name: dict(
                counts.most_common()
            )
            for format_name, counts in sorted(
                detection_counts_by_format.items()
            )
        },
        "output_directory": str(
            OUTPUT_DIR.relative_to(PROJECT_ROOT)
        ),
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
    print("[done] structure-intact audit batch")
    print(f"input candidates : {len(rows)}")
    print(f"audit rows       : {len(audit_rows)}")

    for format_name in [
        "markdown",
        "json",
        "yaml",
        "code_block",
        "repository_file",
    ]:
        print(
            f"  {format_name:<16}: "
            f"{format_counts[format_name]}"
        )

    print(f"combined csv     : {combined_path}")
    print(f"summary          : {SUMMARY_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    main()