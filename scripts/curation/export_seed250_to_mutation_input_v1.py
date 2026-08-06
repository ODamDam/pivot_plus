from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


INPUT_PATH = Path(
    "data/review/batches/seed_curation_250_v1.csv"
)
OUTPUT_PATH = Path(
    "data/inputs/mutation_seeds_diagnostic_v1_seed250.jsonl"
)


def as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    normalized = str(value).strip().lower()

    if normalized in {"true", "1", "yes", "y"}:
        return True

    if normalized in {"false", "0", "no", "n", ""}:
        return False

    return default


def first_nonempty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue

        text = str(value).strip()

        if text:
            return text

    return ""


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Input CSV not found: {INPUT_PATH}"
        )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_rows: list[dict[str, Any]] = []

    with INPUT_PATH.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as src:
        reader = csv.DictReader(src)

        for row_index, raw in enumerate(
            reader,
            start=1,
        ):
            scanner_input = first_nonempty(
                raw.get("scanner_input"),
                raw.get("scanner_input_prompt_only"),
            )

            if not scanner_input:
                raise ValueError(
                    "Missing scanner input at "
                    f"CSV row {row_index + 1}"
                )

            record_id = first_nonempty(
                raw.get("normalized_record_id"),
                raw.get("sample_id"),
                raw.get("text_sha256"),
                f"seed250-{row_index:04d}",
            )

            parent_seed_id = first_nonempty(
                raw.get("parent_seed_id"),
                raw.get("sample_id"),
                record_id,
            )

            output_row: dict[str, Any] = dict(raw)

            # Fields required or expected by run_llm01_batch.py
            output_row.update(
                {
                    "record_id": record_id,
                    "normalized_record_id": record_id,
                    "parent_seed_id": parent_seed_id,
                    "mutation_target_text": scanner_input,
                    "mutation_target_role": "user",
                    "is_mutable": True,
                    "surface": "PROMPT_TEXT",
                    "attack_type": first_nonempty(
                        raw.get("attack_type"),
                        "unknown_or_other",
                    ),
                    "attack_goal": first_nonempty(
                        raw.get("attack_goal"),
                        "unspecified",
                    ),
                    "attack_surface": first_nonempty(
                        raw.get("attack_surface"),
                        "user_prompt",
                    ),
                    "input_format": first_nonempty(
                        raw.get("input_format"),
                        "plain_text",
                    ),
                    "language": first_nonempty(
                        raw.get("language"),
                        "english",
                    ),
                    "label": "malicious",
                    "ground_truth_decision": "malicious",
                    "is_malicious": True,
                    "is_mutated": False,
                    "source_id": first_nonempty(
                        raw.get("source_id"),
                        "unknown_source",
                    ),
                    "source_record_id": first_nonempty(
                        raw.get("source_record_id"),
                        record_id,
                    ),
                }
            )

            output_rows.append(output_row)

    if len(output_rows) != 250:
        raise RuntimeError(
            "Expected 250 rows, "
            f"but exported {len(output_rows)}"
        )

    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()

    for row in output_rows:
        record_id = str(row["record_id"])
        text_hash = str(
            row.get("text_sha256", "")
        ).strip()

        if record_id in seen_ids:
            raise RuntimeError(
                f"Duplicate record_id: {record_id}"
            )

        seen_ids.add(record_id)

        if text_hash:
            if text_hash in seen_hashes:
                raise RuntimeError(
                    f"Duplicate text_sha256: {text_hash}"
                )

            seen_hashes.add(text_hash)

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as dst:
        for row in output_rows:
            dst.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    print(f"[OK] input rows : {len(output_rows)}")
    print(f"[OK] output     : {OUTPUT_PATH}")


if __name__ == "__main__":
    main()