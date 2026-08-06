from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_INPUT = Path("data/final/mutation_smoke_valid_manual_v1.jsonl")
DEFAULT_OUTPUT = Path("data/final/mutation_smoke_valid_dataset_schema_v1.csv")
DEFAULT_SUMMARY = Path("reports/mutation_smoke_valid_dataset_schema_export_summary_v1.md")


DATASET_SCHEMA_V1_FIELDS = [
    "review_decision",
    "review_note",
    "needs_relabel",
    "sample_id",
    "subset",
    "parent_seed_id",
    "source_id",
    "source_record_id",
    "source_split",
    "scanner_input",
    "scanner_input_prompt_only",
    "scanner_input_with_context",
    "is_malicious",
    "ground_truth_decision",
    "attack_category",
    "attack_type",
    "attack_goal",
    "attack_surface",
    "input_format",
    "language",
    "is_mutated",
    "mutation_family",
    "mutation_operator",
    "mutation_strength",
    "target_evaluator_weakness",
    "semantic_preservation",
    "expected_behavior",
    "review_status",
    "notes",
    "normalized_record_id",
    "text_sha256",
    "metadata_json",
    "candidate_use",
    "original_label",
    "is_structure_intact",
    "is_context_eval",
    "is_augmented",
    "group_id",
    "text_length",
    "scanner_input_preview",
]


ATTACK_CATEGORY_BY_TYPE = {
    "data_exfiltration": "data_risk",
    "instruction_override": "instruction_control",
    "role_play_bypass": "instruction_control",
    "policy_bypass": "policy_control",
    "format_injection": "format_control",
}


def norm(value: Any) -> str:
    return str(value or "").strip()


def bool_text(value: bool) -> str:
    return "true" if value else "false"


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
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {e}") from e

    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=DATASET_SCHEMA_V1_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def preview(text: str, max_len: int = 180) -> str:
    compact = " ".join(text.split())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def infer_source_split(source_record_id: str) -> str:
    left = source_record_id.split(":", 1)[0].lower()

    if "train" in left:
        return "train"
    if "test" in left:
        return "test"
    if "valid" in left or "validation" in left:
        return "validation"
    if "dev" in left:
        return "dev"

    return ""


def build_metadata(row: dict[str, Any]) -> str:
    source_metadata = row.get("source_metadata")
    if not isinstance(source_metadata, dict):
        source_metadata = {}

    metadata = {
        "adapter": "export_mutation_smoke_valid_to_dataset_schema_v1",
        "adapter_version": "v1",
        "original_text": row.get("original_text", ""),
        "engine_surface": row.get("engine_surface", ""),
        "mutation_id": row.get("mutation_id", ""),
        "mutation_seed_id": row.get("mutation_seed_id", ""),
        "source_sample_id": row.get("source_sample_id", ""),
        "source_metadata": source_metadata,
        "validation_status": row.get("validation_status", ""),
        "validation_reason": row.get("validation_reason", ""),
        "manual_review_decision": row.get("manual_review_decision", ""),
        "manual_review_note": row.get("manual_review_note", ""),
        "mutation_trace": row.get("mutation_trace", []),
    }

    return json.dumps(metadata, ensure_ascii=False, sort_keys=True)


def to_dataset_schema_row(row: dict[str, Any]) -> dict[str, Any]:
    mutated_text = norm(row.get("mutated_text"))
    original_text = norm(row.get("original_text"))
    source_metadata = row.get("source_metadata")
    if not isinstance(source_metadata, dict):
        source_metadata = {}

    mutation_id = norm(row.get("mutation_id"))
    source_record_id = norm(row.get("source_record_id"))
    attack_type = norm(row.get("attack_type"))
    attack_category = norm(row.get("attack_category")) or ATTACK_CATEGORY_BY_TYPE.get(attack_type, "")

    validation_reason = norm(row.get("validation_reason"))
    manual_review_decision = norm(row.get("manual_review_decision"))
    manual_review_note = norm(row.get("manual_review_note"))

    review_note_parts = []
    if validation_reason:
        review_note_parts.append(f"validation={validation_reason}")
    if manual_review_decision:
        review_note_parts.append(f"manual={manual_review_decision}")
    if manual_review_note:
        review_note_parts.append(manual_review_note)

    if not review_note_parts:
        review_note_parts.append("exported from validated mutation smoke output")

    notes_parts = [
        f"parent_seed_id={norm(row.get('parent_seed_id'))}",
        f"mutation_seed_id={norm(row.get('mutation_seed_id'))}",
        f"source_sample_id={norm(row.get('source_sample_id'))}",
        f"engine_surface={norm(row.get('engine_surface'))}",
    ]

    return {
        "review_decision": "keep",
        "review_note": " | ".join(part for part in review_note_parts if part),
        "needs_relabel": "no",
        "sample_id": mutation_id,
        "subset": "mutated_malicious",
        "parent_seed_id": norm(row.get("parent_seed_id")),
        "source_id": norm(row.get("source_id")),
        "source_record_id": source_record_id,
        "source_split": norm(row.get("source_split")) or infer_source_split(source_record_id),
        "scanner_input": mutated_text,
        "scanner_input_prompt_only": mutated_text,
        "scanner_input_with_context": "",
        "is_malicious": "true",
        "ground_truth_decision": norm(row.get("ground_truth_decision")) or "malicious",
        "attack_category": attack_category,
        "attack_type": attack_type,
        "attack_goal": norm(row.get("attack_goal")),
        "attack_surface": norm(row.get("attack_surface")),
        "input_format": norm(row.get("input_format")) or "plain_text",
        "language": norm(row.get("language")) or "english",
        "is_mutated": "true",
        "mutation_family": norm(row.get("mutation_family")),
        "mutation_operator": norm(row.get("mutation_operator")),
        "mutation_strength": norm(row.get("mutation_strength")),
        "target_evaluator_weakness": norm(row.get("target_evaluator_weakness")),
        "semantic_preservation": norm(row.get("semantic_preservation")) or "preserved_validated",
        "expected_behavior": norm(source_metadata.get("expected_behavior")) or "detect_as_malicious",
        "review_status": "manual_validated" if manual_review_decision else "auto_validated",
        "notes": " | ".join(part for part in notes_parts if part and not part.endswith("=")),
        "normalized_record_id": mutation_id,
        "text_sha256": sha256_text(mutated_text),
        "metadata_json": build_metadata(row),
        "candidate_use": "mutation_smoke_valid",
        "original_label": norm(row.get("label")) or "malicious",
        "is_structure_intact": "false",
        "is_context_eval": bool_text(norm(row.get("engine_surface")) == "SYSTEM_MESSAGE"),
        "is_augmented": "true",
        "group_id": norm(row.get("parent_seed_id")) or norm(row.get("mutation_seed_id")),
        "text_length": str(len(mutated_text)),
        "scanner_input_preview": preview(mutated_text),
    }


def write_summary(path: Path, *, input_path: Path, output_path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    attack_counts: dict[str, int] = {}
    operator_counts: dict[str, int] = {}

    for row in rows:
        attack_type = norm(row.get("attack_type"))
        operator = norm(row.get("mutation_operator"))
        attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        operator_counts[operator] = operator_counts.get(operator, 0) + 1

    lines = [
        "# Mutation Smoke Valid Dataset Schema Export Summary v1",
        "",
        f"- input: `{input_path.as_posix()}`",
        f"- output_csv: `{output_path.as_posix()}`",
        f"- exported_rows: {len(rows)}",
        "",
        "## Attack Type Counts",
        "",
        "| key | count |",
        "| --- | ---: |",
    ]

    for key, value in sorted(attack_counts.items()):
        lines.append(f"| `{key or '<blank>'}` | {value} |")

    lines += [
        "",
        "## Mutation Operator Counts",
        "",
        "| key | count |",
        "| --- | ---: |",
    ]

    for key, value in sorted(operator_counts.items()):
        lines.append(f"| `{key or '<blank>'}` | {value} |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--summary-output", default=str(DEFAULT_SUMMARY))
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(args.summary_output)

    input_rows = read_jsonl(input_path)
    output_rows = [to_dataset_schema_row(row) for row in input_rows]

    write_csv(output_path, output_rows)
    write_summary(summary_path, input_path=input_path, output_path=output_path, rows=output_rows)

    print(f"[OK] input rows: {len(input_rows)}")
    print(f"[OK] exported rows: {len(output_rows)}")
    print(f"[OK] output: {output_path}")
    print(f"[OK] summary: {summary_path}")


if __name__ == "__main__":
    main()
