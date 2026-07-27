from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from src.common.jsonl import iter_jsonl
from src.dataset.models import DatasetRecord


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    if value is None:
        return False

    normalized = str(value).strip().lower()

    if normalized in {"true", "1", "yes", "y"}:
        return True

    if normalized in {"false", "0", "no", "n", ""}:
        return False

    raise ValueError(f"Cannot parse boolean value: {value!r}")


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def parse_dataset_record(raw: dict[str, Any]) -> DatasetRecord:
    dataset_id = str(raw.get("dataset_id") or "").strip()

    if not dataset_id:
        raise ValueError("Dataset record is missing dataset_id")

    dataset_subset = str(raw.get("dataset_subset") or "").strip()

    if not dataset_subset:
        raise ValueError(
            f"Dataset record {dataset_id} is missing dataset_subset"
        )

    return DatasetRecord(
        dataset_id=dataset_id,
        dataset_subset=dataset_subset,
        prompt_text=str(raw.get("prompt_text") or "").strip(),
        context_text=str(raw.get("context_text") or "").strip(),
        context_available=_parse_bool(raw.get("context_available")),
        context_type=str(raw.get("context_type") or "none").strip(),
        context_dependency=str(
            raw.get("context_dependency") or "not_applicable"
        ).strip(),
        attack_type=_optional_text(raw.get("attack_type")),
        is_malicious=_parse_bool(raw.get("is_malicious")),
        standalone_prompt_label=_optional_text(
            raw.get("standalone_prompt_label")
        ),
        contextual_prompt_label=_optional_text(
            raw.get("contextual_prompt_label")
        ),
        final_review_decision=_optional_text(
            raw.get("final_review_decision")
        ),
        raw=raw,
    )


def iter_dataset_records(path: Path) -> Iterator[DatasetRecord]:
    seen_dataset_ids: set[str] = set()

    for raw in iter_jsonl(path):
        record = parse_dataset_record(raw)

        if record.dataset_id in seen_dataset_ids:
            raise ValueError(
                f"Duplicate dataset_id found: {record.dataset_id}"
            )

        seen_dataset_ids.add(record.dataset_id)
        yield record


def load_dataset_records(path: Path) -> list[DatasetRecord]:
    return list(iter_dataset_records(path))