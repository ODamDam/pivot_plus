from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .schemas import CaseResult


class JsonlRecorder:
    def __init__(self, path: Path):
        self.path = path

    def append(self, result: CaseResult) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(result.to_mapping(), ensure_ascii=False, sort_keys=True) + "\n")

    def completed_sample_ids(self) -> list[str]:
        if not self.path.exists():
            return []
        values: list[str] = []
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    values.append(str(json.loads(line)["sample_id"]))
                except (json.JSONDecodeError, KeyError) as exc:
                    raise ValueError(f"invalid result JSONL at line {line_number}") from exc
        return values


def validate_case_output(rows: Iterable[dict]) -> None:
    required = {"schema_version", "sample_id", "raw_input", "constructed_request", "raw_response", "parsed_response", "decision"}
    for index, row in enumerate(rows, 1):
        missing = required - set(row)
        if missing:
            raise ValueError(f"output row {index} missing fields: {sorted(missing)}")
