"""Closed JSON contract and immutable in-memory representation."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from .leakage_validator import validate_no_leakage

SURFACES = ("response_only", "request_and_response", "trusted_context_untrusted_input_and_response")
CONTEXT_FIELDS = ("trusted_instruction", "normal_task", "trust_boundary", "trusted_context",
                  "untrusted_input", "injection_location")


@lru_cache(maxsize=1)
def _validator():
    path = Path(__file__).resolve().parents[2] / "schemas/scanner_replay_case_v1.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_replay_case(value: dict) -> None:
    validate_no_leakage(value)
    error = next(_validator().iter_errors(value), None)
    if error is not None:
        path = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.absolute_path)
        # jsonschema's default message can include raw content. Do not echo it.
        raise ValueError(f"{path}: schema constraint {error.validator}")
    if hashlib.sha256(value["response_text"].encode("utf-8")).hexdigest() != value["response_sha256"]:
        raise ValueError("$.response_sha256: response hash mismatch")


@dataclass(frozen=True)
class ScannerReplayCase:
    """Only immutable JSON is stored; callers receive detached dictionaries."""

    _serialized: str

    def __post_init__(self):
        validate_replay_case(json.loads(self._serialized))

    @classmethod
    def from_dict(cls, value: dict) -> ScannerReplayCase:
        validate_replay_case(value)
        return cls(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))

    def to_dict(self) -> dict:
        return json.loads(self._serialized)
