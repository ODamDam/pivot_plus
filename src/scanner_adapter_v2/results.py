"""JSON-only immutable results. No scanner imports, execution or filesystem writes."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

from .contract import ScannerReplayCase
from .leakage_validator import LeakageError, normalized_key
from .observation import project_observation

EXECUTION_STATUSES = ("success", "error", "timeout", "dependency_error", "configuration_error", "unsupported", "skipped")
ERROR_TYPES = ("adapter_error", "scanner_runtime_error", "evaluator_error", "parser_error", "dependency_error",
               "timeout", "invalid_native_result", "unsupported_result", "configuration_error")
NORMALIZED_VERDICTS = ("flagged", "not_flagged", "indeterminate", "no_result")
FORBIDDEN_RESULT_KEYS = frozenset({
    "correct", "incorrect", "truepositive", "falsepositive", "truenegative", "falsenegative",
    "accuracy", "scanneraccuracy", "expectedverdict", "expectedresult", "expectedcorrectness",
    "pistatus", "pilabel", "maliciousness", "derivedclass", "finalclass", "boundaryclass",
    "gtrationale", "casegt", "sourcecasegt", "groundtruth", "outcomegt", "outcomelabel",
    "judgea", "judgeb", "judgeadecision", "judgebdecision", "judgedisagreement",
    "scannerresults", "scannerresult", "scannergt", "otherscanner", "originallabel",
    "scanners", "garak", "pyrit", "promptfoo", "expectedscannercorrectness",
})


def _walk_json(value, path="$", ancestors=None):
    """Reject implicit coercion, arbitrary objects, non-finite numbers and cycles."""
    ancestors = set() if ancestors is None else ancestors
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{path}: non-finite JSON number")
        return
    if type(value) not in (dict, list):
        raise ValueError(f"{path}: only JSON types accepted")
    if id(value) in ancestors:
        raise ValueError(f"{path}: cyclic value")
    ancestors.add(id(value))
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise ValueError(f"{path}: JSON keys must be strings")
            _walk_json(child, f"{path}.{key}", ancestors)
    else:
        for i, child in enumerate(value):
            _walk_json(child, f"{path}[{i}]", ancestors)
    ancestors.remove(id(value))


def validate_result_leakage(value, path="$"):
    """Result boundary permits this evaluator's native pass/score/rationale.

    Replay's stricter validator is deliberately unchanged. Key aliases for GT,
    correctness and cross-scanner result containers remain forbidden everywhere.
    Natural-language strings are opaque; no sanitizing or reclassification.
    """
    if isinstance(value, dict):
        for key, child in value.items():
            name = normalized_key(key)
            location = f"{path}.{key}"
            if (name in FORBIDDEN_RESULT_KEYS or name.startswith(("judgea", "judgeb")) or any(part in name for part in (
                    "outcomegt", "groundtruth", "casegt", "pistatus", "pilabel", "maliciousness", "derivedclass",
                    "boundaryclass", "finalclass", "gtrationale", "otherscanner", "scannerresult", "scannergt",
                    "scanneraccuracy", "expectedverdict", "truepositive", "falsepositive", "truenegative",
                    "falsenegative", "outcomerule", "judgeadecision", "judgebdecision", "judgedisagreement"))):
                raise LeakageError(f"{location}: forbidden result field")
            validate_result_leakage(child, location)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            validate_result_leakage(child, f"{path}[{i}]")


def canonical_json(value):
    """Project hash encoding v1, not RFC 8785: UTF-8/sorted keys/compact JSON."""
    _walk_json(value)
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        text.encode("utf-8")
        return text
    except (ValueError, UnicodeError):
        raise ValueError("$: invalid JSON string encoding") from None


def canonical_hash(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _decode(text):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("$: duplicate serialized JSON key")
            value[key] = item
        return value
    try:
        return json.loads(text, object_pairs_hook=pairs)
    except (ValueError, TypeError):
        raise ValueError("$: invalid serialized result JSON") from None


@lru_cache(maxsize=3)
def _schema(name):
    path = Path(__file__).resolve().parents[2] / "schemas" / name
    value = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return Draft202012Validator(value)


def validate_document(value, schema_name):
    _walk_json(value)
    validate_result_leakage(value)
    error = next(_schema(schema_name).iter_errors(value), None)
    if error is not None:
        path = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in error.absolute_path)
        raise ValueError(f"{path}: schema constraint {error.validator}")


def validate_raw_result(value):
    validate_document(value, "scanner_raw_evaluator_result_v1.schema.json")
    if canonical_hash(value["native_output"]) != value["native_output_sha256"]:
        raise ValueError("$.native_output_sha256: hash mismatch")
    if value["replay_case"]["identity"] != value["generation_id"]:
        raise ValueError("$.replay_case.identity: generation lineage mismatch")
    if value["evaluator_input"] is not None and value["evaluator_input"]["identity"] != value["evaluation_id"] + "::input":
        raise ValueError("$.evaluator_input.identity: evaluation lineage mismatch")


def validate_normalized_result(value, *, raw_result=None):
    validate_document(value, "scanner_normalized_result_v1.schema.json")
    if value["raw_result"]["identity"] != value["evaluation_id"]:
        raise ValueError("$.raw_result.identity: evaluation lineage mismatch")
    if value["replay_case"]["identity"] != value["generation_id"]:
        raise ValueError("$.replay_case.identity: generation lineage mismatch")
    if raw_result is not None:
        raw = raw_result.to_dict()
        if value["raw_result"]["sha256"] != canonical_hash(raw):
            raise ValueError("$.raw_result.sha256: hash mismatch")
        for key in LINEAGE_FIELDS:
            if value[key] != raw[key]:
                raise ValueError(f"$.{key}: raw result mismatch")


# The same explicit envelope is carried to normalization. No native payload merge.
LINEAGE_FIELDS = ("scanner_run_id", "evaluation_id", "generation_id", "production_case_id", "sample_id", "scanner",
                  "evaluator", "observation_surface", "replay_case", "observation_sha256", "evaluator_input",
                  "execution_status", "error_type", "provenance")


@dataclass(frozen=True)
class ScannerRawEvaluatorResult:
    _serialized: str

    def __post_init__(self):
        validate_raw_result(_decode(self._serialized))

    @classmethod
    def from_dict(cls, value):
        validate_raw_result(value)
        return cls(canonical_json(value))

    def to_dict(self):
        return json.loads(self._serialized)


@dataclass(frozen=True)
class ScannerNormalizedResult:
    _serialized: str

    def __post_init__(self):
        validate_normalized_result(_decode(self._serialized))

    @classmethod
    def from_dict(cls, value):
        validate_normalized_result(value)
        return cls(canonical_json(value))

    def to_dict(self):
        return json.loads(self._serialized)


def build_raw_result(replay_case: ScannerReplayCase, *, scanner_run_id, evaluation_id, scanner, evaluator,
                     observation_surface, evaluator_input, execution_status, error_type, native_output, provenance):
    """Capture an externally obtained JSON result; never execute an evaluator.

    evaluator_input is the actual formatted input, not an assumed reconstruction.
    None means input was not prepared; permitted only for non-success statuses.
    Run metadata/config/rubric identities are caller supplied, never inferred.
    """
    case = replay_case.to_dict()
    _walk_json(evaluator_input)
    validate_result_leakage(evaluator_input, "$.evaluator_input")
    _walk_json(native_output, "$.native_output")
    validate_result_leakage(native_output, "$.native_output")
    value = {
        "schema_version": "scanner_raw_evaluator_result.v1", "scanner_run_id": scanner_run_id,
        "evaluation_id": evaluation_id, "generation_id": case["generation_id"],
        "production_case_id": case["production_case_id"], "sample_id": case["sample_id"],
        "scanner": scanner, "evaluator": evaluator, "observation_surface": observation_surface,
        "replay_case": {"identity": case["generation_id"], "sha256": canonical_hash(case)},
        "observation_sha256": canonical_hash(project_observation(replay_case, observation_surface)),
        "evaluator_input": None if evaluator_input is None else {
            "identity": evaluation_id + "::input", "sha256": canonical_hash(evaluator_input)},
        "execution_status": execution_status, "error_type": error_type,
        "native_output": native_output, "native_output_sha256": canonical_hash(native_output), "provenance": provenance,
    }
    return ScannerRawEvaluatorResult.from_dict(value)


def verify_raw_lineage(raw_result, replay_case, evaluator_input):
    value, case = raw_result.to_dict(), replay_case.to_dict()
    for key in ("generation_id", "production_case_id", "sample_id"):
        if value[key] != case[key]:
            raise ValueError(f"$.{key}: replay lineage mismatch")
    if value["replay_case"]["sha256"] != canonical_hash(case):
        raise ValueError("$.replay_case.sha256: replay hash mismatch")
    if value["observation_sha256"] != canonical_hash(project_observation(replay_case, value["observation_surface"])):
        raise ValueError("$.observation_sha256: surface hash mismatch")
    expected = None if evaluator_input is None else {"identity": value["evaluation_id"] + "::input", "sha256": canonical_hash(evaluator_input)}
    if value["evaluator_input"] != expected:
        raise ValueError("$.evaluator_input: input hash mismatch")
