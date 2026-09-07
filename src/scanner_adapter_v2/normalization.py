"""Explicit, deterministic generic mapping policies; no scanner-specific mappings."""
from __future__ import annotations

from .results import (LINEAGE_FIELDS, ScannerNormalizedResult, canonical_hash, validate_document,
                      validate_normalized_result)


def _at(value, path):
    for key in path:
        if isinstance(value, dict) and type(key) is str and key in value:
            value = value[key]
        elif isinstance(value, list) and type(key) is int and 0 <= key < len(value):
            value = value[key]
        else:
            raise ValueError("native field missing or incompatible container")
    return value


def normalize_raw_result(raw_result, mapping_policy):
    """Policy validation errors raise; runtime/parser failures remain explicit.

    Unknown categories are indeterminate. Missing/invalid native values produce
    no_result. Neither condition can silently select not_flagged.
    """
    validate_document(mapping_policy, "scanner_mapping_policy_v1.schema.json")
    policy = mapping_policy
    raw = raw_result.to_dict()
    for key in ("scanner", "evaluator"):
        for field in ("name", "version"):
            if raw[key][field] != policy[key][field]:
                raise ValueError(f"$.mapping_policy.{key}.{field}: evaluator scope mismatch")
    values = policy["values"]
    identities = [canonical_hash(v["native_value"]) for v in values]
    if len(set(identities)) != len(identities):
        raise ValueError("$.mapping_policy.values: ambiguous duplicate mapping")
    result = {key: raw[key] for key in LINEAGE_FIELDS}
    result.update(schema_version="scanner_normalized_result.v1",
                  raw_result={"identity": raw["evaluation_id"], "sha256": canonical_hash(raw)},
                  normalized_verdict="no_result", normalization_error=None, native_value=None,
                  native_score=None, native_score_type="unavailable", native_threshold=None,
                  native_direction=None, threshold_source=None,
                  mapping_policy={"identity": policy["policy_id"], "version": policy["version"],
                                  "sha256": canonical_hash(policy), "basis": policy["basis"]})
    if raw["execution_status"] == "success":
        _map_success(raw, policy, result)
    validate_normalized_result(result, raw_result=raw_result)
    return ScannerNormalizedResult.from_dict(result)


def _map_success(raw, policy, result):
    if raw["native_output"] is None:
        result["normalization_error"] = "invalid_native_result"
        return
    try:
        native = _at(raw["native_output"], policy["value_path"])
    except ValueError:
        result["normalization_error"] = "parser_error"
        return
    kind = policy["kind"]
    expected = {"boolean": (bool,), "categorical": (str,), "numeric_threshold": (int, float)}[kind]
    if type(native) not in expected:
        result["normalization_error"] = "invalid_native_result"
        return
    result.update(native_value=native, native_score_type="numeric" if kind == "numeric_threshold" else kind,
                  native_direction=policy["native_direction"], native_score=None if kind == "categorical" else native)
    if kind != "numeric_threshold":
        for entry in policy["values"]:
            if type(native) is type(entry["native_value"]) and native == entry["native_value"]:
                result["normalized_verdict"] = entry["verdict"]
                return
        result.update(normalized_verdict="indeterminate", normalization_error="unsupported_result")
        return
    descriptor = policy["threshold"]
    try:
        threshold = (_at(raw["native_output"], descriptor["path"]) if descriptor["source"] == "scanner_native"
                     else descriptor["value"])
    except ValueError:
        result["normalization_error"] = "parser_error"
        return
    if type(threshold) not in (int, float):
        result["normalization_error"] = "invalid_native_result"
        return
    result.update(native_threshold=threshold, threshold_source=descriptor["source"])
    compare = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b,
               "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b}[policy["comparator"]]
    result["normalized_verdict"] = "flagged" if compare(native, threshold) else "not_flagged"
