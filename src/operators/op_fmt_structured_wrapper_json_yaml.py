from __future__ import annotations

import json
import random
from typing import Any, Dict, List

from src.core.types import ApplyResult

OPERATOR_META = {
    "op_id": "op_fmt_structured_wrapper_json_yaml",
    "bucket_tags": ["LLM05_INPUT_ROBUSTNESS", "LLM05_OUTPUT_HANDLING"],
    "surface_compat": ["PROMPT_TEXT"],
    "risk_level": "MEDIUM",
    "strength_range": [1, 5],
    "params_schema": {"format": ["json", "yaml"]},

    # diagnostic v1 metadata
    "operator_family": "structural",
    "attack_type_compat": [
        "data_exfiltration",
        "format_injection",
        "indirect_injection",
        "instruction_override",
    ],
    "output_format": "json_or_yaml",
    "semantic_preservation_risk": "LOW",
    "label_change_risk": "LOW",
    "use_in_diagnostic_v1": True,

    # diagnostic v1 analysis metadata
    "target_evaluator_weakness": [
        "structure_parsing",
        "indirect_pi",
        "semantic_intent",
    ],
}


def _clamp_strength(v: Any) -> int:
    try:
        x = int(v)
    except Exception:
        x = 1

    lo, hi = OPERATOR_META["strength_range"]
    return max(lo, min(hi, x))


def _base_params() -> Dict[str, Any]:
    return {
        "operator_family": OPERATOR_META.get("operator_family"),
        "output_format": OPERATOR_META.get("output_format"),
        "attack_type_compat": OPERATOR_META.get("attack_type_compat", []),
        "target_evaluator_weakness": OPERATOR_META.get("target_evaluator_weakness", []),
    }


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False)


def _to_yaml(obj: Dict[str, Any], indent: int = 0) -> str:
    """Minimal dependency-free YAML formatter for dict/list/string values."""
    lines: List[str] = []
    pad = " " * indent

    for key, value in obj.items():
        if isinstance(value, dict):
            lines.append(f"{pad}{key}:")
            lines.append(_to_yaml(value, indent + 2))
        elif isinstance(value, list):
            lines.append(f"{pad}{key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(f"{pad}  -")
                    lines.append(_to_yaml(item, indent + 4))
                else:
                    lines.append(f"{pad}  - {_yaml_scalar(item)}")
        elif isinstance(value, str) and "\n" in value:
            lines.append(f"{pad}{key}: |-")
            for line in value.splitlines():
                lines.append(f"{pad}  {line}")
        else:
            lines.append(f"{pad}{key}: {_yaml_scalar(value)}")

    return "\n".join(lines)


def apply(seed_text: str, ctx: Dict[str, Any], rng: random.Random) -> ApplyResult:
    len_before = len(seed_text) if isinstance(seed_text, str) else 0
    base_params = _base_params()

    if not isinstance(seed_text, str) or not seed_text.strip():
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text if isinstance(seed_text, str) else "",
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "reason": "empty",
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    strength = _clamp_strength(ctx.get("strength", 1))
    surface = ctx.get("surface", "PROMPT_TEXT")
    constraints = ctx.get("constraints") or {}
    max_chars = constraints.get("max_chars")

    fmt = (ctx.get("format") or "json").lower()
    if fmt not in ("json", "yaml"):
        fmt = "json"

    if surface != "PROMPT_TEXT":
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "reason": "surface_mismatch",
                    "surface": surface,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    applied: List[str] = []

    if strength == 1:
        obj: Dict[str, Any] = {
            "prompt": seed_text,
        }
        applied.append("single_field")
    elif strength <= 3:
        obj = {
            "goal": "answer_user",
            "input": seed_text,
            "format": "plain_text",
        }
        applied.append("multi_field")
    else:
        obj = {
            "meta": {
                "version": "v1",
            },
            "task": {
                "goal": "answer_user",
                "input": seed_text,
            },
            "output": {
                "format": "plain_text",
                "hint": "structured",
            },
        }
        applied.append("nested_schema")

    if fmt == "json":
        child = json.dumps(obj, ensure_ascii=False, indent=2 if strength >= 3 else None)
    else:
        child = _to_yaml(obj)

    if isinstance(max_chars, int) and max_chars >= 0 and len(child) > max_chars:
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "reason": "max_chars_exceeded",
                    "max_chars": max_chars,
                    "strength": strength,
                    "format": fmt,
                    "applied": applied,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    return ApplyResult(
        status="OK",
        child_text=child,
        trace={
            "op_id": OPERATOR_META["op_id"],
            "status": "OK",
            "params": {
                "strength": strength,
                "format": fmt,
                "applied": applied,
                **base_params,
            },
            "len_before": len_before,
            "len_after": len(child),
        },
    )