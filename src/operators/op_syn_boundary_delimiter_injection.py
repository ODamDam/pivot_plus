from __future__ import annotations

import random
from typing import Any, Dict

from src.core.types import ApplyResult

OPERATOR_META = {
    "op_id": "op_syn_boundary_delimiter_injection",
    "bucket_tags": ["LLM01_PROMPT_INJECTION", "LLM05_INPUT_ROBUSTNESS"],
    "surface_compat": ["PROMPT_TEXT", "SYSTEM_MESSAGE"],
    "risk_level": "MEDIUM",
    "strength_range": [1, 5],
    "params_schema": {
        "strength": "int(1..5)",
        "mode": ["wrap"],
    },

    # diagnostic v1 metadata
    "operator_family": "structural",
    "attack_type_compat": [
        "data_exfiltration",
        "format_injection",
        "instruction_override",
    ],
    "output_format": "plain_text",
    "semantic_preservation_risk": "LOW",
    "label_change_risk": "LOW",
    "use_in_diagnostic_v1": True,

    # diagnostic v1 analysis metadata
    "target_evaluator_weakness": [
        "structure_parsing",
        "exact_match",
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


def apply(seed_text: str, ctx: Dict[str, Any], rng: random.Random) -> ApplyResult:
    len_before = len(seed_text) if isinstance(seed_text, str) else 0
    strength = _clamp_strength(ctx.get("strength", 1))
    surface = ctx.get("surface", "PROMPT_TEXT")
    constraints = ctx.get("constraints") or {}
    max_chars = constraints.get("max_chars")
    base_params = _base_params()

    if not isinstance(seed_text, str) or not seed_text.strip():
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text if isinstance(seed_text, str) else "",
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "strength": strength,
                    "reason": "empty",
                    "surface": surface,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    if surface not in ("PROMPT_TEXT", "SYSTEM_MESSAGE"):
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "strength": strength,
                    "reason": "surface_mismatch",
                    "surface": surface,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    if strength == 1:
        child = f"BEGIN\n{seed_text}\nEND"
        framing = "single"
    elif strength <= 3:
        child = f"BEGIN_INSTRUCTION\n{seed_text}\nEND_INSTRUCTION"
        framing = "split"
    elif strength == 4:
        inner = f"<<<INSTRUCTION>>>\n{seed_text}\n<<<END_INSTRUCTION>>>"
        child = f"BEGIN_BLOCK\n{inner}\nEND_BLOCK"
        framing = "nested_1"
    else:
        inner = f"<<<INSTRUCTION>>>\n{seed_text}\n<<<END_INSTRUCTION>>>"
        child = (
            "BEGIN_MESSAGE\n"
            "BEGIN_INSTRUCTION_BLOCK\n"
            f"{inner}\n"
            "END_INSTRUCTION_BLOCK\n"
            "END_MESSAGE"
        )
        framing = "nested_2"

    if child == seed_text:
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "strength": strength,
                    "reason": "no_change",
                    "surface": surface,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    if isinstance(max_chars, int) and max_chars >= 0 and len(child) > max_chars:
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "strength": strength,
                    "reason": "max_chars_exceeded",
                    "max_chars": max_chars,
                    "surface": surface,
                    "mode": "wrap",
                    "framing": framing,
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
                "mode": "wrap",
                "surface": surface,
                "framing": framing,
                **base_params,
            },
            "len_before": len_before,
            "len_after": len(child),
        },
    )