from __future__ import annotations

import random
from typing import Any, Dict, List

from src.core.types import ApplyResult

OPERATOR_META = {
    "op_id": "op_fmt_markdown_wrapper",
    "bucket_tags": ["LLM01_PROMPT_INJECTION", "LLM05_INPUT_ROBUSTNESS"],
    "surface_compat": ["PROMPT_TEXT"],
    "risk_level": "MEDIUM",
    "strength_range": [1, 5],
    "params_schema": {},

    # diagnostic v1 metadata
    "operator_family": "structural",
    "attack_type_compat": [
        "data_exfiltration",
        "format_injection",
        "indirect_injection",
        "instruction_override",
    ],
    "output_format": "markdown",
    "semantic_preservation_risk": "LOW",
    "label_change_risk": "LOW",
    "use_in_diagnostic_v1": True,

    "target_evaluator_weakness": [
        "structure_parsing",
        "indirect_pi",
        "semantic_intent",
        "exact_match",
    ],    
}


def _clamp_strength(v: Any) -> int:
    try:
        x = int(v)
    except Exception:
        x = 1
    return max(1, min(5, x))


def apply(seed_text: str, ctx: Dict[str, Any], rng: random.Random) -> ApplyResult:
    len_before = len(seed_text) if isinstance(seed_text, str) else 0

    base_params = {
        "operator_family": OPERATOR_META.get("operator_family"),
        "output_format": OPERATOR_META.get("output_format"),
        "attack_type_compat": OPERATOR_META.get("attack_type_compat", []),
        "target_evaluator_weakness": OPERATOR_META.get("target_evaluator_weakness", []),
    }

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

    constraints = ctx.get("constraints") or {}
    max_chars = constraints.get("max_chars")

    if strength == 1:
        child = f"> {seed_text}"
        applied: List[str] = ["quote"]
    elif strength <= 3:
        child = f"```text\n{seed_text}\n```"
        applied = ["code_block"]
    else:
        child = (
            "# Instruction\n\n"
            "## Task\n"
            f"{seed_text}\n\n"
            "## Output\n"
            "Provide a structured answer."
        )
        applied = ["multi_section"]

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
                "applied": applied,
                **base_params,
            },
            "len_before": len_before,
            "len_after": len(child),
        },
    )