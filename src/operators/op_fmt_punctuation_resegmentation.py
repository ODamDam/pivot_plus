from __future__ import annotations

import random
import re
from typing import Any, Dict, List

from src.core.types import ApplyResult

OPERATOR_META = {
    "op_id": "op_fmt_punctuation_resegmentation",
    "bucket_tags": ["LLM05_INPUT_ROBUSTNESS"],
    "surface_compat": ["PROMPT_TEXT"],
    "risk_level": "LOW",
    "strength_range": [1, 5],
    "params_schema": {},

    # diagnostic v1 metadata
    "operator_family": "syntactic",
    "attack_type_compat": [
        "data_exfiltration",
        "instruction_override",
        "policy_bypass",
    ],
    "output_format": "plain_text",
    "semantic_preservation_risk": "LOW",
    "label_change_risk": "LOW",
    "use_in_diagnostic_v1": True,

    # diagnostic v1 analysis metadata
    "target_evaluator_weakness": [
        "syntax_filter",
        "keyword_regex",
        "exact_match",
        "semantic_intent",
    ],
}


def _clamp_strength(v: Any) -> int:
    try:
        strength = int(v)
    except Exception:
        strength = 1

    lo, hi = OPERATOR_META["strength_range"]
    return max(lo, min(hi, strength))


def _base_params() -> Dict[str, Any]:
    return {
        "operator_family": OPERATOR_META.get("operator_family"),
        "output_format": OPERATOR_META.get("output_format"),
        "attack_type_compat": OPERATOR_META.get("attack_type_compat", []),
        "target_evaluator_weakness": OPERATOR_META.get("target_evaluator_weakness", []),
    }


def _space_before_punctuation(text: str) -> str:
    """
    Add a space before punctuation marks.
    This changes surface form while preserving token order and intent.
    """
    return re.sub(r"\s*([.,;:!?])", r" \1", text)


def _soft_replace_sentence_periods(text: str) -> str:
    """
    Replace sentence-ending periods with semicolons.
    This tests punctuation-sensitive matching without removing content.
    """
    return re.sub(r"\.(?=\s|$)", ";", text)


def _split_into_segments(text: str) -> List[str]:
    """
    Split text into sentence-like segments while preserving content.
    If no punctuation-based split exists, return the original text as one segment.
    """
    normalized = text.strip()
    if not normalized:
        return []

    parts = re.split(r"(?<=[.!?;])\s+", normalized)
    parts = [p.strip() for p in parts if p.strip()]

    if parts:
        return parts

    return [normalized]


def _bullet_resegment(text: str) -> str:
    segments = _split_into_segments(text)
    return "\n".join(f"- {segment}" for segment in segments)


def _numbered_resegment(text: str) -> str:
    segments = _split_into_segments(text)
    return "\n".join(f"{idx + 1}. {segment}" for idx, segment in enumerate(segments))


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
                    "reason": "empty",
                    "strength": strength,
                    "surface": surface,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    if surface not in OPERATOR_META["surface_compat"]:
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "reason": "surface_mismatch",
                    "surface": surface,
                    "strength": strength,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    applied: List[str] = []

    if strength == 1:
        child = _space_before_punctuation(seed_text)
        if child != seed_text:
            applied.append("space_before_punctuation")
        else:
            child = f"{seed_text} ."
            applied.append("terminal_punctuation_padding")

    elif strength == 2:
        child = _soft_replace_sentence_periods(seed_text)
        if child != seed_text:
            applied.append("period_to_semicolon")
        else:
            child = _space_before_punctuation(seed_text)
            if child != seed_text:
                applied.append("space_before_punctuation")
            else:
                child = f"{seed_text} ;"
                applied.append("terminal_semicolon_padding")

    elif strength == 3:
        child = _bullet_resegment(seed_text)
        applied.append("bullet_resegment")

    elif strength == 4:
        child = _numbered_resegment(seed_text)
        applied.append("numbered_resegment")

    else:
        child = "Reformatted segments:\n" + _bullet_resegment(seed_text)
        applied.append("sectioned_bullet_resegment")

    child = child.rstrip(" \t")

    if child == seed_text:
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "reason": "no_change",
                    "strength": strength,
                    "surface": surface,
                    "applied": applied,
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
                    "reason": "max_chars_exceeded",
                    "max_chars": max_chars,
                    "strength": strength,
                    "surface": surface,
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
                "surface": surface,
                "applied": applied,
                **base_params,
            },
            "len_before": len_before,
            "len_after": len(child),
        },
    )