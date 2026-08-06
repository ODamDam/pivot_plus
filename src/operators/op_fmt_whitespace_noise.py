# -*- coding: utf-8 -*-
from __future__ import annotations

import random
import re
from typing import Any, Dict, List

from src.core.types import ApplyResult

OPERATOR_META = {
    "op_id": "op_fmt_whitespace_noise",
    "bucket_tags": ["LLM05_INPUT_ROBUSTNESS"],
    "surface_compat": ["PROMPT_TEXT", "SYSTEM_MESSAGE"],
    "risk_level": "MEDIUM",
    "strength_range": [1, 5],
    "params_schema": {},

    # diagnostic v1 metadata
    "operator_family": "noise_injection",
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
        "normalization",
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


def _add_punctuation_spacing(text: str) -> str:
    """
    Add a space after punctuation when punctuation is immediately followed by
    a non-space character. This preserves token order and semantic intent.
    """
    return re.sub(r"([.,;:!?])(?=\S)", r"\1 ", text)


def _double_some_word_spaces(text: str, count: int) -> str:
    """
    Double a limited number of word-boundary spaces.
    This tests whitespace normalization without splitting words.
    """
    if count <= 0:
        return text

    return re.sub(r"(?<=\w) (?=\w)", "  ", text, count=count)


def _soft_line_wrap(text: str, group_size: int) -> str:
    """
    Re-segment text by inserting newlines between word groups.
    Words are preserved in order.
    """
    words = text.split()
    if len(words) <= group_size:
        return text

    chunks = [
        " ".join(words[i:i + group_size])
        for i in range(0, len(words), group_size)
    ]
    return "\n".join(chunks)


def _heavy_resegment(text: str) -> str:
    """
    Place each token on its own paragraph-like segment.
    This is high-strength whitespace noise, but it preserves token order.
    """
    words = text.split()
    if len(words) <= 1:
        return text

    return "\n\n".join(words)


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
                    "strength": strength,
                    "surface": surface,
                    **base_params,
                },
                "len_before": len_before,
                "len_after": len_before,
            },
        )

    text = seed_text
    applied: List[str] = []

    if strength == 1:
        text = f"\n{seed_text}\n"
        applied.append("boundary_newlines")

    elif strength == 2:
        before = text
        text = _add_punctuation_spacing(text)
        if text != before:
            applied.append("punctuation_spacing")

        before = text
        text = _double_some_word_spaces(text, count=2)
        if text != before:
            applied.append("limited_double_spaces")

        if text == seed_text:
            text = f" {seed_text} "
            applied.append("boundary_spaces")

    elif strength == 3:
        before = text
        text = _add_punctuation_spacing(text)
        if text != before:
            applied.append("punctuation_spacing")

        before = text
        text = _double_some_word_spaces(text, count=10)
        if text != before:
            applied.append("double_spaces")

        before = text
        text = re.sub(r"([.;!?])\s+", r"\1\n", text)
        if text != before:
            applied.append("sentence_newlines")

        if text == seed_text:
            text = _soft_line_wrap(seed_text, group_size=5)
            if text != seed_text:
                applied.append("soft_line_wrap")

    elif strength == 4:
        text = _soft_line_wrap(seed_text, group_size=4)
        if text != seed_text:
            applied.append("soft_line_wrap")
        else:
            text = f"\n\n{seed_text}\n\n"
            applied.append("paragraph_boundary_padding")

    else:
        text = _heavy_resegment(seed_text)
        if text != seed_text:
            applied.append("heavy_resegmentation")
        else:
            text = f"\n\n{seed_text}\n\n"
            applied.append("paragraph_boundary_padding")

    # Keep line breaks, but remove unstable trailing spaces/tabs.
    text = text.rstrip(" \t")

    if text == seed_text:
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

    if isinstance(max_chars, int) and max_chars >= 0 and len(text) > max_chars:
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
        child_text=text,
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
            "len_after": len(text),
        },
    )