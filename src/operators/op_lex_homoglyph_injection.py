from __future__ import annotations

import random
from typing import Any, Dict, List, Tuple

from src.core.types import ApplyResult

OPERATOR_META = {
    "op_id": "op_lex_homoglyph_injection",
    "bucket_tags": ["LLM01_PROMPT_INJECTION", "LLM05_INPUT_ROBUSTNESS"],
    "surface_compat": ["PROMPT_TEXT"],
    "risk_level": "MEDIUM",
    "strength_range": [1, 5],
    "params_schema": {
        "mode": ["homoglyph_substitution"],
    },

    # diagnostic v1 metadata
    "operator_family": "encoding",
    "attack_type_compat": [
        "data_exfiltration",
        "instruction_override",
        "policy_bypass",
    ],
    "output_format": "plain_text",
    "semantic_preservation_risk": "MEDIUM",
    "label_change_risk": "MEDIUM",
    "use_in_diagnostic_v1": True,

    # diagnostic v1 analysis metadata
    "target_evaluator_weakness": [
        "normalization",
        "keyword_regex",
        "exact_match",
        "semantic_intent",
    ],
}

# Confusable Unicode characters.
# Avoid combining marks such as l + U+0337 because they caused terminal
# encoding/display issues in earlier smoke tests.
_HOMOGLYPHS: Dict[str, Tuple[str, str]] = {
    "a": ("\u0430", "a_to_cyrillic_a"),       # а
    "c": ("\u0441", "c_to_cyrillic_es"),      # с
    "e": ("\u0435", "e_to_cyrillic_ie"),      # е
    "i": ("\u0456", "i_to_cyrillic_i"),       # і
    "o": ("\u043e", "o_to_cyrillic_o"),      # о
    "p": ("\u0440", "p_to_cyrillic_er"),     # р
    "s": ("\u0455", "s_to_cyrillic_dze"),    # ѕ
    "x": ("\u0445", "x_to_cyrillic_ha"),     # х
    "y": ("\u0443", "y_to_cyrillic_u"),      # у
    "A": ("\u0410", "A_to_cyrillic_A"),       # А
    "E": ("\u0395", "E_to_greek_Epsilon"),   # Ε
    "I": ("\u0406", "I_to_cyrillic_I"),       # І
    "O": ("\u041e", "O_to_cyrillic_O"),       # О
    "P": ("\u03a1", "P_to_greek_Rho"),        # Ρ
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


def _mutation_budget(strength: int, candidate_count: int) -> int:
    """
    Limit the number of homoglyph substitutions.
    Full-string substitution can hurt readability and increase label-change risk.
    """
    budget_by_strength = {
        1: 1,
        2: 2,
        3: 4,
        4: 6,
        5: 8,
    }
    return min(candidate_count, budget_by_strength.get(strength, 1))


def _substitute_homoglyphs(text: str, strength: int) -> Tuple[str, List[Dict[str, Any]]]:
    candidates: List[int] = [
        idx for idx, ch in enumerate(text)
        if ch in _HOMOGLYPHS
    ]

    if not candidates:
        return text, []

    budget = _mutation_budget(strength, len(candidates))

    # Deterministic left-to-right substitution keeps examples stable and readable.
    selected = candidates[:budget]

    chars = list(text)
    applied: List[Dict[str, Any]] = []

    for idx in selected:
        original = chars[idx]
        replacement, label = _HOMOGLYPHS[original]
        chars[idx] = replacement
        applied.append({
            "index": idx,
            "replacement": label,
        })

    return "".join(chars), applied


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

    if surface != "PROMPT_TEXT":
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

    child, applied = _substitute_homoglyphs(seed_text, strength)

    if child == seed_text or not applied:
        return ApplyResult(
            status="SKIPPED",
            child_text=seed_text,
            trace={
                "op_id": OPERATOR_META["op_id"],
                "status": "SKIPPED",
                "params": {
                    "reason": "no_homoglyph_candidates",
                    "strength": strength,
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
                    "reason": "max_chars_exceeded",
                    "max_chars": max_chars,
                    "strength": strength,
                    "surface": surface,
                    "mode": "homoglyph_substitution",
                    "applied_count": len(applied),
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
                "mode": "homoglyph_substitution",
                "applied_count": len(applied),
                "applied": applied,
                **base_params,
            },
            "len_before": len_before,
            "len_after": len(child),
        },
    )