# src/core/selector_weights.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


_OPERATOR_WEIGHTS: Dict[str, float] = {
    "op_fmt_markdown_wrapper": 1.2,
    "op_fmt_structured_wrapper_json_yaml": 1.5,
    "op_syn_boundary_delimiter_injection": 1.4,
    "op_lex_homoglyph_injection": 1.2,
    "op_fmt_punctuation_resegmentation": 1.1,
    "op_fmt_whitespace_noise": 1.1,
    "op_lex_override_instructions": 1.4,
    "op_lex_polite_prefix": 1.0,
    "op_lex_refusal_suppression": 1.0,
    "op_lex_shorten": 0.8,
    "op_comp_expand_context": 1.0,
    "op_ctx_bypass_review_wrapper": 0.8,
    "op_salience_preserving_line_compression": 1.0,
    "op_syn_fake_tool_instruction_injection": 1.1,
}

_FAMILY_MULTIPLIERS: Dict[str, float] = {
    "lexical": 1.0,
    "syntactic": 1.0,
    "semantic_paraphrase": 1.2,
    "encoding": 1.1,
    "structural": 1.2,
    "contextual": 0.9,
    "noise_injection": 1.0,
    "cross_lingual": 0.8,
    "tool_manipulation": 0.9,
    "unknown": 0.5,
}


@dataclass(frozen=True)
class QuotaPolicy:
    min_samples_before_enforcement: int = 4

    max_operator_share: float = 0.25
    max_family_share: float = 0.40

    max_attack_operator_share: float = 0.50
    max_attack_family_share: float = 0.70

    forbid_immediate_operator_repeat: bool = True
    max_consecutive_family: int = 2

    single_candidate_bypass: bool = True


DEFAULT_QUOTA_POLICY = QuotaPolicy()


def weight_for(
    selection_scope: str,
    op_id: str,
    *,
    operator_family: Optional[str] = None,
) -> float:
    """
    기본 operator 가중치.

    Quota는 selector에서 별도로 적용하며,
    여기서는 operator와 family의 초기 선호도만 계산한다.
    """
    _ = selection_scope

    base = float(
        _OPERATOR_WEIGHTS.get(
            str(op_id),
            1.0,
        )
    )

    family_multiplier = float(
        _FAMILY_MULTIPLIERS.get(
            str(operator_family or "unknown"),
            1.0,
        )
    )

    weight = base * family_multiplier
    return max(0.0, weight)