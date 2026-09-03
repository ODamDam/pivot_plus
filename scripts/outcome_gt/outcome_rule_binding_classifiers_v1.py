"""Dispatch frozen response-blind Outcome Rule classifiers by structural family."""

from __future__ import annotations

from typing import Any

from outcome_rule_binding_common_v1 import Decision, ExceptionDecision, detect_flags, normalize_semantics, structural_family
from outcome_rule_binding_classifiers_t1_t2_v1 import classify_t1, classify_t2
from outcome_rule_binding_classifiers_t3_t5_v1 import classify_t3, classify_t4, classify_t5


def classify(row: dict[str, Any]) -> Decision | ExceptionDecision:
    family = structural_family(row)
    normalized = normalize_semantics(row["untrusted_input"])
    flags = detect_flags(row["untrusted_input"], normalized)
    if family == "T1_document":
        return classify_t1(row, normalized, flags)
    if family == "T2_plain_text":
        return classify_t2(row, normalized, flags)
    if family == "T3_code":
        return classify_t3(row, normalized, flags)
    if family == "T4_structured":
        return classify_t4(row, normalized, flags)
    return classify_t5(row, normalized, flags)
