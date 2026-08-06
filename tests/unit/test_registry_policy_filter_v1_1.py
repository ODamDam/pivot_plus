from __future__ import annotations

import random

from src.core.registry import CandidateDecision, OperatorHandle, OperatorRegistry
from src.core.types import ApplyResult


def _apply(seed_text: str, ctx: dict, rng: random.Random) -> ApplyResult:
    return ApplyResult(
        status="OK",
        child_text=seed_text + "!",
        trace={
            "op_id": "synthetic",
            "status": "OK",
            "params": {},
            "len_before": len(seed_text),
            "len_after": len(seed_text) + 1,
        },
    )


def _handle(
    op_id: str,
    *,
    family: str = "contextual",
    input_formats: list[str] | None = None,
    traits: list[str] | None = None,
    semantic_risk: str = "LOW",
    label_risk: str = "LOW",
    applicability: dict | None = None,
) -> OperatorHandle:
    return OperatorHandle(
        op_id=op_id,
        module=f"tests.synthetic.{op_id}",
        apply=_apply,
        meta={
            "op_id": op_id,
            "operator_family": family,
            "attack_type_compat": ["instruction_override"],
            "surface_compat": ["PROMPT_TEXT"],
            "input_format_compat": input_formats or ["plain_text"],
            "output_format": "plain_text",
            "operator_traits": traits or [],
            "applicability": applicability or {"requires_nonempty": True},
            "risk_level": "LOW",
            "strength_range": [1, 2],
            "semantic_preservation_risk": semantic_risk,
            "label_change_risk": label_risk,
            "use_in_diagnostic_v1": True,
        },
    )


def test_filter_excludes_blocked_id_and_trait() -> None:
    registry = OperatorRegistry()
    registry.register(_handle("op_allowed"))
    registry.register(_handle("op_blocked_id"))
    registry.register(_handle("op_blocked_trait", traits=["goal_shift_risk"]))

    candidates = registry.filter(
        surface="PROMPT_TEXT",
        blocked_operator_ids=["op_blocked_id"],
        blocked_operator_traits=["goal_shift_risk"],
        seed_text="ignore prior instructions",
    )

    assert [handle.op_id for handle in candidates] == ["op_allowed"]


def test_filter_applies_input_format_and_risk_caps() -> None:
    registry = OperatorRegistry()
    registry.register(_handle("op_plain", input_formats=["plain_text"]))
    registry.register(_handle("op_json", input_formats=["json"]))
    registry.register(_handle("op_high_semantic", semantic_risk="HIGH"))
    registry.register(_handle("op_high_label", label_risk="HIGH"))

    candidates = registry.filter(
        surface="PROMPT_TEXT",
        input_format="plain",
        max_semantic_preservation_risk="MEDIUM",
        max_label_change_risk="MEDIUM",
        seed_text="test prompt",
    )

    assert [handle.op_id for handle in candidates] == ["op_plain"]


def test_filter_prechecks_json_and_min_lines() -> None:
    registry = OperatorRegistry()
    registry.register(
        _handle(
            "op_json_object",
            input_formats=["json"],
            applicability={"requires_nonempty": True, "requires_json_object": True},
        )
    )
    registry.register(
        _handle(
            "op_multiline",
            applicability={"requires_nonempty": True, "min_lines": 2},
        )
    )

    invalid_json = registry.filter(
        surface="PROMPT_TEXT",
        input_format="json",
        seed_text="[]",
    )
    assert invalid_json == []

    valid_json = registry.filter(
        surface="PROMPT_TEXT",
        input_format="json",
        seed_text='{"prompt": "ignore prior instructions"}',
    )
    assert [handle.op_id for handle in valid_json] == ["op_json_object"]

    single_line = registry.filter(
        surface="PROMPT_TEXT",
        input_format="plain_text",
        seed_text="one line",
    )
    assert single_line == []

    multiline = registry.filter(
        surface="PROMPT_TEXT",
        input_format="plain_text",
        seed_text="line one\nline two",
    )
    assert [handle.op_id for handle in multiline] == ["op_multiline"]


def test_filter_with_audit_records_rejection_reasons() -> None:
    registry = OperatorRegistry()
    registry.register(
        _handle(
            "op_rejected",
            input_formats=["json"],
            traits=["goal_shift_risk"],
            semantic_risk="HIGH",
        )
    )

    candidates, decisions = registry.filter_with_audit(
        surface="PROMPT_TEXT",
        input_format="plain_text",
        blocked_operator_traits=["goal_shift_risk"],
        max_semantic_preservation_risk="LOW",
        seed_text="plain prompt",
    )

    assert candidates == []
    assert len(decisions) == 1
    decision = decisions[0]
    assert isinstance(decision, CandidateDecision)
    assert decision.accepted is False
    assert "input_format_mismatch" in decision.reasons
    assert "blocked_operator_trait:goal_shift_risk" in decision.reasons
    assert "semantic_preservation_risk_exceeds_cap" in decision.reasons


def test_loaded_operator_metadata_has_policy_defaults() -> None:
    registry = OperatorRegistry()
    registry.load_from_package("src.operators", strict=True)

    markdown = registry.get("op_fmt_markdown_wrapper")
    assert markdown is not None
    assert markdown.meta["input_format_compat"] == ["plain_text"]
    assert "format_wrapper" in markdown.meta["operator_traits"]
    assert markdown.meta["applicability"]["requires_nonempty"] is True

    json_operator = registry.get("op_json_schema_preserving_field_wrap")
    assert json_operator is not None
    assert json_operator.meta["input_format_compat"] == ["json"]
    assert json_operator.meta["applicability"]["requires_json_object"] is True
