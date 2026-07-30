from __future__ import annotations

from src.core.registry import OperatorRegistry


def test_manual_review_policy_is_loaded() -> None:
    registry = OperatorRegistry()
    registry.load_from_package("src.operators", strict=True)

    allowed = {
        "op_fmt_markdown_wrapper",
        "op_fmt_structured_wrapper_json_yaml",
        "op_syn_boundary_delimiter_injection",
    }
    conditional = {
        "op_comp_expand_context",
        "op_fmt_whitespace_noise",
        "op_lex_polite_prefix",
    }
    denied = {
        "op_ctx_bypass_review_wrapper",
        "op_salience_preserving_line_compression",
    }

    for op_id in allowed:
        handle = registry.get(op_id)
        assert handle is not None
        assert handle.meta["diagnostic_eligibility"] == "allow"
        assert handle.meta["requires_post_filter"] is False
        assert handle.meta["use_in_diagnostic_v1"] is True

    for op_id in conditional:
        handle = registry.get(op_id)
        assert handle is not None
        assert handle.meta["diagnostic_eligibility"] == "conditional"
        assert handle.meta["requires_post_filter"] is True
        assert handle.meta["use_in_diagnostic_v1"] is True

    for op_id in denied:
        handle = registry.get(op_id)
        assert handle is not None
        assert handle.meta["diagnostic_eligibility"] == "deny"
        assert handle.meta["requires_post_filter"] is False
        assert handle.meta["use_in_diagnostic_v1"] is False
