from __future__ import annotations

from dataclasses import dataclass
from typing import Any


POLICY_VERSION = "operator_assignment.v1.1"


@dataclass(frozen=True)
class OperatorAssignment:
    """Seed-level operator selection contract.

    v1.1 deliberately separates operator *families* from blocking traits and
    conditional validity rules.  Earlier versions normalized values such as
    ``full_encoding`` and ``destructive_format`` into broad families.  That
    could make an allowed family simultaneously appear blocked.  The fields
    below keep those policy concepts independent.
    """

    allowed_operator_families: tuple[str, ...]
    blocked_operator_ids: tuple[str, ...]
    blocked_operator_traits: tuple[str, ...]
    conditional_block_rules: tuple[str, ...]
    target_evaluator_weaknesses: tuple[str, ...]
    engine_surface: str
    input_format: str
    max_strength: int
    mutation_budget: int
    requires_structure_preservation: bool
    max_semantic_preservation_risk: str
    max_label_change_risk: str
    policy_version: str = POLICY_VERSION


# Canonical engine-side family names. These must match
# OPERATOR_META["operator_family"] values used by src/operators.
CANONICAL_FAMILIES = {
    "lexical",
    "syntactic",
    "semantic_paraphrase",
    "encoding",
    "structural",
    "contextual",
    "noise_injection",
    "cross_lingual",
    "tool_manipulation",
    "indirect_injection",
}


# Family aliases only. Operator traits such as ``full_encoding`` or
# ``destructive_format`` must never be normalized through this mapping.
FAMILY_ALIASES = {
    "paraphrase": "semantic_paraphrase",
    "semantic": "semantic_paraphrase",
    "semantic_paraphrase": "semantic_paraphrase",
    "context_padding": "noise_injection",
    "contextual_padding": "noise_injection",
    "noise": "noise_injection",
    "noise_injection": "noise_injection",
    "format": "structural",
    "structure_preserving": "structural",
    "structural": "structural",
    "markdown_wrapper": "structural",
    "json_wrapper": "structural",
    "yaml_wrapper": "structural",
    "code_wrapper": "structural",
    "log_wrapper": "structural",
    "partial_encoding": "encoding",
    "encoding": "encoding",
    "roleplay": "contextual",
    "role_play": "contextual",
    "adversarial_suffix": "contextual",
    "contextual": "contextual",
    "multilingual": "cross_lingual",
    "cross_lingual": "cross_lingual",
    "indirect_wrapper": "indirect_injection",
    "indirect": "indirect_injection",
    "indirect_injection": "indirect_injection",
    "command_wrapper": "tool_manipulation",
    "tool": "tool_manipulation",
    "tool_manipulation": "tool_manipulation",
}


INPUT_FORMAT_ALIASES = {
    "": "unknown",
    "text": "plain_text",
    "plain": "plain_text",
    "plain_text": "plain_text",
    "md": "markdown",
    "markdown": "markdown",
    "jsonl": "json",
    "json": "json",
    "yml": "yaml",
    "yaml": "yaml",
    "xml": "xml",
    "htm": "html",
    "html": "html",
    "code": "code_block",
    "codeblock": "code_block",
    "code_block": "code_block",
    "command": "command",
    "log": "log",
    "repo": "repository_file",
    "repository": "repository_file",
    "repository_file": "repository_file",
    "encoded": "encoded",
    "mixed": "mixed",
    "unknown": "unknown",
}


RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}


# Policy fields:
# - allowed_families: broad candidate families
# - blocked_operator_ids: exact operators that must not be selected
# - blocked_traits: operator behavior traits, not families
# - conditional_rules: seed-dependent post/filter rules
# - semantic_risk_cap / label_risk_cap: maximum metadata risks
ATTACK_TYPE_POLICY: dict[str, dict[str, Any]] = {
    "instruction_override": {
        "allowed_families": ("lexical", "syntactic", "contextual", "structural", "encoding"),
        "blocked_operator_ids": (),
        "blocked_traits": ("destructive_format", "full_encoding"),
        "conditional_rules": ("preserve_required_structure",),
        "weaknesses": ("keyword_matching", "regex_boundary", "semantic_understanding"),
        "semantic_risk_cap": "MEDIUM",
        "label_risk_cap": "MEDIUM",
        "max_strength": 2,
    },
    "role_play_bypass": {
        "allowed_families": ("semantic_paraphrase", "contextual", "cross_lingual"),
        "blocked_operator_ids": (),
        "blocked_traits": ("full_encoding", "destructive_format", "goal_shift_risk"),
        "conditional_rules": ("avoid_goal_shift", "preserve_required_structure"),
        "weaknesses": ("semantic_understanding", "judge_consistency"),
        "semantic_risk_cap": "LOW",
        "label_risk_cap": "LOW",
        "max_strength": 2,
    },
    "policy_bypass": {
        "allowed_families": ("lexical", "semantic_paraphrase", "contextual", "cross_lingual"),
        "blocked_operator_ids": (),
        "blocked_traits": ("destructive_format", "goal_shift_risk"),
        "conditional_rules": ("preserve_required_structure",),
        "weaknesses": ("semantic_understanding", "judge_consistency"),
        "semantic_risk_cap": "LOW",
        "label_risk_cap": "LOW",
        "max_strength": 2,
    },
    "system_prompt_extraction": {
        "allowed_families": ("lexical", "semantic_paraphrase", "contextual", "noise_injection"),
        "blocked_operator_ids": (),
        "blocked_traits": ("goal_shift_risk", "full_encoding"),
        "conditional_rules": ("preserve_required_disclosure_target", "preserve_required_structure"),
        "weaknesses": ("semantic_understanding", "context_awareness"),
        "semantic_risk_cap": "MEDIUM",
        "label_risk_cap": "LOW",
        "max_strength": 2,
    },
    "data_exfiltration": {
        "allowed_families": (
            "lexical",
            "semantic_paraphrase",
            "contextual",
            "structural",
            "encoding",
            "noise_injection",
        ),
        "blocked_operator_ids": (),
        "blocked_traits": ("secret_target_removal", "full_encoding"),
        "conditional_rules": ("preserve_required_secret_target", "preserve_required_structure"),
        "weaknesses": ("keyword_matching", "normalization", "semantic_understanding", "context_awareness"),
        "semantic_risk_cap": "MEDIUM",
        "label_risk_cap": "MEDIUM",
        "max_strength": 2,
    },
    "format_injection": {
        "allowed_families": ("structural", "encoding", "noise_injection"),
        "blocked_operator_ids": (),
        "blocked_traits": ("syntax_breaking", "destructive_unicode", "destructive_format"),
        "conditional_rules": ("preserve_required_structure",),
        "weaknesses": ("structure_handling", "normalization"),
        "semantic_risk_cap": "MEDIUM",
        "label_risk_cap": "LOW",
        "max_strength": 2,
    },
    "indirect_injection": {
        "allowed_families": ("structural", "noise_injection", "indirect_injection", "contextual"),
        "blocked_operator_ids": (),
        "blocked_traits": ("plain_text_flattening", "destructive_format"),
        "conditional_rules": ("preserve_required_structure", "preserve_indirect_delivery_context"),
        "weaknesses": ("context_awareness", "structure_handling"),
        "semantic_risk_cap": "MEDIUM",
        "label_risk_cap": "MEDIUM",
        "max_strength": 2,
    },
    "tool_manipulation": {
        "allowed_families": ("structural", "contextual", "tool_manipulation"),
        "blocked_operator_ids": (),
        "blocked_traits": ("action_target_removal", "destructive_format"),
        "conditional_rules": ("preserve_required_action_target", "preserve_required_structure"),
        "weaknesses": ("structure_handling", "context_awareness", "action_risk"),
        "semantic_risk_cap": "MEDIUM",
        "label_risk_cap": "MEDIUM",
        "max_strength": 2,
    },
}


DEFAULT_MALICIOUS_POLICY: dict[str, Any] = {
    "allowed_families": ("lexical", "contextual"),
    "blocked_operator_ids": (),
    "blocked_traits": ("destructive_format", "full_encoding", "goal_shift_risk"),
    "conditional_rules": ("preserve_required_structure",),
    "weaknesses": ("semantic_understanding",),
    "semantic_risk_cap": "LOW",
    "label_risk_cap": "LOW",
    "max_strength": 1,
}


BENIGN_ATTACK_TYPES = {
    "benign_general",
    "benign_hard_negative",
}


def normalize_family(family: str) -> str:
    value = str(family or "").strip()
    return FAMILY_ALIASES.get(value, value)


def normalize_families(families: Any) -> tuple[str, ...]:
    if families is None:
        return ()
    if isinstance(families, str):
        items = [families]
    else:
        items = list(families)

    out: list[str] = []
    for item in items:
        normalized = normalize_family(str(item))
        if normalized and normalized not in out:
            out.append(normalized)
    return tuple(out)


def normalize_string_tuple(values: Any) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        items = [values]
    else:
        items = list(values)

    out: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if value and value not in out:
            out.append(value)
    return tuple(out)


def normalize_input_format(value: Any) -> str:
    raw = str(value or "").strip().lower()
    return INPUT_FORMAT_ALIASES.get(raw, raw or "unknown")


def normalize_risk_cap(value: Any, *, default: str = "MEDIUM") -> str:
    risk = str(value or default).strip().upper()
    return risk if risk in RISK_LEVELS else default


def infer_engine_surface(seed: dict[str, Any]) -> str:
    attack_surface = str(seed.get("attack_surface", "") or "").strip()
    input_format = normalize_input_format(seed.get("input_format"))

    if attack_surface == "system_user_context":
        return "SYSTEM_MESSAGE"

    if attack_surface == "tool_context":
        return "TOOL_ARGUMENTS"

    if input_format in {"json", "yaml"} and attack_surface == "tool_context":
        return "TOOL_ARGUMENTS"

    return "PROMPT_TEXT"


def requires_structure_preservation(seed: dict[str, Any]) -> bool:
    attack_surface = str(seed.get("attack_surface", "") or "").strip()
    input_format = normalize_input_format(seed.get("input_format"))

    return (
        attack_surface in {"external_document", "repository_file", "structured_input", "tool_context"}
        or input_format in {
            "json",
            "yaml",
            "xml",
            "html",
            "code_block",
            "command",
            "log",
            "repository_file",
            "mixed",
        }
    )


def is_main_malicious_mutation_candidate(seed: dict[str, Any]) -> bool:
    subset = str(seed.get("subset", "") or "")
    decision = str(seed.get("ground_truth_decision", "") or "")
    attack_type = str(seed.get("attack_type", "") or "")
    scanner_input = str(seed.get("scanner_input", "") or seed.get("text", "") or "")

    if subset != "seed_malicious":
        return False
    if decision != "malicious":
        return False
    if attack_type in {"", "unspecified", "benign_general", "benign_hard_negative"}:
        return False
    if not scanner_input.strip():
        return False

    return True


def is_smoke_test_candidate(seed: dict[str, Any]) -> bool:
    if not is_main_malicious_mutation_candidate(seed):
        return False

    attack_surface = str(seed.get("attack_surface", "") or "")
    input_format = normalize_input_format(seed.get("input_format"))

    if attack_surface in {"repository_file", "external_document", "tool_context"}:
        return False
    if input_format in {"repository_file", "unknown"}:
        return False

    return True


def get_operator_assignment(seed: dict[str, Any], *, smoke_test: bool = False) -> OperatorAssignment:
    attack_type = str(seed.get("attack_type", "") or "").strip()
    input_format = normalize_input_format(seed.get("input_format"))
    structure_required = requires_structure_preservation(seed)

    if attack_type in BENIGN_ATTACK_TYPES:
        return OperatorAssignment(
            allowed_operator_families=(),
            blocked_operator_ids=(),
            blocked_operator_traits=("malicious_operator",),
            conditional_block_rules=("do_not_apply_main_malicious_mutation",),
            target_evaluator_weaknesses=("false_positive",),
            engine_surface=infer_engine_surface(seed),
            input_format=input_format,
            max_strength=0,
            mutation_budget=0,
            requires_structure_preservation=structure_required,
            max_semantic_preservation_risk="LOW",
            max_label_change_risk="LOW",
        )

    policy = ATTACK_TYPE_POLICY.get(attack_type, DEFAULT_MALICIOUS_POLICY)

    allowed = normalize_families(policy.get("allowed_families", ()))
    blocked_ids = normalize_string_tuple(policy.get("blocked_operator_ids", ()))
    blocked_traits = normalize_string_tuple(policy.get("blocked_traits", ()))
    conditional_rules = normalize_string_tuple(policy.get("conditional_rules", ()))
    weaknesses = normalize_string_tuple(policy.get("weaknesses", ("unknown",)))

    max_strength = min(int(policy.get("max_strength", 2)), 2 if smoke_test else 3)
    mutation_budget = 1 if smoke_test else 2

    # Until registry v1.1 enforces input-format and structure-preservation
    # compatibility, retain the conservative smoke-test exclusion.  The next
    # patch removes this guard after the new registry filter is wired in.
    if structure_required and smoke_test:
        mutation_budget = 0

    return OperatorAssignment(
        allowed_operator_families=allowed,
        blocked_operator_ids=blocked_ids,
        blocked_operator_traits=blocked_traits,
        conditional_block_rules=conditional_rules,
        target_evaluator_weaknesses=weaknesses,
        engine_surface=infer_engine_surface(seed),
        input_format=input_format,
        max_strength=max_strength,
        mutation_budget=mutation_budget,
        requires_structure_preservation=structure_required,
        max_semantic_preservation_risk=normalize_risk_cap(policy.get("semantic_risk_cap"), default="MEDIUM"),
        max_label_change_risk=normalize_risk_cap(policy.get("label_risk_cap"), default="MEDIUM"),
    )


def to_engine_input(seed: dict[str, Any], *, mutation_seed_id: str, smoke_test: bool = False) -> dict[str, Any]:
    assignment = get_operator_assignment(seed, smoke_test=smoke_test)

    text = str(seed.get("scanner_input", "") or seed.get("text", "") or "")
    source_sample_id = str(seed.get("sample_id", "") or seed.get("source_sample_id", ""))
    parent_seed_id = str(seed.get("parent_seed_id", "") or source_sample_id)

    return {
        "policy_version": assignment.policy_version,
        "mutation_seed_id": mutation_seed_id,
        "parent_seed_id": parent_seed_id,
        "source_sample_id": source_sample_id,
        "source_id": str(seed.get("source_id", "")),
        "source_record_id": str(seed.get("source_record_id", "")),
        "text": text,
        "prompt": text,
        "label": str(seed.get("ground_truth_decision", "malicious")),
        "ground_truth_decision": str(seed.get("ground_truth_decision", "malicious")),
        "attack_type": str(seed.get("attack_type", "")),
        "attack_goal": str(seed.get("attack_goal", "")),
        "attack_surface": str(seed.get("attack_surface", "")),
        "input_format": assignment.input_format,
        "language": str(seed.get("language", "unknown")),
        "engine_surface": assignment.engine_surface,
        "allowed_operator_families": list(assignment.allowed_operator_families),
        "blocked_operator_ids": list(assignment.blocked_operator_ids),
        "blocked_operator_traits": list(assignment.blocked_operator_traits),
        "conditional_block_rules": list(assignment.conditional_block_rules),
        "target_evaluator_weaknesses": list(assignment.target_evaluator_weaknesses),
        "mutation_budget": assignment.mutation_budget,
        "max_strength": assignment.max_strength,
        "requires_structure_preservation": assignment.requires_structure_preservation,
        "max_semantic_preservation_risk": assignment.max_semantic_preservation_risk,
        "max_label_change_risk": assignment.max_label_change_risk,
        "metadata": {
            "expected_behavior": seed.get("expected_behavior", "detect_as_malicious"),
            "review_status": seed.get("review_status", ""),
            "review_decision": seed.get("review_decision", ""),
            "normalized_record_id": seed.get("normalized_record_id", ""),
            "text_sha256": seed.get("text_sha256", ""),
            "notes": seed.get("notes", ""),
        },
    }
