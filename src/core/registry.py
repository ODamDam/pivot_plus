from __future__ import annotations

import importlib
import json
import pkgutil
import random
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from .operator_assignment_policy import normalize_input_format
from .trace import ensure_min_trace_fields
from .types import ApplyResult, validate_meta

ApplyFn = Callable[[str, Dict[str, Any], random.Random], ApplyResult]


@dataclass(frozen=True)
class OperatorHandle:
    op_id: str
    meta: Dict[str, Any]
    apply: ApplyFn
    module: str


@dataclass(frozen=True)
class CandidateDecision:
    """Registry 후보 하나에 대한 수락·제외 결과이다."""

    op_id: str
    accepted: bool
    reasons: Tuple[str, ...]


ValueOrValues = Optional[Union[str, Iterable[str]]]


class OperatorRegistry:
    """Bucket-free operator registry.

    ``bucket_tags``는 legacy compatibility metadata로만 유지한다.
    후보 operator 선택은 다음 metadata와 seed-level policy를 사용한다.

    - use_in_diagnostic_v1
    - operator_family
    - attack_type_compat
    - surface_compat
    - input_format_compat
    - output_format
    - risk_level
    - semantic_preservation_risk
    - label_change_risk
    - blocked operator id / trait
    - applicability precheck
    """

    _META_DEFAULTS_BY_OP_ID: Dict[str, Dict[str, Any]] = {
        "op_comp_expand_context": {
            "operator_family": "noise_injection",
            "attack_type_compat": [
                "instruction_override",
                "data_exfiltration",
                "indirect_injection",
            ],
            "output_format": "plain_text",
            "semantic_preservation_risk": "MEDIUM",
            "label_change_risk": "MEDIUM",
            "use_in_diagnostic_v1": True,
        },
        "op_constraint_schema_preserving_mutation": {
            "operator_family": "structural",
            "attack_type_compat": ["format_injection", "tool_manipulation"],
            "output_format": "json",
            "semantic_preservation_risk": "MEDIUM",
            "label_change_risk": "MEDIUM",
            "use_in_diagnostic_v1": True,
        },
        "op_fmt_markdown_wrapper": {
            "operator_family": "structural",
            "attack_type_compat": [
                "instruction_override",
                "data_exfiltration",
                "format_injection",
                "indirect_injection",
            ],
            "output_format": "markdown",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_fmt_punctuation_resegmentation": {
            "operator_family": "syntactic",
            "attack_type_compat": [
                "instruction_override",
                "policy_bypass",
                "data_exfiltration",
            ],
            "output_format": "plain_text",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_fmt_structured_wrapper_json_yaml": {
            "operator_family": "structural",
            "attack_type_compat": [
                "instruction_override",
                "data_exfiltration",
                "format_injection",
                "indirect_injection",
            ],
            "output_format": "json_or_yaml",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_fmt_whitespace_noise": {
            "operator_family": "noise_injection",
            "attack_type_compat": [
                "instruction_override",
                "policy_bypass",
                "data_exfiltration",
            ],
            "output_format": "plain_text",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_lex_homoglyph_injection": {
            "operator_family": "encoding",
            "attack_type_compat": [
                "instruction_override",
                "policy_bypass",
                "data_exfiltration",
            ],
            "output_format": "plain_text",
            "semantic_preservation_risk": "MEDIUM",
            "label_change_risk": "MEDIUM",
            "use_in_diagnostic_v1": True,
        },
        "op_lex_override_instructions": {
            "operator_family": "lexical",
            "attack_type_compat": ["instruction_override"],
            "output_format": "plain_text",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_lex_polite_prefix": {
            "operator_family": "contextual",
            "attack_type_compat": ["instruction_override", "policy_bypass"],
            "output_format": "plain_text",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_lex_refusal_suppression": {
            "operator_family": "contextual",
            "attack_type_compat": ["policy_bypass", "instruction_override"],
            "output_format": "plain_text",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_lex_shorten": {
            "operator_family": "lexical",
            "attack_type_compat": [
                "instruction_override",
                "data_exfiltration",
                "policy_bypass",
            ],
            "output_format": "plain_text",
            "semantic_preservation_risk": "MEDIUM",
            "label_change_risk": "MEDIUM",
            "use_in_diagnostic_v1": True,
        },
        "op_syn_boundary_delimiter_injection": {
            "operator_family": "structural",
            "attack_type_compat": [
                "instruction_override",
                "data_exfiltration",
                "format_injection",
            ],
            "output_format": "plain_text",
            "semantic_preservation_risk": "LOW",
            "label_change_risk": "LOW",
            "use_in_diagnostic_v1": True,
        },
        "op_syn_fake_tool_instruction_injection": {
            "operator_family": "tool_manipulation",
            "attack_type_compat": ["tool_manipulation", "instruction_override"],
            "output_format": "plain_text",
            "semantic_preservation_risk": "MEDIUM",
            "label_change_risk": "MEDIUM",
            "use_in_diagnostic_v1": True,
        },
        "op_syn_tool_call_argument_perturbation": {
            "operator_family": "tool_manipulation",
            "attack_type_compat": ["tool_manipulation", "format_injection"],
            "output_format": "json",
            "semantic_preservation_risk": "HIGH",
            "label_change_risk": "HIGH",
            "use_in_diagnostic_v1": False,
        },
        "op_syn_trust_violation_trigger": {
            "operator_family": "contextual",
            "attack_type_compat": ["policy_bypass", "indirect_injection"],
            "output_format": "plain_text",
            "semantic_preservation_risk": "HIGH",
            "label_change_risk": "HIGH",
            "use_in_diagnostic_v1": False,
        },
        "op_syn_unverified_data_injection": {
            "operator_family": "contextual",
            "attack_type_compat": ["indirect_injection", "data_exfiltration"],
            "output_format": "plain_text",
            "semantic_preservation_risk": "HIGH",
            "label_change_risk": "HIGH",
            "use_in_diagnostic_v1": False,
        },
    }

    _POLICY_DEFAULTS_BY_OP_ID: Dict[str, Dict[str, Any]] = {
        "op_comp_expand_context": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["context_expansion"],
            "applicability": {"requires_nonempty": True},
        },
        "op_ctx_bypass_review_wrapper": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["context_wrapper"],
            "applicability": {"requires_nonempty": True},
        },
        "op_direct_override_prefix": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["goal_shift_risk", "malicious_operator"],
            "applicability": {"requires_nonempty": True},
        },
        "op_fmt_markdown_wrapper": {
            "input_format_compat": ["plain_text"],
            "operator_traits": ["format_wrapper"],
            "applicability": {"requires_nonempty": True},
        },
        "op_fmt_punctuation_resegmentation": {
            "input_format_compat": ["plain_text"],
            "operator_traits": ["syntax_resegmentation"],
            "applicability": {"requires_nonempty": True},
        },
        "op_fmt_structured_wrapper_json_yaml": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["format_conversion"],
            "applicability": {"requires_nonempty": True},
        },
        "op_fmt_whitespace_noise": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["whitespace_noise"],
            "applicability": {"requires_nonempty": True},
        },
        "op_json_schema_preserving_field_wrap": {
            "input_format_compat": ["json"],
            "operator_traits": ["structure_preserving"],
            "applicability": {
                "requires_nonempty": True,
                "requires_json_object": True,
            },
        },
        "op_lex_homoglyph_injection": {
            "input_format_compat": ["plain_text"],
            "operator_traits": ["partial_encoding"],
            "applicability": {"requires_nonempty": True},
        },
        "op_lex_polite_prefix": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["context_prefix"],
            "applicability": {"requires_nonempty": True},
        },
        "op_lex_refusal_suppression": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["goal_shift_risk", "malicious_operator"],
            "applicability": {"requires_nonempty": True},
        },
        "op_salience_preserving_line_compression": {
            "input_format_compat": ["plain_text", "markdown", "log"],
            "operator_traits": ["content_reduction"],
            "applicability": {
                "requires_nonempty": True,
                "min_lines": 2,
            },
        },
        "op_syn_boundary_delimiter_injection": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["format_wrapper"],
            "applicability": {"requires_nonempty": True},
        },
        "op_syn_fake_tool_instruction_injection": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": [
                "goal_shift_risk",
                "action_target_injection",
                "malicious_operator",
            ],
            "applicability": {"requires_nonempty": True},
        },
        "op_syn_tool_call_argument_perturbation": {
            "input_format_compat": ["json"],
            "operator_traits": ["action_target_mutation", "structure_preserving"],
            "applicability": {
                "requires_nonempty": True,
                "requires_json_object": True,
            },
        },
        "op_syn_trust_violation_trigger": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["goal_shift_risk"],
            "applicability": {"requires_nonempty": True},
        },
        "op_syn_unverified_data_injection": {
            "input_format_compat": ["plain_text", "markdown"],
            "operator_traits": ["context_injection"],
            "applicability": {"requires_nonempty": True},
        },
    }

    _MANUAL_REVIEW_POLICY_BY_OP_ID: Dict[str, Dict[str, Any]] = {
        "op_fmt_markdown_wrapper": {
            "diagnostic_eligibility": "allow",
            "requires_post_filter": False,
            "use_in_diagnostic_v1": True,
        },
        "op_fmt_structured_wrapper_json_yaml": {
            "diagnostic_eligibility": "allow",
            "requires_post_filter": False,
            "use_in_diagnostic_v1": True,
        },
        "op_syn_boundary_delimiter_injection": {
            "diagnostic_eligibility": "allow",
            "requires_post_filter": False,
            "use_in_diagnostic_v1": True,
        },
        "op_comp_expand_context": {
            "diagnostic_eligibility": "conditional",
            "requires_post_filter": True,
            "use_in_diagnostic_v1": True,
        },
        "op_fmt_whitespace_noise": {
            "diagnostic_eligibility": "conditional",
            "requires_post_filter": True,
            "use_in_diagnostic_v1": True,
        },
        "op_lex_polite_prefix": {
            "diagnostic_eligibility": "conditional",
            "requires_post_filter": True,
            "use_in_diagnostic_v1": True,
        },
        "op_ctx_bypass_review_wrapper": {
            "diagnostic_eligibility": "deny",
            "requires_post_filter": False,
            "use_in_diagnostic_v1": False,
        },
        "op_salience_preserving_line_compression": {
            "diagnostic_eligibility": "deny",
            "requires_post_filter": False,
            "use_in_diagnostic_v1": False,
        },
    }

    def __init__(self) -> None:
        self._ops: Dict[str, OperatorHandle] = {}
        self.load_errors: List[Tuple[str, str]] = []

    # ---------- internal helpers ----------
    @staticmethod
    def _canon_applied(applied: Any) -> Any:
        if not isinstance(applied, list):
            return applied

        def key(value: Any) -> Tuple[Any, ...]:
            if isinstance(value, list) and len(value) >= 3:
                first = str(value[0])
                second: Any = value[1]
                try:
                    second = int(second)
                except (TypeError, ValueError):
                    second = str(second)
                third = str(value[2])
                return first, third, second
            return str(type(value)), str(value)

        try:
            return sorted(applied, key=key)
        except (TypeError, ValueError):
            return applied

    @staticmethod
    def _as_set(value: ValueOrValues) -> Optional[set[str]]:
        if value is None:
            return None
        if isinstance(value, str):
            return {value}
        try:
            return {str(item) for item in value}
        except TypeError:
            return {str(value)}

    @staticmethod
    def _risk_rank(value: Any) -> int:
        ranks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        if isinstance(value, str):
            return ranks.get(value.upper(), 2)
        return 2

    @staticmethod
    def _format_matches(
        meta_formats: Any,
        requested_formats: Optional[set[str]],
    ) -> bool:
        """Seed input format과 operator input compatibility를 비교한다."""

        if requested_formats is None:
            return True

        raw_formats = meta_formats or []
        if isinstance(raw_formats, str):
            raw_formats = [raw_formats]

        compat = {
            normalize_input_format(value)
            for value in raw_formats
        }

        if not compat or "*" in compat or "any" in compat:
            return True

        return bool(compat & requested_formats)

    @staticmethod
    def _applicability_reasons(
        meta: Dict[str, Any],
        seed_text: Optional[str],
    ) -> List[str]:
        """명백히 적용할 수 없는 operator를 선택 전에 제외한다."""

        spec = meta.get("applicability")

        # 기존 호출은 seed_text를 전달하지 않으므로 하위 호환성을 위해
        # applicability 검사를 생략한다.
        if not isinstance(spec, dict) or seed_text is None:
            return []

        text = str(seed_text)
        stripped = text.strip()
        reasons: List[str] = []

        if bool(spec.get("requires_nonempty")) and not stripped:
            reasons.append("applicability_empty")

        min_chars = spec.get("min_chars")
        if isinstance(min_chars, int) and len(text) < min_chars:
            reasons.append(f"applicability_min_chars:{min_chars}")

        max_chars = spec.get("max_chars")
        if isinstance(max_chars, int) and len(text) > max_chars:
            reasons.append(f"applicability_max_chars:{max_chars}")

        min_lines = spec.get("min_lines")
        line_count = len(text.splitlines()) if text else 0
        if isinstance(min_lines, int) and line_count < min_lines:
            reasons.append(f"applicability_min_lines:{min_lines}")

        if bool(spec.get("requires_json_object")):
            try:
                parsed = json.loads(text)
            except (TypeError, ValueError):
                parsed = None

            if not isinstance(parsed, dict):
                reasons.append("applicability_requires_json_object")

        lowered = text.casefold()

        required_terms = spec.get("requires_any_terms")
        if isinstance(required_terms, list) and required_terms:
            found = any(
                str(term).casefold() in lowered
                for term in required_terms
            )
            if not found:
                reasons.append("applicability_requires_any_terms")

        forbidden_terms = spec.get("forbids_any_terms")
        if isinstance(forbidden_terms, list) and forbidden_terms:
            matched = [
                str(term)
                for term in forbidden_terms
                if str(term).casefold() in lowered
            ]
            if matched:
                reasons.append(f"applicability_forbidden_term:{matched[0]}")

        return reasons

    # ---------- load / register ----------
    def load_from_package(
        self,
        package: str = "src.operators",
        *,
        strict: bool = False,
    ) -> int:
        pkg = importlib.import_module(package)
        count = 0

        modnames: List[str] = []
        for modinfo in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
            modname = modinfo.name
            if modname.split(".")[-1].startswith("op_"):
                modnames.append(modname)

        for modname in sorted(modnames):
            try:
                module = importlib.import_module(modname)
                count += self._register_from_module(module, strict=strict)
            except Exception as exc:
                message = f"import failed: {exc.__class__.__name__}: {exc}"
                self.load_errors.append((modname, message))
                if strict:
                    raise

        return count

    def _register_from_module(
        self,
        module: ModuleType,
        *,
        strict: bool = False,
    ) -> int:
        modname = getattr(module, "__name__", "<unknown>")

        if not hasattr(module, "OPERATOR_META") or not hasattr(module, "apply"):
            reason = "missing OPERATOR_META or apply()"
            self.load_errors.append((modname, reason))
            if strict:
                raise ValueError(f"{modname}: {reason}")
            return 0

        meta = getattr(module, "OPERATOR_META")
        apply_fn = getattr(module, "apply")

        if not isinstance(meta, dict):
            reason = "OPERATOR_META is not dict"
            self.load_errors.append((modname, reason))
            if strict:
                raise ValueError(f"{modname}: {reason}")
            return 0

        if not callable(apply_fn):
            reason = "apply is not callable"
            self.load_errors.append((modname, reason))
            if strict:
                raise ValueError(f"{modname}: {reason}")
            return 0

        # Registry normalization이 module-level constant를 직접 변경하지 않도록 복사한다.
        normalized_meta = dict(meta)
        self._normalize_meta_inplace(normalized_meta)

        error = validate_meta(normalized_meta)
        if error:
            reason = f"meta invalid: {error}"
            self.load_errors.append((modname, reason))
            if strict:
                raise ValueError(f"{modname}: {reason}")
            return 0

        op_id = normalized_meta["op_id"]
        handle = OperatorHandle(
            op_id=op_id,
            meta=normalized_meta,
            apply=apply_fn,
            module=modname,
        )
        self.register(handle)
        return 1

    def _normalize_meta_inplace(self, meta: Dict[str, Any]) -> None:
        op_id = str(meta.get("op_id", ""))
        defaults = dict(self._META_DEFAULTS_BY_OP_ID.get(op_id, {}))
        policy_defaults = dict(self._POLICY_DEFAULTS_BY_OP_ID.get(op_id, {}))

        for source in (defaults, policy_defaults):
            for key, value in source.items():
                meta.setdefault(key, value)

        # 수동 검토 결과는 operator module의 기존 metadata보다 우선한다.
        review_policy = self._MANUAL_REVIEW_POLICY_BY_OP_ID.get(op_id)
        if review_policy:
            meta.update(review_policy)

        # 아직 명시적 mapping이 없는 신규 operator를 위한 fallback이다.
        meta.setdefault("operator_family", "unknown")
        meta.setdefault("attack_type_compat", ["generic"])
        meta.setdefault("output_format", "plain_text")
        meta.setdefault("semantic_preservation_risk", "MEDIUM")
        meta.setdefault("label_change_risk", "MEDIUM")
        meta.setdefault("input_format_compat", ["*"])
        meta.setdefault("operator_traits", [])
        meta.setdefault("applicability", {"requires_nonempty": True})
        meta.setdefault("diagnostic_eligibility", "conditional")
        meta.setdefault("requires_post_filter", True)
        meta.setdefault("use_in_diagnostic_v1", True)
        meta.setdefault("params_schema", {})
        meta.setdefault("target_evaluator_weakness", [])
        meta.setdefault("bucket_tags", [])  # legacy compatibility only

        risk_level = meta.get("risk_level")
        if isinstance(risk_level, str):
            meta["risk_level"] = risk_level.upper()

        for risk_key in ("semantic_preservation_risk", "label_change_risk"):
            risk_value = meta.get(risk_key)
            if isinstance(risk_value, str):
                meta[risk_key] = risk_value.upper()

        list_keys = (
            "bucket_tags",
            "surface_compat",
            "attack_type_compat",
            "input_format_compat",
            "operator_traits",
            "target_evaluator_weakness",
        )
        for key in list_keys:
            value = meta.get(key)
            if isinstance(value, (list, tuple, set)):
                meta[key] = sorted({str(item) for item in value})

    def register(self, handle: OperatorHandle) -> None:
        if handle.op_id in self._ops:
            raise ValueError(f"duplicate op_id: {handle.op_id}")
        self._ops[handle.op_id] = handle

    # ---------- query ----------
    def list_ops(self) -> List[OperatorHandle]:
        return [self._ops[key] for key in sorted(self._ops)]

    def get(self, op_id: str) -> Optional[OperatorHandle]:
        return self._ops.get(op_id)

    def filter(
        self,
        *,
        surface: Optional[str] = None,
        risk_max: Optional[str] = None,
        use_in_diagnostic_v1: Optional[bool] = True,
        operator_family: ValueOrValues = None,
        attack_type: ValueOrValues = None,
        output_format: ValueOrValues = None,
        input_format: ValueOrValues = None,
        op_ids: Optional[Iterable[str]] = None,
        blocked_operator_ids: Optional[Iterable[str]] = None,
        blocked_operator_traits: ValueOrValues = None,
        max_semantic_preservation_risk: Optional[str] = None,
        max_label_change_risk: Optional[str] = None,
        seed_text: Optional[str] = None,
        # Deprecated compatibility argument. Ignored by design.
        bucket_id: Optional[str] = None,
    ) -> List[OperatorHandle]:
        candidates, _ = self.filter_with_audit(
            surface=surface,
            risk_max=risk_max,
            use_in_diagnostic_v1=use_in_diagnostic_v1,
            operator_family=operator_family,
            attack_type=attack_type,
            output_format=output_format,
            input_format=input_format,
            op_ids=op_ids,
            blocked_operator_ids=blocked_operator_ids,
            blocked_operator_traits=blocked_operator_traits,
            max_semantic_preservation_risk=max_semantic_preservation_risk,
            max_label_change_risk=max_label_change_risk,
            seed_text=seed_text,
            bucket_id=bucket_id,
        )
        return candidates

    def filter_with_audit(
        self,
        *,
        surface: Optional[str] = None,
        risk_max: Optional[str] = None,
        use_in_diagnostic_v1: Optional[bool] = True,
        operator_family: ValueOrValues = None,
        attack_type: ValueOrValues = None,
        output_format: ValueOrValues = None,
        input_format: ValueOrValues = None,
        op_ids: Optional[Iterable[str]] = None,
        blocked_operator_ids: Optional[Iterable[str]] = None,
        blocked_operator_traits: ValueOrValues = None,
        max_semantic_preservation_risk: Optional[str] = None,
        max_label_change_risk: Optional[str] = None,
        seed_text: Optional[str] = None,
        # Deprecated compatibility argument. Ignored by design.
        bucket_id: Optional[str] = None,
    ) -> Tuple[List[OperatorHandle], List[CandidateDecision]]:
        del bucket_id

        family_set = self._as_set(operator_family)
        attack_set = self._as_set(attack_type)
        output_set = self._as_set(output_format)

        raw_input_formats = self._as_set(input_format)
        input_format_set = (
            {
                normalize_input_format(value)
                for value in raw_input_formats
            }
            if raw_input_formats is not None
            else None
        )

        op_id_set = (
            {str(value) for value in op_ids}
            if op_ids is not None
            else None
        )
        blocked_id_set = (
            {str(value) for value in blocked_operator_ids}
            if blocked_operator_ids is not None
            else set()
        )
        blocked_trait_set = self._as_set(blocked_operator_traits) or set()

        risk_cap = self._risk_rank(risk_max) if isinstance(risk_max, str) else 999
        semantic_cap = (
            self._risk_rank(max_semantic_preservation_risk)
            if isinstance(max_semantic_preservation_risk, str)
            else 999
        )
        label_cap = (
            self._risk_rank(max_label_change_risk)
            if isinstance(max_label_change_risk, str)
            else 999
        )

        accepted: List[OperatorHandle] = []
        decisions: List[CandidateDecision] = []

        for handle in self.list_ops():
            meta = handle.meta
            reasons: List[str] = []

            if op_id_set is not None and handle.op_id not in op_id_set:
                reasons.append("not_in_op_id_allowlist")

            if handle.op_id in blocked_id_set:
                reasons.append("blocked_operator_id")

            if use_in_diagnostic_v1 is not None:
                actual = bool(meta.get("use_in_diagnostic_v1", True))
                if actual != bool(use_in_diagnostic_v1):
                    reasons.append("diagnostic_flag_mismatch")

            if surface and surface not in meta.get("surface_compat", []):
                reasons.append(f"surface_mismatch:{surface}")

            family = str(meta.get("operator_family", ""))
            if family_set is not None and family not in family_set:
                reasons.append("operator_family_mismatch")

            output = str(meta.get("output_format", ""))
            if output_set is not None and output not in output_set:
                reasons.append("output_format_mismatch")

            if attack_set is not None:
                compat = {
                    str(value)
                    for value in meta.get("attack_type_compat", [])
                }
                if "generic" not in compat and not (attack_set & compat):
                    reasons.append("attack_type_mismatch")

            if risk_max and self._risk_rank(meta.get("risk_level", "HIGH")) > risk_cap:
                reasons.append("risk_level_exceeds_cap")

            if not self._format_matches(
                meta.get("input_format_compat"),
                input_format_set,
            ):
                reasons.append("input_format_mismatch")

            traits = {
                str(value)
                for value in meta.get("operator_traits", [])
            }
            blocked_hits = sorted(traits & blocked_trait_set)
            reasons.extend(
                f"blocked_operator_trait:{trait}"
                for trait in blocked_hits
            )

            if (
                max_semantic_preservation_risk
                and self._risk_rank(
                    meta.get("semantic_preservation_risk", "HIGH")
                )
                > semantic_cap
            ):
                reasons.append("semantic_preservation_risk_exceeds_cap")

            if (
                max_label_change_risk
                and self._risk_rank(meta.get("label_change_risk", "HIGH"))
                > label_cap
            ):
                reasons.append("label_change_risk_exceeds_cap")

            reasons.extend(self._applicability_reasons(meta, seed_text))

            accepted_candidate = not reasons
            decisions.append(
                CandidateDecision(
                    op_id=handle.op_id,
                    accepted=accepted_candidate,
                    reasons=tuple(reasons),
                )
            )

            if accepted_candidate:
                accepted.append(handle)

        accepted.sort(key=lambda item: item.op_id)
        decisions.sort(key=lambda item: item.op_id)
        return accepted, decisions

    # ---------- apply wrapper ----------
    def apply(
        self,
        op_id: str,
        seed_text: str,
        ctx: Dict[str, Any],
        rng: random.Random,
    ) -> ApplyResult:
        handle = self.get(op_id)
        if handle is None:
            return ApplyResult(
                status="INVALID",
                child_text=seed_text,
                trace={
                    "op_id": op_id,
                    "status": "INVALID",
                    "params": {},
                    "len_before": len(seed_text),
                    "len_after": len(seed_text),
                    "notes": "operator not found",
                },
                error="operator not found",
            )

        surface = ctx.get("surface")
        if surface and surface not in handle.meta.get("surface_compat", []):
            return ApplyResult(
                status="SKIPPED",
                child_text=seed_text,
                trace={
                    "op_id": handle.op_id,
                    "status": "SKIPPED",
                    "params": {
                        "reason": "surface_mismatch",
                        "surface": surface,
                    },
                    "len_before": len(seed_text),
                    "len_after": len(seed_text),
                },
            )

        try:
            result = handle.apply(seed_text, ctx, rng)
        except Exception as exc:
            return ApplyResult(
                status="INVALID",
                child_text=seed_text,
                trace={
                    "op_id": handle.op_id,
                    "status": "INVALID",
                    "params": {},
                    "len_before": len(seed_text),
                    "len_after": len(seed_text),
                    "notes": "exception",
                },
                error=str(exc),
            )

        result.trace = ensure_min_trace_fields(result.trace)
        result.trace["op_id"] = handle.op_id
        result.trace["status"] = result.status
        result.trace["len_before"] = len(seed_text)
        result.trace["len_after"] = len(result.child_text)

        params = result.trace.get("params")
        if isinstance(params, dict) and "applied" in params:
            params["applied"] = self._canon_applied(params.get("applied"))
            result.trace["params"] = params

        # Downstream 분석용 bucket-free metadata를 trace에 포함한다.
        params = result.trace.get("params")
        if isinstance(params, dict):
            params.setdefault("operator_family", handle.meta.get("operator_family"))
            params.setdefault("output_format", handle.meta.get("output_format"))
            params.setdefault(
                "attack_type_compat",
                handle.meta.get("attack_type_compat"),
            )
            params.setdefault(
                "input_format_compat",
                handle.meta.get("input_format_compat"),
            )
            params.setdefault("operator_traits", handle.meta.get("operator_traits"))
            result.trace["params"] = params

        return result
