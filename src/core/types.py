from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, TypedDict

Status = Literal["OK", "SKIPPED", "INVALID"]
RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class ApplicabilitySpec(TypedDict, total=False):
    """Optional registry-level applicability precheck metadata.

    Operators may still perform their own detailed checks in ``apply``.  These
    fields allow the registry to reject obvious non-applicable candidates before
    selection, reducing avoidable SKIPPED results.
    """

    requires_nonempty: bool
    min_chars: int
    max_chars: int
    min_lines: int
    requires_json_object: bool
    requires_any_terms: List[str]
    forbids_any_terms: List[str]


class OperatorMeta(TypedDict, total=False):
    """Bucket-free operator metadata schema.

    Required after registry normalization:
      - op_id
      - operator_family
      - surface_compat
      - risk_level
      - strength_range

    Policy v1.1 fields:
      - input_format_compat
      - operator_traits
      - applicability
      - semantic_preservation_risk
      - label_change_risk

    ``bucket_tags`` remains legacy compatibility metadata and must not be used
    as the primary selection criterion.
    """

    op_id: str

    # Bucket-free diagnostic fields
    operator_family: str
    attack_type_compat: List[str]
    surface_compat: List[str]
    input_format_compat: List[str]
    output_format: str
    operator_traits: List[str]
    applicability: ApplicabilitySpec
    risk_level: RiskLevel
    strength_range: List[int]  # [min, max]
    semantic_preservation_risk: RiskLevel
    label_change_risk: RiskLevel
    use_in_diagnostic_v1: bool

    # Optional metadata
    params_schema: Dict[str, Any]
    notes: str
    target_evaluator_weakness: List[str]

    # Legacy compatibility only
    bucket_tags: List[str]


@dataclass
class ApplyResult:
    status: Status
    child_text: str
    trace: Dict[str, Any]
    error: Optional[str] = None


REQUIRED_META_KEYS = (
    "op_id",
    "operator_family",
    "surface_compat",
    "risk_level",
    "strength_range",
)

VALID_RISK_LEVELS = ("LOW", "MEDIUM", "HIGH")


def _is_list_of_str(x: Any) -> bool:
    return isinstance(x, list) and all(isinstance(v, str) for v in x)


def validate_meta(meta: Dict[str, Any]) -> Optional[str]:
    """Return an error string when invalid; otherwise return ``None``."""

    for key in REQUIRED_META_KEYS:
        if key not in meta:
            return f"missing meta key: {key}"

    if not isinstance(meta["op_id"], str) or not meta["op_id"]:
        return "op_id must be non-empty string"

    if not isinstance(meta["operator_family"], str) or not meta["operator_family"]:
        return "operator_family must be non-empty string"

    for list_key in (
        "surface_compat",
        "attack_type_compat",
        "input_format_compat",
        "operator_traits",
        "target_evaluator_weakness",
        "bucket_tags",
    ):
        if list_key in meta and not _is_list_of_str(meta[list_key]):
            return f"{list_key} must be list[str] when provided"

    if meta["risk_level"] not in VALID_RISK_LEVELS:
        return "risk_level must be one of LOW|MEDIUM|HIGH"

    for optional_risk in ("semantic_preservation_risk", "label_change_risk"):
        if optional_risk in meta and meta[optional_risk] not in VALID_RISK_LEVELS:
            return f"{optional_risk} must be one of LOW|MEDIUM|HIGH"

    strength_range = meta["strength_range"]
    if (
        not isinstance(strength_range, list)
        or len(strength_range) != 2
        or not all(isinstance(x, int) for x in strength_range)
        or strength_range[0] > strength_range[1]
    ):
        return "strength_range must be [min:int, max:int] with min<=max"

    if "use_in_diagnostic_v1" in meta and not isinstance(meta["use_in_diagnostic_v1"], bool):
        return "use_in_diagnostic_v1 must be bool"

    if "params_schema" in meta and not isinstance(meta["params_schema"], dict):
        return "params_schema must be dict when provided"

    applicability = meta.get("applicability")
    if applicability is not None:
        if not isinstance(applicability, dict):
            return "applicability must be dict when provided"

        for int_key in ("min_chars", "max_chars", "min_lines"):
            if int_key in applicability:
                value = applicability[int_key]
                if not isinstance(value, int) or value < 0:
                    return f"applicability.{int_key} must be non-negative int"

        for bool_key in ("requires_nonempty", "requires_json_object"):
            if bool_key in applicability and not isinstance(applicability[bool_key], bool):
                return f"applicability.{bool_key} must be bool"

        for list_key in ("requires_any_terms", "forbids_any_terms"):
            if list_key in applicability and not _is_list_of_str(applicability[list_key]):
                return f"applicability.{list_key} must be list[str]"

    return None
