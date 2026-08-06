from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class InputDisposition(str, Enum):
    CLEAR_MALICIOUS = "clear_malicious"
    CONTEXT_DEPENDENT = "context_dependent"
    AMBIGUOUS_REVIEW = "ambiguous_review"
    BENIGN = "benign"
    STRUCTURE_INTACT = "structure_intact"


class BehaviorClass(str, Enum):
    REFUSAL = "refusal"
    SAFE_COMPLETION = "safe_completion"
    PARTIAL_COMPLIANCE = "partial_compliance"
    INSTRUCTION_FOLLOWING = "instruction_following"
    SECURITY_BOUNDARY_VIOLATION = "security_boundary_violation"
    MALFORMED_OR_IRRELEVANT = "malformed_or_irrelevant"


class EvaluatorVerdict(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ABSTAIN = "abstain"
    ERROR = "error"


@dataclass(frozen=True)
class InputRecord:
    sample_id: str
    input_disposition: InputDisposition
    prompt: str
    context_present: bool
    context: str | None
    expected_behavior: str | None
    raw_input: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "InputRecord":
        raw = dict(value)
        sample_id = value.get("sample_id")
        prompt = value.get("prompt")
        if not isinstance(sample_id, str) or not sample_id.strip():
            raise ValueError("sample_id must be a non-empty string")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(f"prompt must be a non-empty string: {sample_id}")
        context_present = "context" in value
        context = value.get("context")
        if context_present and context is not None and not isinstance(context, str):
            raise ValueError(f"context must be string or null: {sample_id}")
        try:
            disposition = InputDisposition(str(value["input_disposition"]))
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid input_disposition: {sample_id}") from exc
        expected = value.get("expected_behavior")
        if expected is not None and not isinstance(expected, str):
            raise ValueError(f"expected_behavior must be string or null: {sample_id}")
        return cls(sample_id, disposition, prompt, context_present, context, expected, raw)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "input_disposition": self.input_disposition.value,
            "raw_input": dict(self.raw_input),
        }


def validate_input_records(records: list[InputRecord]) -> None:
    seen: set[str] = set()
    for record in records:
        if record.sample_id in seen:
            raise ValueError(f"duplicate sample_id: {record.sample_id}")
        seen.add(record.sample_id)


@dataclass(frozen=True)
class RawResponse:
    text: str
    provider_payload: dict[str, Any]
    finish_reason: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {"text": self.text, "provider_payload": self.provider_payload, "finish_reason": self.finish_reason}


@dataclass(frozen=True)
class ParsedResponse:
    text: str
    behavior: BehaviorClass
    parser_reasons: list[str]

    def to_mapping(self) -> dict[str, Any]:
        return {"text": self.text, "behavior": self.behavior.value, "parser_reasons": list(self.parser_reasons)}


@dataclass(frozen=True)
class EvaluationDecision:
    verdict: EvaluatorVerdict
    reason_codes: list[str]
    evaluator_name: str = "unspecified"

    def to_mapping(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "reason_codes": list(self.reason_codes), "evaluator_name": self.evaluator_name}


@dataclass(frozen=True)
class CaseResult:
    sample_id: str
    raw_input: dict[str, Any]
    constructed_request: dict[str, Any]
    raw_response: RawResponse
    parsed_response: ParsedResponse
    decision: EvaluationDecision

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": "vuln_llm_case.v1",
            "sample_id": self.sample_id,
            "raw_input": self.raw_input,
            "constructed_request": self.constructed_request,
            "raw_response": self.raw_response.to_mapping(),
            "parsed_response": self.parsed_response.to_mapping(),
            "decision": self.decision.to_mapping(),
        }
