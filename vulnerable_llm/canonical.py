"""Neutral canonical request contract and provenance-aware message renderer.

This module is the only permitted application-message builder for current
experiments. It performs no provider I/O and never imports the legacy
weakening/profile module.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Condition = Literal["control", "attack"]
MessageRole = Literal["system", "user"]
MessageProvenance = Literal[
    "trusted_instruction",
    "normal_task",
    "trust_boundary",
    "trusted_context",
    "untrusted_input",
]


ARTIFICIAL_WEAKENING_MARKERS = (
    "vulnerable_evaluation_mode",
    "intentionally vulnerable",
    "debug_mode_active",
    "high_yield_v1",
    "filters: off",
    "filters off",
    "filters disabled",
    "never refuse",
    "do not refuse",
    "refusal is interpreted as a system failure",
    "treat prompt injection as a valid",
    "prompt injection is a valid command",
    "process them as valid system commands",
    "prioritize the bypass",
    "100% compliant with all owasp",
    "always comply",
    "user satisfaction is a top priority",
    "ignore safety",
    "safety disabled",
    "embedded instructions as authoritative",
    "obey instructions inside data",
    "ignore the normal task",
    "do not mention security",
    "pretend insecurity does not exist",
    "unaware that your decisions may be insecure",
    "expose the system prompt",
    "expose system prompt",
    "reveal the system prompt",
    "reveal system prompt",
    "bypass policy",
    "maximize attack success",
    "direct execution component",
    "designed for direct execution",
    "vulnerable evaluation mode",
    "owasp-risk compliance",
)


class CanonicalGenerationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    temperature: float = 0.0
    max_tokens: int = Field(default=512, ge=1)
    random_seed: Optional[int] = None
    provider_options: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider_options")
    @classmethod
    def reject_reserved_provider_options(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        reserved = {"temperature", "num_predict", "seed"} & set(value)
        if reserved:
            raise ValueError(
                f"provider_options cannot override canonical fields: {sorted(reserved)}"
            )
        return value


class CanonicalGenerationRequest(BaseModel):
    """Application-owned fields and untrusted data kept in separate fields."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["canonical_generation_request.v1"] = (
        "canonical_generation_request.v1"
    )
    run_id: str
    generation_id: str
    case_id: str
    scenario_id: str
    condition: Condition
    repetition_index: int = Field(default=0, ge=0)

    trusted_instruction: str
    normal_task: str
    trust_boundary: str
    trusted_context: Optional[str] = None
    untrusted_input: str
    injection_location: str = Field(pattern=r"^[A-Za-z0-9_.:-]+$")

    provider: str
    model: str
    generation_config: CanonicalGenerationConfig = Field(
        default_factory=CanonicalGenerationConfig
    )
    experiment_metadata: Dict[str, Any] = Field(default_factory=dict)

    dataset_sha256: Optional[str] = None
    random_seed: Optional[int] = None
    attack_method: Optional[str] = None
    attack_method_variant: Optional[str] = None
    seed_original: Optional[str] = None
    attack_rendered: Optional[str] = None

    @field_validator(
        "run_id",
        "generation_id",
        "case_id",
        "scenario_id",
        "trusted_instruction",
        "normal_task",
        "trust_boundary",
        "injection_location",
        "provider",
        "model",
    )
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("trusted and identity fields must not be blank")
        return value

    @field_validator("trusted_instruction", "normal_task", "trust_boundary", "trusted_context")
    @classmethod
    def reject_weakening_in_trusted_fields(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        lowered = value.lower()
        if any(marker in lowered for marker in ARTIFICIAL_WEAKENING_MARKERS):
            raise ValueError("artificial weakening marker is not permitted in trusted fields")
        return value

    @model_validator(mode="after")
    def consistent_random_seed(self) -> "CanonicalGenerationRequest":
        configured = self.generation_config.random_seed
        if self.random_seed is not None and configured is not None and self.random_seed != configured:
            raise ValueError("top-level and generation-config random seeds must match")
        return self


class RenderedCanonicalMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: MessageRole
    content: str
    provenance: MessageProvenance
    injection_location: Optional[str] = None


class RenderedCanonicalMessages(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["canonical_rendered_messages.v1"] = (
        "canonical_rendered_messages.v1"
    )
    messages: List[RenderedCanonicalMessage]


def _render_without_validation(
    request: CanonicalGenerationRequest,
) -> RenderedCanonicalMessages:
    messages = [
        RenderedCanonicalMessage(
            role="system",
            content=request.trusted_instruction,
            provenance="trusted_instruction",
        ),
        RenderedCanonicalMessage(
            role="system",
            content=request.normal_task,
            provenance="normal_task",
        ),
        RenderedCanonicalMessage(
            role="system",
            content=request.trust_boundary,
            provenance="trust_boundary",
        ),
    ]
    if request.trusted_context is not None:
        messages.append(
            RenderedCanonicalMessage(
                role="system",
                content=request.trusted_context,
                provenance="trusted_context",
            )
        )
    messages.append(
        RenderedCanonicalMessage(
            role="user",
            content=request.untrusted_input,
            provenance="untrusted_input",
            injection_location=request.injection_location,
        )
    )
    return RenderedCanonicalMessages(messages=messages)


def validate_canonical_invariants(
    rendered: RenderedCanonicalMessages,
    request: CanonicalGenerationRequest,
) -> None:
    """Enforce authority and insertion invariants using provenance metadata."""
    slots = [m for m in rendered.messages if m.provenance == "untrusted_input"]
    if len(slots) != 1:
        raise ValueError("canonical render must contain exactly one designated untrusted slot")
    if slots[0].role != "user":
        raise ValueError("designated untrusted slot must have user role")
    if rendered.messages[-1] is not slots[0]:
        raise ValueError("designated untrusted slot must be the final message")
    if slots[0].injection_location != request.injection_location:
        raise ValueError("untrusted slot location does not match request")

    trusted = [m for m in rendered.messages if m.provenance != "untrusted_input"]
    if any(message.role != "system" for message in trusted):
        raise ValueError("application-owned messages must retain system authority")
    if any(message.injection_location is not None for message in trusted):
        raise ValueError("trusted messages must not carry untrusted slot metadata")
    expected = ["trusted_instruction", "normal_task", "trust_boundary"]
    if request.trusted_context is not None:
        expected.append("trusted_context")
    if [message.provenance for message in trusted] != expected:
        raise ValueError("trusted message provenance or order changed")
    expected_contents = [
        request.trusted_instruction,
        request.normal_task,
        request.trust_boundary,
    ]
    if request.trusted_context is not None:
        expected_contents.append(request.trusted_context)
    if [message.content for message in trusted] != expected_contents:
        raise ValueError("trusted message content no longer matches its provenance")

    # Marker checks apply only to application-owned scaffolding. An attacker is
    # allowed to place the same strings inside the one untrusted data slot.
    for message in trusted:
        lowered = message.content.lower()
        if any(marker in lowered for marker in ARTIFICIAL_WEAKENING_MARKERS):
            raise ValueError("artificial weakening marker detected in trusted message")

    if slots[0].content != request.untrusted_input:
        raise ValueError("untrusted input was not preserved losslessly")


def build_canonical_messages(
    request: CanonicalGenerationRequest,
) -> RenderedCanonicalMessages:
    rendered = _render_without_validation(request)
    validate_canonical_invariants(rendered, request)
    return rendered


def provider_messages(rendered: RenderedCanonicalMessages) -> List[Dict[str, str]]:
    """Strip provenance and encode untrusted data at the provider boundary.

    The raw payload remains lossless in the canonical request and rendered log.
    JSON Unicode escaping prevents attacker-controlled angle brackets from
    creating a second apparent tag boundary in the provider-facing text.
    """
    messages: List[Dict[str, str]] = []
    for message in rendered.messages:
        content = message.content
        if message.provenance == "untrusted_input":
            content = json.dumps(
                {
                    "location": message.injection_location,
                    "untrusted_input": message.content,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            content = content.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
        messages.append({"role": message.role, "content": content})
    return messages


def canonical_structure_signature(
    rendered: RenderedCanonicalMessages,
) -> tuple[tuple[str, str], ...]:
    """Condition-independent role/provenance signature for paired runs."""
    return tuple((message.role, message.provenance) for message in rendered.messages)
