from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnerable_llm.canonical import CanonicalGenerationConfig


class DiagnosticExecutionSafety(BaseModel):
    model_config = ConfigDict(extra="allow")

    safe_to_execute: bool
    uses_synthetic_assets: bool
    external_side_effects_enabled: bool

    @model_validator(mode="after")
    def require_safe_local_execution(self) -> "DiagnosticExecutionSafety":
        if not self.safe_to_execute:
            raise ValueError("diagnostic input must be marked safe_to_execute")
        if self.external_side_effects_enabled:
            raise ValueError("external side effects must be disabled")
        return self


class DiagnosticInputRecord(BaseModel):
    """Execution input independent from Dataset A and its GT schema."""

    model_config = ConfigDict(extra="forbid")

    diagnostic_schema_version: Literal["target_llm_diagnostic_input.v1"]
    diagnostic_case_id: str
    source_candidate_id: str
    source_record_id: str | None = None
    source_file: str
    source_provenance: dict[str, Any]
    diagnostic_only: Literal[True]
    pair_id: str
    scenario_id: str
    attack_family: list[str] = Field(min_length=1)
    condition_input_information: dict[str, Any]
    normal_task: str
    trusted_instruction: str
    trust_boundary: str
    trusted_context: str | None = None
    injection_location: str
    control_input: str
    attack_input: str
    attacker_goal: dict[str, Any]
    objective_success_criterion: str
    transformation_notes: str
    repetitions: int = Field(ge=1)
    provider: str
    model: str
    generation_config: CanonicalGenerationConfig
    execution_safety: DiagnosticExecutionSafety

    @field_validator(
        "diagnostic_case_id", "source_candidate_id", "source_file", "pair_id",
        "scenario_id", "normal_task", "trusted_instruction", "trust_boundary",
        "injection_location", "control_input", "attack_input",
        "objective_success_criterion", "transformation_notes", "provider", "model",
    )
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("diagnostic string fields must not be blank")
        return value


class BehavioralEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    normal_task_completed: bool | None = None
    attacker_goal_achieved: bool | None = None
    boundary_violated: bool | None = None
    refusal: bool | None = None
    execution_failure: bool | None = None
    human_review_required: bool = True
    evidence: list[str] = Field(default_factory=list)


class DiagnosticResultRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_schema_version: Literal["target_llm_diagnostic_result.v1"] = (
        "target_llm_diagnostic_result.v1"
    )
    generation_key: str
    diagnostic_case_id: str
    source_candidate_id: str
    source_record_id: str | None
    source_file: str
    source_provenance: dict[str, Any]
    pair_id: str
    condition: Literal["control", "attack"]
    repetition_index: int
    generation_id: str
    execution_status: str
    endpoint_response: dict[str, Any]
    request_id: str | None
    server_generation_id: str | None
    response_text: str
    response_sha256: str
    model_metadata: dict[str, Any]
    behavioral_evaluation: BehavioralEvaluation = Field(
        default_factory=BehavioralEvaluation
    )


class DiagnosticFailureRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    failure_schema_version: Literal["target_llm_diagnostic_failure.v1"] = (
        "target_llm_diagnostic_failure.v1"
    )
    generation_key: str
    diagnostic_case_id: str
    source_candidate_id: str
    pair_id: str
    condition: Literal["control", "attack"]
    repetition_index: int
    generation_id: str
    execution_status: Literal["execution_failure"] = "execution_failure"
    error_type: str
    error_message: str
    http_status: int | None = None
    retryable: bool
    attempts: int
    endpoint_response_body: str | None = None
    behavioral_evaluation: BehavioralEvaluation = Field(
        default_factory=lambda: BehavioralEvaluation(
            execution_failure=True,
            human_review_required=False,
            evidence=["provider_execution_failed"],
        )
    )
