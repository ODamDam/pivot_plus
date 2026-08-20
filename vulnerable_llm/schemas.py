from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator


JsonContext = Union[str, Dict[str, Any], List[Any]]
MessageRole = Literal["system", "user", "assistant"]
GenerationProfile = Literal["high_yield_v1"]


class GenerateParams(BaseModel):
    """Target LLM generation parameters supplied by the caller."""

    temperature: Optional[float] = Field(
        default=None,
        description=(
            "Requested temperature. "
            "The server may override it for reproducibility."
        ),
    )
    max_tokens: Optional[int] = Field(
        default=None,
        description=(
            "Requested maximum output tokens. "
            "The server applies its configured cap."
        ),
    )

    model_config = {
        "extra": "forbid",
    }


class GenerateRequest(BaseModel):
    """Legacy request contract for prompt/context-based generation."""

    prompt: str = Field(
        ...,
        description="Prompt sent to the vulnerable target application",
    )

    # Stable experiment lineage.
    case_id: Optional[str] = Field(default=None)
    generation_id: Optional[str] = Field(default=None)
    testcase_id: Optional[str] = Field(default=None)
    seed_id: Optional[str] = Field(default=None)
    mutation_id: Optional[str] = Field(default=None)
    run_id: Optional[str] = Field(default=None)

    # Benchmark and objective metadata.
    benchmark_category: Optional[str] = Field(default=None)
    delivery_channel: Optional[str] = Field(default=None)
    attack_type: Optional[str] = Field(default=None)
    primary_objective_id: Optional[str] = Field(default=None)
    objective_text: Optional[str] = Field(default=None)
    triggers: List[str] = Field(default_factory=list)

    # Optional external context and lossless source metadata.
    context: Optional[JsonContext] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    params: GenerateParams = Field(default_factory=GenerateParams)

    model_config = {
        "extra": "forbid",
    }


class GenerateResponse(BaseModel):
    schema_version: str = "generate_response.v0.2"
    request_id: str
    case_id: str
    generation_id: str
    execution_status: str = "completed"
    response: str
    meta: Dict[str, Any]


class ChatMessageRequest(BaseModel):
    """Single chat message passed to the vulnerable target model."""

    role: MessageRole
    content: str = Field(
        ...,
        min_length=1,
        description="Non-empty chat message content",
    )

    model_config = {
        "extra": "forbid",
    }

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        stripped = value.strip()

        if not stripped:
            raise ValueError("message content must not be blank")

        return value


class ChatGenerateRequest(BaseModel):
    """
    Research generation request based on explicit chat messages.

    source messages are supplied by the dataset MessageBuilder.
    The server may apply a declared vulnerability profile before
    forwarding final messages to Ollama.
    """

    messages: List[ChatMessageRequest] = Field(
        ...,
        min_length=1,
        description="Original messages constructed from the dataset",
    )

    generation_profile: GenerationProfile = Field(
        default="high_yield_v1",
    )

    # Stable research lineage.
    dataset_id: str = Field(
        ...,
        min_length=1,
    )
    experiment_id: str = Field(
        ...,
        min_length=1,
    )
    generation_id: Optional[str] = Field(default=None)
    run_id: Optional[str] = Field(default=None)

    input_view: Literal["prompt_only", "context_prompt"] = Field(...)

    dataset_subset: Optional[str] = Field(default=None)
    attack_type: Optional[str] = Field(default=None)
    is_malicious: Optional[bool] = Field(default=None)

    metadata: Dict[str, Any] = Field(default_factory=dict)
    params: GenerateParams = Field(default_factory=GenerateParams)

    model_config = {
        "extra": "forbid",
    }

    @field_validator("dataset_id", "experiment_id")
    @classmethod
    def validate_required_identifier(cls, value: str) -> str:
        stripped = value.strip()

        if not stripped:
            raise ValueError("identifier must not be blank")

        return stripped


class ChatGenerateResponse(BaseModel):
    schema_version: str = "chat_generate_response.v1"
    request_id: str
    dataset_id: str
    experiment_id: str
    generation_id: str
    execution_status: str = "completed"
    generation_profile: GenerationProfile
    response: str
    meta: Dict[str, Any]


class CanonicalGenerateResponse(BaseModel):
    schema_version: str = "canonical_generate_response.v1"
    request_id: str
    run_id: str
    generation_id: str
    case_id: str
    scenario_id: str
    condition: Literal["control", "attack"]
    repetition_index: int
    execution_status: str = "completed"
    provider: str
    model: str
    response: str
    meta: Dict[str, Any]
