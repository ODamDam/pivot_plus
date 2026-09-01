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

# ---------------------------------------------------------------------------
# Neutral direct generation contract for non-PI supplemental production data.
# This path must not apply any legacy vulnerability profile or canonical
# untrusted-input rendering.
# ---------------------------------------------------------------------------

NEUTRAL_DIRECT_SYSTEM_PROMPT = (
    "You are a general-purpose assistant. Respond to the user's request."
)


class DirectGenerationConfig(BaseModel):
    temperature: float = 0.0
    max_tokens: int = Field(default=512, ge=1)
    random_seed: Optional[int] = None
    provider_options: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "extra": "forbid",
    }

    @field_validator("provider_options")
    @classmethod
    def reject_reserved_provider_options(
        cls, value: Dict[str, Any]
    ) -> Dict[str, Any]:
        reserved = {"temperature", "num_predict", "seed"} & set(value)
        if reserved:
            raise ValueError(
                f"provider_options cannot override direct fields: {sorted(reserved)}"
            )
        return value


class DirectMessageRequest(BaseModel):
    role: Literal["system", "user"]
    content: str = Field(..., min_length=1)

    model_config = {
        "extra": "forbid",
    }


class DirectGenerateRequest(BaseModel):
    schema_version: Literal["direct_generation_request.v1"] = (
        "direct_generation_request.v1"
    )

    run_id: str
    generation_id: str
    case_id: str
    repetition_index: int = Field(default=0, ge=0)

    provider: str
    model: str

    messages: List[DirectMessageRequest]
    generation_config: DirectGenerationConfig = Field(
        default_factory=DirectGenerationConfig
    )

    dataset_sha256: Optional[str] = None

    model_config = {
        "extra": "forbid",
    }

    @field_validator("run_id", "generation_id", "case_id", "provider", "model")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identity fields must not be blank")
        return value

    @field_validator("messages")
    @classmethod
    def validate_neutral_direct_messages(
        cls, value: List[DirectMessageRequest]
    ) -> List[DirectMessageRequest]:
        if len(value) != 2:
            raise ValueError(
                "neutral direct generation requires exactly two messages"
            )

        system_message, user_message = value

        if system_message.role != "system":
            raise ValueError("first direct message must have role=system")

        if user_message.role != "user":
            raise ValueError("second direct message must have role=user")

        if system_message.content != NEUTRAL_DIRECT_SYSTEM_PROMPT:
            raise ValueError(
                "direct system prompt must match the frozen neutral system prompt"
            )

        return value


class DirectGenerateResponse(BaseModel):
    schema_version: str = "direct_generate_response.v1"

    request_id: str
    run_id: str
    generation_id: str
    case_id: str
    repetition_index: int

    execution_status: str = "completed"
    provider: str
    model: str
    response: str
    meta: Dict[str, Any]
