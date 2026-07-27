from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


JsonContext = Union[str, Dict[str, Any], List[Any]]


class GenerateParams(BaseModel):
    """Target LLM generation parameters supplied by the caller."""

    temperature: Optional[float] = Field(
        default=None,
        description="Requested temperature. The server may override it for reproducibility.",
    )
    max_tokens: Optional[int] = Field(
        default=None,
        description="Requested maximum output tokens. The server applies its configured cap.",
    )

    class Config:
        extra = "forbid"


class GenerateRequest(BaseModel):
    """Request contract for a single generated prompt-response evaluation case."""

    prompt: str = Field(..., description="Prompt sent to the vulnerable target application")

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

    class Config:
        # Unknown top-level fields previously disappeared silently. Reject them so
        # schema mismatches are visible before a large benchmark run.
        extra = "forbid"


class GenerateResponse(BaseModel):
    schema_version: str = "generate_response.v0.2"
    request_id: str
    case_id: str
    generation_id: str
    execution_status: str = "completed"
    response: str
    meta: Dict[str, Any]
