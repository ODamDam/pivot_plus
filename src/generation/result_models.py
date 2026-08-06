from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class GenerationRunRecord:
    schema_version: str

    experiment_id: str
    run_id: str
    generation_id: str

    dataset_id: str
    dataset_subset: str
    input_view: str

    generation_profile: str

    prompt_text: str
    context_text: str
    context_type: str

    source_messages: list[dict[str, str]]

    attack_type: str | None
    is_malicious: bool

    execution_status: str
    response_text: str

    request_id: str | None
    server_generation_id: str | None

    metadata: dict[str, Any] = field(default_factory=dict)
    server_meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
            "generation_id": self.generation_id,
            "dataset_id": self.dataset_id,
            "dataset_subset": self.dataset_subset,
            "input_view": self.input_view,
            "generation_profile": self.generation_profile,
            "prompt_text": self.prompt_text,
            "context_text": self.context_text,
            "context_type": self.context_type,
            "source_messages": self.source_messages,
            "attack_type": self.attack_type,
            "is_malicious": self.is_malicious,
            "execution_status": self.execution_status,
            "response_text": self.response_text,
            "request_id": self.request_id,
            "server_generation_id": self.server_generation_id,
            "metadata": self.metadata,
            "server_meta": self.server_meta,
        }


@dataclass(frozen=True)
class GenerationFailureRecord:
    schema_version: str

    experiment_id: str
    run_id: str
    generation_id: str

    dataset_id: str
    dataset_subset: str
    input_view: str
    generation_profile: str

    error_type: str
    error_message: str

    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
            "generation_id": self.generation_id,
            "dataset_id": self.dataset_id,
            "dataset_subset": self.dataset_subset,
            "input_view": self.input_view,
            "generation_profile": self.generation_profile,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }