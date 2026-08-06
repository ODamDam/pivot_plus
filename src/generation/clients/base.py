from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from src.generation.models import GenerationInput


@dataclass(frozen=True)
class ClientGenerationResult:
    execution_status: str
    response_text: str

    request_id: str | None = None
    generation_id: str | None = None

    meta: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)


class GenerationClientError(RuntimeError):
    """Base exception raised by a generation client."""


class GenerationHTTPError(GenerationClientError):
    def __init__(
        self,
        *,
        status_code: int,
        message: str,
        response_body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class GenerationResponseError(GenerationClientError):
    """Raised when the generation server returns an invalid response."""


class GenerationClient(ABC):
    @abstractmethod
    def generate(
        self,
        generation_input: GenerationInput,
        *,
        experiment_id: str,
        generation_profile: str,
        generation_id: str,
        run_id: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> ClientGenerationResult:
        raise NotImplementedError