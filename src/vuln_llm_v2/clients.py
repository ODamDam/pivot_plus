from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

from .schemas import RawResponse


class ModelError(RuntimeError):
    pass


class RetryableModelError(ModelError):
    pass


class TimeoutModelError(RetryableModelError):
    pass


class NonRetryableModelError(ModelError):
    pass


class ModelClient(Protocol):
    name: str

    def generate(self, request: dict[str, Any]) -> RawResponse: ...


@dataclass(frozen=True)
class AdapterSpec:
    """Configuration contract for a future real adapter; never reads credentials."""

    name: str
    credential_env_var: str
    parameters: dict[str, Any]

    def sanitized_mapping(self) -> dict[str, Any]:
        return {"name": self.name, "credential_env_var": self.credential_env_var, "parameters": dict(self.parameters)}


class DeterministicMockClient:
    name = "deterministic-mock-v1"

    def __init__(self, *, seed: int, response_mode: str = "normal"):
        self.seed = seed
        self.response_mode = response_mode

    def generate(self, request: dict[str, Any]) -> RawResponse:
        if self.response_mode == "timeout":
            raise TimeoutModelError("mock timeout")
        if self.response_mode == "retryable_error":
            raise RetryableModelError("mock retryable error")
        if self.response_mode == "terminal_error":
            raise NonRetryableModelError("mock terminal error")
        if self.response_mode == "empty":
            return RawResponse("", {"mock": True, "mode": "empty"})
        if self.response_mode == "malformed":
            return RawResponse("\x00\x00", {"mock": True, "mode": "malformed"})
        digest = hashlib.sha256(f"{self.seed}:{request['sample_id']}".encode("utf-8")).hexdigest()[:12]
        text = f"SAFE_COMPLETION: boundary preserved [{digest}]"
        return RawResponse(text, {"mock": True, "seed": self.seed, "digest": digest}, "stop")
