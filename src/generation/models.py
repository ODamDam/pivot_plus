from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


MessageRole = Literal["system", "user", "assistant"]
InputView = Literal["prompt_only", "context_prompt"]


@dataclass(frozen=True)
class ChatMessage:
    role: MessageRole
    content: str

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "content": self.content,
        }


@dataclass(frozen=True)
class GenerationInput:
    dataset_id: str
    dataset_subset: str
    input_view: InputView

    prompt_text: str
    context_text: str
    context_type: str

    messages: list[ChatMessage]

    attack_type: str | None
    is_malicious: bool

    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "dataset_subset": self.dataset_subset,
            "input_view": self.input_view,
            "prompt_text": self.prompt_text,
            "context_text": self.context_text,
            "context_type": self.context_type,
            "messages": [
                message.to_dict()
                for message in self.messages
            ],
            "attack_type": self.attack_type,
            "is_malicious": self.is_malicious,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ExcludedGenerationInput:
    dataset_id: str
    dataset_subset: str
    input_view: InputView
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "dataset_id": self.dataset_id,
            "dataset_subset": self.dataset_subset,
            "input_view": self.input_view,
            "reason": self.reason,
        }