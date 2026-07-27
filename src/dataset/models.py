from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DatasetRecord:
    dataset_id: str
    dataset_subset: str

    prompt_text: str
    context_text: str
    context_available: bool
    context_type: str
    context_dependency: str

    attack_type: str | None
    is_malicious: bool

    standalone_prompt_label: str | None
    contextual_prompt_label: str | None
    final_review_decision: str | None

    raw: dict[str, Any]