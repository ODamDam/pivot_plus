"""Typing-only adapter contract. This module implements no integrations."""
from __future__ import annotations

from typing import Protocol

from .contract import ScannerReplayCase
from .results import ScannerNormalizedResult, ScannerRawEvaluatorResult


class ScannerAdapter(Protocol):
    """One evaluation ID per evaluator/case/attempt; no implicit aggregation.

    prepare_input returns strict JSON containing the actual evaluator input.
    execute must bind its hash and the explicit run_context to the raw result,
    preserving native JSON output. Credentials never belong in run_context.
    Implementations must persist exact input/output and policy in the run directory.
    """

    def prepare_input(self, replay_case: ScannerReplayCase, *, observation_surface: str) -> dict:
        ...

    def execute(self, prepared_input: dict, *, replay_case: ScannerReplayCase, run_context: dict) -> ScannerRawEvaluatorResult:
        ...

    def normalize(self, raw_result: ScannerRawEvaluatorResult, mapping_policy: dict) -> ScannerNormalizedResult:
        ...
