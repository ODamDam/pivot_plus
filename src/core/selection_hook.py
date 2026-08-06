from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from .registry import OperatorHandle


@dataclass(frozen=True)
class SelectionDecision:
    op_id: str
    params: Dict[str, Any]


class SelectionHook(Protocol):
    """
    Bucket-free selection hook.

    Required input:
      - selection_scope
      - surface
      - stats_by_scope

    Output:
      - op_id + params
    """

    def choose(
        self,
        *,
        selection_scope: str,
        surface: str,
        stats_by_scope: Dict[str, Any],
        candidates: List[OperatorHandle],
        rng: random.Random,
        strength: int,
        risk_max: Optional[str],
        operator_family: Optional[Any] = None,
        attack_type: Optional[Any] = None,
    ) -> Optional[SelectionDecision]:
        ...


class DefaultWeightedHook:
    def choose(
        self,
        *,
        selection_scope: str,
        surface: str,
        stats_by_scope: Dict[str, Any],
        candidates: List[OperatorHandle],
        rng: random.Random,
        strength: int,
        risk_max: Optional[str],
        operator_family: Optional[Any] = None,
        attack_type: Optional[Any] = None,
    ) -> Optional[SelectionDecision]:
        _ = (selection_scope, surface, stats_by_scope, risk_max, operator_family, attack_type)
        if not candidates:
            return None

        h = rng.choice(candidates)
        return SelectionDecision(op_id=h.op_id, params={"strength": strength})
