from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .novelty_tracker import NoveltyTracker
from .registry import (
    CandidateDecision,
    OperatorHandle,
    OperatorRegistry,
)
from .selector_weights import (
    DEFAULT_QUOTA_POLICY,
    QuotaPolicy,
    weight_for,
)


@dataclass(frozen=True)
class RandomSelection:
    op_id: str
    handle: OperatorHandle
    reason: str = "random_choice"
    candidate_audit: tuple[CandidateDecision, ...] = ()
    quota_audit: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class SelectionResult:
    op_id: str
    handle: OperatorHandle
    weight: float
    reason: str = "weighted_choice"
    candidate_audit: tuple[CandidateDecision, ...] = ()
    quota_audit: tuple[dict[str, Any], ...] = ()


def _scope_stats(
    stats_by_scope: Optional[Dict[str, Any]],
    selection_scope: str,
) -> Dict[str, Any]:
    if not isinstance(stats_by_scope, dict):
        return {}

    value = stats_by_scope.get(
        selection_scope,
        {},
    )

    return value if isinstance(value, dict) else {}


def _counter_value(
    scope_stats: Dict[str, Any],
    counter_name: str,
    key: str,
) -> int:
    counter = scope_stats.get(
        counter_name,
        {},
    )

    if not isinstance(counter, dict):
        return 0

    try:
        return int(counter.get(key, 0))
    except (TypeError, ValueError):
        return 0


def _total_successful(
    scope_stats: Dict[str, Any],
) -> int:
    try:
        return int(
            scope_stats.get(
                "_successful_total",
                0,
            )
        )
    except (TypeError, ValueError):
        return 0


def _attack_total(
    scope_stats: Dict[str, Any],
    attack_type: str,
) -> int:
    return _counter_value(
        scope_stats,
        "_attack_counts",
        attack_type,
    )


def _nested_counter_value(
    scope_stats: Dict[str, Any],
    counter_name: str,
    outer_key: str,
    inner_key: str,
) -> int:
    outer = scope_stats.get(
        counter_name,
        {},
    )

    if not isinstance(outer, dict):
        return 0

    inner = outer.get(
        outer_key,
        {},
    )

    if not isinstance(inner, dict):
        return 0

    try:
        return int(
            inner.get(inner_key, 0)
        )
    except (TypeError, ValueError):
        return 0


def _consecutive_family_count(
    recent_families: Any,
    family: str,
) -> int:
    if not isinstance(recent_families, list):
        return 0

    count = 0

    for value in reversed(recent_families):
        if str(value) != family:
            break
        count += 1

    return count


def _quota_reasons(
    *,
    handle: OperatorHandle,
    scope_stats: Dict[str, Any],
    attack_type: str,
    policy: QuotaPolicy,
) -> List[str]:
    op_id = handle.op_id
    family = str(
        handle.meta.get(
            "operator_family",
            "unknown",
        )
    )

    reasons: List[str] = []

    recent_ops = scope_stats.get(
        "_recent_ops",
        [],
    )

    if (
        policy.forbid_immediate_operator_repeat
        and isinstance(recent_ops, list)
        and recent_ops
        and str(recent_ops[-1]) == op_id
    ):
        reasons.append(
            "quota_immediate_operator_repeat"
        )

    recent_families = scope_stats.get(
        "_recent_families",
        [],
    )

    if (
        _consecutive_family_count(
            recent_families,
            family,
        )
        >= policy.max_consecutive_family
    ):
        reasons.append(
            "quota_consecutive_family_limit"
        )

    total = _total_successful(
        scope_stats
    )

    if total >= policy.min_samples_before_enforcement:
        next_total = total + 1

        operator_count = _counter_value(
            scope_stats,
            "_operator_counts",
            op_id,
        )

        next_operator_share = (
            float(operator_count + 1)
            / float(next_total)
        )

        if (
            next_operator_share
            > policy.max_operator_share
        ):
            reasons.append(
                "quota_operator_share_exceeded"
            )

        family_count = _counter_value(
            scope_stats,
            "_family_counts",
            family,
        )

        next_family_share = (
            float(family_count + 1)
            / float(next_total)
        )

        if (
            next_family_share
            > policy.max_family_share
        ):
            reasons.append(
                "quota_family_share_exceeded"
            )

    if attack_type:
        attack_total = _attack_total(
            scope_stats,
            attack_type,
        )

        if (
            attack_total
            >= policy.min_samples_before_enforcement
        ):
            next_attack_total = (
                attack_total + 1
            )

            attack_operator_count = (
                _nested_counter_value(
                    scope_stats,
                    "_attack_operator_counts",
                    attack_type,
                    op_id,
                )
            )

            next_attack_operator_share = (
                float(
                    attack_operator_count + 1
                )
                / float(next_attack_total)
            )

            if (
                next_attack_operator_share
                > policy.max_attack_operator_share
            ):
                reasons.append(
                    "quota_attack_operator_share_exceeded"
                )

            attack_family_count = (
                _nested_counter_value(
                    scope_stats,
                    "_attack_family_counts",
                    attack_type,
                    family,
                )
            )

            next_attack_family_share = (
                float(
                    attack_family_count + 1
                )
                / float(next_attack_total)
            )

            if (
                next_attack_family_share
                > policy.max_attack_family_share
            ):
                reasons.append(
                    "quota_attack_family_share_exceeded"
                )

    return reasons


def _apply_quota_filter(
    *,
    candidates: List[OperatorHandle],
    stats_by_scope: Optional[Dict[str, Any]],
    selection_scope: str,
    attack_type: Optional[Any],
    policy: QuotaPolicy,
) -> Tuple[
    List[OperatorHandle],
    List[dict[str, Any]],
]:
    if not candidates:
        return [], []

    if (
        policy.single_candidate_bypass
        and len(candidates) == 1
    ):
        return candidates, [
            {
                "op_id": candidates[0].op_id,
                "accepted": True,
                "reasons": [
                    "single_candidate_quota_bypass"
                ],
            }
        ]

    scope_stats = _scope_stats(
        stats_by_scope,
        selection_scope,
    )

    attack_value = (
        str(attack_type)
        if attack_type is not None
        else ""
    )

    accepted: List[
        OperatorHandle
    ] = []

    audit: List[
        dict[str, Any]
    ] = []

    for handle in candidates:
        reasons = _quota_reasons(
            handle=handle,
            scope_stats=scope_stats,
            attack_type=attack_value,
            policy=policy,
        )

        accepted_flag = not reasons

        audit.append(
            {
                "op_id": handle.op_id,
                "accepted": accepted_flag,
                "reasons": reasons,
            }
        )

        if accepted_flag:
            accepted.append(handle)

    # Quota가 모든 후보를 막으면 hard failure 대신
    # 가장 덜 사용된 후보 집합으로 완화한다.
    if not accepted:
        operator_counts = scope_stats.get(
            "_operator_counts",
            {},
        )

        if not isinstance(
            operator_counts,
            dict,
        ):
            operator_counts = {}

        minimum_count = min(
            int(
                operator_counts.get(
                    handle.op_id,
                    0,
                )
            )
            for handle in candidates
        )

        accepted = [
            handle
            for handle in candidates
            if int(
                operator_counts.get(
                    handle.op_id,
                    0,
                )
            )
            == minimum_count
        ]

        accepted_ids = {
            handle.op_id
            for handle in accepted
        }

        for item in audit:
            if item["op_id"] in accepted_ids:
                item["accepted"] = True
                item["reasons"] = [
                    *item["reasons"],
                    "quota_least_used_fallback",
                ]

    return accepted, audit


class RandomSelector:
    def __init__(
        self,
        registry: OperatorRegistry,
        *,
        quota_policy: QuotaPolicy = (
            DEFAULT_QUOTA_POLICY
        ),
    ) -> None:
        self.registry = registry
        self.quota_policy = quota_policy

    def choose(
        self,
        *,
        surface: str,
        rng: random.Random,
        strength: int = 2,
        risk_max: Optional[str] = None,
        stats_by_scope: Optional[
            Dict[str, Any]
        ] = None,
        selection_scope: str = (
            "diagnostic_v1"
        ),
        operator_family: Optional[
            Any
        ] = None,
        attack_type: Optional[Any] = None,
        output_format: Optional[
            Any
        ] = None,
        input_format: Optional[
            Any
        ] = None,
        use_in_diagnostic_v1: Optional[
            bool
        ] = True,
        op_ids: Optional[
            Iterable[str]
        ] = None,
        blocked_operator_ids: Optional[
            Iterable[str]
        ] = None,
        blocked_operator_traits: Optional[
            Any
        ] = None,
        max_semantic_preservation_risk: Optional[
            str
        ] = None,
        max_label_change_risk: Optional[
            str
        ] = None,
        seed_text: Optional[str] = None,
        bucket_id: Optional[str] = None,
        stats_by_bucket: Optional[
            Dict[str, Any]
        ] = None,
    ) -> Optional[RandomSelection]:
        _ = (
            strength,
            bucket_id,
        )

        if (
            stats_by_scope is None
            and stats_by_bucket is not None
        ):
            stats_by_scope = stats_by_bucket

        candidates, audit = (
            self.registry.filter_with_audit(
                surface=surface,
                risk_max=risk_max,
                use_in_diagnostic_v1=(
                    use_in_diagnostic_v1
                ),
                operator_family=(
                    operator_family
                ),
                attack_type=attack_type,
                output_format=output_format,
                input_format=input_format,
                op_ids=op_ids,
                blocked_operator_ids=(
                    blocked_operator_ids
                ),
                blocked_operator_traits=(
                    blocked_operator_traits
                ),
                max_semantic_preservation_risk=(
                    max_semantic_preservation_risk
                ),
                max_label_change_risk=(
                    max_label_change_risk
                ),
                seed_text=seed_text,
            )
        )

        candidates, quota_audit = (
            _apply_quota_filter(
                candidates=candidates,
                stats_by_scope=(
                    stats_by_scope
                ),
                selection_scope=(
                    selection_scope
                ),
                attack_type=attack_type,
                policy=self.quota_policy,
            )
        )

        if not candidates:
            return None

        handle = candidates[
            rng.randrange(
                0,
                len(candidates),
            )
        ]

        return RandomSelection(
            op_id=handle.op_id,
            handle=handle,
            reason="random_choice",
            candidate_audit=tuple(audit),
            quota_audit=tuple(
                quota_audit
            ),
        )


class MetaWeightedSelector:
    def __init__(
        self,
        registry: OperatorRegistry,
        *,
        novelty: Optional[
            NoveltyTracker
        ] = None,
        seen_penalty: float = 0.2,
        quota_policy: QuotaPolicy = (
            DEFAULT_QUOTA_POLICY
        ),
    ) -> None:
        self.registry = registry
        self.novelty = (
            novelty
            or NoveltyTracker()
        )
        self.seen_penalty = float(
            seen_penalty
        )
        self.quota_policy = quota_policy

    def choose(
        self,
        *,
        surface: str,
        rng: random.Random,
        strength: int = 2,
        risk_max: Optional[str] = None,
        stats_by_scope: Optional[
            Dict[str, Any]
        ] = None,
        selection_scope: str = (
            "diagnostic_v1"
        ),
        operator_family: Optional[
            Any
        ] = None,
        attack_type: Optional[Any] = None,
        output_format: Optional[
            Any
        ] = None,
        input_format: Optional[
            Any
        ] = None,
        use_in_diagnostic_v1: Optional[
            bool
        ] = True,
        op_ids: Optional[
            Iterable[str]
        ] = None,
        blocked_operator_ids: Optional[
            Iterable[str]
        ] = None,
        blocked_operator_traits: Optional[
            Any
        ] = None,
        max_semantic_preservation_risk: Optional[
            str
        ] = None,
        max_label_change_risk: Optional[
            str
        ] = None,
        seed_text: Optional[str] = None,
        bucket_id: Optional[str] = None,
        stats_by_bucket: Optional[
            Dict[str, Any]
        ] = None,
    ) -> Optional[SelectionResult]:
        _ = (
            strength,
            bucket_id,
        )

        if (
            stats_by_scope is None
            and stats_by_bucket
            is not None
        ):
            stats_by_scope = (
                stats_by_bucket
            )

        candidates, audit = (
            self.registry.filter_with_audit(
                surface=surface,
                risk_max=risk_max,
                use_in_diagnostic_v1=(
                    use_in_diagnostic_v1
                ),
                operator_family=(
                    operator_family
                ),
                attack_type=attack_type,
                output_format=output_format,
                input_format=input_format,
                op_ids=op_ids,
                blocked_operator_ids=(
                    blocked_operator_ids
                ),
                blocked_operator_traits=(
                    blocked_operator_traits
                ),
                max_semantic_preservation_risk=(
                    max_semantic_preservation_risk
                ),
                max_label_change_risk=(
                    max_label_change_risk
                ),
                seed_text=seed_text,
            )
        )

        candidates, quota_audit = (
            _apply_quota_filter(
                candidates=candidates,
                stats_by_scope=(
                    stats_by_scope
                ),
                selection_scope=(
                    selection_scope
                ),
                attack_type=attack_type,
                policy=self.quota_policy,
            )
        )

        if not candidates:
            return None

        weights: List[float] = []

        scope_stats = _scope_stats(
            stats_by_scope,
            selection_scope,
        )

        operator_counts = (
            scope_stats.get(
                "_operator_counts",
                {},
            )
        )

        if not isinstance(
            operator_counts,
            dict,
        ):
            operator_counts = {}

        for handle in candidates:
            family = str(
                handle.meta.get(
                    "operator_family",
                    "unknown",
                )
            )

            weight = weight_for(
                selection_scope,
                handle.op_id,
                operator_family=family,
            )

            count = int(
                operator_counts.get(
                    handle.op_id,
                    0,
                )
            )

            # 이미 많이 사용된 operator에 점진적 감쇠 적용
            weight *= 1.0 / (
                1.0 + (0.35 * count)
            )

            weights.append(
                max(
                    0.0,
                    float(weight),
                )
            )

        total = sum(weights)

        if total <= 0.0:
            index = rng.randrange(
                0,
                len(candidates),
            )
            handle = candidates[index]

            return SelectionResult(
                op_id=handle.op_id,
                handle=handle,
                weight=1.0,
                reason="uniform_fallback",
                candidate_audit=tuple(
                    audit
                ),
                quota_audit=tuple(
                    quota_audit
                ),
            )

        draw = rng.random() * total
        accumulated = 0.0

        for handle, weight in zip(
            candidates,
            weights,
        ):
            accumulated += weight

            if draw <= accumulated:
                return SelectionResult(
                    op_id=handle.op_id,
                    handle=handle,
                    weight=weight,
                    reason="weighted_choice",
                    candidate_audit=tuple(
                        audit
                    ),
                    quota_audit=tuple(
                        quota_audit
                    ),
                )

        handle = candidates[-1]

        return SelectionResult(
            op_id=handle.op_id,
            handle=handle,
            weight=weights[-1],
            reason="rounding_fallback",
            candidate_audit=tuple(
                audit
            ),
            quota_audit=tuple(
                quota_audit
            ),
        )