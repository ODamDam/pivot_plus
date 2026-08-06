# src/core/mutator.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .rng import derive_rng
from .selector import RandomSelector
from .validity_guard import GuardConfig, guard_text_with_meta


@dataclass
class MutationOutput:
    child_text: str
    mutation_trace: List[Dict[str, Any]]
    last_status: str


class Mutator:
    """Bucket-free mutation engine with policy-aware retry and quota stats."""

    def __init__(self, registry: Any, selector: Optional[Any] = None) -> None:
        self.registry = registry
        self.selector = selector or RandomSelector(registry)

    def _make_guard_cfg(self, constraints: Dict[str, Any]) -> GuardConfig:
        return GuardConfig(
            max_len=int(constraints.get("max_chars", 8000)),
            schema_mode=bool(constraints.get("schema_mode", False)),
            placeholder=str(constraints.get("placeholder", "N/A")),
        )

    def _resolve_handler_from_selection(self, selection: Any) -> Optional[Any]:
        handle = getattr(selection, "handler", None) or getattr(selection, "handle", None)
        if handle is not None:
            return handle

        op_id = (
            getattr(selection, "op_id", None)
            or getattr(selection, "selected_op_id", None)
            or getattr(selection, "chosen_op_id", None)
        )
        if not op_id:
            return None

        get_fn = getattr(self.registry, "get", None)
        if callable(get_fn):
            try:
                return get_fn(op_id)
            except Exception:
                pass

        list_ops = getattr(self.registry, "list_ops", None)
        if callable(list_ops):
            try:
                for candidate in list_ops():
                    if getattr(candidate, "op_id", None) == op_id:
                        return candidate
            except Exception:
                pass

        return None

    def _normalize_apply_result(
        self,
        result: Any,
        fallback_text: str,
    ) -> Tuple[str, str, Dict[str, Any]]:
        status = "INVALID"
        child_text = fallback_text
        params: Dict[str, Any] = {}

        if isinstance(result, dict):
            status = str(result.get("status", "INVALID")).upper()
            child_text = result.get("child_text", fallback_text)
            raw_params = result.get("params", result.get("trace", {}))
            params = dict(raw_params) if isinstance(raw_params, dict) else {"params": raw_params}
        else:
            raw_status = getattr(result, "status", None)
            raw_child = getattr(result, "child_text", None)
            raw_trace = getattr(result, "trace", None)
            raw_params = getattr(result, "params", None)

            if raw_status is not None:
                status = str(raw_status).upper()
            if raw_child is not None:
                child_text = raw_child

            if isinstance(raw_trace, dict):
                trace_params = raw_trace.get("params")
                params = dict(trace_params) if isinstance(trace_params, dict) else dict(raw_trace)
            elif raw_params is not None:
                params = dict(raw_params) if isinstance(raw_params, dict) else {"params": raw_params}

        if not isinstance(child_text, str):
            params = {**params, "reason": "non_str_child_text"}
            status = "INVALID"
            child_text = fallback_text

        return status, child_text, params

    def _stats_scope(
        self,
        stats_by_scope: Dict[str, Any],
        selection_scope: str,
    ) -> Dict[str, Any]:
        scope_stats = stats_by_scope.get(selection_scope)
        if not isinstance(scope_stats, dict):
            scope_stats = {}
            stats_by_scope[selection_scope] = scope_stats
        return scope_stats

    @staticmethod
    def _increment_counter(container: Dict[str, Any], key: str) -> None:
        container[key] = int(container.get(key, 0)) + 1

    def _update_recent_ops(
        self,
        stats_by_scope: Dict[str, Any],
        selection_scope: str,
        op_id: str,
        limit: int = 20,
    ) -> None:
        scope_stats = self._stats_scope(stats_by_scope, selection_scope)
        recent = scope_stats.get("_recent_ops")
        if not isinstance(recent, list):
            recent = []
            scope_stats["_recent_ops"] = recent
        recent.append(op_id)
        if len(recent) > limit:
            del recent[:-limit]

    def _update_selection_stats(
        self,
        *,
        stats_by_scope: Dict[str, Any],
        selection_scope: str,
        op_id: str,
        operator_family: str,
        attack_type: str,
    ) -> None:
        scope_stats = self._stats_scope(stats_by_scope, selection_scope)
        scope_stats["_successful_total"] = int(scope_stats.get("_successful_total", 0)) + 1

        operator_counts = scope_stats.setdefault("_operator_counts", {})
        family_counts = scope_stats.setdefault("_family_counts", {})
        attack_counts = scope_stats.setdefault("_attack_counts", {})
        attack_operator_counts = scope_stats.setdefault("_attack_operator_counts", {})
        attack_family_counts = scope_stats.setdefault("_attack_family_counts", {})

        self._increment_counter(operator_counts, op_id)
        self._increment_counter(family_counts, operator_family)

        if attack_type:
            self._increment_counter(attack_counts, attack_type)
            per_attack_ops = attack_operator_counts.setdefault(attack_type, {})
            per_attack_families = attack_family_counts.setdefault(attack_type, {})
            self._increment_counter(per_attack_ops, op_id)
            self._increment_counter(per_attack_families, operator_family)

        recent_families = scope_stats.setdefault("_recent_families", [])
        recent_families.append(operator_family)
        if len(recent_families) > 20:
            del recent_families[:-20]

    def _update_novelty(
        self,
        stats_by_scope: Dict[str, Any],
        selection_scope: str,
        child_text: str,
    ) -> Dict[str, Any]:
        scope_stats = self._stats_scope(stats_by_scope, selection_scope)
        tracker = getattr(self.selector, "novelty", None)

        if tracker is not None and hasattr(tracker, "mark_seen"):
            seen = bool(tracker.mark_seen(selection_scope, child_text))
            snapshot = (
                tracker.snapshot_one(selection_scope)
                if hasattr(tracker, "snapshot_one")
                else {}
            )
        else:
            seen = False
            snapshot = {}

        novelty = scope_stats.get("_novelty")
        if not isinstance(novelty, dict):
            novelty = {}
            scope_stats["_novelty"] = novelty

        if isinstance(snapshot, dict) and snapshot:
            novelty.update(snapshot)
        else:
            novelty["total"] = int(novelty.get("total", 0)) + 1
            novelty["unique"] = int(novelty.get("unique", 0)) + (0 if seen else 1)
            novelty["seen_hits"] = int(novelty.get("seen_hits", 0)) + (1 if seen else 0)
            total = int(novelty.get("total", 0))
            unique = int(novelty.get("unique", 0))
            novelty["unique_ratio"] = float(unique) / float(total) if total > 0 else 0.0

        return {"seen_before": seen, "novelty": dict(novelty)}

    @staticmethod
    def _candidate_audit_to_rows(candidate_audit: Any) -> Tuple[int, List[Dict[str, Any]]]:
        accepted_count = 0
        rejected_candidates: List[Dict[str, Any]] = []

        for decision in candidate_audit or ():
            if bool(getattr(decision, "accepted", False)):
                accepted_count += 1
            else:
                rejected_candidates.append(
                    {
                        "op_id": str(getattr(decision, "op_id", "")),
                        "reasons": list(getattr(decision, "reasons", ())),
                    }
                )

        return accepted_count, rejected_candidates

    def _selection_trace(
        self,
        *,
        selection: Any,
        op_id: str,
        status: str,
        params: Dict[str, Any],
        before: str,
        after: str,
        retry_index: int,
        candidate_audit: Any,
        guard_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        accepted_count, rejected_candidates = self._candidate_audit_to_rows(candidate_audit)

        trace: Dict[str, Any] = {
            "op_id": op_id,
            "status": status,
            "params": dict(params),
            "len_before": len(before),
            "len_after": len(after),
            "selection": {
                "reason": getattr(selection, "reason", "unknown"),
                "retry_index": retry_index,
                "candidate_count": accepted_count,
                "rejected_candidates": rejected_candidates,
                "quota_audit": list(getattr(selection, "quota_audit", ())),
            },
        }

        if guard_meta and guard_meta.get("guard_applied"):
            trace["params"]["guard_meta"] = guard_meta

        return trace

    def generate_children(
        self,
        *,
        seed_text: str,
        selection_scope: str = "diagnostic_v1",
        surface: str = "PROMPT_TEXT",
        n: int = 10,
        k: int = 1,
        seed_base: int = 1337,
        strength: int = 2,
        risk_max: Optional[str] = None,
        operator_family: Optional[Any] = None,
        attack_type: Optional[Any] = None,
        output_format: Optional[Any] = None,
        input_format: Optional[Any] = None,
        use_in_diagnostic_v1: Optional[bool] = True,
        op_ids: Optional[Iterable[str]] = None,
        blocked_operator_ids: Optional[Iterable[str]] = None,
        blocked_operator_traits: Optional[Any] = None,
        max_semantic_preservation_risk: Optional[str] = None,
        max_label_change_risk: Optional[str] = None,
        constraints: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        stats_by_scope: Optional[Dict[str, Any]] = None,
        bucket_id: Optional[str] = None,
        stats_by_bucket: Optional[Dict[str, Any]] = None,
    ) -> List[MutationOutput]:
        outputs: List[MutationOutput] = []
        constraints = constraints or {}
        metadata = metadata or {}

        if stats_by_scope is None and stats_by_bucket is not None:
            stats_by_scope = stats_by_bucket
        stats_by_scope = stats_by_scope or {}

        if bucket_id and selection_scope == "diagnostic_v1":
            metadata = {**metadata, "legacy_bucket_id": bucket_id}

        guard_cfg = self._make_guard_cfg(constraints)
        retry_limit = max(1, int(constraints.get("selection_retry_limit", 20)))
        original_blocked_ids = {str(op_id) for op_id in (blocked_operator_ids or [])}
        explicit_op_ids = [str(op_id) for op_id in op_ids] if op_ids is not None else None

        for child_index in range(n):
            testcase_id = f"{metadata.get('seed_id', 'seed')}:{child_index}"
            rng = derive_rng(seed_base, testcase_id)

            ctx_base: Dict[str, Any] = {
                "selection_scope": selection_scope,
                "surface": surface,
                "strength": strength,
                "constraints": constraints,
                "metadata": {
                    **metadata,
                    "testcase_id": testcase_id,
                    "child_index": child_index,
                },
                "stats_by_scope": stats_by_scope,
                "operator_family": operator_family,
                "attack_type": attack_type,
                "output_format": output_format,
                "input_format": input_format,
                "blocked_operator_ids": sorted(original_blocked_ids),
                "blocked_operator_traits": list(blocked_operator_traits or []),
                "max_semantic_preservation_risk": max_semantic_preservation_risk,
                "max_label_change_risk": max_label_change_risk,
            }

            mutation_trace: List[Dict[str, Any]] = []
            last_status = "SKIPPED"
            child = seed_text

            guarded_seed, seed_guard_meta = guard_text_with_meta(child, guard_cfg)
            if seed_guard_meta.get("guard_applied"):
                mutation_trace.append(
                    {
                        "op_id": "__guard__",
                        "status": "OK",
                        "params": {"guard_meta": seed_guard_meta},
                        "len_before": len(child),
                        "len_after": len(guarded_seed),
                    }
                )
            child = guarded_seed

            for mutation_step in range(k):
                attempted_ids: set[str] = set()
                step_completed = False

                for retry_index in range(retry_limit):
                    effective_blocked_ids = original_blocked_ids | attempted_ids

                    selection = self.selector.choose(
                        surface=surface,
                        rng=rng,
                        strength=strength,
                        risk_max=risk_max,
                        stats_by_scope=stats_by_scope,
                        selection_scope=selection_scope,
                        operator_family=operator_family,
                        attack_type=attack_type,
                        output_format=output_format,
                        input_format=input_format,
                        use_in_diagnostic_v1=use_in_diagnostic_v1,
                        op_ids=explicit_op_ids,
                        blocked_operator_ids=sorted(effective_blocked_ids),
                        blocked_operator_traits=blocked_operator_traits,
                        max_semantic_preservation_risk=max_semantic_preservation_risk,
                        max_label_change_risk=max_label_change_risk,
                        seed_text=child,
                    )

                    if selection is None:
                        mutation_trace.append(
                            {
                                "op_id": "__selection__",
                                "status": "SKIPPED",
                                "params": {
                                    "reason": "no_candidate_available",
                                    "mutation_step": mutation_step,
                                    "retry_index": retry_index,
                                    "attempted_operator_ids": sorted(attempted_ids),
                                },
                                "len_before": len(child),
                                "len_after": len(child),
                                "selection": {
                                    "reason": "no_candidate_available",
                                    "retry_index": retry_index,
                                    "candidate_count": 0,
                                    "rejected_candidates": [],
                                    "quota_audit": [],
                                },
                            }
                        )
                        last_status = "SKIPPED"
                        break

                    handle = self._resolve_handler_from_selection(selection)
                    selected_op_id = str(
                        getattr(selection, "op_id", "")
                        or getattr(handle, "op_id", "")
                        or "<unknown>"
                    )
                    candidate_audit = getattr(selection, "candidate_audit", ())

                    if handle is None:
                        mutation_trace.append(
                            self._selection_trace(
                                selection=selection,
                                op_id=selected_op_id,
                                status="SKIPPED",
                                params={
                                    "reason": "handler_not_found",
                                    "mutation_step": mutation_step,
                                },
                                before=child,
                                after=child,
                                retry_index=retry_index,
                                candidate_audit=candidate_audit,
                            )
                        )
                        if selected_op_id != "<unknown>":
                            attempted_ids.add(selected_op_id)
                        last_status = "SKIPPED"
                        continue

                    before = child
                    try:
                        result = handle.apply(before, ctx_base, rng)
                    except Exception as exc:
                        result = {
                            "status": "INVALID",
                            "child_text": before,
                            "params": {"error": repr(exc)},
                        }

                    status, candidate_text, params = self._normalize_apply_result(result, before)
                    guarded_text, guard_meta = guard_text_with_meta(candidate_text, guard_cfg)

                    params = dict(params)
                    params.setdefault("mutation_step", mutation_step)

                    if hasattr(handle, "meta") and isinstance(handle.meta, dict):
                        params.setdefault("operator_family", handle.meta.get("operator_family"))
                        params.setdefault("output_format", handle.meta.get("output_format"))
                        params.setdefault("attack_type_compat", handle.meta.get("attack_type_compat"))
                        params.setdefault(
                            "diagnostic_eligibility",
                            handle.meta.get("diagnostic_eligibility", "conditional"),
                        )
                        params.setdefault(
                            "requires_post_filter",
                            bool(handle.meta.get("requires_post_filter", True)),
                        )

                    mutation_trace.append(
                        self._selection_trace(
                            selection=selection,
                            op_id=selected_op_id,
                            status=status,
                            params=params,
                            before=before,
                            after=guarded_text,
                            retry_index=retry_index,
                            candidate_audit=candidate_audit,
                            guard_meta=guard_meta,
                        )
                    )

                    self._update_recent_ops(stats_by_scope, selection_scope, selected_op_id)
                    last_status = status

                    if status == "SKIPPED":
                        attempted_ids.add(selected_op_id)
                        child = before
                        continue

                    if status == "INVALID":
                        child = before
                        step_completed = True
                        break

                    if status == "OK":
                        operator_family_value = str(
                            handle.meta.get("operator_family", "unknown")
                            if isinstance(getattr(handle, "meta", None), dict)
                            else "unknown"
                        )
                        self._update_selection_stats(
                            stats_by_scope=stats_by_scope,
                            selection_scope=selection_scope,
                            op_id=selected_op_id,
                            operator_family=operator_family_value,
                            attack_type=str(attack_type or ""),
                        )

                    child = guarded_text
                    step_completed = True
                    break

                if not step_completed:
                    break
                if last_status == "INVALID":
                    break

            novelty_meta = self._update_novelty(stats_by_scope, selection_scope, child)
            if mutation_trace:
                mutation_trace[-1]["params"] = dict(mutation_trace[-1].get("params", {}))
                mutation_trace[-1]["params"]["novelty"] = novelty_meta

            outputs.append(
                MutationOutput(
                    child_text=child,
                    mutation_trace=mutation_trace,
                    last_status=last_status,
                )
            )

        return outputs
