# src/pipelines/inspect_registry.py
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

from src.core.registry import OperatorRegistry


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(x) for x in value]
    if value is None:
        return []
    return [str(value)]


def _is_diagnostic_enabled(meta: Dict[str, Any]) -> bool:
    # New bucket-free criterion.
    if "use_in_diagnostic_v1" in meta:
        return bool(meta.get("use_in_diagnostic_v1"))

    # Legacy fallback only. This should disappear after operator metadata is fully migrated.
    return "LLM01_PROMPT_INJECTION" in _as_list(meta.get("bucket_tags"))


def _registry_filter(
    registry: OperatorRegistry,
    *,
    surface: Optional[str] = None,
    risk_max: Optional[str] = None,
    operator_family: Optional[str] = None,
    attack_type: Optional[str] = None,
    use_in_diagnostic_v1: bool = True,
):
    """
    Compatibility wrapper.

    Preferred bucket-free registry.filter signature:
        filter(
            surface=...,
            risk_max=...,
            operator_family=...,
            attack_type=...,
            use_in_diagnostic_v1=True,
        )

    If the local core has not been fully refactored yet, this falls back to
    legacy filtering and then applies bucket-free criteria in this script.
    """
    try:
        return registry.filter(
            surface=surface,
            risk_max=risk_max,
            operator_family=operator_family,
            attack_type=attack_type,
            use_in_diagnostic_v1=use_in_diagnostic_v1,
        )
    except TypeError:
        candidates = registry.filter(surface=surface, risk_max=risk_max)

        out = []
        for h in candidates:
            meta = h.meta
            if use_in_diagnostic_v1 and not _is_diagnostic_enabled(meta):
                continue
            if operator_family and meta.get("operator_family") != operator_family:
                continue
            if attack_type:
                compat = _as_list(meta.get("attack_type_compat"))
                if compat and attack_type not in compat:
                    continue
            out.append(h)
        return out


def _print_operator(h) -> None:
    meta = h.meta
    print("-" * 80)
    print(f"op_id                      : {h.op_id}")
    print(f"module                     : {h.module}")
    print(f"operator_family            : {meta.get('operator_family', 'UNKNOWN')}")
    print(f"attack_type_compat         : {_as_list(meta.get('attack_type_compat'))}")
    print(f"surface_compat             : {_as_list(meta.get('surface_compat'))}")
    print(f"output_format              : {meta.get('output_format', 'UNKNOWN')}")
    print(f"risk_level                 : {meta.get('risk_level', None)}")
    print(f"strength_range             : {meta.get('strength_range', None)}")
    print(f"semantic_preservation_risk : {meta.get('semantic_preservation_risk', 'UNKNOWN')}")
    print(f"label_change_risk          : {meta.get('label_change_risk', 'UNKNOWN')}")
    print(f"use_in_diagnostic_v1       : {meta.get('use_in_diagnostic_v1', False)}")

    # Legacy visibility only. Not used as selection criterion.
    if meta.get("bucket_tags"):
        print(f"legacy_bucket_tags         : {_as_list(meta.get('bucket_tags'))}")


def main() -> None:
    registry = OperatorRegistry()
    loaded = registry.load_from_package("src.operators", strict=False)

    print("=" * 80)
    print("[registry: bucket-free diagnostic view]")
    print(f"loaded operators : {loaded}")
    print(f"load_errors      : {len(registry.load_errors)}")
    print("=" * 80)

    if registry.load_errors:
        print("\n[load errors]")
        for modname, reason in registry.load_errors:
            print(f"- {modname}: {reason}")

    all_ops = registry.list_ops()
    diagnostic_ops = _registry_filter(registry, use_in_diagnostic_v1=True)

    print("\n[all importable operators]")
    for h in all_ops:
        _print_operator(h)

    print("\n" + "=" * 80)
    print(f"[diagnostic_v1 operators] {len(diagnostic_ops)}")
    print("=" * 80)
    for h in diagnostic_ops:
        meta = h.meta
        print(
            f"- {h.op_id} "
            f"| family={meta.get('operator_family', 'UNKNOWN')} "
            f"| output={meta.get('output_format', 'UNKNOWN')} "
            f"| risk={meta.get('risk_level', 'UNKNOWN')}"
        )

    by_family = defaultdict(list)
    by_attack_type = defaultdict(list)
    by_surface = defaultdict(list)

    for h in diagnostic_ops:
        meta = h.meta
        by_family[str(meta.get("operator_family", "UNKNOWN"))].append(h.op_id)

        attack_types = _as_list(meta.get("attack_type_compat")) or ["UNKNOWN"]
        for attack_type in attack_types:
            by_attack_type[attack_type].append(h.op_id)

        surfaces = _as_list(meta.get("surface_compat")) or ["UNKNOWN"]
        for surface in surfaces:
            by_surface[surface].append(h.op_id)

    print("\n[summary by operator_family]")
    for family in sorted(by_family):
        ops = sorted(by_family[family])
        print(f"- {family}: {len(ops)}")
        for op_id in ops:
            print(f"    - {op_id}")

    print("\n[summary by attack_type_compat]")
    for attack_type in sorted(by_attack_type):
        ops = sorted(set(by_attack_type[attack_type]))
        print(f"- {attack_type}: {len(ops)}")
        for op_id in ops:
            print(f"    - {op_id}")

    print("\n[summary by surface_compat]")
    for surface in sorted(by_surface):
        ops = sorted(set(by_surface[surface]))
        print(f"- {surface}: {len(ops)}")
        for op_id in ops:
            print(f"    - {op_id}")

    if not diagnostic_ops:
        raise RuntimeError(
            "No diagnostic_v1 operators found. "
            "Check OPERATOR_META['use_in_diagnostic_v1'] or registry.filter()."
        )


if __name__ == "__main__":
    main()
