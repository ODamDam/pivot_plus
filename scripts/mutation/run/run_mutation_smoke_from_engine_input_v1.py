from __future__ import annotations

import argparse
import dataclasses
import inspect
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.mutator import Mutator  # noqa: E402
from src.core.registry import OperatorRegistry  # noqa: E402
from src.core.selector import MetaWeightedSelector, RandomSelector  # noqa: E402


DEFAULT_INPUT = (
    PROJECT_ROOT
    / "data"
    / "final"
    / "mutation_input_smoke_v1.jsonl"
)

DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data"
    / "final"
    / "mutation_smoke_output_v1.jsonl"
)

DEFAULT_SUMMARY = (
    PROJECT_ROOT
    / "reports"
    / "mutation_smoke_summary_v1.md"
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Input file not found: {path}"
        )

    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Invalid JSONL at "
                    f"{path}:{line_no}: {e}"
                ) from e

    return rows


def write_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )


def safe_asdict(obj: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)

    if isinstance(obj, dict):
        return dict(obj)

    out: dict[str, Any] = {}

    for name in dir(obj):
        if name.startswith("_"):
            continue

        try:
            value = getattr(obj, name)
        except Exception:
            continue

        if callable(value):
            continue

        try:
            json.dumps(
                value,
                ensure_ascii=False,
            )
            out[name] = value
        except TypeError:
            out[name] = str(value)

    return out


def normalize_trace(
    value: Any,
) -> list[dict[str, Any]]:
    if value is None:
        return []

    if isinstance(value, list):
        out: list[dict[str, Any]] = []

        for item in value:
            if isinstance(item, dict):
                out.append(item)
            else:
                out.append(
                    safe_asdict(item)
                )

        return out

    if isinstance(value, dict):
        return [value]

    return [safe_asdict(value)]


def get_first_present(
    data: dict[str, Any],
    keys: list[str],
    default: Any = None,
) -> Any:
    for key in keys:
        if (
            key in data
            and data[key] not in (None, "")
        ):
            return data[key]

    return default


def as_string_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, (list, tuple, set)):
        return [
            str(item)
            for item in value
            if item not in (None, "")
        ]

    return [str(value)]


def get_policy_value(
    row: dict[str, Any],
    key: str,
    default: Any = None,
) -> Any:
    """
    정책 값이 top-level에 있거나
    operator_assignment_policy 내부에 있어도 읽는다.
    """

    if key in row and row[key] is not None:
        return row[key]

    policy = row.get(
        "operator_assignment_policy",
        {},
    )

    if (
        isinstance(policy, dict)
        and key in policy
        and policy[key] is not None
    ):
        return policy[key]

    return default


def infer_operator_from_trace(
    trace: list[dict[str, Any]],
) -> tuple[str, str, str]:
    op_id = ""
    family = ""
    target_weakness = ""

    for item in trace:
        if not isinstance(item, dict):
            continue

        op_id = str(
            item.get("op_id")
            or op_id
        )

        params = item.get("params")

        if isinstance(params, dict):
            family = str(
                params.get("operator_family")
                or family
            )

            weaknesses = params.get(
                "target_evaluator_weakness"
            )

            if (
                isinstance(weaknesses, list)
                and weaknesses
            ):
                target_weakness = str(
                    weaknesses[0]
                )
            elif weaknesses:
                target_weakness = str(
                    weaknesses
                )

        family = str(
            item.get("operator_family")
            or family
        )

    return (
        op_id,
        family,
        target_weakness,
    )


def extract_selection_audit(
    trace: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Mutator trace의 selection 필드에서
    후보 수와 제외 사유를 모은다.
    """

    accepted_candidate_count: int | None = None
    rejected_candidates: list[
        dict[str, Any]
    ] = []
    selection_reasons: list[str] = []

    for item in trace:
        if not isinstance(item, dict):
            continue

        selection = item.get("selection")

        if not isinstance(selection, dict):
            continue

        reason = selection.get("reason")

        if reason:
            selection_reasons.append(
                str(reason)
            )

        candidate_count = selection.get(
            "candidate_count"
        )

        if isinstance(candidate_count, int):
            accepted_candidate_count = (
                candidate_count
            )

        rejected = selection.get(
            "rejected_candidates",
            [],
        )

        if isinstance(rejected, list):
            for candidate in rejected:
                if isinstance(candidate, dict):
                    rejected_candidates.append(
                        {
                            "op_id": str(
                                candidate.get(
                                    "op_id",
                                    "",
                                )
                            ),
                            "reasons": (
                                as_string_list(
                                    candidate.get(
                                        "reasons",
                                        [],
                                    )
                                )
                            ),
                        }
                    )

    return {
        "accepted_candidate_count": (
            accepted_candidate_count
        ),
        "rejected_candidates": (
            rejected_candidates
        ),
        "selection_reasons": sorted(
            set(selection_reasons)
        ),
    }


def build_registry() -> OperatorRegistry:
    registry = OperatorRegistry()

    registry.load_from_package(
        "src.operators",
        strict=False,
    )

    return registry


def try_construct(
    cls: Any,
    candidates: list[
        tuple[
            tuple[Any, ...],
            dict[str, Any],
        ]
    ],
) -> Any:
    errors: list[str] = []

    for args, kwargs in candidates:
        try:
            return cls(*args, **kwargs)
        except TypeError as e:
            errors.append(str(e))

    try:
        signature = str(
            inspect.signature(cls)
        )
    except Exception:
        signature = ""

    raise TypeError(
        f"Could not construct {cls}. "
        f"signature={signature}. "
        f"errors={errors}"
    )


def build_selector(
    registry: OperatorRegistry,
    selector_name: str,
) -> Any:
    selector_cls = (
        RandomSelector
        if selector_name == "random"
        else MetaWeightedSelector
    )

    return try_construct(
        selector_cls,
        [
            ((registry,), {}),
            ((), {"registry": registry}),
            ((), {}),
        ],
    )


def build_mutator(
    registry: OperatorRegistry,
    selector: Any,
) -> Mutator:
    return try_construct(
        Mutator,
        [
            (
                (),
                {
                    "registry": registry,
                    "selector": selector,
                },
            ),
            ((registry, selector), {}),
            (
                (registry,),
                {"selector": selector},
            ),
            ((selector,), {}),
            (
                (),
                {"selector": selector},
            ),
            ((registry,), {}),
            ((), {}),
        ],
    )


def build_policy_snapshot(
    row: dict[str, Any],
    risk_max: str | None,
) -> dict[str, Any]:
    return {
        "allowed_operator_families": (
            as_string_list(
                get_policy_value(
                    row,
                    "allowed_operator_families",
                    [],
                )
            )
        ),
        "blocked_operator_ids": (
            as_string_list(
                get_policy_value(
                    row,
                    "blocked_operator_ids",
                    [],
                )
            )
        ),
        "blocked_operator_traits": (
            as_string_list(
                get_policy_value(
                    row,
                    "blocked_operator_traits",
                    [],
                )
            )
        ),
        "input_format": str(
            get_policy_value(
                row,
                "input_format",
                row.get(
                    "input_format",
                    "plain_text",
                ),
            )
        ),
        "attack_type": str(
            row.get("attack_type", "")
        ),
        "risk_max": risk_max or "",
        "max_semantic_preservation_risk": (
            get_policy_value(
                row,
                "max_semantic_preservation_risk",
                "MEDIUM",
            )
        ),
        "max_label_change_risk": (
            get_policy_value(
                row,
                "max_label_change_risk",
                "MEDIUM",
            )
        ),
    }


def mutation_output_to_row(
    *,
    engine_row: dict[str, Any],
    output_obj: Any,
    child_index: int,
    strength: int,
    policy_snapshot: dict[str, Any],
) -> dict[str, Any]:
    raw = safe_asdict(output_obj)

    trace = normalize_trace(
        get_first_present(
            raw,
            [
                "mutation_trace",
                "trace",
                "traces",
            ],
            default=[],
        )
    )

    mutated_text = get_first_present(
        raw,
        [
            "child_text",
            "mutated_text",
            "text",
            "output_text",
            "scanner_input",
        ],
        default="",
    )

    status = str(
        get_first_present(
            raw,
            [
                "status",
                "last_status",
            ],
            default=(
                "OK"
                if mutated_text
                else "UNKNOWN"
            ),
        )
    )

    error = get_first_present(
        raw,
        ["error"],
        default="",
    )

    (
        mutation_operator,
        mutation_family,
        target_weakness,
    ) = infer_operator_from_trace(trace)

    if not mutation_family:
        mutation_family = str(
            get_first_present(
                raw,
                [
                    "operator_family",
                    "mutation_family",
                ],
                default="",
            )
        )

    if not mutation_operator:
        mutation_operator = str(
            get_first_present(
                raw,
                [
                    "op_id",
                    "operator_id",
                    "mutation_operator",
                ],
                default="",
            )
        )

    if not target_weakness:
        weaknesses = engine_row.get(
            "target_evaluator_weaknesses",
            [],
        )

        if (
            isinstance(weaknesses, list)
            and weaknesses
        ):
            target_weakness = str(
                weaknesses[0]
            )

    selection_audit = extract_selection_audit(
        trace
    )

    mutation_seed_id = engine_row.get(
        "mutation_seed_id",
        "MSEED",
    )

    mutation_id = (
        f"MUTSMOKE-"
        f"{mutation_seed_id}-"
        f"{child_index:02d}"
    )

    return {
        "mutation_id": mutation_id,
        "mutation_seed_id": (
            engine_row.get(
                "mutation_seed_id",
                "",
            )
        ),
        "parent_seed_id": (
            engine_row.get(
                "parent_seed_id",
                "",
            )
        ),
        "source_sample_id": (
            engine_row.get(
                "source_sample_id",
                "",
            )
        ),
        "source_id": engine_row.get(
            "source_id",
            "",
        ),
        "source_record_id": (
            engine_row.get(
                "source_record_id",
                "",
            )
        ),
        "original_text": engine_row.get(
            "text",
            "",
        ),
        "mutated_text": mutated_text,
        "label": engine_row.get(
            "label",
            "",
        ),
        "ground_truth_decision": (
            engine_row.get(
                "ground_truth_decision",
                "",
            )
        ),
        "attack_type": engine_row.get(
            "attack_type",
            "",
        ),
        "attack_goal": engine_row.get(
            "attack_goal",
            "",
        ),
        "attack_surface": engine_row.get(
            "attack_surface",
            "",
        ),
        "input_format": engine_row.get(
            "input_format",
            "",
        ),
        "language": engine_row.get(
            "language",
            "",
        ),
        "engine_surface": engine_row.get(
            "engine_surface",
            "",
        ),
        "mutation_family": mutation_family,
        "mutation_operator": (
            mutation_operator
        ),
        "mutation_strength": strength,
        "target_evaluator_weakness": (
            target_weakness
        ),
        "semantic_preservation": (
            "preserved_pending_review"
        ),
        "status": status,
        "error": error,
        "policy_snapshot": policy_snapshot,
        "selection_audit": selection_audit,
        "mutation_trace": trace,
        "source_metadata": (
            engine_row.get(
                "metadata",
                {},
            )
        ),
        "raw_engine_output": raw,
    }


def collect_audit_statistics(
    outputs: list[dict[str, Any]],
) -> dict[str, Any]:
    rejection_reason_counts: Counter[str] = (
        Counter()
    )
    rejected_operator_counts: Counter[str] = (
        Counter()
    )
    selection_reason_counts: Counter[str] = (
        Counter()
    )
    candidate_count_distribution: Counter[
        str
    ] = Counter()

    zero_candidate_rows: list[
        dict[str, Any]
    ] = []

    for row in outputs:
        audit = row.get(
            "selection_audit",
            {},
        )

        if not isinstance(audit, dict):
            continue

        candidate_count = audit.get(
            "accepted_candidate_count"
        )

        candidate_key = (
            "unknown"
            if candidate_count is None
            else str(candidate_count)
        )

        candidate_count_distribution[
            candidate_key
        ] += 1

        if candidate_count == 0:
            zero_candidate_rows.append(
                {
                    "mutation_seed_id": (
                        row.get(
                            "mutation_seed_id",
                            "",
                        )
                    ),
                    "attack_type": row.get(
                        "attack_type",
                        "",
                    ),
                    "input_format": row.get(
                        "input_format",
                        "",
                    ),
                    "status": row.get(
                        "status",
                        "",
                    ),
                }
            )

        for reason in audit.get(
            "selection_reasons",
            [],
        ):
            selection_reason_counts[
                str(reason)
            ] += 1

        rejected_candidates = audit.get(
            "rejected_candidates",
            [],
        )

        if not isinstance(
            rejected_candidates,
            list,
        ):
            continue

        for candidate in rejected_candidates:
            if not isinstance(
                candidate,
                dict,
            ):
                continue

            op_id = str(
                candidate.get("op_id", "")
            )

            if op_id:
                rejected_operator_counts[
                    op_id
                ] += 1

            for reason in as_string_list(
                candidate.get(
                    "reasons",
                    [],
                )
            ):
                rejection_reason_counts[
                    reason
                ] += 1

    return {
        "candidate_count_distribution": dict(
            candidate_count_distribution
        ),
        "rejection_reason_counts": dict(
            rejection_reason_counts
        ),
        "rejected_operator_counts": dict(
            rejected_operator_counts
        ),
        "selection_reason_counts": dict(
            selection_reason_counts
        ),
        "zero_candidate_rows": (
            zero_candidate_rows
        ),
    }


def run_smoke(
    *,
    rows: list[dict[str, Any]],
    seed_base: int,
    selector_name: str,
    risk_max: str | None,
    max_chars: int,
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
]:
    registry = build_registry()

    selector = build_selector(
        registry,
        selector_name,
    )

    mutator = build_mutator(
        registry,
        selector,
    )

    stats_by_scope: dict[str, Any] = {}
    outputs: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    no_output_rows: list[dict[str, Any]] = []

    skipped_budget_rows = 0

    for idx, row in enumerate(
        rows,
        start=1,
    ):
        raw_mutation_budget = row.get(
            "mutation_budget",
            1,
        )

        if raw_mutation_budget in (None, ""):
            mutation_budget = 1
        else:
            mutation_budget = int(
                raw_mutation_budget
            )

        strength = int(
            row.get(
                "max_strength",
                1,
            )
            or 1
        )

        if mutation_budget <= 0:
            skipped_budget_rows += 1
            continue

        policy_snapshot = (
            build_policy_snapshot(
                row,
                risk_max,
            )
        )

        allowed_families = (
            policy_snapshot[
                "allowed_operator_families"
            ]
        )

        blocked_operator_ids = (
            policy_snapshot[
                "blocked_operator_ids"
            ]
        )

        blocked_operator_traits = (
            policy_snapshot[
                "blocked_operator_traits"
            ]
        )

        input_format = (
            policy_snapshot["input_format"]
        )

        max_semantic_risk = (
            policy_snapshot[
                "max_semantic_preservation_risk"
            ]
        )

        max_label_risk = (
            policy_snapshot[
                "max_label_change_risk"
            ]
        )

        metadata = dict(
            row.get("metadata", {})
            or {}
        )

        metadata.update(
            {
                "seed_id": row.get(
                    "mutation_seed_id",
                    f"MSEED-{idx:06d}",
                ),
                "parent_seed_id": (
                    row.get(
                        "parent_seed_id",
                        "",
                    )
                ),
                "source_sample_id": (
                    row.get(
                        "source_sample_id",
                        "",
                    )
                ),
                "adapter_mode": (
                    metadata.get(
                        "adapter_mode",
                        "smoke_test",
                    )
                ),
                "policy_snapshot": (
                    policy_snapshot
                ),
            }
        )

        try:
            children = (
                mutator.generate_children(
                    seed_text=str(
                        row.get(
                            "text",
                            "",
                        )
                    ),
                    selection_scope=(
                        "diagnostic_v1"
                    ),
                    surface=str(
                        row.get(
                            "engine_surface",
                            "PROMPT_TEXT",
                        )
                    ),
                    n=mutation_budget,
                    k=1,
                    seed_base=seed_base,
                    strength=strength,
                    risk_max=risk_max,
                    operator_family=(
                        allowed_families
                    ),
                    attack_type=str(
                        row.get(
                            "attack_type",
                            "",
                        )
                    ),
                    output_format=None,
                    input_format=input_format,
                    use_in_diagnostic_v1=True,
                    blocked_operator_ids=(
                        blocked_operator_ids
                    ),
                    blocked_operator_traits=(
                        blocked_operator_traits
                    ),
                    max_semantic_preservation_risk=(
                        max_semantic_risk
                    ),
                    max_label_change_risk=(
                        max_label_risk
                    ),
                    constraints={
                        "max_chars": max_chars,
                    },
                    metadata=metadata,
                    stats_by_scope=(
                        stats_by_scope
                    ),
                )
            )
        except Exception as e:
            failures.append(
                {
                    "mutation_seed_id": (
                        row.get(
                            "mutation_seed_id",
                            "",
                        )
                    ),
                    "parent_seed_id": (
                        row.get(
                            "parent_seed_id",
                            "",
                        )
                    ),
                    "attack_type": row.get(
                        "attack_type",
                        "",
                    ),
                    "input_format": (
                        input_format
                    ),
                    "allowed_operator_families": (
                        allowed_families
                    ),
                    "blocked_operator_ids": (
                        blocked_operator_ids
                    ),
                    "blocked_operator_traits": (
                        blocked_operator_traits
                    ),
                    "error": repr(e),
                }
            )
            continue

        children = list(children or [])

        if not children:
            no_output_rows.append(
                {
                    "mutation_seed_id": (
                        row.get(
                            "mutation_seed_id",
                            "",
                        )
                    ),
                    "parent_seed_id": (
                        row.get(
                            "parent_seed_id",
                            "",
                        )
                    ),
                    "attack_type": row.get(
                        "attack_type",
                        "",
                    ),
                    "input_format": (
                        input_format
                    ),
                    "allowed_operator_families": (
                        allowed_families
                    ),
                    "blocked_operator_ids": (
                        blocked_operator_ids
                    ),
                    "blocked_operator_traits": (
                        blocked_operator_traits
                    ),
                }
            )
            continue

        for child_index, child in enumerate(
            children,
            start=1,
        ):
            outputs.append(
                mutation_output_to_row(
                    engine_row=row,
                    output_obj=child,
                    child_index=(
                        child_index
                    ),
                    strength=strength,
                    policy_snapshot=(
                        policy_snapshot
                    ),
                )
            )

    status_counts = Counter(
        row.get("status", "")
        for row in outputs
    )

    operator_counts = Counter(
        row.get(
            "mutation_operator",
            "",
        )
        for row in outputs
    )

    family_counts = Counter(
        row.get(
            "mutation_family",
            "",
        )
        for row in outputs
    )

    attack_counts = Counter(
        row.get(
            "attack_type",
            "",
        )
        for row in outputs
    )

    input_format_counts = Counter(
        row.get(
            "input_format",
            "",
        )
        for row in outputs
    )

    unchanged_rows = [
        {
            "mutation_seed_id": row.get(
                "mutation_seed_id",
                "",
            ),
            "mutation_operator": row.get(
                "mutation_operator",
                "",
            ),
            "status": row.get(
                "status",
                "",
            ),
        }
        for row in outputs
        if (
            str(
                row.get(
                    "original_text",
                    "",
                )
            )
            == str(
                row.get(
                    "mutated_text",
                    "",
                )
            )
        )
    ]

    audit_stats = (
        collect_audit_statistics(
            outputs
        )
    )

    summary = {
        "input_rows": len(rows),
        "skipped_budget_rows": (
            skipped_budget_rows
        ),
        "output_rows": len(outputs),
        "failure_rows": len(failures),
        "no_output_row_count": len(
            no_output_rows
        ),
        "unchanged_row_count": len(
            unchanged_rows
        ),
        "loaded_operators": len(
            registry.list_ops()
        ),
        "registry_load_errors": (
            registry.load_errors
        ),
        "selector": selector_name,
        "risk_max": risk_max or "",
        "seed_base": seed_base,
        "status_counts": dict(
            status_counts
        ),
        "operator_counts": dict(
            operator_counts
        ),
        "family_counts": dict(
            family_counts
        ),
        "attack_type_counts": dict(
            attack_counts
        ),
        "input_format_counts": dict(
            input_format_counts
        ),
        "candidate_count_distribution": (
            audit_stats[
                "candidate_count_distribution"
            ]
        ),
        "selection_reason_counts": (
            audit_stats[
                "selection_reason_counts"
            ]
        ),
        "rejection_reason_counts": (
            audit_stats[
                "rejection_reason_counts"
            ]
        ),
        "rejected_operator_counts": (
            audit_stats[
                "rejected_operator_counts"
            ]
        ),
        "zero_candidate_rows": (
            audit_stats[
                "zero_candidate_rows"
            ]
        ),
        "no_output_rows": no_output_rows,
        "unchanged_rows": unchanged_rows,
        "failures": failures,
    }

    return outputs, summary


def table_from_counter(
    title: str,
    data: dict[str, Any],
) -> str:
    lines = [
        f"## {title}",
        "",
        "| key | count |",
        "| --- | ---: |",
    ]

    for key, value in sorted(
        data.items(),
        key=lambda item: str(item[0]),
    ):
        lines.append(
            f"| `{key}` | {value} |"
        )

    if not data:
        lines.append("| — | 0 |")

    lines.append("")

    return "\n".join(lines)


def write_summary(
    path: Path,
    summary: dict[str, Any],
    output_path: Path,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = [
        "# Mutation Smoke Summary v1.1",
        "",
        (
            f"- output: "
            f"`{output_path.relative_to(PROJECT_ROOT).as_posix()}`"
        ),
        (
            f"- input_rows: "
            f"{summary['input_rows']}"
        ),
        (
            f"- skipped_budget_rows: "
            f"{summary['skipped_budget_rows']}"
        ),
        (
            f"- output_rows: "
            f"{summary['output_rows']}"
        ),
        (
            f"- failure_rows: "
            f"{summary['failure_rows']}"
        ),
        (
            f"- no_output_row_count: "
            f"{summary['no_output_row_count']}"
        ),
        (
            f"- unchanged_row_count: "
            f"{summary['unchanged_row_count']}"
        ),
        (
            f"- loaded_operators: "
            f"{summary['loaded_operators']}"
        ),
        (
            f"- registry_load_errors: "
            f"{len(summary['registry_load_errors'])}"
        ),
        (
            f"- selector: "
            f"`{summary['selector']}`"
        ),
        (
            f"- risk_max: "
            f"`{summary['risk_max']}`"
        ),
        (
            f"- seed_base: "
            f"`{summary['seed_base']}`"
        ),
        "",
        table_from_counter(
            "Status Counts",
            summary["status_counts"],
        ),
        table_from_counter(
            "Operator Counts",
            summary["operator_counts"],
        ),
        table_from_counter(
            "Family Counts",
            summary["family_counts"],
        ),
        table_from_counter(
            "Attack Type Counts",
            summary[
                "attack_type_counts"
            ],
        ),
        table_from_counter(
            "Input Format Counts",
            summary[
                "input_format_counts"
            ],
        ),
        table_from_counter(
            "Accepted Candidate Count Distribution",
            summary[
                "candidate_count_distribution"
            ],
        ),
        table_from_counter(
            "Selection Reason Counts",
            summary[
                "selection_reason_counts"
            ],
        ),
        table_from_counter(
            "Candidate Rejection Reason Counts",
            summary[
                "rejection_reason_counts"
            ],
        ),
        table_from_counter(
            "Rejected Operator Counts",
            summary[
                "rejected_operator_counts"
            ],
        ),
    ]

    if summary["zero_candidate_rows"]:
        lines.extend(
            [
                "## Zero Candidate Rows",
                "",
                (
                    "| mutation_seed_id "
                    "| attack_type "
                    "| input_format "
                    "| status |"
                ),
                (
                    "| --- | --- | --- | --- |"
                ),
            ]
        )

        for item in summary[
            "zero_candidate_rows"
        ]:
            lines.append(
                f"| `{item.get('mutation_seed_id', '')}` "
                f"| `{item.get('attack_type', '')}` "
                f"| `{item.get('input_format', '')}` "
                f"| `{item.get('status', '')}` |"
            )

        lines.append("")

    if summary["no_output_rows"]:
        lines.extend(
            [
                "## No Output Rows",
                "",
                (
                    "| mutation_seed_id "
                    "| attack_type "
                    "| input_format "
                    "| allowed_operator_families |"
                ),
                (
                    "| --- | --- | --- | --- |"
                ),
            ]
        )

        for item in summary[
            "no_output_rows"
        ]:
            families = ", ".join(
                item.get(
                    "allowed_operator_families",
                    [],
                )
            )

            lines.append(
                f"| `{item.get('mutation_seed_id', '')}` "
                f"| `{item.get('attack_type', '')}` "
                f"| `{item.get('input_format', '')}` "
                f"| `{families}` |"
            )

        lines.append("")

    if summary["unchanged_rows"]:
        lines.extend(
            [
                "## Unchanged Rows",
                "",
                (
                    "| mutation_seed_id "
                    "| mutation_operator "
                    "| status |"
                ),
                "| --- | --- | --- |",
            ]
        )

        for item in summary[
            "unchanged_rows"
        ]:
            lines.append(
                f"| `{item.get('mutation_seed_id', '')}` "
                f"| `{item.get('mutation_operator', '')}` "
                f"| `{item.get('status', '')}` |"
            )

        lines.append("")

    if summary["failures"]:
        lines.extend(
            [
                "## Failures",
                "",
                (
                    "| mutation_seed_id "
                    "| attack_type "
                    "| error |"
                ),
                "| --- | --- | --- |",
            ]
        )

        for item in summary["failures"]:
            error = str(
                item.get("error", "")
            ).replace("|", "/")

            lines.append(
                f"| `{item.get('mutation_seed_id', '')}` "
                f"| `{item.get('attack_type', '')}` "
                f"| `{error}` |"
            )

        lines.append("")

    if summary["registry_load_errors"]:
        lines.extend(
            [
                "## Registry Load Errors",
                "",
                "| module | error |",
                "| --- | --- |",
            ]
        )

        for module, error in summary[
            "registry_load_errors"
        ]:
            safe_error = str(error).replace(
                "|",
                "/",
            )

            lines.append(
                f"| `{module}` | `{safe_error}` |"
            )

        lines.append("")

    path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT),
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
    )

    parser.add_argument(
        "--summary-output",
        default=str(DEFAULT_SUMMARY),
    )

    parser.add_argument(
        "--seed-base",
        type=int,
        default=1337,
    )

    parser.add_argument(
        "--selector",
        choices=[
            "weighted",
            "random",
        ],
        default="weighted",
    )

    parser.add_argument(
        "--risk-max",
        default="MEDIUM",
    )

    parser.add_argument(
        "--max-chars",
        type=int,
        default=4000,
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(
        args.summary_output
    )

    rows = read_jsonl(input_path)

    outputs, summary = run_smoke(
        rows=rows,
        seed_base=args.seed_base,
        selector_name=args.selector,
        risk_max=args.risk_max,
        max_chars=args.max_chars,
    )

    write_jsonl(
        output_path,
        outputs,
    )

    write_summary(
        summary_path,
        summary,
        output_path,
    )

    print(
        f"[OK] input rows: "
        f"{summary['input_rows']}"
    )
    print(
        f"[OK] skipped budget rows: "
        f"{summary['skipped_budget_rows']}"
    )
    print(
        f"[OK] output rows: "
        f"{summary['output_rows']}"
    )
    print(
        f"[OK] failure rows: "
        f"{summary['failure_rows']}"
    )
    print(
        f"[OK] no-output rows: "
        f"{summary['no_output_row_count']}"
    )
    print(
        f"[OK] unchanged rows: "
        f"{summary['unchanged_row_count']}"
    )
    print(
        f"[OK] loaded operators: "
        f"{summary['loaded_operators']}"
    )
    print(
        f"[OK] registry load errors: "
        f"{len(summary['registry_load_errors'])}"
    )
    print(
        f"[OK] output: "
        f"{output_path.relative_to(PROJECT_ROOT)}"
    )
    print(
        f"[OK] summary: "
        f"{summary_path.relative_to(PROJECT_ROOT)}"
    )

    if summary["failure_rows"]:
        print(
            "[WARN] Some rows failed. "
            "Check the summary file."
        )

    if summary["no_output_row_count"]:
        print(
            "[WARN] Some rows generated no output. "
            "Check No Output Rows."
        )

    if summary["unchanged_row_count"]:
        print(
            "[WARN] Some mutations were unchanged."
        )

    if not outputs:
        print(
            "[WARN] No mutation outputs generated."
        )


if __name__ == "__main__":
    main()