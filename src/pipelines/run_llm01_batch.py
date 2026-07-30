# src/pipelines/run_llm01_batch.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from src.core.registry import OperatorRegistry
from src.core.rng import derive_rng


INPUT_PATH = Path(
    "data/inputs/mutation_seeds_diagnostic_v1_seed250.jsonl"
)
OUTPUT_PATH = Path(
    "data/outputs/runs/mutation_candidates_seed250_v1.jsonl"
)
ATTEMPT_LOG_PATH = Path(
    "data/outputs/runs/"
    "mutation_candidates_seed250_v1_attempts.jsonl"
)
UNRESOLVED_PATH = Path(
    "data/outputs/runs/"
    "mutation_candidates_seed250_v1_unresolved.jsonl"
)

DEFAULT_STRENGTH = 2
DEFAULT_RISK_MAX = "MEDIUM"
DEFAULT_SEED_BASE = 1337

CHILDREN_PER_SEED = 5
MAX_ATTEMPTS_PER_SEED = 30
STRICT_REQUIRE_COMPLETE = True
SELECTION_SCOPE = "diagnostic_v1"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"invalid jsonl at line {line_no}: {e}") from e
    return rows


def save_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _as_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(x) for x in value]
    if value is None:
        return []
    return [str(value)]


def _is_diagnostic_enabled(meta: Dict[str, Any]) -> bool:
    if "use_in_diagnostic_v1" in meta:
        return bool(meta.get("use_in_diagnostic_v1"))
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


def is_target_seed(row: Dict[str, Any]) -> bool:
    # If the field exists, respect it. If it does not exist, allow the row.
    if "is_mutable" in row and not bool(row.get("is_mutable")):
        return False

    target_text = row.get("mutation_target_text")
    if not isinstance(target_text, str) or not target_text.strip():
        return False

    # Bucket tags are intentionally ignored.
    return True


def map_surface(raw_surface: Any) -> str:
    if raw_surface is None:
        return "PROMPT_TEXT"

    s = str(raw_surface).strip().lower()

    if s in {"prompt_text", "email_body", "body", "text", "user_prompt", "prompt"}:
        return "PROMPT_TEXT"

    if s in {"system_message", "system", "developer_message"}:
        return "SYSTEM_MESSAGE"

    if s in {"tool_call", "toolcall_json"}:
        return "TOOL_CALL"

    if s in {"tool_arguments", "tool_argument", "arguments"}:
        return "TOOL_ARGUMENTS"

    return "PROMPT_TEXT"


def normalize_attack_type(row: Dict[str, Any]) -> str:
    for key in ("attack_type", "primary_attack_type", "category", "label_attack_type"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown_or_other"


def get_allowed_operator_families(row: Dict[str, Any]) -> List[str]:
    value = row.get("allowed_operator_families")
    if isinstance(value, list):
        return [str(x) for x in value if str(x).strip()]

    value = row.get("mutation_family")
    if isinstance(value, str) and value.strip():
        return [value.strip()]

    return []


def build_ctx(
    row: Dict[str, Any],
    *,
    strength: int,
    desired_child_index: int,
    attempt_index: int,
    attack_type: str,
    operator_meta: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "record_id": row.get("record_id"),
        "selection_scope": SELECTION_SCOPE,
        "surface": map_surface(row.get("attack_surface")),
        "attack_type": attack_type,
        "operator_family": operator_meta.get("operator_family"),
        "output_format": operator_meta.get("output_format"),
        "mutation_target_role": row.get("mutation_target_role"),
        "source_format": row.get("source_format"),
        "strength": strength,
        "desired_child_index": desired_child_index,
        "attempt_index": attempt_index,
        "constraints": row.get("constraints", {}),
        "raw_row": row,
    }


def _operator_weight(op_id: str, family: str, attack_type: str, recent_ops: List[str]) -> float:
    # Simple bucket-free weighting. This is intentionally transparent.
    family_weights = {
        "structural": 1.35,
        "contextual": 1.25,
        "encoding": 1.20,
        "noise_injection": 1.10,
        "syntactic": 1.05,
        "lexical": 1.00,
        "tool_manipulation": 0.95,
    }

    w = family_weights.get(family, 1.0)

    # Slight preference for attack-specific operators.
    if attack_type == "tool_manipulation" and family == "tool_manipulation":
        w *= 1.35
    if attack_type == "format_injection" and family == "structural":
        w *= 1.35
    if attack_type == "instruction_override" and family in {"lexical", "contextual", "structural"}:
        w *= 1.15
    if attack_type == "data_exfiltration" and family in {"structural", "encoding", "noise_injection"}:
        w *= 1.15
    if attack_type == "indirect_injection" and family in {"structural", "noise_injection", "contextual"}:
        w *= 1.15

    # Avoid immediate repetition.
    if recent_ops and recent_ops[-1] == op_id:
        w *= 0.5

    return max(0.0, float(w))


def choose_operator(
    *,
    registry: OperatorRegistry,
    surface: str,
    attack_type: str,
    allowed_families: List[str],
    risk_max: str,
    rng,
    used_success_ops: Set[str],
    recent_ops: List[str],
):
    # Prefer attack_type-aware filtering.
    candidates = _registry_filter(
        registry,
        surface=surface,
        risk_max=risk_max,
        attack_type=attack_type,
        use_in_diagnostic_v1=True,
    )

    # Fallback for attack types not yet represented in OPERATOR_META.
    if not candidates:
        candidates = _registry_filter(
            registry,
            surface=surface,
            risk_max=risk_max,
            use_in_diagnostic_v1=True,
        )

    if allowed_families:
        filtered = [h for h in candidates if str(h.meta.get("operator_family")) in set(allowed_families)]
        if filtered:
            candidates = filtered

    if not candidates:
        return None, [], "no_candidates_after_filter", 0.0

    # Prefer not reusing a successful operator for the same parent if alternatives exist.
    fresh = [h for h in candidates if h.op_id not in used_success_ops]
    if fresh:
        candidates = fresh

    weights = []
    for h in candidates:
        family = str(h.meta.get("operator_family", "UNKNOWN"))
        weights.append(_operator_weight(h.op_id, family, attack_type, recent_ops))

    total = sum(weights)
    if total <= 0:
        idx = rng.randrange(0, len(candidates))
        return candidates[idx], candidates, "uniform_fallback", 1.0

    r = rng.random() * total
    acc = 0.0
    for h, w in zip(candidates, weights):
        acc += w
        if r <= acc:
            return h, candidates, "bucket_free_weighted_choice", w

    return candidates[-1], candidates, "rounding_fallback", weights[-1]


def main() -> None:
    seeds = load_jsonl(INPUT_PATH)

    registry = OperatorRegistry()
    loaded = registry.load_from_package("src.operators", strict=False)

    print(f"[info] loaded operators: {loaded}")
    print(f"[info] load_errors: {len(registry.load_errors)}")
    if registry.load_errors:
        for modname, reason in registry.load_errors:
            print(f"  - {modname}: {reason}")

    success_rows: List[Dict[str, Any]] = []
    attempt_logs: List[Dict[str, Any]] = []
    unresolved_rows: List[Dict[str, Any]] = []

    ok_children_count = 0
    failed_attempt_count = 0
    recent_ops: List[str] = []

    target_rows = [row for row in seeds if is_target_seed(row)]

    print(f"[info] selection_scope     : {SELECTION_SCOPE}")
    print(f"[info] total input rows    : {len(seeds)}")
    print(f"[info] target seed rows   : {len(target_rows)}")
    print(f"[info] children per seed  : {CHILDREN_PER_SEED}")
    print(f"[info] max attempts/seed  : {MAX_ATTEMPTS_PER_SEED}")
    print(f"[info] risk_max           : {DEFAULT_RISK_MAX}")

    for row in target_rows:
        record_id = str(row.get("record_id", "unknown"))
        seed_text = row["mutation_target_text"]
        base_strength = int(row.get("strength", DEFAULT_STRENGTH))
        mapped_surface = map_surface(row.get("attack_surface"))
        attack_type = normalize_attack_type(row)
        allowed_families = get_allowed_operator_families(row)

        ok_for_seed = 0
        attempt_index = 0
        used_success_ops: Set[str] = set()

        while ok_for_seed < CHILDREN_PER_SEED and attempt_index < MAX_ATTEMPTS_PER_SEED:
            attempt_index += 1
            desired_child_index = ok_for_seed + 1
            testcase_id = f"{record_id}:child{desired_child_index}:attempt{attempt_index}"
            rng = derive_rng(DEFAULT_SEED_BASE, testcase_id)

            selected, candidates, selection_reason, selection_weight = choose_operator(
                registry=registry,
                surface=mapped_surface,
                attack_type=attack_type,
                allowed_families=allowed_families,
                risk_max=DEFAULT_RISK_MAX,
                rng=rng,
                used_success_ops=used_success_ops,
                recent_ops=recent_ops,
            )

            if selected is None:
                attempt_logs.append({
                    "parent_record_id": record_id,
                    "desired_child_index": desired_child_index,
                    "attempt_index": attempt_index,
                    "selection_scope": SELECTION_SCOPE,
                    "attack_type": attack_type,
                    "attack_surface": row.get("attack_surface"),
                    "mapped_surface": mapped_surface,
                    "status": "SKIPPED",
                    "reason": selection_reason,
                })
                failed_attempt_count += 1
                break

            ctx = build_ctx(
                row=row,
                strength=base_strength,
                desired_child_index=desired_child_index,
                attempt_index=attempt_index,
                attack_type=attack_type,
                operator_meta=selected.meta,
            )

            result = registry.apply(
                op_id=selected.op_id,
                seed_text=seed_text,
                ctx=ctx,
                rng=rng,
            )

            operator_family = str(selected.meta.get("operator_family", "UNKNOWN"))
            output_format = str(selected.meta.get("output_format", "UNKNOWN"))

            attempt_logs.append({
                "parent_record_id": record_id,
                "desired_child_index": desired_child_index,
                "attempt_index": attempt_index,
                "selection_scope": SELECTION_SCOPE,
                "attack_type": attack_type,
                "attack_surface": row.get("attack_surface"),
                "mapped_surface": mapped_surface,
                "candidate_count": len(candidates),
                "selected_op_id": selected.op_id,
                "operator_family": operator_family,
                "output_format": output_format,
                "selection_reason": selection_reason,
                "selection_weight": selection_weight,
                "status": result.status,
                "error": result.error,
                "trace": result.trace,
            })

            if result.status != "OK":
                failed_attempt_count += 1
                continue

            child_record_id = f"{record_id}__child_{desired_child_index:02d}"

            recent_ops.append(selected.op_id)
            if len(recent_ops) > 20:
                del recent_ops[:-20]

            success_rows.append({
                "parent_record_id": record_id,
                "child_record_id": child_record_id,
                "child_index": desired_child_index,
                "attempt_index": attempt_index,
                "selection_scope": SELECTION_SCOPE,
                "attack_type": attack_type,
                "attack_surface": row.get("attack_surface"),
                "mapped_surface": mapped_surface,
                "mutation_target_role": row.get("mutation_target_role"),
                "source_format": row.get("source_format"),
                "selected_op_id": selected.op_id,
                "operator_family": operator_family,
                "output_format": output_format,
                "selection_reason": selection_reason,
                "selection_weight": selection_weight,
                "status": result.status,
                "child_text": result.child_text,
                "trace": result.trace,
                "error": result.error,
            })

            used_success_ops.add(selected.op_id)
            ok_for_seed += 1
            ok_children_count += 1

        if ok_for_seed < CHILDREN_PER_SEED:
            unresolved_rows.append({
                "parent_record_id": record_id,
                "selection_scope": SELECTION_SCOPE,
                "attack_type": attack_type,
                "attack_surface": row.get("attack_surface"),
                "mapped_surface": mapped_surface,
                "ok_children_obtained": ok_for_seed,
                "required_children": CHILDREN_PER_SEED,
                "attempts_used": attempt_index,
                "max_attempts": MAX_ATTEMPTS_PER_SEED,
            })

    save_jsonl(OUTPUT_PATH, success_rows)
    save_jsonl(ATTEMPT_LOG_PATH, attempt_logs)
    save_jsonl(UNRESOLVED_PATH, unresolved_rows)

    expected_ok_rows = len(target_rows) * CHILDREN_PER_SEED

    print("=" * 80)
    print("[done] run_diagnostic_v1_batch")
    print(f"input_path        : {INPUT_PATH}")
    print(f"output_path       : {OUTPUT_PATH}")
    print(f"attempt_log_path  : {ATTEMPT_LOG_PATH}")
    print(f"unresolved_path   : {UNRESOLVED_PATH}")
    print(f"total_rows        : {len(seeds)}")
    print(f"target_rows       : {len(target_rows)}")
    print(f"expected_ok_rows  : {expected_ok_rows}")
    print(f"written_ok_rows   : {len(success_rows)}")
    print(f"failed_attempts   : {failed_attempt_count}")
    print(f"unresolved_seeds  : {len(unresolved_rows)}")
    print("=" * 80)

    if STRICT_REQUIRE_COMPLETE and len(success_rows) != expected_ok_rows:
        raise RuntimeError(
            "Failed to guarantee the required number of OK children per seed. "
            f"expected_ok_rows={expected_ok_rows}, written_ok_rows={len(success_rows)}, "
            f"unresolved_seeds={len(unresolved_rows)}"
        )


if __name__ == "__main__":
    main()
