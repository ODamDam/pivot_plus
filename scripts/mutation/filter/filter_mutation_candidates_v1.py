from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


SEED_PATH = Path(
    "data/inputs/mutation_seeds_diagnostic_v1_seed250.jsonl"
)
CANDIDATE_PATH = Path(
    "data/outputs/runs/mutation_candidates_seed250_v1.jsonl"
)

OUTPUT_DIR = Path("data/review/mutation_filter")

CLASSIFIED_CSV_PATH = OUTPUT_DIR / (
    "mutation_candidates_1150_classified_v1.csv"
)
VALID_PATH = OUTPUT_DIR / (
    "mutation_candidates_1150_valid_v1.jsonl"
)
REVIEW_PATH = OUTPUT_DIR / (
    "mutation_candidates_1150_review_v1.jsonl"
)
DROP_PATH = OUTPUT_DIR / (
    "mutation_candidates_1150_drop_v1.jsonl"
)

SUMMARY_PATH = Path(
    "reports/mutation_candidates_1150_filter_summary_v1.json"
)


DENIED_OPERATORS = {
    "op_ctx_bypass_review_wrapper",
    "op_salience_preserving_line_compression",
}

CONDITIONAL_OPERATORS = {
    "op_comp_expand_context",
    "op_fmt_whitespace_noise",
    "op_lex_polite_prefix",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL at {path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(value, dict):
                raise ValueError(
                    f"Expected object at {path}:{line_number}"
                )

            rows.append(value)

    return rows


def save_jsonl(
    path: Path,
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as file:
        for row in rows:
            file.write(
                json.dumps(row, ensure_ascii=False) + "\n"
            )


def text_hash(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


def first_nonempty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue

        result = str(value).strip()

        if result:
            return result

    return ""


def build_seed_index(
    seeds: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}

    for seed in seeds:
        possible_ids = {
            first_nonempty(seed.get("record_id")),
            first_nonempty(seed.get("normalized_record_id")),
            first_nonempty(seed.get("sample_id")),
            first_nonempty(seed.get("parent_seed_id")),
        }

        for seed_id in possible_ids:
            if seed_id:
                index[seed_id] = seed

    return index


def classify_candidate(
    candidate: dict[str, Any],
    seed_index: dict[str, dict[str, Any]],
    seen_child_hashes: set[str],
) -> tuple[str, list[str], dict[str, Any]]:
    reasons: list[str] = []

    status = first_nonempty(candidate.get("status"))
    selected_op_id = first_nonempty(
        candidate.get("selected_op_id"),
        candidate.get("op_id"),
    )
    parent_record_id = first_nonempty(
        candidate.get("parent_record_id"),
        candidate.get("record_id"),
    )
    child_text = first_nonempty(
        candidate.get("child_text"),
        candidate.get("mutated_text"),
        candidate.get("prompt_text"),
    )

    seed = seed_index.get(parent_record_id)

    parent_text = ""

    if seed is not None:
        parent_text = first_nonempty(
            seed.get("mutation_target_text"),
            seed.get("scanner_input"),
        )

    metadata = {
        "parent_record_id": parent_record_id,
        "selected_op_id": selected_op_id,
        "status": status,
        "parent_text_length": len(parent_text),
        "child_text_length": len(child_text),
        "length_ratio": None,
        "child_sha256": "",
    }

    # Clear DROP conditions
    if status != "OK":
        reasons.append(f"non_ok_status:{status or 'missing'}")
        return "DROP", reasons, metadata

    if not child_text:
        reasons.append("missing_child_text")
        return "DROP", reasons, metadata

    if not parent_record_id:
        reasons.append("missing_parent_record_id")
        return "DROP", reasons, metadata

    if seed is None:
        reasons.append("parent_seed_not_found")
        return "DROP", reasons, metadata

    if not parent_text:
        reasons.append("missing_parent_text")
        return "DROP", reasons, metadata

    if selected_op_id in DENIED_OPERATORS:
        reasons.append(f"denied_operator:{selected_op_id}")
        return "DROP", reasons, metadata

    if child_text.strip() == parent_text.strip():
        reasons.append("unchanged_text")
        return "DROP", reasons, metadata

    child_sha256 = text_hash(child_text)
    metadata["child_sha256"] = child_sha256

    if child_sha256 in seen_child_hashes:
        reasons.append("duplicate_child_text")
        return "DROP", reasons, metadata

    seen_child_hashes.add(child_sha256)

    if len(child_text) < 8:
        reasons.append("child_text_too_short")
        return "DROP", reasons, metadata

    # Conditions requiring review
    length_ratio = len(child_text) / max(len(parent_text), 1)
    metadata["length_ratio"] = round(length_ratio, 4)

    parent_attack_type = first_nonempty(
        seed.get("attack_type")
    )
    child_attack_type = first_nonempty(
        candidate.get("attack_type")
    )

    if (
        parent_attack_type
        and child_attack_type
        and parent_attack_type != child_attack_type
    ):
        reasons.append(
            "attack_type_mismatch:"
            f"{parent_attack_type}->{child_attack_type}"
        )

    if length_ratio < 0.60:
        reasons.append("large_text_reduction")

    if length_ratio > 4.00:
        reasons.append("extreme_text_expansion")

    if (
        selected_op_id in CONDITIONAL_OPERATORS
        and length_ratio > 2.50
    ):
        reasons.append("conditional_operator_large_expansion")

    semantic_risk = first_nonempty(
        candidate.get("semantic_preservation_risk")
    ).upper()
    label_risk = first_nonempty(
        candidate.get("label_change_risk")
    ).upper()

    if semantic_risk == "HIGH":
        reasons.append("high_semantic_preservation_risk")

    if label_risk == "HIGH":
        reasons.append("high_label_change_risk")

    if reasons:
        return "REVIEW", reasons, metadata

    return "VALID", ["passed_auto_filter"], metadata


def main() -> None:
    seeds = load_jsonl(SEED_PATH)
    candidates = load_jsonl(CANDIDATE_PATH)

    if len(seeds) != 250:
        raise RuntimeError(
            f"Expected 250 seeds, found {len(seeds)}"
        )

    seed_index = build_seed_index(seeds)
    seen_child_hashes: set[str] = set()

    classified_rows: list[dict[str, Any]] = []
    valid_rows: list[dict[str, Any]] = []
    review_rows: list[dict[str, Any]] = []
    drop_rows: list[dict[str, Any]] = []

    for candidate_index, candidate in enumerate(
        candidates,
        start=1,
    ):
        decision, reasons, metadata = classify_candidate(
            candidate,
            seed_index,
            seen_child_hashes,
        )

        classified = dict(candidate)
        classified.update(metadata)
        classified["filter_decision"] = decision
        classified["filter_reasons"] = reasons
        classified["candidate_index"] = candidate_index

        classified_rows.append(classified)

        if decision == "VALID":
            valid_rows.append(classified)
        elif decision == "REVIEW":
            review_rows.append(classified)
        else:
            drop_rows.append(classified)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)

    save_jsonl(VALID_PATH, valid_rows)
    save_jsonl(REVIEW_PATH, review_rows)
    save_jsonl(DROP_PATH, drop_rows)

    csv_columns = [
        "candidate_index",
        "parent_record_id",
        "attack_type",
        "selected_op_id",
        "operator_family",
        "input_format",
        "output_format",
        "parent_text_length",
        "child_text_length",
        "length_ratio",
        "child_sha256",
        "filter_decision",
        "filter_reasons",
        "child_text",
    ]

    with CLASSIFIED_CSV_PATH.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=csv_columns,
            extrasaction="ignore",
        )
        writer.writeheader()

        for row in classified_rows:
            csv_row = dict(row)
            csv_row["filter_reasons"] = "; ".join(
                row.get("filter_reasons", [])
            )
            writer.writerow(csv_row)

    decision_counts = Counter(
        row["filter_decision"]
        for row in classified_rows
    )

    attack_decision_counts: dict[str, Counter[str]] = (
        defaultdict(Counter)
    )
    operator_decision_counts: dict[str, Counter[str]] = (
        defaultdict(Counter)
    )
    children_by_parent: dict[str, Counter[str]] = (
        defaultdict(Counter)
    )

    for row in classified_rows:
        attack_type = first_nonempty(
            row.get("attack_type"),
            "unknown",
        )
        operator = first_nonempty(
            row.get("selected_op_id"),
            "unknown",
        )
        parent_id = first_nonempty(
            row.get("parent_record_id"),
            "unknown",
        )
        decision = row["filter_decision"]

        attack_decision_counts[attack_type][decision] += 1
        operator_decision_counts[operator][decision] += 1
        children_by_parent[parent_id][decision] += 1

    parents_with_two_valid = sum(
        1
        for counts in children_by_parent.values()
        if counts["VALID"] >= 2
    )

    parents_with_two_usable = sum(
        1
        for counts in children_by_parent.values()
        if counts["VALID"] + counts["REVIEW"] >= 2
    )

    reason_counts = Counter()

    for row in classified_rows:
        for reason in row.get("filter_reasons", []):
            reason_counts[reason] += 1

    summary = {
        "seed_count": len(seeds),
        "candidate_count": len(candidates),
        "decision_counts": dict(decision_counts),
        "attack_type_decision_counts": {
            key: dict(value)
            for key, value in sorted(
                attack_decision_counts.items()
            )
        },
        "operator_decision_counts": {
            key: dict(value)
            for key, value in sorted(
                operator_decision_counts.items()
            )
        },
        "reason_counts": dict(
            reason_counts.most_common()
        ),
        "parent_seed_coverage": {
            "parents_seen": len(children_by_parent),
            "parents_with_at_least_2_valid": (
                parents_with_two_valid
            ),
            "parents_with_at_least_2_valid_or_review": (
                parents_with_two_usable
            ),
        },
        "output_paths": {
            "classified_csv": str(CLASSIFIED_CSV_PATH),
            "valid_jsonl": str(VALID_PATH),
            "review_jsonl": str(REVIEW_PATH),
            "drop_jsonl": str(DROP_PATH),
        },
    }

    SUMMARY_PATH.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 72)
    print("[done] mutation candidate auto filter")
    print(f"seeds       : {len(seeds)}")
    print(f"candidates  : {len(candidates)}")
    print(f"VALID       : {len(valid_rows)}")
    print(f"REVIEW      : {len(review_rows)}")
    print(f"DROP        : {len(drop_rows)}")
    print(
        "parents >=2 VALID        : "
        f"{parents_with_two_valid}/250"
    )
    print(
        "parents >=2 VALID+REVIEW : "
        f"{parents_with_two_usable}/250"
    )
    print(f"summary     : {SUMMARY_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    main()