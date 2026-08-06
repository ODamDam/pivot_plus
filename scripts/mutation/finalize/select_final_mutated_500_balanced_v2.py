from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from typing import Any

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import csr_matrix, lil_matrix


def find_project_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "data").is_dir() and (candidate / "scripts").is_dir():
            return candidate
    raise FileNotFoundError("Could not find project root containing data/ and scripts/.")


PROJECT_ROOT = find_project_root(Path(__file__).parent)

SEED_PATH = (
    PROJECT_ROOT / "data" / "inputs" / "mutation"
    / "mutation_seeds_diagnostic_v1_seed250.jsonl"
)
CANDIDATE_PATH = (
    PROJECT_ROOT / "data" / "outputs" / "runs"
    / "mutation_candidates_seed250_v1.jsonl"
)
OUTPUT_JSONL = (
    PROJECT_ROOT / "data" / "final"
    / "mutated_malicious_500_v2_balanced.jsonl"
)
OUTPUT_CSV = (
    PROJECT_ROOT / "data" / "final"
    / "mutated_malicious_500_v2_balanced.csv"
)
SUMMARY_PATH = (
    PROJECT_ROOT / "reports"
    / "mutated_malicious_500_v2_balanced_summary.json"
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

# Feasibility-aware targets. Exact 100 per family is infeasible because all
# format_injection parents only have structural VALID candidates.
OPERATOR_TARGETS = {
    "op_fmt_punctuation_resegmentation": 100,
    "op_lex_homoglyph_injection": 100,
    "op_lex_polite_prefix": 89,
    "op_fmt_whitespace_noise": 65,
    "op_comp_expand_context": 35,
    "op_fmt_structured_wrapper_json_yaml": 37,
    "op_fmt_markdown_wrapper": 37,
    "op_syn_boundary_delimiter_injection": 37,
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def first(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def build_valid_candidates(
    seeds: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    seed_index: dict[str, dict[str, Any]] = {}
    for seed in seeds:
        for key in ("record_id", "normalized_record_id", "sample_id", "parent_seed_id"):
            value = first(seed.get(key))
            if value:
                seed_index[value] = seed

    seen_hashes: set[str] = set()
    valid: list[dict[str, Any]] = []

    for candidate_index, candidate in enumerate(candidates, start=1):
        status = first(candidate.get("status"))
        op_id = first(candidate.get("selected_op_id"), candidate.get("op_id"))
        parent_id = first(candidate.get("parent_record_id"), candidate.get("record_id"))
        child_text = first(candidate.get("child_text"), candidate.get("mutated_text"))
        seed = seed_index.get(parent_id)
        parent_text = first(
            (seed or {}).get("mutation_target_text"),
            (seed or {}).get("scanner_input"),
        )

        if status != "OK" or not child_text or not parent_id or seed is None or not parent_text:
            continue
        if op_id in DENIED_OPERATORS or child_text.strip() == parent_text.strip():
            continue
        if len(child_text) < 8:
            continue

        child_hash = sha256_text(child_text)
        if child_hash in seen_hashes:
            continue
        seen_hashes.add(child_hash)

        ratio = len(child_text) / max(len(parent_text), 1)
        parent_attack = first(seed.get("attack_type"))
        child_attack = first(candidate.get("attack_type"))

        review_reasons: list[str] = []
        if parent_attack and child_attack and parent_attack != child_attack:
            review_reasons.append("attack_type_mismatch")
        if ratio < 0.60:
            review_reasons.append("large_text_reduction")
        if ratio > 4.00:
            review_reasons.append("extreme_text_expansion")
        if op_id in CONDITIONAL_OPERATORS and ratio > 2.50:
            review_reasons.append("conditional_operator_large_expansion")
        if first(candidate.get("semantic_preservation_risk")).upper() == "HIGH":
            review_reasons.append("high_semantic_preservation_risk")
        if first(candidate.get("label_change_risk")).upper() == "HIGH":
            review_reasons.append("high_label_change_risk")

        if review_reasons:
            continue

        row = dict(candidate)
        row["candidate_index"] = candidate_index
        row["length_ratio"] = round(ratio, 4)
        row["child_sha256"] = child_hash
        row["filter_decision"] = "VALID"
        valid.append(row)

    return valid


def main() -> None:
    seeds = load_jsonl(SEED_PATH)
    candidates = load_jsonl(CANDIDATE_PATH)
    valid = build_valid_candidates(seeds, candidates)

    by_parent: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in valid:
        by_parent[row["parent_record_id"]].append(row)

    if len(by_parent) != 250:
        raise RuntimeError(
            f"Expected 250 parents with VALID candidates, found {len(by_parent)}"
        )

    parents = sorted(by_parent)
    pair_options: list[dict[str, Any]] = []

    for parent_id in parents:
        rows = by_parent[parent_id]
        if len(rows) < 2:
            raise RuntimeError(f"Parent has fewer than two VALID candidates: {parent_id}")

        for left_index, right_index in combinations(range(len(rows)), 2):
            left = rows[left_index]
            right = rows[right_index]
            pair_options.append({
                "parent_id": parent_id,
                "left": left,
                "right": right,
                "operator_counts": Counter(
                    [left["selected_op_id"], right["selected_op_id"]]
                ),
                "same_family": left["operator_family"] == right["operator_family"],
                "same_operator": left["selected_op_id"] == right["selected_op_id"],
                "length_penalty": (
                    abs(float(left["length_ratio"]) - 1.0)
                    + abs(float(right["length_ratio"]) - 1.0)
                ),
            })

    option_count = len(pair_options)
    operators = sorted(OPERATOR_TARGETS)
    parent_index = {parent: index for index, parent in enumerate(parents)}

    # Variables:
    # - one binary variable for each possible two-candidate parent pair
    # - positive/negative deviation slack for each operator target
    variable_count = option_count + (2 * len(operators))
    matrix = lil_matrix(
        (len(parents) + len(operators), variable_count),
        dtype=float,
    )
    lower: list[float] = []
    upper: list[float] = []

    for option_index, option in enumerate(pair_options):
        matrix[parent_index[option["parent_id"]], option_index] = 1.0

    for _ in parents:
        lower.append(1.0)
        upper.append(1.0)

    for operator_index, operator_id in enumerate(operators):
        row_index = len(parents) + operator_index

        for option_index, option in enumerate(pair_options):
            matrix[row_index, option_index] = (
                option["operator_counts"].get(operator_id, 0)
            )

        positive_slack = option_count + operator_index
        negative_slack = option_count + len(operators) + operator_index

        matrix[row_index, positive_slack] = -1.0
        matrix[row_index, negative_slack] = 1.0

        target = float(OPERATOR_TARGETS[operator_id])
        lower.append(target)
        upper.append(target)

    objective = np.zeros(variable_count, dtype=float)

    for option_index, option in enumerate(pair_options):
        objective[option_index] = (
            (10.0 if option["same_family"] else 0.0)
            + (100.0 if option["same_operator"] else 0.0)
            + (0.05 * option["length_penalty"])
        )

    # Deviating from operator targets is penalized, but never at the cost of
    # violating parent coverage or selecting more than one pair per parent.
    objective[option_count:] = 5.0

    integrality = np.concatenate([
        np.ones(option_count, dtype=int),
        np.zeros(2 * len(operators), dtype=int),
    ])

    result = milp(
        objective,
        integrality=integrality,
        bounds=Bounds(
            np.zeros(variable_count),
            np.concatenate([
                np.ones(option_count),
                np.full(2 * len(operators), 500.0),
            ]),
        ),
        constraints=LinearConstraint(
            csr_matrix(matrix),
            np.asarray(lower),
            np.asarray(upper),
        ),
        options={"time_limit": 120},
    )

    if not result.success:
        raise RuntimeError(f"MILP selection failed: {result.message}")

    selected_pairs = [
        pair_options[index]
        for index in range(option_count)
        if result.x[index] > 0.5
    ]

    selected_rows: list[dict[str, Any]] = []

    for pair in selected_pairs:
        ordered = sorted(
            [pair["left"], pair["right"]],
            key=lambda row: (
                abs(float(row["length_ratio"]) - 1.0),
                row["child_sha256"],
                int(row["candidate_index"]),
            ),
        )

        for selection_index, row in enumerate(ordered, start=1):
            output = dict(row)
            parent_id = output["parent_record_id"]
            output["final_dataset_role"] = "mutated_malicious"
            output["final_selection_index"] = selection_index
            output["is_selected_final_v2"] = True
            output["is_mutated"] = True
            output["label"] = "malicious"
            output["ground_truth_decision"] = "malicious"
            output["final_sample_id"] = f"{parent_id}::mut{selection_index:02d}"
            output["selection_policy_version"] = (
                "constraint_balanced_selection.v2"
            )
            selected_rows.append(output)

    if len(selected_rows) != 500:
        raise RuntimeError(f"Expected 500 rows, found {len(selected_rows)}")
    if len({row["parent_record_id"] for row in selected_rows}) != 250:
        raise RuntimeError("Parent coverage is not 250")
    if any(
        count != 2
        for count in Counter(
            row["parent_record_id"] for row in selected_rows
        ).values()
    ):
        raise RuntimeError("A parent does not have exactly two selected children")
    if len({row["child_sha256"] for row in selected_rows}) != 500:
        raise RuntimeError("Duplicate child hashes detected")
    if any(
        len({row["selected_op_id"] for row in rows}) != 2
        for rows in (
            [
                row for row in selected_rows
                if row["parent_record_id"] == parent_id
            ]
            for parent_id in parents
        )
    ):
        raise RuntimeError("A parent contains a duplicated operator")

    OUTPUT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_JSONL.open("w", encoding="utf-8", newline="\n") as f:
        for row in selected_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    columns = [
        "final_sample_id",
        "parent_record_id",
        "final_selection_index",
        "attack_type",
        "selected_op_id",
        "operator_family",
        "input_format",
        "output_format",
        "length_ratio",
        "child_sha256",
        "filter_decision",
        "child_text",
        "selection_policy_version",
    ]

    with OUTPUT_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=columns,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(selected_rows)

    family_counts = Counter(
        row["operator_family"] for row in selected_rows
    )
    operator_counts = Counter(
        row["selected_op_id"] for row in selected_rows
    )
    attack_counts = Counter(
        row["attack_type"] for row in selected_rows
    )

    summary = {
        "dataset_name": "mutated_malicious_500_v2_balanced",
        "input_valid_candidates": len(valid),
        "selected_count": len(selected_rows),
        "parent_seed_count": 250,
        "children_per_parent": 2,
        "family_counts": dict(family_counts.most_common()),
        "operator_counts": dict(operator_counts.most_common()),
        "attack_type_counts": dict(attack_counts.most_common()),
        "duplicate_child_hashes": 0,
        "selection_policy_version": (
            "constraint_balanced_selection.v2"
        ),
    }

    SUMMARY_PATH.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("=" * 72)
    print("[done] constraint-balanced mutated malicious selection v2")
    print(f"VALID candidates : {len(valid)}")
    print(f"selected rows    : {len(selected_rows)}")
    print(f"family counts    : {dict(family_counts)}")
    print(f"operator counts  : {dict(operator_counts)}")
    print(f"output jsonl     : {OUTPUT_JSONL}")
    print(f"output csv       : {OUTPUT_CSV}")
    print(f"summary          : {SUMMARY_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    main()
