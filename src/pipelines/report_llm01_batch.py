# src/pipelines/report_llm01_batch.py
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List


INPUT_PATH = Path("data/inputs/mutation_seeds_llm01.jsonl")
OUTPUT_PATH = Path("data/outputs/runs/run_diagnostic_v1_batch.jsonl")
ATTEMPT_LOG_PATH = Path("data/outputs/runs/run_diagnostic_v1_batch_attempts.jsonl")
UNRESOLVED_PATH = Path("data/outputs/runs/run_diagnostic_v1_batch_unresolved.jsonl")

DEFAULT_STRENGTH = 2
DEFAULT_RISK_MAX = "HIGH"
DEFAULT_SEED_BASE = 1001

CHILDREN_PER_SEED = 2
MAX_ATTEMPTS_PER_SEED = 12


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


def pct(n: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((n / total) * 100.0, 2)


def main() -> None:
    rows = load_jsonl(INPUT_PATH)

    total = len(rows)
    status_counter = Counter()
    operator_counter = Counter()
    family_counter = Counter()
    attack_type_counter = Counter()
    surface_counter = Counter()
    output_format_counter = Counter()

    operator_by_attack_type = defaultdict(Counter)
    family_by_attack_type = defaultdict(Counter)
    operator_by_surface = defaultdict(Counter)

    for row in rows:
        status = str(row.get("status", "UNKNOWN"))
        op_id = str(row.get("selected_op_id", "NONE"))
        family = str(row.get("operator_family", "UNKNOWN"))
        attack_type = str(row.get("attack_type", "unknown_or_other"))
        surface = str(row.get("mapped_surface") or row.get("attack_surface") or "UNKNOWN")
        output_format = str(row.get("output_format", "UNKNOWN"))

        status_counter[status] += 1
        operator_counter[op_id] += 1
        family_counter[family] += 1
        attack_type_counter[attack_type] += 1
        surface_counter[surface] += 1
        output_format_counter[output_format] += 1

        operator_by_attack_type[attack_type][op_id] += 1
        family_by_attack_type[attack_type][family] += 1
        operator_by_surface[surface][op_id] += 1

    def counter_items(counter: Counter, total_ref: int = total):
        return [
            {"name": k, "count": v, "ratio_pct": pct(v, total_ref)}
            for k, v in counter.most_common()
        ]

    attack_type_stats = []
    for attack_type, count in attack_type_counter.most_common():
        attack_type_stats.append({
            "attack_type": attack_type,
            "count": count,
            "ratio_pct": pct(count, total),
            "operators": [
                {
                    "op_id": op_id,
                    "count": op_count,
                    "ratio_within_attack_type_pct": pct(op_count, count),
                }
                for op_id, op_count in operator_by_attack_type[attack_type].most_common()
            ],
            "families": [
                {
                    "operator_family": family,
                    "count": fam_count,
                    "ratio_within_attack_type_pct": pct(fam_count, count),
                }
                for family, fam_count in family_by_attack_type[attack_type].most_common()
            ],
        })

    surface_stats = []
    for surface, count in surface_counter.most_common():
        surface_stats.append({
            "surface": surface,
            "count": count,
            "ratio_pct": pct(count, total),
            "operators": [
                {
                    "op_id": op_id,
                    "count": op_count,
                    "ratio_within_surface_pct": pct(op_count, count),
                }
                for op_id, op_count in operator_by_surface[surface].most_common()
            ],
        })

    report = {
        "schema_version": "diagnostic_v1_batch_report.v1",
        "input_path": str(INPUT_PATH),
        "total_rows": total,
        "status_distribution": counter_items(status_counter),
        "operator_distribution": [
            {"op_id": k, "count": v, "ratio_pct": pct(v, total)}
            for k, v in operator_counter.most_common()
        ],
        "operator_family_distribution": [
            {"operator_family": k, "count": v, "ratio_pct": pct(v, total)}
            for k, v in family_counter.most_common()
        ],
        "attack_type_distribution": attack_type_stats,
        "surface_distribution": surface_stats,
        "output_format_distribution": [
            {"output_format": k, "count": v, "ratio_pct": pct(v, total)}
            for k, v in output_format_counter.most_common()
        ],
    }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("=" * 80)
    print("[diagnostic_v1 batch report]")
    print("=" * 80)
    print(f"input_path : {INPUT_PATH}")
    print(f"total_rows : {total}")

    print("\n[status distribution]")
    for item in report["status_distribution"]:
        print(f"- {item['name']}: {item['count']} ({item['ratio_pct']}%)")

    print("\n[operator family distribution]")
    for item in report["operator_family_distribution"]:
        print(f"- {item['operator_family']}: {item['count']} ({item['ratio_pct']}%)")

    print("\n[operator distribution]")
    for item in report["operator_distribution"]:
        print(f"- {item['op_id']}: {item['count']} ({item['ratio_pct']}%)")

    print("\n[attack type distribution]")
    for item in attack_type_stats:
        print(f"- {item['attack_type']}: {item['count']} ({item['ratio_pct']}%)")

    print("\n[surface distribution]")
    for item in surface_stats:
        print(f"- {item['surface']}: {item['count']} ({item['ratio_pct']}%)")

    print(f"\n[report saved] {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
