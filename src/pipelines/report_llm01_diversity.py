# src/pipelines/report_llm01_diversity.py
from __future__ import annotations

import json
import math
import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List


INPUT_PATH = Path("data/outputs/runs/run_diagnostic_v1_batch.jsonl")
OUTPUT_JSON = Path("data/outputs/reports/run_diagnostic_v1_diversity.json")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def shannon_entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0

    ent = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def normalized_entropy(counter: Counter) -> float:
    if not counter:
        return 0.0
    ent = shannon_entropy(counter)
    max_ent = math.log2(len(counter)) if len(counter) > 1 else 0.0
    if max_ent == 0.0:
        return 0.0
    return ent / max_ent


def pct(n: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((n / total) * 100.0, 2)


def _group_uniqueness(grouped_hashes: Dict[str, List[str]], label_name: str) -> List[Dict[str, Any]]:
    rows = []
    for label, hashes in grouped_hashes.items():
        total = len(hashes)
        unique = len(set(hashes))
        rows.append({
            label_name: label,
            "count": total,
            "unique_count": unique,
            "unique_ratio": round(unique / total, 4) if total > 0 else 0.0,
        })
    return sorted(rows, key=lambda x: (-x["count"], str(x[label_name])))


def main() -> None:
    rows = load_jsonl(INPUT_PATH)

    total = len(rows)
    operator_counter = Counter()
    family_counter = Counter()
    attack_type_counter = Counter()
    surface_counter = Counter()

    child_hashes = []
    hashes_by_surface = defaultdict(list)
    hashes_by_attack_type = defaultdict(list)
    hashes_by_family = defaultdict(list)
    children_by_parent = defaultdict(list)

    for row in rows:
        op_id = str(row.get("selected_op_id", "NONE"))
        family = str(row.get("operator_family", "UNKNOWN"))
        attack_type = str(row.get("attack_type", "unknown_or_other"))
        surface = str(row.get("mapped_surface") or row.get("attack_surface") or "UNKNOWN")
        child_text = str(row.get("child_text", ""))

        operator_counter[op_id] += 1
        family_counter[family] += 1
        attack_type_counter[attack_type] += 1
        surface_counter[surface] += 1

        h = hash_text(child_text)
        child_hashes.append(h)
        hashes_by_surface[surface].append(h)
        hashes_by_attack_type[attack_type].append(h)
        hashes_by_family[family].append(h)

        parent_id = str(row.get("parent_record_id", "UNKNOWN"))
        children_by_parent[parent_id].append(h)

    unique_hash_count = len(set(child_hashes))
    unique_ratio = unique_hash_count / total if total > 0 else 0.0

    same_child_parent_count = 0
    different_child_parent_count = 0

    for _parent_id, hashes in children_by_parent.items():
        if len(hashes) < 2:
            continue
        if len(set(hashes)) == 1:
            same_child_parent_count += 1
        else:
            different_child_parent_count += 1

    op_entropy = shannon_entropy(operator_counter)
    op_entropy_norm = normalized_entropy(operator_counter)
    family_entropy = shannon_entropy(family_counter)
    family_entropy_norm = normalized_entropy(family_counter)

    report = {
        "schema_version": "diagnostic_v1_diversity_report.v1",
        "input_path": str(INPUT_PATH),
        "total_rows": total,
        "unique_child_count": unique_hash_count,
        "unique_child_ratio": round(unique_ratio, 4),
        "parent_pair_stats": {
            "same_child_parent_count": same_child_parent_count,
            "different_child_parent_count": different_child_parent_count,
            "different_ratio_pct": pct(
                different_child_parent_count,
                same_child_parent_count + different_child_parent_count,
            ),
        },
        "operator_entropy": {
            "shannon_entropy": round(op_entropy, 4),
            "normalized_entropy": round(op_entropy_norm, 4),
            "operator_count": len(operator_counter),
        },
        "operator_family_entropy": {
            "shannon_entropy": round(family_entropy, 4),
            "normalized_entropy": round(family_entropy_norm, 4),
            "operator_family_count": len(family_counter),
        },
        "surface_uniqueness": _group_uniqueness(hashes_by_surface, "surface"),
        "attack_type_uniqueness": _group_uniqueness(hashes_by_attack_type, "attack_type"),
        "operator_family_uniqueness": _group_uniqueness(hashes_by_family, "operator_family"),
        "operator_distribution": [
            {"op_id": k, "count": v, "ratio_pct": pct(v, total)}
            for k, v in operator_counter.most_common()
        ],
        "operator_family_distribution": [
            {"operator_family": k, "count": v, "ratio_pct": pct(v, total)}
            for k, v in family_counter.most_common()
        ],
        "attack_type_distribution": [
            {"attack_type": k, "count": v, "ratio_pct": pct(v, total)}
            for k, v in attack_type_counter.most_common()
        ],
    }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("=" * 80)
    print("[diagnostic_v1 mutation diversity report]")
    print("=" * 80)
    print(f"input_path             : {INPUT_PATH}")
    print(f"total_rows             : {total}")
    print(f"unique_child_count     : {unique_hash_count}")
    print(f"unique_child_ratio     : {report['unique_child_ratio']}")
    print(f"parent different ratio : {report['parent_pair_stats']['different_ratio_pct']}%")
    print(f"operator entropy       : {report['operator_entropy']['shannon_entropy']}")
    print(f"family entropy         : {report['operator_family_entropy']['shannon_entropy']}")

    print("\n[operator family uniqueness]")
    for item in report["operator_family_uniqueness"]:
        print(
            f"- {item['operator_family']}: "
            f"{item['unique_count']}/{item['count']} "
            f"({round(item['unique_ratio'] * 100, 2)}%)"
        )

    print(f"\n[report saved] {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
