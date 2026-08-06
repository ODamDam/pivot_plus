from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

REVIEW_FILES = [
    PROJECT_ROOT / "data" / "review" / "manual_review_seed_malicious_schema_v1.csv",
    PROJECT_ROOT / "data" / "review" / "manual_review_bypass_candidate_schema_v1.csv",
    PROJECT_ROOT / "data" / "review" / "manual_review_structure_intact_malicious_schema_v1.csv",
    PROJECT_ROOT / "data" / "review" / "manual_review_benign_schema_v1.csv",
    PROJECT_ROOT / "data" / "review" / "manual_review_hard_negative_schema_v1.csv",
    PROJECT_ROOT / "data" / "review" / "manual_review_context_eval_schema_v1.csv",
]

OUTPUT = PROJECT_ROOT / "reports" / "manual_review_curation_status_v1.md"


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


def norm(value: Any) -> str:
    return str(value or "").strip()


def lower(value: Any) -> str:
    return norm(value).lower()


def counter_table(title: str, counter: Counter[str]) -> list[str]:
    lines = [
        "",
        f"### {title}",
        "",
        "| key | count |",
        "| --- | ---: |",
    ]

    for key, count in counter.most_common():
        shown = key if key else "<blank>"
        lines.append(f"| `{shown}` | {count} |")

    return lines


def main() -> None:
    lines: list[str] = [
        "# Manual Review Curation Status v1",
        "",
        "This report summarizes current manual review CSV status for seed curation.",
    ]

    global_review_decision = Counter()
    global_subset = Counter()
    global_attack_type = Counter()
    global_source = Counter()
    global_source_attack = Counter()

    total_rows = 0
    file_summaries: list[dict[str, Any]] = []

    for path in REVIEW_FILES:
        rows = read_csv(path)
        total_rows += len(rows)

        review_decision = Counter(lower(r.get("review_decision")) for r in rows)
        keep_or_drop = Counter(lower(r.get("keep_or_drop")) for r in rows)
        review_status = Counter(lower(r.get("review_status") or r.get("manual_review_status")) for r in rows)
        subset = Counter(norm(r.get("subset")) for r in rows)
        attack_type = Counter(norm(r.get("attack_type")) for r in rows)
        source = Counter(norm(r.get("source_id")) for r in rows)
        input_format = Counter(norm(r.get("input_format")) for r in rows)
        attack_surface = Counter(norm(r.get("attack_surface")) for r in rows)

        for r in rows:
            global_review_decision[lower(r.get("review_decision"))] += 1
            global_subset[norm(r.get("subset"))] += 1
            global_attack_type[norm(r.get("attack_type"))] += 1
            global_source[norm(r.get("source_id"))] += 1
            global_source_attack[f"{norm(r.get('source_id'))} / {norm(r.get('attack_type'))}"] += 1

        file_summaries.append(
            {
                "file": path.relative_to(PROJECT_ROOT).as_posix(),
                "rows": len(rows),
                "review_decision": review_decision,
                "keep_or_drop": keep_or_drop,
                "review_status": review_status,
                "subset": subset,
                "attack_type": attack_type,
                "source": source,
                "input_format": input_format,
                "attack_surface": attack_surface,
            }
        )

    lines += [
        "",
        "## Overall",
        "",
        f"- total_rows: {total_rows}",
        "",
        "| file | rows |",
        "| --- | ---: |",
    ]

    for item in file_summaries:
        lines.append(f"| `{item['file']}` | {item['rows']} |")

    lines += counter_table("Global Review Decision", global_review_decision)
    lines += counter_table("Global Subset", global_subset)
    lines += counter_table("Global Attack Type", global_attack_type)
    lines += counter_table("Global Source", global_source)
    lines += counter_table("Global Source / Attack Type", global_source_attack)

    lines += [
        "",
        "## Per-file Details",
        "",
    ]

    for item in file_summaries:
        lines += [
            "",
            f"## {item['file']}",
            "",
            f"- rows: {item['rows']}",
        ]

        lines += counter_table("review_decision", item["review_decision"])
        lines += counter_table("keep_or_drop", item["keep_or_drop"])
        lines += counter_table("review_status", item["review_status"])
        lines += counter_table("subset", item["subset"])
        lines += counter_table("attack_type", item["attack_type"])
        lines += counter_table("source_id", item["source"])
        lines += counter_table("input_format", item["input_format"])
        lines += counter_table("attack_surface", item["attack_surface"])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] wrote {OUTPUT.relative_to(PROJECT_ROOT)}")
    print(f"[OK] total rows: {total_rows}")


if __name__ == "__main__":
    main()
