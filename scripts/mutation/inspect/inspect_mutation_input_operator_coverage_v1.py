from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.registry import OperatorRegistry  # noqa: E402


INPUT = PROJECT_ROOT / "data" / "final" / "mutation_input_smoke_v1.jsonl"
OUTPUT = PROJECT_ROOT / "reports" / "mutation_input_operator_coverage_v1.md"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def main() -> None:
    rows = load_jsonl(INPUT)

    registry = OperatorRegistry()
    registry.load_from_package("src.operators", strict=False)

    report_rows: list[dict[str, Any]] = []

    for row in rows:
        attack_type = str(row.get("attack_type", ""))
        surface = str(row.get("engine_surface", "PROMPT_TEXT"))
        families = row.get("allowed_operator_families", [])

        if not isinstance(families, list):
            families = [str(families)]

        candidates = registry.filter(
            surface=surface,
            risk_max="MEDIUM",
            use_in_diagnostic_v1=True,
            operator_family=families,
            attack_type=attack_type,
        )

        report_rows.append(
            {
                "mutation_seed_id": row.get("mutation_seed_id", ""),
                "source_sample_id": row.get("source_sample_id", ""),
                "attack_type": attack_type,
                "attack_surface": row.get("attack_surface", ""),
                "input_format": row.get("input_format", ""),
                "engine_surface": surface,
                "allowed_families": ", ".join(families),
                "candidate_count": len(candidates),
                "candidate_ops": ", ".join(h.op_id for h in candidates),
            }
        )

    by_attack = Counter()
    zero_by_attack = Counter()

    for row in report_rows:
        by_attack[row["attack_type"]] += 1
        if row["candidate_count"] == 0:
            zero_by_attack[row["attack_type"]] += 1

    lines = [
        "# Mutation Input Operator Coverage v1",
        "",
        f"- input: `{INPUT.relative_to(PROJECT_ROOT).as_posix()}`",
        f"- total_rows: {len(report_rows)}",
        f"- loaded_operators: {len(registry.list_ops())}",
        "",
        "## Coverage by Attack Type",
        "",
        "| attack_type | rows | zero_candidate_rows |",
        "| --- | ---: | ---: |",
    ]

    for attack_type in sorted(by_attack):
        lines.append(
            f"| `{attack_type}` | {by_attack[attack_type]} | {zero_by_attack[attack_type]} |"
        )

    lines += [
        "",
        "## Per-row Coverage",
        "",
        "| mutation_seed_id | attack_type | surface | allowed_families | candidate_count | candidate_ops |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]

    for row in report_rows:
        lines.append(
            f"| `{row['mutation_seed_id']}` "
            f"| `{row['attack_type']}` "
            f"| `{row['engine_surface']}` "
            f"| `{row['allowed_families']}` "
            f"| {row['candidate_count']} "
            f"| `{row['candidate_ops']}` |"
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] wrote {OUTPUT.relative_to(PROJECT_ROOT)}")
    print(f"[OK] total rows: {len(report_rows)}")
    print(f"[OK] zero candidate rows: {sum(1 for r in report_rows if r['candidate_count'] == 0)}")


if __name__ == "__main__":
    main()
