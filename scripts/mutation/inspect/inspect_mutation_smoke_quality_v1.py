from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


INPUT = Path("data/final/mutation_smoke_output_v1.jsonl")
OUTPUT = Path("reports/mutation_smoke_quality_v1.md")


def load_rows(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def changed(original: str, mutated: str) -> bool:
    return original != mutated


def length_ratio(original: str, mutated: str) -> float:
    if not original:
        return 0.0
    return len(mutated) / max(len(original), 1)


def main() -> None:
    rows = load_rows(INPUT)

    status_counts = Counter(r.get("status", "") for r in rows)
    operator_counts = Counter(r.get("mutation_operator", "") for r in rows)
    family_counts = Counter(r.get("mutation_family", "") for r in rows)
    attack_counts = Counter(r.get("attack_type", "") for r in rows)

    blank_operator = [r for r in rows if not r.get("mutation_operator")]
    blank_family = [r for r in rows if not r.get("mutation_family")]
    unchanged = [
        r for r in rows
        if not changed(str(r.get("original_text", "")), str(r.get("mutated_text", "")))
    ]
    empty_mutated = [r for r in rows if not str(r.get("mutated_text", "")).strip()]

    long_growth = [
        r for r in rows
        if length_ratio(str(r.get("original_text", "")), str(r.get("mutated_text", ""))) > 3.0
    ]

    lines = [
        "# Mutation Smoke Quality Report v1",
        "",
        f"- input_file: `{INPUT.as_posix()}`",
        f"- total_rows: {len(rows)}",
        f"- blank_operator_rows: {len(blank_operator)}",
        f"- blank_family_rows: {len(blank_family)}",
        f"- unchanged_rows: {len(unchanged)}",
        f"- empty_mutated_rows: {len(empty_mutated)}",
        f"- long_growth_rows_ratio_gt_3: {len(long_growth)}",
        "",
        "## Status Counts",
        "",
        "| status | count |",
        "| --- | ---: |",
    ]

    for k, v in sorted(status_counts.items()):
        lines.append(f"| `{k}` | {v} |")

    lines += [
        "",
        "## Operator Counts",
        "",
        "| operator | count |",
        "| --- | ---: |",
    ]

    for k, v in sorted(operator_counts.items()):
        shown = k if k else "<blank>"
        lines.append(f"| `{shown}` | {v} |")

    lines += [
        "",
        "## Family Counts",
        "",
        "| family | count |",
        "| --- | ---: |",
    ]

    for k, v in sorted(family_counts.items()):
        shown = k if k else "<blank>"
        lines.append(f"| `{shown}` | {v} |")

    lines += [
        "",
        "## Attack Type Counts",
        "",
        "| attack_type | count |",
        "| --- | ---: |",
    ]

    for k, v in sorted(attack_counts.items()):
        lines.append(f"| `{k}` | {v} |")

    lines += [
        "",
        "## Rows Requiring Attention",
        "",
        "| issue | mutation_id | operator | family | attack_type | note |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for r in blank_operator:
        lines.append(
            f"| blank_operator | `{r.get('mutation_id', '')}` | `{r.get('mutation_operator', '')}` "
            f"| `{r.get('mutation_family', '')}` | `{r.get('attack_type', '')}` | missing operator metadata |"
        )

    for r in unchanged:
        lines.append(
            f"| unchanged | `{r.get('mutation_id', '')}` | `{r.get('mutation_operator', '')}` "
            f"| `{r.get('mutation_family', '')}` | `{r.get('attack_type', '')}` | mutated text equals original |"
        )

    for r in empty_mutated:
        lines.append(
            f"| empty_mutated | `{r.get('mutation_id', '')}` | `{r.get('mutation_operator', '')}` "
            f"| `{r.get('mutation_family', '')}` | `{r.get('attack_type', '')}` | empty mutated text |"
        )

    for r in long_growth:
        ratio = length_ratio(str(r.get("original_text", "")), str(r.get("mutated_text", "")))
        lines.append(
            f"| long_growth | `{r.get('mutation_id', '')}` | `{r.get('mutation_operator', '')}` "
            f"| `{r.get('mutation_family', '')}` | `{r.get('attack_type', '')}` | len ratio {ratio:.2f} |"
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8")

    print(f"[OK] wrote {OUTPUT}")
    print(f"[OK] total_rows={len(rows)} blank_operator={len(blank_operator)} unchanged={len(unchanged)} empty={len(empty_mutated)}")


if __name__ == "__main__":
    main()
