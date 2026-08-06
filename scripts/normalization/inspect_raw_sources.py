from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


RAW_DIR = Path("data/raw")
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CSV_OUT = REPORT_DIR / "source_schema_summary.csv"
MD_OUT = REPORT_DIR / "source_schema_summary.md"


TEXT_HINTS = [
    "text", "prompt", "input", "instruction", "query",
    "content", "message", "user", "system"
]

LABEL_HINTS = [
    "label", "class", "category", "severity", "degree",
    "injection", "jailbreak", "attack"
]


def detect_source_id(path: Path) -> str:
    rel = path.relative_to(RAW_DIR)
    return rel.parts[0] if rel.parts else ""


def detect_split(path: Path) -> str:
    name = path.name.lower()
    if "train" in name:
        return "train"
    if "test" in name:
        return "test"
    if "validation" in name or "valid" in name:
        return "validation"
    return "unknown"


def safe_preview(value: Any, limit: int = 160) -> str:
    if value is None:
        return ""
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    return text[:limit]


def infer_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return type(value).__name__


def summarize_jsonl(path: Path) -> dict[str, Any]:
    row_count = 0
    parse_errors = 0
    keys_seen: dict[str, str] = {}
    first_row: dict[str, Any] | None = None

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            row_count += 1

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue

            if isinstance(obj, dict):
                if first_row is None:
                    first_row = obj

                for k, v in obj.items():
                    if k not in keys_seen:
                        keys_seen[k] = infer_type(v)

    columns = list(keys_seen.keys())

    text_like_columns = [
        c for c in columns
        if any(h in c.lower() for h in TEXT_HINTS)
    ]

    label_like_columns = [
        c for c in columns
        if any(h in c.lower() for h in LABEL_HINTS)
    ]

    sample_values = {}
    if first_row:
        for c in columns:
            sample_values[c] = safe_preview(first_row.get(c))

    return {
        "source_id": detect_source_id(path),
        "relative_path": str(path.as_posix()),
        "split": detect_split(path),
        "is_preview": "preview" in path.name.lower(),
        "row_count": row_count,
        "parse_errors": parse_errors,
        "columns": "; ".join(columns),
        "column_types": json.dumps(keys_seen, ensure_ascii=False),
        "text_like_columns": "; ".join(text_like_columns),
        "label_like_columns": "; ".join(label_like_columns),
        "sample_values": json.dumps(sample_values, ensure_ascii=False),
    }


def main() -> None:
    jsonl_files = sorted(RAW_DIR.rglob("*.jsonl"))

    # preview 파일은 실제 source schema 확인에는 보조용이라 기본 요약에서는 제외한다.
    target_files = [
        p for p in jsonl_files
        if "preview" not in p.name.lower()
    ]

    rows = [summarize_jsonl(path) for path in target_files]

    fieldnames = [
        "source_id",
        "relative_path",
        "split",
        "is_preview",
        "row_count",
        "parse_errors",
        "columns",
        "column_types",
        "text_like_columns",
        "label_like_columns",
        "sample_values",
    ]

    with CSV_OUT.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with MD_OUT.open("w", encoding="utf-8") as f:
        f.write("# Source Schema Summary\n\n")
        f.write("| source_id | split | rows | parse_errors | path | columns | text_like | label_like |\n")
        f.write("| --- | --- | ---: | ---: | --- | --- | --- | --- |\n")

        for r in rows:
            f.write(
                f"| {r['source_id']} "
                f"| {r['split']} "
                f"| {r['row_count']} "
                f"| {r['parse_errors']} "
                f"| `{r['relative_path']}` "
                f"| {r['columns']} "
                f"| {r['text_like_columns']} "
                f"| {r['label_like_columns']} |\n"
            )

    print(f"[OK] wrote {CSV_OUT}")
    print(f"[OK] wrote {MD_OUT}")
    print(f"[OK] inspected {len(rows)} jsonl files")


if __name__ == "__main__":
    main()
