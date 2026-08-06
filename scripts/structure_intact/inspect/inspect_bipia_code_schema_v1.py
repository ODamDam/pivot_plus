from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

BIPIA_ROOT = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "src11_microsoft_bipia"
)

FILES = {
    "context_train": (
        BIPIA_ROOT
        / "benchmark"
        / "code"
        / "train.jsonl"
    ),
    "context_test": (
        BIPIA_ROOT
        / "benchmark"
        / "code"
        / "test.jsonl"
    ),
    "attack_train": (
        BIPIA_ROOT
        / "benchmark"
        / "code_attack_train.json"
    ),
    "attack_test": (
        BIPIA_ROOT
        / "benchmark"
        / "code_attack_test.json"
    ),
}


def preview(value: Any, limit: int = 700) -> str:
    text = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
    )

    if len(text) <= limit:
        return text

    return text[:limit] + "\n...<truncated>"


def inspect_jsonl(path: Path) -> None:
    count = 0
    first_rows: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            row = json.loads(line)
            count += 1

            if len(first_rows) < 3:
                first_rows.append(row)

    print(f"rows: {count}")

    for index, row in enumerate(
        first_rows,
        start=1,
    ):
        print(f"\nrow {index}")
        print("keys:", sorted(row.keys()))
        print(preview(row))


def inspect_json(path: Path) -> None:
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    print("root type:", type(data).__name__)

    if isinstance(data, list):
        print("items:", len(data))

        for index, item in enumerate(
            data[:3],
            start=1,
        ):
            print(f"\nitem {index}")

            if isinstance(item, dict):
                print("keys:", sorted(item.keys()))

            print(preview(item))

    elif isinstance(data, dict):
        print("root keys:", sorted(data.keys()))

        for key in list(data.keys())[:5]:
            value = data[key]
            print(f"\nkey: {key}")
            print("value type:", type(value).__name__)
            print(preview(value))


def main() -> None:
    print("=" * 72)
    print("[BIPIA CodeQA schema inspection]")
    print("=" * 72)

    for name, path in FILES.items():
        print(f"\n{'-' * 72}")
        print(name)
        print(path)
        print(f"exists: {path.exists()}")

        if not path.exists():
            continue

        print(f"size: {path.stat().st_size} bytes")

        if path.suffix == ".jsonl":
            inspect_jsonl(path)
        else:
            inspect_json(path)

    print(f"\n{'=' * 72}")
    print("[done]")
    print("=" * 72)


if __name__ == "__main__":
    main()