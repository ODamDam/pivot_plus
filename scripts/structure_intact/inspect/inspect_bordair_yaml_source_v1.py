from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def find_project_root(start: Path) -> Path:
    current = start.resolve()

    for candidate in [current, *current.parents]:
        if (
            (candidate / "data").is_dir()
            and (candidate / "scripts").is_dir()
        ):
            return candidate

    raise FileNotFoundError(
        "data/와 scripts/가 함께 존재하는 프로젝트 루트를 "
        "찾지 못했습니다."
    )


PROJECT_ROOT = find_project_root(
    Path(__file__).parent
)

BORDAIR_ROOT = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "src12_bordair_multimodal"
)

TARGET_DIRS = {
    "structured_data_injection": (
        BORDAIR_ROOT
        / "payloads_v3"
        / "structured_data_injection"
    ),
    "serialization_boundary_rce": (
        BORDAIR_ROOT
        / "payloads_v5"
        / "serialization_boundary_rce"
    ),
}


def preview(
    value: Any,
    limit: int = 1600,
) -> str:
    text = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        default=str,
    )

    if len(text) <= limit:
        return text

    return text[:limit] + "\n...<truncated>"


def load_json_file(
    path: Path,
) -> list[dict[str, Any]]:
    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    if isinstance(data, list):
        return [
            row
            for row in data
            if isinstance(row, dict)
        ]

    if isinstance(data, dict):
        # 단일 payload
        if any(
            key in data
            for key in {
                "text",
                "payload",
                "content",
                "id",
                "category",
            }
        ):
            return [data]

        # 이름별 payload collection
        rows: list[dict[str, Any]] = []

        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        copied = dict(item)
                        copied.setdefault(
                            "_collection_key",
                            key,
                        )
                        rows.append(copied)

        return rows

    return []


def load_jsonl_file(
    path: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

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

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL: {path}:{line_number}"
                ) from exc

            if isinstance(row, dict):
                rows.append(row)

    return rows


def load_file(
    path: Path,
) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        return load_jsonl_file(path)

    if path.suffix.lower() == ".json":
        return load_json_file(path)

    return []


def candidate_text(
    row: dict[str, Any],
) -> str:
    for key in [
        "text",
        "payload",
        "content",
        "doc_content",
        "image_content",
        "attack",
        "prompt",
    ]:
        value = row.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip()

    return ""


def main() -> None:
    print(
        f"[info] project root: {PROJECT_ROOT}"
    )
    print(
        f"[info] Bordair root: {BORDAIR_ROOT}"
    )

    total_rows = 0

    for category, directory in TARGET_DIRS.items():
        print("\n" + "=" * 72)
        print(category)
        print(directory)
        print(f"exists: {directory.exists()}")

        if not directory.exists():
            continue

        paths = sorted(
            [
                path
                for path in directory.rglob("*")
                if path.is_file()
                and path.suffix.lower()
                in {".json", ".jsonl"}
            ]
        )

        print(f"data files: {len(paths)}")

        category_rows: list[
            tuple[Path, dict[str, Any]]
        ] = []

        for path in paths:
            rows = load_file(path)

            for row in rows:
                category_rows.append(
                    (path, row)
                )

        total_rows += len(category_rows)

        print(
            f"payload rows: {len(category_rows)}"
        )

        key_counts: dict[str, int] = {}

        for _, row in category_rows:
            for key in row:
                key_counts[key] = (
                    key_counts.get(key, 0) + 1
                )

        print("common fields:")

        for key, count in sorted(
            key_counts.items(),
            key=lambda item: (
                -item[1],
                item[0],
            ),
        )[:30]:
            print(f"  {key:<30}: {count}")

        for index, (path, row) in enumerate(
            category_rows[:5],
            start=1,
        ):
            print("\n" + "-" * 72)
            print(f"sample {index}")
            print(
                "file:",
                path.relative_to(PROJECT_ROOT),
            )
            print(
                "keys:",
                sorted(row.keys()),
            )
            print(
                "candidate text:"
            )
            print(
                candidate_text(row)[:1200]
            )
            print("\nfull record:")
            print(preview(row))

    print("\n" + "=" * 72)
    print(f"total rows: {total_rows}")
    print("[done]")
    print("=" * 72)


if __name__ == "__main__":
    main()