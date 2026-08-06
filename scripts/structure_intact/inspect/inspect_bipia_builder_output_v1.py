# BIPIA가 실제로 생성하는 결합 데이터의 필드와 공격 삽입 형태를 확인하는 스크립트

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

BIPIA_ROOT = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "src11_microsoft_bipia"
)

CONTEXT_PATH = (
    BIPIA_ROOT
    / "benchmark"
    / "code"
    / "test.jsonl"
)

ATTACK_PATH = (
    BIPIA_ROOT
    / "benchmark"
    / "code_attack_test.json"
)


def preview(value: Any, limit: int = 1800) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()

    text = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        default=str,
    )

    if len(text) <= limit:
        return text

    return text[:limit] + "\n...<truncated>"


def main() -> None:
    if not BIPIA_ROOT.exists():
        raise FileNotFoundError(
            f"BIPIA repository not found: {BIPIA_ROOT}"
        )

    if not CONTEXT_PATH.exists():
        raise FileNotFoundError(CONTEXT_PATH)

    if not ATTACK_PATH.exists():
        raise FileNotFoundError(ATTACK_PATH)

    # Clone한 BIPIA package를 현재 Python path에 추가
    sys.path.insert(0, str(BIPIA_ROOT))

    try:
        from bipia import AutoPIABuilder
    except ImportError as exc:
        raise RuntimeError(
            "BIPIA package import에 실패했습니다.\n"
            "먼저 다음 명령을 실행하세요:\n"
            "python -m pip install -e "
            ".\\data\\raw\\src11_microsoft_bipia"
        ) from exc

    builder_class = AutoPIABuilder.from_name("code")
    builder = builder_class(seed=2023)

    samples = builder(
        str(CONTEXT_PATH),
        str(ATTACK_PATH),
        enable_stealth=False,
    )

    print("=" * 72)
    print("[BIPIA official builder output inspection]")
    print("=" * 72)

    print("output type:", type(samples).__name__)

    if hasattr(samples, "shape"):
        print("shape:", samples.shape)

    if hasattr(samples, "columns"):
        print("columns:")
        for column in samples.columns:
            print(f"  - {column}")

    if hasattr(samples, "head"):
        preview_rows = samples.head(3).to_dict(
            orient="records"
        )
    elif isinstance(samples, list):
        preview_rows = samples[:3]
    else:
        raise TypeError(
            f"Unsupported builder output: {type(samples)}"
        )

    for index, row in enumerate(
        preview_rows,
        start=1,
    ):
        print(f"\n{'-' * 72}")
        print(f"sample {index}")

        if isinstance(row, dict):
            print("keys:", sorted(row.keys()))

        print(preview(row))

    print(f"\n{'=' * 72}")
    print("[done]")
    print("=" * 72)


if __name__ == "__main__":
    main()