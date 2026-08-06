from __future__ import annotations

import csv
import hashlib
import json
import random
import re
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

EXISTING_KEEP_PATHS = [
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_audit_v1"
    / "structure_audit_code_block_v1_completed.csv",

    PROJECT_ROOT
    / "data"
    / "review"
    / "external_structure_candidates"
    / "src10_scout450_v1"
    / "src10_scout450_code_block_candidates_v1_completed.csv",
]

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "external_structure_candidates"
    / "src11_bipia_v1"
)

ALL_OUTPUT = (
    OUTPUT_DIR
    / "src11_bipia_code_candidates_all_v1.csv"
)

AUDIT_OUTPUT = (
    OUTPUT_DIR
    / "src11_bipia_code_audit_30_v1.csv"
)

SUMMARY_OUTPUT = (
    PROJECT_ROOT
    / "reports"
    / "src11_bipia_code_candidate_summary_v1.json"
)

SOURCE_ID = "SRC-11_microsoft_BIPIA"
SOURCE_DATASET = "microsoft/BIPIA"
RNG_SEED = 2023


def norm(value: Any) -> str:
    return str(value or "").strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL: {path}:{line_number}"
                ) from exc

            if not isinstance(row, dict):
                raise TypeError(
                    f"Expected object: {path}:{line_number}"
                )

            rows.append(row)

    return rows


def load_attacks(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)

    if not isinstance(raw, dict):
        raise TypeError(
            "BIPIA attack file root must be an object."
        )

    flattened: dict[str, str] = {}

    for category, attack_list in raw.items():
        if not isinstance(attack_list, list):
            continue

        for index, attack_text in enumerate(attack_list):
            text = norm(attack_text)

            if not text:
                continue

            attack_name = f"{category}-{index}"
            flattened[attack_name] = text

    return flattened


def load_existing_keep_hashes() -> set[str]:
    hashes: set[str] = set()

    for path in EXISTING_KEEP_PATHS:
        if not path.exists():
            continue

        with path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:
            for row in csv.DictReader(file):
                decision = norm(
                    row.get("review_decision")
                ).lower()

                if decision != "keep":
                    continue

                text_hash = norm(row.get("text_sha256"))
                text = norm(row.get("scanner_input"))

                if not text_hash and text:
                    text_hash = sha256_text(text)

                if text_hash:
                    hashes.add(text_hash)

    return hashes


def join_context(row: dict[str, Any]) -> str:
    context = row.get("context")

    if isinstance(context, list):
        return "\n".join(
            str(line)
            for line in context
        ).strip()

    return norm(context)


def insert_start(
    context: str,
    attack: str,
) -> str:
    return "\n".join([attack, context])


def insert_end(
    context: str,
    attack: str,
) -> str:
    return "\n".join([context, attack])


def sentence_boundaries(text: str) -> list[int]:
    """
    BIPIA의 PunktSentenceTokenizer 기반 middle insertion을
    외부 NLTK 의존성 없이 근사 재현한다.

    문장 종료 구두점 또는 줄바꿈 뒤를 후보 경계로 사용한다.
    """
    boundaries: set[int] = set()

    for match in re.finditer(
        r"(?<=[.!?])(?:[\"')\]]*)\s+",
        text,
    ):
        boundaries.add(match.end())

    for match in re.finditer(r"\n+", text):
        boundaries.add(match.end())

    valid = sorted(
        position
        for position in boundaries
        if 0 < position < len(text)
    )

    return valid


def insert_middle(
    context: str,
    attack: str,
    random_state: random.Random,
) -> tuple[str, int]:
    boundaries = sentence_boundaries(context)

    if not boundaries:
        middle = len(context) // 2
    else:
        middle = random_state.choice(boundaries)

    poisoned = "\n".join(
        [
            context[:middle],
            attack,
            context[middle:],
        ]
    )

    return poisoned, middle


def contains_fenced_code(text: str) -> bool:
    return bool(
        re.search(
            r"```(?:python|py|bash|sh|javascript|js|"
            r"java|c|cpp|go|rust|sql)?"
            r"\s*\n[\s\S]+?\n```",
            text,
            flags=re.IGNORECASE,
        )
    )


def contains_attack_code(text: str) -> bool:
    risky_patterns = [
        r"requests\.(?:post|get)\(",
        r"socket\.",
        r"subprocess\.",
        r"open\(.+['\"]r",
        r"pyautogui\.",
        r"platform\.",
        r"getpass\.",
        r"os\.environ",
        r"sendall?\(",
        r"scp",
        r"ssh\s+-",
    ]

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in risky_patterns
    )


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if not CONTEXT_PATH.exists():
        raise FileNotFoundError(CONTEXT_PATH)

    if not ATTACK_PATH.exists():
        raise FileNotFoundError(ATTACK_PATH)

    contexts = load_jsonl(CONTEXT_PATH)
    attacks = load_attacks(ATTACK_PATH)
    existing_hashes = load_existing_keep_hashes()

    rng = random.Random(RNG_SEED)

    generated: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    attack_items = sorted(attacks.items())
    positions = ["start", "middle", "end"]

    for context_index, context_row in enumerate(
        contexts,
        start=1,
    ):
        clean_context = join_context(context_row)

        if not clean_context:
            continue

        for attack_name, attack_str in attack_items:
            category, variant_text = attack_name.rsplit(
                "-",
                maxsplit=1,
            )
            attack_variant = int(variant_text)

            for position in positions:
                insertion_offset = ""

                if position == "start":
                    poisoned_context = insert_start(
                        clean_context,
                        attack_str,
                    )

                elif position == "end":
                    poisoned_context = insert_end(
                        clean_context,
                        attack_str,
                    )

                else:
                    poisoned_context, offset = insert_middle(
                        clean_context,
                        attack_str,
                        rng,
                    )
                    insertion_offset = offset

                text_hash = sha256_text(poisoned_context)

                if text_hash in existing_hashes:
                    continue

                if text_hash in seen_hashes:
                    continue

                if not contains_fenced_code(
                    poisoned_context
                ):
                    continue

                seen_hashes.add(text_hash)

                source_record_id = (
                    f"test-context-{context_index:03d}"
                    f"__{attack_name}"
                    f"__{position}"
                )

                generated.append(
                    {
                        "candidate_id": (
                            f"SRC11-STRUCT-"
                            f"{len(generated) + 1:05d}"
                        ),
                        "source_id": SOURCE_ID,
                        "source_dataset": SOURCE_DATASET,
                        "source_split": "test",
                        "source_record_id": source_record_id,
                        "context_index": context_index,
                        "context_url": norm(
                            context_row.get("context_url")
                        ),
                        "context_author_url": norm(
                            context_row.get(
                                "context_author_url"
                            )
                        ),
                        "attack_category": category,
                        "attack_variant": attack_variant,
                        "attack_name": attack_name,
                        "attack_str": attack_str,
                        "insertion_position": position,
                        "insertion_offset": insertion_offset,
                        "clean_context": clean_context,
                        "scanner_input": poisoned_context,
                        "text_sha256": text_hash,
                        "text_length": len(poisoned_context),
                        "candidate_structure_format": (
                            "code_block"
                        ),
                        "structure_detection_reason": (
                            "bipia_codeqa_fenced_attack"
                        ),
                        "ground_truth_decision": "malicious",
                        "attack_type": "tool_misuse",
                        "attack_surface": (
                            "indirect_repository_or_code_context"
                        ),
                        "structure_origin": (
                            "synthetic_source_original"
                        ),
                        "provenance_type": (
                            "open_source_synthetic"
                        ),
                        "provenance_status": "traceable",
                        "generation_method": (
                            "reproduced_official_bipia_builder"
                        ),
                        "builder_seed": RNG_SEED,
                        "structure_valid": "",
                        "attack_semantics_valid": "",
                        "provenance_valid": "",
                        "review_decision": "",
                        "review_note": "",
                    }
                )

    if not generated:
        raise RuntimeError(
            "No BIPIA candidates were generated."
        )

    # 공격 범주별로 start/middle/end 하나씩 골라 30개 audit 구성
    audit_rows: list[dict[str, Any]] = []

    categories = sorted(
        {
            row["attack_category"]
            for row in generated
        }
    )

    used_contexts: set[int] = set()

    for category_index, category in enumerate(categories):
        category_rows = [
            row
            for row in generated
            if row["attack_category"] == category
        ]

        for position_index, position in enumerate(positions):
            position_rows = [
                row
                for row in category_rows
                if row["insertion_position"] == position
            ]

            # 범주와 위치별로 context가 겹치지 않도록 우선 선택
            preferred = [
                row
                for row in position_rows
                if int(row["context_index"])
                not in used_contexts
            ]

            pool = preferred or position_rows

            pool.sort(
                key=lambda row: (
                    int(row["attack_variant"]),
                    int(row["context_index"]),
                    row["text_sha256"],
                )
            )

            selection_index = (
                category_index + position_index
            ) % len(pool)

            selected = dict(pool[selection_index])
            audit_rows.append(selected)
            used_contexts.add(
                int(selected["context_index"])
            )

    fieldnames = list(generated[0].keys())

    write_csv(
        ALL_OUTPUT,
        generated,
        fieldnames,
    )

    write_csv(
        AUDIT_OUTPUT,
        audit_rows,
        fieldnames,
    )

    category_counts: dict[str, int] = {}
    position_counts: dict[str, int] = {}

    for row in audit_rows:
        category = row["attack_category"]
        position = row["insertion_position"]

        category_counts[category] = (
            category_counts.get(category, 0) + 1
        )
        position_counts[position] = (
            position_counts.get(position, 0) + 1
        )

    summary = {
        "source_id": SOURCE_ID,
        "context_path": str(
            CONTEXT_PATH.relative_to(PROJECT_ROOT)
        ),
        "attack_path": str(
            ATTACK_PATH.relative_to(PROJECT_ROOT)
        ),
        "context_count": len(contexts),
        "flattened_attack_count": len(attacks),
        "generated_candidate_count": len(generated),
        "audit_candidate_count": len(audit_rows),
        "audit_counts_by_category": category_counts,
        "audit_counts_by_position": position_counts,
        "existing_keep_hash_count": len(
            existing_hashes
        ),
        "all_output": str(
            ALL_OUTPUT.relative_to(PROJECT_ROOT)
        ),
        "audit_output": str(
            AUDIT_OUTPUT.relative_to(PROJECT_ROOT)
        ),
    }

    SUMMARY_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    SUMMARY_OUTPUT.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 72)
    print("[done] BIPIA code structure candidate collection")
    print(f"contexts             : {len(contexts)}")
    print(f"flattened attacks    : {len(attacks)}")
    print(f"generated candidates : {len(generated)}")
    print(f"audit candidates     : {len(audit_rows)}")
    print("\naudit position counts")

    for position in positions:
        print(
            f"  {position:<8}: "
            f"{position_counts.get(position, 0)}"
        )

    print(f"\nall output  : {ALL_OUTPUT}")
    print(f"audit output: {AUDIT_OUTPUT}")
    print(f"summary     : {SUMMARY_OUTPUT}")
    print("=" * 72)


if __name__ == "__main__":
    main()