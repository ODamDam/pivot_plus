from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# 저장 위치가 다르면 자동 탐색합니다.
NORMALIZED_CANDIDATES = [
    PROJECT_ROOT / "data" / "normalized" / "all_sources_normalized_v1.jsonl",
    PROJECT_ROOT / "data" / "processed" / "all_sources_normalized_v1.jsonl",
    PROJECT_ROOT / "data" / "all_sources_normalized_v1.jsonl",
]

SEED_250_PATH = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "batches"
    / "seed_curation_250_v1.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_candidates_v1"
)

COMBINED_OUTPUT = (
    OUTPUT_DIR
    / "structure_intact_candidates_all_v1.csv"
)

SUMMARY_OUTPUT = (
    PROJECT_ROOT
    / "reports"
    / "structure_intact_candidate_extraction_summary_v1.json"
)

TARGET_FORMATS = {
    "markdown",
    "json",
    "yaml",
    "code_block",
    "repository_file",
}

# 자동 추출 단계에서는 넉넉하게 보존합니다.
MAX_CANDIDATES_PER_FORMAT = 250


def norm(value: Any) -> str:
    return str(value or "").strip()


def lower(value: Any) -> str:
    return norm(value).lower()


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


def find_normalized_path() -> Path:
    for path in NORMALIZED_CANDIDATES:
        if path.exists():
            return path

    matches = list(
        (PROJECT_ROOT / "data").rglob(
            "all_sources_normalized_v1.jsonl"
        )
    )

    if len(matches) == 1:
        return matches[0]

    if not matches:
        raise FileNotFoundError(
            "all_sources_normalized_v1.jsonl을 "
            "data 하위에서 찾지 못했습니다."
        )

    raise RuntimeError(
        "동일한 normalized 파일이 여러 개 발견됐습니다: "
        + ", ".join(str(path) for path in matches)
    )


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
                    f"Invalid JSONL: {path}:{line_number}: {exc}"
                ) from exc

            if isinstance(row, dict):
                rows.append(row)

    return rows


def load_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def get_text(row: dict[str, Any]) -> str:
    candidates = [
        row.get("scanner_input"),
        row.get("scanner_input_prompt_only"),
        row.get("text"),
        row.get("prompt"),
        row.get("content"),
        row.get("input"),
        row.get("user_prompt"),
    ]

    for value in candidates:
        text = norm(value)

        if text:
            return text

    return ""


def is_true(value: Any) -> bool:
    return lower(value) in {
        "true",
        "1",
        "yes",
        "y",
    }


def is_malicious(row: dict[str, Any]) -> bool:
    decision = lower(
        row.get("ground_truth_decision")
        or row.get("decision")
        or row.get("verdict")
    )

    label = lower(
        row.get("label")
        or row.get("original_label")
        or row.get("class")
    )

    malicious_flag = row.get("is_malicious")

    if decision in {
        "malicious",
        "attack",
        "unsafe",
        "prompt_injection",
    }:
        return True

    if label in {
        "malicious",
        "attack",
        "unsafe",
        "prompt_injection",
        "1",
    }:
        return True

    return is_true(malicious_flag)


def is_mutated(row: dict[str, Any]) -> bool:
    if is_true(row.get("is_mutated")):
        return True

    subset = lower(row.get("subset"))

    if subset == "mutated_malicious":
        return True

    mutation_operator = norm(
        row.get("mutation_operator")
        or row.get("selected_op_id")
    )

    return bool(mutation_operator)


def declared_format(row: dict[str, Any]) -> str:
    value = lower(
        row.get("input_format")
        or row.get("format")
        or row.get("content_type")
    )

    aliases = {
        "md": "markdown",
        "markdown_text": "markdown",
        "jsonl": "json",
        "yml": "yaml",
        "code": "code_block",
        "source_code": "code_block",
        "codeblock": "code_block",
        "repository": "repository_file",
        "repo_file": "repository_file",
        "repository-file": "repository_file",
    }

    return aliases.get(value, value)


def detect_json(text: str) -> tuple[bool, str]:
    stripped = text.strip()

    if not (
        stripped.startswith("{")
        or stripped.startswith("[")
    ):
        return False, ""

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return False, ""

    if isinstance(parsed, dict):
        return True, "strict_json_object"

    if isinstance(parsed, list):
        return True, "strict_json_array"

    return False, ""


def detect_yaml(text: str) -> tuple[bool, str]:
    stripped = text.strip()

    # JSON은 YAML의 부분집합이므로 먼저 제외합니다.
    json_ok, _ = detect_json(stripped)

    if json_ok:
        return False, ""

    try:
        import yaml  # type: ignore

        parsed = yaml.safe_load(stripped)

        if isinstance(parsed, dict) and len(parsed) >= 1:
            return True, "yaml_mapping_parse_success"

        if isinstance(parsed, list) and len(parsed) >= 2:
            return True, "yaml_sequence_parse_success"

    except (ImportError, Exception):
        pass

    key_value_lines = re.findall(
        r"(?m)^[ \t]*[A-Za-z_][\w.-]*[ \t]*:[ \t]*.+$",
        stripped,
    )

    multiline_markers = re.findall(
        r"(?m)^[ \t]*[A-Za-z_][\w.-]*[ \t]*:[ \t]*[>|][+-]?[ \t]*$",
        stripped,
    )

    if len(key_value_lines) >= 2:
        return True, "yaml_key_value_heuristic"

    if key_value_lines and multiline_markers:
        return True, "yaml_multiline_heuristic"

    return False, ""


def detect_code_block(text: str) -> tuple[bool, str]:
    fenced = re.search(
        r"```(?:python|py|javascript|js|typescript|ts|"
        r"bash|sh|shell|powershell|ps1|java|c|cpp|"
        r"csharp|cs|go|rust|ruby|php|sql|html|xml)?"
        r"\s*\n[\s\S]+?\n```",
        text,
        flags=re.IGNORECASE,
    )

    if fenced:
        return True, "fenced_code_block"

    code_patterns = [
        r"(?m)^\s*(def|class|function)\s+\w+",
        r"(?m)^\s*(import|from)\s+[\w.]+",
        r"(?m)^\s*(const|let|var)\s+\w+\s*=",
        r"(?m)^\s*#include\s*[<\"]",
        r"(?m)^\s*(public|private|protected)\s+"
        r"(class|static|void|int|string)",
        r"(?m)^\s*(if|for|while)\s*\(.+\)\s*\{",
        r"(?m)^\s*#!/(?:usr/)?bin/",
        r"(?m)^\s*(SELECT|INSERT|UPDATE|DELETE)\s+",
    ]

    hits = sum(
        bool(re.search(pattern, text, re.IGNORECASE))
        for pattern in code_patterns
    )

    if hits >= 2:
        return True, "multi_pattern_source_code"

    return False, ""


def detect_markdown(text: str) -> tuple[bool, str]:
    features = {
        "heading": bool(
            re.search(r"(?m)^\s{0,3}#{1,6}\s+\S", text)
        ),
        "bullet_list": bool(
            re.search(r"(?m)^\s*[-*+]\s+\S", text)
        ),
        "numbered_list": bool(
            re.search(r"(?m)^\s*\d+\.\s+\S", text)
        ),
        "blockquote": bool(
            re.search(r"(?m)^\s*>\s+\S", text)
        ),
        "link": bool(
            re.search(r"\[[^\]]+\]\([^)]+\)", text)
        ),
        "emphasis": bool(
            re.search(r"(\*\*[^*\n]+\*\*|__[^_\n]+__)", text)
        ),
        "fence": "```" in text,
        "table": bool(
            re.search(
                r"(?m)^\s*\|.+\|\s*$\n"
                r"^\s*\|?\s*:?-{3,}",
                text,
            )
        ),
    }

    active = [
        key
        for key, value in features.items()
        if value
    ]

    if len(active) >= 2:
        return True, "markdown_features:" + ",".join(active)

    if "heading" in active and len(text.splitlines()) >= 3:
        return True, "markdown_heading_document"

    return False, ""


def detect_repository_file(
    row: dict[str, Any],
    text: str,
) -> tuple[bool, str]:
    declared = declared_format(row)
    source_id = lower(row.get("source_id"))
    source_record_id = lower(row.get("source_record_id"))
    metadata = lower(row.get("metadata_json"))

    if declared == "repository_file":
        return True, "declared_repository_file"

    if "src-07" in source_id or "prodnull" in source_id:
        return True, "repository_dataset_source"

    extension_pattern = (
        r"\.(md|rst|txt|py|js|ts|java|go|rs|c|cpp|h|"
        r"json|ya?ml|toml|ini|cfg|xml|html)$"
    )

    if re.search(extension_pattern, source_record_id):
        return True, "repository_path_extension"

    repository_terms = [
        "readme",
        "pull request",
        "repository",
        "source file",
        "configuration file",
        "package.json",
        "dockerfile",
        ".github/",
    ]

    combined = f"{source_record_id}\n{metadata}\n{text[:500]}".lower()

    if any(term in combined for term in repository_terms):
        return True, "repository_context_terms"

    return False, ""


def assign_primary_format(
    row: dict[str, Any],
    text: str,
) -> tuple[str, str]:
    declared = declared_format(row)

    detectors = {
        "json": detect_json(text),
        "yaml": detect_yaml(text),
        "code_block": detect_code_block(text),
        "markdown": detect_markdown(text),
        "repository_file": detect_repository_file(
            row,
            text,
        ),
    }

    # 명시된 형식이 실제 detector로 검증되면 우선합니다.
    if declared in TARGET_FORMATS:
        matched, reason = detectors[declared]

        if matched:
            return declared, (
                f"declared_and_verified:{reason}"
            )

    # repository_file은 문서 컨텍스트 자체가 핵심인 별도 축입니다.
    if detectors["repository_file"][0]:
        return (
            "repository_file",
            detectors["repository_file"][1],
        )

    # 구조 구문이 명확한 형식부터 우선합니다.
    for format_name in [
        "json",
        "yaml",
        "code_block",
        "markdown",
    ]:
        matched, reason = detectors[format_name]

        if matched:
            return format_name, reason

    # 선언값만 있고 실제 구조 검증에 실패한 경우에는 후보로 넣되
    # 반드시 수동 검토 대상으로 표시합니다.
    if declared in TARGET_FORMATS:
        return declared, "declared_only_unverified"

    return "", ""


def eligible_record(
    row: dict[str, Any],
    text: str,
) -> tuple[bool, str]:
    if not text:
        return False, "missing_text"

    if not is_malicious(row):
        return False, "not_malicious"

    if is_mutated(row):
        return False, "mutated_record"

    if len(text) < 12:
        return False, "too_short"

    return True, "eligible"


def main() -> None:
    normalized_path = find_normalized_path()

    normalized_rows = load_jsonl(normalized_path)
    seed_rows = load_csv(SEED_250_PATH)

    seed_hashes = {
        norm(row.get("text_sha256"))
        or sha256_text(get_text(row))
        for row in seed_rows
        if get_text(row)
    }

    candidates: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    exclusion_counts: Counter[str] = Counter()
    format_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    detection_counts: Counter[str] = Counter()

    for row_index, row in enumerate(
        normalized_rows,
        start=1,
    ):
        text = get_text(row)

        allowed, exclusion_reason = eligible_record(
            row,
            text,
        )

        if not allowed:
            exclusion_counts[exclusion_reason] += 1
            continue

        text_hash = (
            norm(row.get("text_sha256"))
            or sha256_text(text)
        )

        if text_hash in seed_hashes:
            exclusion_counts["overlap_seed250"] += 1
            continue

        if text_hash in seen_hashes:
            exclusion_counts["duplicate_text"] += 1
            continue

        structure_format, detection_reason = (
            assign_primary_format(row, text)
        )

        if not structure_format:
            exclusion_counts["no_target_structure"] += 1
            continue

        seen_hashes.add(text_hash)

        candidate = {
            "candidate_id": (
                f"STRUCT-CAND-{len(candidates) + 1:06d}"
            ),
            "normalized_row_index": row_index,
            "source_id": norm(row.get("source_id")),
            "source_record_id": norm(
                row.get("source_record_id")
            ),
            "source_split": norm(row.get("source_split")),
            "normalized_record_id": norm(
                row.get("normalized_record_id")
            ),
            "text_sha256": text_hash,
            "scanner_input": text,
            "scanner_input_preview": (
                text[:300].replace("\r", " ").replace("\n", "\\n")
            ),
            "attack_type": norm(row.get("attack_type")),
            "attack_goal": norm(row.get("attack_goal")),
            "attack_surface": norm(
                row.get("attack_surface")
            ),
            "declared_input_format": declared_format(row),
            "candidate_structure_format": structure_format,
            "structure_detection_reason": detection_reason,
            "text_length": len(text),
            "ground_truth_decision": (
                norm(row.get("ground_truth_decision"))
                or "malicious"
            ),
            "provenance_type": "normalized_open_source",
            "provenance_status": (
                "traceable"
                if norm(row.get("source_id"))
                and norm(row.get("source_record_id"))
                else "incomplete"
            ),
            # 수동 검토 입력 칼럼
            "structure_valid": "",
            "attack_semantics_valid": "",
            "provenance_valid": "",
            "review_decision": "",
            "review_note": "",
        }

        candidates.append(candidate)
        format_counts[structure_format] += 1
        source_counts[candidate["source_id"] or "unknown"] += 1
        detection_counts[detection_reason] += 1

    # 형식별 길이 범위를 고르게 검토할 수 있도록 정렬합니다.
    selected_for_review: list[dict[str, Any]] = []

    for format_name in sorted(TARGET_FORMATS):
        format_rows = [
            row
            for row in candidates
            if row["candidate_structure_format"]
            == format_name
        ]

        format_rows.sort(
            key=lambda row: (
                int(row["text_length"]),
                str(row["source_id"]),
                str(row["text_sha256"]),
            )
        )

        if len(format_rows) <= MAX_CANDIDATES_PER_FORMAT:
            selected_for_review.extend(format_rows)
            continue

        # 전체 길이 분포에서 균등 간격으로 최대 250개 선택
        spread: list[dict[str, Any]] = []

        for index in range(MAX_CANDIDATES_PER_FORMAT):
            position = round(
                index
                * (len(format_rows) - 1)
                / (MAX_CANDIDATES_PER_FORMAT - 1)
            )
            spread.append(format_rows[position])

        selected_for_review.extend(spread)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "candidate_id",
        "normalized_row_index",
        "source_id",
        "source_record_id",
        "source_split",
        "normalized_record_id",
        "text_sha256",
        "scanner_input",
        "scanner_input_preview",
        "attack_type",
        "attack_goal",
        "attack_surface",
        "declared_input_format",
        "candidate_structure_format",
        "structure_detection_reason",
        "text_length",
        "ground_truth_decision",
        "provenance_type",
        "provenance_status",
        "structure_valid",
        "attack_semantics_valid",
        "provenance_valid",
        "review_decision",
        "review_note",
    ]

    with COMBINED_OUTPUT.open(
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
        writer.writerows(selected_for_review)

    for format_name in sorted(TARGET_FORMATS):
        format_output = (
            OUTPUT_DIR
            / f"structure_candidates_{format_name}_v1.csv"
        )

        rows_for_format = [
            row
            for row in selected_for_review
            if row["candidate_structure_format"]
            == format_name
        ]

        with format_output.open(
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
            writer.writerows(rows_for_format)

    summary = {
        "normalized_input": str(
            normalized_path.relative_to(PROJECT_ROOT)
        ),
        "normalized_row_count": len(normalized_rows),
        "seed250_hash_count": len(seed_hashes),
        "all_detected_candidate_count": len(candidates),
        "review_export_count": len(selected_for_review),
        "candidate_counts_by_format": dict(
            sorted(format_counts.items())
        ),
        "review_counts_by_format": dict(
            Counter(
                row["candidate_structure_format"]
                for row in selected_for_review
            )
        ),
        "candidate_counts_by_source": dict(
            source_counts.most_common()
        ),
        "detection_reason_counts": dict(
            detection_counts.most_common()
        ),
        "exclusion_counts": dict(
            exclusion_counts.most_common()
        ),
        "output_directory": str(
            OUTPUT_DIR.relative_to(PROJECT_ROOT)
        ),
    }

    SUMMARY_OUTPUT.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 72)
    print("[done] structure-intact candidate extraction")
    print(f"normalized input : {normalized_path}")
    print(f"input rows       : {len(normalized_rows)}")
    print(f"candidates       : {len(candidates)}")
    print(f"review exported  : {len(selected_for_review)}")
    print("\nformat counts")

    for format_name in sorted(TARGET_FORMATS):
        print(
            f"  {format_name:<16}: "
            f"{format_counts[format_name]}"
        )

    print(f"\ncombined csv     : {COMBINED_OUTPUT}")
    print(f"summary          : {SUMMARY_OUTPUT}")
    print("=" * 72)


if __name__ == "__main__":
    main()