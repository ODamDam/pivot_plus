from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

NORMALIZED_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "all_sources_normalized_v1.jsonl"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_markdown_rescan_v2"
)

ALL_OUTPUT = (
    OUTPUT_DIR
    / "markdown_rescan_candidates_all_v2.csv"
)

AUDIT_OUTPUT = (
    OUTPUT_DIR
    / "markdown_rescan_audit_v2.csv"
)

SUMMARY_OUTPUT = (
    PROJECT_ROOT
    / "reports"
    / "markdown_rescan_summary_v2.json"
)

# 기존 normalized Markdown 판정 완료본
EXISTING_MARKDOWN_PATHS = [
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_audit_v1"
    / "structure_audit_markdown_v1_completed.csv",

    PROJECT_ROOT
    / "data"
    / "review"
    / "external_structure_candidates"
    / "src10_scout450_v1"
    / "src10_scout450_markdown_candidates_v1_completed.csv",
]

# 다른 structure format으로 이미 선택된 사례와의 중복 방지
OTHER_STRUCTURE_KEEP_PATHS = [
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_audit_v1"
    / "structure_audit_json_v1_completed.csv",

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
    / "src10_scout450_json_candidates_v1_completed.csv",

    PROJECT_ROOT
    / "data"
    / "review"
    / "external_structure_candidates"
    / "src10_scout450_v1"
    / "src10_scout450_code_block_candidates_v1_completed.csv",

    PROJECT_ROOT
    / "data"
    / "review"
    / "external_structure_candidates"
    / "src11_bipia_v1"
    / "src11_bipia_code_selected_10_v1.csv",
]

# seed 250과의 중복도 제외
SEED_PATHS = [
    PROJECT_ROOT
    / "data"
    / "review"
    / "batches"
    / "seed_curation_250_v1.csv",
]

AUDIT_LIMIT = 120


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
                    f"Invalid JSONL at {path}:{line_number}"
                ) from exc

            if isinstance(row, dict):
                rows.append(row)

    return rows


def load_csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def row_text(row: dict[str, Any]) -> str:
    candidates = [
        row.get("scanner_input"),
        row.get("mutation_target_text"),
        row.get("prompt"),
        row.get("text"),
        row.get("input"),
        row.get("content"),
        row.get("user_input"),
        row.get("instruction"),
    ]

    for value in candidates:
        text = norm(value)

        if text:
            return text

    return ""


def load_excluded_hashes() -> set[str]:
    hashes: set[str] = set()

    for path in (
        EXISTING_MARKDOWN_PATHS
        + OTHER_STRUCTURE_KEEP_PATHS
        + SEED_PATHS
    ):
        for row in load_csv_rows(path):
            decision = norm(
                row.get("review_decision")
            ).lower()

            # 판정 파일은 keep만 제외
            if "completed" in path.name:
                if decision != "keep":
                    continue

            # 최종 선택 파일은 모든 행 제외
            text_hash = norm(row.get("text_sha256"))
            text = row_text(row)

            if not text_hash and text:
                text_hash = sha256_text(text)

            if text_hash:
                hashes.add(text_hash)

    return hashes


def is_malicious(row: dict[str, Any]) -> bool:
    values = [
        row.get("label"),
        row.get("verdict"),
        row.get("ground_truth"),
        row.get("ground_truth_decision"),
        row.get("is_malicious"),
        row.get("malicious"),
        row.get("class"),
    ]

    normalized = {
        norm(value).lower()
        for value in values
        if norm(value)
    }

    malicious_tokens = {
        "malicious",
        "attack",
        "1",
        "true",
        "prompt_injection",
        "injection",
        "jailbreak",
    }

    benign_tokens = {
        "benign",
        "safe",
        "0",
        "false",
        "normal",
    }

    if normalized & malicious_tokens:
        return True

    if normalized & benign_tokens:
        return False

    # 기존 normalized schema의 보조 필드 대응
    attack_type = norm(
        row.get("attack_type")
        or row.get("attack_category")
        or row.get("subtype")
    )

    return bool(attack_type)


def is_mutated(row: dict[str, Any]) -> bool:
    mutation_fields = [
        row.get("mutation_operator"),
        row.get("operator_id"),
        row.get("parent_seed_id"),
        row.get("mutation_id"),
        row.get("is_mutated"),
    ]

    return any(
        norm(value).lower()
        not in {"", "false", "0", "none", "null"}
        for value in mutation_fields
    )


def detect_markdown_features(
    text: str,
) -> dict[str, int]:
    features: dict[str, int] = {}

    features["atx_heading"] = len(
        re.findall(
            r"(?m)^\s{0,3}#{1,6}\s+\S",
            text,
        )
    )

    features["setext_heading"] = len(
        re.findall(
            r"(?m)^.+\n(?:={3,}|-{3,})\s*$",
            text,
        )
    )

    features["unordered_list"] = len(
        re.findall(
            r"(?m)^\s{0,3}[-*+]\s+\S",
            text,
        )
    )

    features["ordered_list"] = len(
        re.findall(
            r"(?m)^\s{0,3}\d+[.)]\s+\S",
            text,
        )
    )

    features["blockquote"] = len(
        re.findall(
            r"(?m)^\s{0,3}>\s+\S",
            text,
        )
    )

    features["table_row"] = len(
        re.findall(
            r"(?m)^\s*\|.+\|\s*$",
            text,
        )
    )

    features["table_separator"] = len(
        re.findall(
            r"(?m)^\s*\|?\s*:?-{3,}:?"
            r"(?:\s*\|\s*:?-{3,}:?)+\s*\|?\s*$",
            text,
        )
    )

    features["html_comment"] = len(
        re.findall(
            r"<!--[\s\S]*?-->",
            text,
        )
    )

    features["reference_link"] = len(
        re.findall(
            r"(?m)^\s*\[[^\]]+\]:\s+\S+",
            text,
        )
    )

    features["inline_link"] = len(
        re.findall(
            r"\[[^\]]+\]\([^)]+\)",
            text,
        )
    )

    features["task_list"] = len(
        re.findall(
            r"(?m)^\s*[-*+]\s+\[[ xX]\]\s+\S",
            text,
        )
    )

    features["emphasis"] = len(
        re.findall(
            r"(?<!\*)\*\*[^*\n]+\*\*(?!\*)"
            r"|(?<!_)__[^_\n]+__(?!_)",
            text,
        )
    )

    features["horizontal_rule"] = len(
        re.findall(
            r"(?m)^\s{0,3}(?:"
            r"\*{3,}|-{3,}|_{3,}"
            r")\s*$",
            text,
        )
    )

    features["fenced_block"] = len(
        re.findall(
            r"```[\s\S]+?```|~~~[\s\S]+?~~~",
            text,
        )
    )

    return features


def markdown_score(
    features: dict[str, int],
) -> tuple[int, list[str]]:
    active: list[str] = []
    score = 0

    weights = {
        "atx_heading": 3,
        "setext_heading": 3,
        "unordered_list": 2,
        "ordered_list": 2,
        "blockquote": 3,
        "table_row": 1,
        "table_separator": 3,
        "html_comment": 3,
        "reference_link": 2,
        "inline_link": 1,
        "task_list": 3,
        "emphasis": 1,
        "horizontal_rule": 1,
        "fenced_block": 2,
    }

    for name, count in features.items():
        if count <= 0:
            continue

        active.append(name)
        score += min(count, 3) * weights[name]

    # Markdown table은 row + separator 조합으로 추가 가점
    if (
        features["table_row"] >= 2
        and features["table_separator"] >= 1
    ):
        score += 4
        active.append("valid_markdown_table")

    # heading + section body
    if (
        features["atx_heading"]
        + features["setext_heading"]
        >= 1
        and len(active) >= 2
    ):
        score += 2
        active.append("structured_document")

    # list가 실제 여러 항목인 경우
    list_count = (
        features["unordered_list"]
        + features["ordered_list"]
        + features["task_list"]
    )

    if list_count >= 2:
        score += 3
        active.append("multi_item_list")

    return score, active


def is_strict_json(text: str) -> bool:
    try:
        parsed = json.loads(text.strip())
    except Exception:
        return False

    return isinstance(parsed, (dict, list))


def looks_like_yaml(text: str) -> bool:
    # 명확한 YAML document marker
    if re.search(r"(?m)^\s*---\s*$", text):
        return True

    mapping_lines = re.findall(
        r"(?m)^\s*[A-Za-z_][\w.-]*\s*:\s+\S",
        text,
    )

    return len(mapping_lines) >= 3


def code_fence_is_primary(
    text: str,
    features: dict[str, int],
) -> bool:
    """
    fenced block만 있고 Markdown 문서 구조가 거의 없는 경우
    code_block 후보로 보아 Markdown에서 제외한다.
    """
    if features["fenced_block"] == 0:
        return False

    document_features = (
        features["atx_heading"]
        + features["setext_heading"]
        + features["unordered_list"]
        + features["ordered_list"]
        + features["blockquote"]
        + features["table_separator"]
        + features["task_list"]
        + features["html_comment"]
    )

    return document_features == 0


def source_record_id(
    row: dict[str, Any],
    index: int,
) -> str:
    values = [
        row.get("source_record_id"),
        row.get("record_id"),
        row.get("sample_id"),
        row.get("id"),
        row.get("original_id"),
    ]

    for value in values:
        text = norm(value)

        if text:
            return text

    return f"normalized-row-{index:06d}"


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not rows:
        return

    fieldnames = list(rows[0].keys())

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


def audit_priority(row: dict[str, Any]) -> tuple:
    """
    source 편향을 줄이고 고득점 구조부터 audit하도록 정렬한다.
    """
    return (
        -int(row["markdown_score"]),
        row["source_id"],
        int(row["text_length"]),
        row["text_sha256"],
    )


def select_audit_rows(
    candidates: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """
    특정 source 하나가 audit batch를 독점하지 않도록 round-robin 선택.
    """
    by_source: dict[str, list[dict[str, Any]]] = {}

    for row in candidates:
        by_source.setdefault(
            row["source_id"],
            [],
        ).append(row)

    for rows in by_source.values():
        rows.sort(key=audit_priority)

    selected: list[dict[str, Any]] = []
    source_names = sorted(by_source)

    while len(selected) < limit:
        progressed = False

        for source_name in source_names:
            rows = by_source[source_name]

            if not rows:
                continue

            selected.append(rows.pop(0))
            progressed = True

            if len(selected) >= limit:
                break

        if not progressed:
            break

    return selected


def main() -> None:
    if not NORMALIZED_PATH.exists():
        raise FileNotFoundError(NORMALIZED_PATH)

    rows = load_jsonl(NORMALIZED_PATH)
    excluded_hashes = load_excluded_hashes()

    candidates: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    exclusion_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    feature_counts: Counter[str] = Counter()

    for index, row in enumerate(rows, start=1):
        if not is_malicious(row):
            exclusion_counts["not_malicious"] += 1
            continue

        if is_mutated(row):
            exclusion_counts["mutated"] += 1
            continue

        text = row_text(row)

        if not text:
            exclusion_counts["empty_text"] += 1
            continue

        text_hash = sha256_text(text)

        if text_hash in excluded_hashes:
            exclusion_counts["already_used_or_reviewed"] += 1
            continue

        if text_hash in seen_hashes:
            exclusion_counts["duplicate"] += 1
            continue

        if is_strict_json(text):
            exclusion_counts["strict_json"] += 1
            continue

        if looks_like_yaml(text):
            exclusion_counts["yaml_like"] += 1
            continue

        features = detect_markdown_features(text)
        score, active_features = markdown_score(features)

        if code_fence_is_primary(text, features):
            exclusion_counts["code_primary"] += 1
            continue

        # 최소 구조 조건:
        # 1) score 6 이상
        # 2) 실질 feature 2종 이상
        # 3) 단순 emphasis/link/구분선 조합만으로는 통과하지 않음
        substantive_features = {
            name
            for name in active_features
            if name
            not in {
                "emphasis",
                "inline_link",
                "horizontal_rule",
            }
        }

        if score < 6:
            exclusion_counts["low_markdown_score"] += 1
            continue

        if len(substantive_features) < 2:
            exclusion_counts[
                "insufficient_structure_diversity"
            ] += 1
            continue

        source_id = norm(
            row.get("source_id")
            or row.get("dataset_id")
            or row.get("source")
            or "UNKNOWN"
        )

        candidate = {
            "candidate_id": (
                f"MD-RESCAN-V2-{len(candidates) + 1:05d}"
            ),
            "source_id": source_id,
            "source_record_id": source_record_id(
                row,
                index,
            ),
            "text_sha256": text_hash,
            "scanner_input": text,
            "text_length": len(text),
            "candidate_structure_format": "markdown",
            "markdown_score": score,
            "markdown_features": "|".join(
                active_features
            ),
            "atx_heading_count": features[
                "atx_heading"
            ],
            "setext_heading_count": features[
                "setext_heading"
            ],
            "unordered_list_count": features[
                "unordered_list"
            ],
            "ordered_list_count": features[
                "ordered_list"
            ],
            "blockquote_count": features[
                "blockquote"
            ],
            "table_row_count": features[
                "table_row"
            ],
            "table_separator_count": features[
                "table_separator"
            ],
            "html_comment_count": features[
                "html_comment"
            ],
            "reference_link_count": features[
                "reference_link"
            ],
            "inline_link_count": features[
                "inline_link"
            ],
            "task_list_count": features[
                "task_list"
            ],
            "emphasis_count": features[
                "emphasis"
            ],
            "horizontal_rule_count": features[
                "horizontal_rule"
            ],
            "fenced_block_count": features[
                "fenced_block"
            ],
            "ground_truth_decision": "malicious",
            "structure_origin": "source_original",
            "provenance_status": (
                "traceable"
                if source_id != "UNKNOWN"
                else "review"
            ),
            "generation_method": "normalized_source_original",
            "structure_valid": "",
            "attack_semantics_valid": "",
            "provenance_valid": "",
            "review_decision": "",
            "review_note": "",
        }

        candidates.append(candidate)
        seen_hashes.add(text_hash)
        source_counts[source_id] += 1

        for feature in active_features:
            feature_counts[feature] += 1

    candidates.sort(key=audit_priority)

    audit_rows = select_audit_rows(
        candidates,
        AUDIT_LIMIT,
    )

    write_csv(
        ALL_OUTPUT,
        candidates,
    )

    write_csv(
        AUDIT_OUTPUT,
        audit_rows,
    )

    summary = {
        "input_rows": len(rows),
        "candidate_count": len(candidates),
        "audit_count": len(audit_rows),
        "audit_limit": AUDIT_LIMIT,
        "excluded_hash_count": len(excluded_hashes),
        "candidate_counts_by_source": dict(
            source_counts.most_common()
        ),
        "feature_counts": dict(
            feature_counts.most_common()
        ),
        "exclusion_counts": dict(
            exclusion_counts.most_common()
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
    print("[done] normalized Markdown expanded rescan v2")
    print(f"input rows      : {len(rows)}")
    print(f"candidates      : {len(candidates)}")
    print(f"audit rows      : {len(audit_rows)}")
    print(f"excluded hashes : {len(excluded_hashes)}")
    print("\ncandidates by source")

    for source_id, count in source_counts.most_common():
        print(f"  {source_id:<20}: {count}")

    print(f"\nall output  : {ALL_OUTPUT}")
    print(f"audit output: {AUDIT_OUTPUT}")
    print(f"summary     : {SUMMARY_OUTPUT}")
    print("=" * 72)


if __name__ == "__main__":
    main()