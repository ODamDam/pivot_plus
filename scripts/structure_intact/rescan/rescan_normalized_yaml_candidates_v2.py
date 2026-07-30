from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


def find_project_root(start: Path) -> Path:
    """
    현재 스크립트 위치에서 상위 디렉터리를 탐색하여
    프로젝트 루트를 찾는다.
    """
    current = start.resolve()

    for candidate in [current, *current.parents]:
        if (
            (candidate / "data").is_dir()
            and (candidate / "scripts").is_dir()
        ):
            return candidate

    raise FileNotFoundError(
        "프로젝트 루트를 찾지 못했습니다. "
        "data/ 및 scripts/ 디렉터리가 함께 있는 상위 경로가 필요합니다."
    )


PROJECT_ROOT = find_project_root(
    Path(__file__).parent
)

NORMALIZED_PATH = (
    PROJECT_ROOT
    / "data"
    / "normalized"
    / "all_sources_normalized_v1.jsonl"
)

print(f"[info] project root: {PROJECT_ROOT}")
print(f"[info] normalized path: {NORMALIZED_PATH}")


OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "04_structure_intact"
    / "yaml_rescan_v2"
)

ALL_OUTPUT = (
    OUTPUT_DIR
    / "yaml_rescan_candidates_all_v2.csv"
)

AUDIT_OUTPUT = (
    OUTPUT_DIR
    / "yaml_rescan_audit_v2.csv"
)

SUMMARY_OUTPUT = (
    PROJECT_ROOT
    / "reports"
    / "yaml_rescan_summary_v2.json"
)

AUDIT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "04_structure_intact"
    / "audit"
)

EXTERNAL_STRUCTURE_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "external_structure_candidates"
)

MARKDOWN_RESCAN_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_markdown_rescan_v2"
)

SEED_REVIEW_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
)

AUDIT_LIMIT = 160


def norm(value: Any) -> str:
    return str(value or "").strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


def discover_exclusion_paths() -> list[Path]:
    """
    기존 structure-intact 판정 완료본과 최종 선택본을 자동 탐색한다.

    우선 탐색 대상:
    - data/review/04_structure_intact/audit
    - data/review/external_structure_candidates
    - data/review/structure_intact_markdown_rescan_v2

    completed 파일은 review_decision=keep인 행만 제외한다.
    selected 파일은 포함된 모든 행을 제외한다.
    """
    paths: set[Path] = set()

    if AUDIT_DIR.exists():
        paths.update(
            AUDIT_DIR.rglob("*_completed.csv")
        )
        paths.update(
            AUDIT_DIR.rglob("*_selected_*.csv")
        )
        paths.update(
            AUDIT_DIR.rglob("*selected*.csv")
        )

    if EXTERNAL_STRUCTURE_DIR.exists():
        paths.update(
            EXTERNAL_STRUCTURE_DIR.rglob(
                "*_completed.csv"
            )
        )
        paths.update(
            EXTERNAL_STRUCTURE_DIR.rglob(
                "*_selected_*.csv"
            )
        )
        paths.update(
            EXTERNAL_STRUCTURE_DIR.rglob(
                "*selected*.csv"
            )
        )

    if MARKDOWN_RESCAN_DIR.exists():
        paths.update(
            MARKDOWN_RESCAN_DIR.rglob(
                "*_completed.csv"
            )
        )
        paths.update(
            MARKDOWN_RESCAN_DIR.rglob(
                "*_selected_*.csv"
            )
        )
        paths.update(
            MARKDOWN_RESCAN_DIR.rglob(
                "*selected*.csv"
            )
        )

    # 현재 프로젝트 폴더 구조가 추가로 바뀌더라도,
    # 04_structure_intact 아래 완료본과 선택본은 모두 탐색한다.
    structure_root = (
        PROJECT_ROOT
        / "data"
        / "review"
        / "04_structure_intact"
    )

    if structure_root.exists():
        paths.update(
            structure_root.rglob(
                "*_completed.csv"
            )
        )
        paths.update(
            structure_root.rglob(
                "*_selected_*.csv"
            )
        )
        paths.update(
            structure_root.rglob(
                "*selected*.csv"
            )
        )

    return sorted(
        path.resolve()
        for path in paths
        if path.is_file()
    )


def load_jsonl(
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
                    f"Invalid JSONL: "
                    f"{path}:{line_number}"
                ) from exc

            if not isinstance(row, dict):
                continue

            rows.append(row)

    return rows


def load_csv_rows(
    path: Path,
) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(
            csv.DictReader(file)
        )


def row_text(
    row: dict[str, Any],
) -> str:
    candidate_fields = [
        "scanner_input",
        "repository_payload",
        "mutation_target_text",
        "prompt",
        "text",
        "input",
        "content",
        "user_input",
        "instruction",
        "eval_content",
        "clean_context",
        "attack_str",
    ]

    for field in candidate_fields:
        text = norm(row.get(field))

        if text:
            return text

    return ""


def should_use_row_for_exclusion(
    path: Path,
    row: dict[str, Any],
) -> bool:
    filename = path.name.lower()

    decision = norm(
        row.get("review_decision")
    ).lower()

    quota_selection = norm(
        row.get("quota_selection")
    ).lower()

    if "completed" in filename:
        return decision == "keep"

    if "selected" in filename:
        if quota_selection:
            return quota_selection in {
                "yes",
                "true",
                "1",
                "selected",
                "keep",
            }

        return True

    # 이름이 애매한 파일은 명시적인 선택/keep만 사용한다.
    return (
        decision == "keep"
        or quota_selection
        in {
            "yes",
            "true",
            "1",
            "selected",
            "keep",
        }
    )


def load_excluded_hashes(
    exclusion_paths: list[Path],
) -> tuple[set[str], dict[str, int]]:
    hashes: set[str] = set()
    file_counts: dict[str, int] = {}

    for path in exclusion_paths:
        added_from_file = 0

        for row in load_csv_rows(path):
            if not should_use_row_for_exclusion(
                path,
                row,
            ):
                continue

            text_hash = norm(
                row.get("text_sha256")
            )

            text = row_text(row)

            if not text_hash and text:
                text_hash = sha256_text(text)

            if not text_hash:
                continue

            before = len(hashes)
            hashes.add(text_hash)

            if len(hashes) > before:
                added_from_file += 1

        file_counts[
            str(
                path.relative_to(
                    PROJECT_ROOT
                )
            )
        ] = added_from_file

    return hashes, file_counts


def is_malicious(
    row: dict[str, Any],
) -> bool:
    values = [
        row.get("label"),
        row.get("verdict"),
        row.get("ground_truth"),
        row.get("ground_truth_decision"),
        row.get("is_malicious"),
        row.get("malicious"),
        row.get("class"),
        row.get("category"),
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
        "prompt injection",
        "injection",
        "jailbreak",
        "unsafe",
    }

    benign_tokens = {
        "benign",
        "safe",
        "0",
        "false",
        "normal",
        "non-malicious",
        "non_malicious",
    }

    if normalized & malicious_tokens:
        return True

    if normalized & benign_tokens:
        return False

    attack_metadata = norm(
        row.get("attack_type")
        or row.get("attack_category")
        or row.get("subtype")
        or row.get("attack_name")
    )

    return bool(attack_metadata)


def is_mutated(
    row: dict[str, Any],
) -> bool:
    explicit_flag = norm(
        row.get("is_mutated")
    ).lower()

    if explicit_flag in {
        "true",
        "1",
        "yes",
    }:
        return True

    if explicit_flag in {
        "false",
        "0",
        "no",
    }:
        return False

    mutation_fields = [
        row.get("mutation_operator"),
        row.get("operator_id"),
        row.get("parent_seed_id"),
        row.get("mutation_id"),
        row.get("mutation_family"),
    ]

    return any(
        norm(value).lower()
        not in {
            "",
            "false",
            "0",
            "none",
            "null",
            "n/a",
        }
        for value in mutation_fields
    )


def source_record_id(
    row: dict[str, Any],
    index: int,
) -> str:
    candidate_fields = [
        "source_record_id",
        "record_id",
        "sample_id",
        "id",
        "original_id",
        "row_id",
    ]

    for field in candidate_fields:
        value = norm(row.get(field))

        if value:
            return value

    return (
        f"normalized-row-{index:06d}"
    )


def source_id(
    row: dict[str, Any],
) -> str:
    return norm(
        row.get("source_id")
        or row.get("dataset_id")
        or row.get("source")
        or row.get("dataset")
        or "UNKNOWN"
    )


def contains_markdown_fence(
    text: str,
) -> bool:
    return bool(
        re.search(
            r"```[\s\S]*?```"
            r"|~~~[\s\S]*?~~~",
            text,
        )
    )


def is_strict_json(
    text: str,
) -> bool:
    try:
        parsed = json.loads(
            text.strip()
        )
    except Exception:
        return False

    return isinstance(
        parsed,
        (dict, list),
    )


def parse_yaml_candidate(
    text: str,
) -> tuple[Any, str] | None:
    stripped = text.strip()

    if not stripped:
        return None

    # JSON은 YAML 문법상 유효하지만
    # JSON quota와 겹치므로 제외한다.
    if is_strict_json(stripped):
        return None

    # Markdown fenced document를 YAML로 중복 분류하지 않는다.
    if contains_markdown_fence(stripped):
        return None

    try:
        parsed = yaml.safe_load(
            stripped
        )
    except yaml.YAMLError:
        return None

    if isinstance(parsed, dict):
        return parsed, "mapping"

    if isinstance(parsed, list):
        return parsed, "sequence"

    return None


def yaml_structure_features(
    parsed: Any,
    text: str,
) -> dict[str, int]:
    features = {
        "top_level_fields": 0,
        "nested_mappings": 0,
        "sequences": 0,
        "block_scalars": 0,
        "document_markers": 0,
        "anchors_or_aliases": 0,
        "explicit_tags": 0,
        "multiline": int(
            "\n" in text
        ),
        "mapping_lines": 0,
        "sequence_lines": 0,
    }

    if isinstance(parsed, dict):
        features[
            "top_level_fields"
        ] = len(parsed)

    elif isinstance(parsed, list):
        features[
            "top_level_fields"
        ] = len(parsed)
        features["sequences"] += 1

    def walk(
        value: Any,
        depth: int = 0,
    ) -> None:
        if isinstance(value, dict):
            if depth > 0:
                features[
                    "nested_mappings"
                ] += 1

            for child in value.values():
                walk(
                    child,
                    depth + 1,
                )

        elif isinstance(value, list):
            if depth > 0:
                features[
                    "sequences"
                ] += 1

            for child in value:
                walk(
                    child,
                    depth + 1,
                )

    walk(parsed)

    features["block_scalars"] = len(
        re.findall(
            r"(?m)^\s*"
            r"[\w.'\"/-]+\s*:\s*"
            r"[>|][-+]?\s*$",
            text,
        )
    )

    features["document_markers"] = len(
        re.findall(
            r"(?m)^\s*"
            r"(?:---|\.\.\.)"
            r"\s*$",
            text,
        )
    )

    features[
        "anchors_or_aliases"
    ] = len(
        re.findall(
            r"(?<!\w)"
            r"[&*][A-Za-z_]"
            r"[\w-]*",
            text,
        )
    )

    features["explicit_tags"] = len(
        re.findall(
            r"(?<!\w)"
            r"!!?[A-Za-z_]"
            r"[\w:/.+-]*",
            text,
        )
    )

    features["mapping_lines"] = len(
        re.findall(
            r"(?m)^\s*"
            r"(?:[-?]\s+)?"
            r"[A-Za-z_'\".]"
            r"[^:\n]{0,100}"
            r":(?:\s|$)",
            text,
        )
    )

    features["sequence_lines"] = len(
        re.findall(
            r"(?m)^\s*-\s+\S",
            text,
        )
    )

    return features


def yaml_structure_score(
    features: dict[str, int],
    root_type: str,
) -> tuple[int, list[str]]:
    score = 0
    active: list[str] = []

    top_fields = features[
        "top_level_fields"
    ]

    if root_type == "mapping":
        if top_fields >= 2:
            score += min(
                top_fields,
                6,
            ) * 2

            active.append(
                "multi_field_mapping"
            )

    elif root_type == "sequence":
        if top_fields >= 2:
            score += min(
                top_fields,
                6,
            ) * 2

            active.append(
                "multi_item_sequence"
            )

    if features[
        "nested_mappings"
    ] > 0:
        score += min(
            features[
                "nested_mappings"
            ],
            4,
        ) * 3

        active.append(
            "nested_mapping"
        )

    if features[
        "sequences"
    ] > 0:
        score += min(
            features["sequences"],
            4,
        ) * 3

        active.append(
            "sequence"
        )

    if features[
        "block_scalars"
    ] > 0:
        score += min(
            features[
                "block_scalars"
            ],
            3,
        ) * 4

        active.append(
            "block_scalar"
        )

    if features[
        "document_markers"
    ] > 0:
        score += 2
        active.append(
            "document_marker"
        )

    if features[
        "anchors_or_aliases"
    ] > 0:
        score += 4
        active.append(
            "anchor_or_alias"
        )

    if features[
        "explicit_tags"
    ] > 0:
        score += 4
        active.append(
            "explicit_tag"
        )

    if features["multiline"]:
        score += 2
        active.append(
            "multiline"
        )

    if features[
        "mapping_lines"
    ] >= 2:
        score += min(
            features[
                "mapping_lines"
            ],
            5,
        )
        active.append(
            "multiple_mapping_lines"
        )

    if features[
        "sequence_lines"
    ] >= 2:
        score += 3
        active.append(
            "multiple_sequence_lines"
        )

    return score, active


def scalar_texts(
    value: Any,
) -> list[str]:
    texts: list[str] = []

    if isinstance(value, dict):
        for key, child in value.items():
            texts.append(str(key))
            texts.extend(
                scalar_texts(child)
            )

    elif isinstance(value, list):
        for child in value:
            texts.extend(
                scalar_texts(child)
            )

    elif value is not None:
        texts.append(str(value))

    return texts


def attack_semantic_signal(
    parsed: Any,
) -> tuple[int, list[str]]:
    joined = "\n".join(
        scalar_texts(parsed)
    ).lower()

    patterns = {
        "instruction_override": (
            r"\b("
            r"ignore|disregard|override|"
            r"replace|forget|supersede"
            r")\b"
            r".{0,100}"
            r"\b("
            r"instruction|rule|policy|"
            r"system|previous|above|"
            r"developer"
            r")\b"
        ),
        "safety_bypass": (
            r"\b("
            r"disable|bypass|evade|"
            r"remove|turn off"
            r")\b"
            r".{0,100}"
            r"\b("
            r"safety|filter|guardrail|"
            r"security|policy|restriction"
            r")\b"
        ),
        "secret_exfiltration": (
            r"\b("
            r"reveal|show|print|leak|"
            r"exfiltrat|send|upload|"
            r"return|display"
            r")\b"
            r".{0,120}"
            r"\b("
            r"secret|password|token|"
            r"credential|api key|"
            r"ssh|environment|shadow|"
            r"database|private key|"
            r"system prompt"
            r")\b"
        ),
        "unsafe_execution": (
            r"\b("
            r"run|execute|eval|shell|"
            r"powershell|command|subprocess"
            r")\b"
        ),
        "fixed_malicious_output": (
            r"\bpwned\b"
            r"|system override"
            r"|developer mode"
            r"|jailbreak"
        ),
        "ai_target": (
            r"\b("
            r"ai|assistant|model|chatgpt|"
            r"claude|copilot|gemini|"
            r"llm"
            r")\b"
        ),
        "concealment": (
            r"\b("
            r"hide|conceal|suppress|"
            r"do not mention|without warning|"
            r"silently"
            r")\b"
        ),
    }

    hits = [
        name
        for name, pattern
        in patterns.items()
        if re.search(
            pattern,
            joined,
            re.IGNORECASE
            | re.DOTALL,
        )
    ]

    return len(hits), hits


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not rows:
        # 후보가 없어도 빈 파일 대신
        # 로그와 summary로 명확히 알린다.
        return

    fieldnames = list(
        rows[0].keys()
    )

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


def select_audit_rows(
    candidates: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """
    특정 source 하나가 audit batch를 독점하지 않도록
    source별 round-robin으로 선택한다.
    """
    by_source: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for row in candidates:
        by_source.setdefault(
            row["source_id"],
            [],
        ).append(row)

    for source_rows in by_source.values():
        source_rows.sort(
            key=lambda row: (
                -int(
                    row[
                        "semantic_signal_count"
                    ]
                ),
                -int(
                    row[
                        "yaml_structure_score"
                    ]
                ),
                int(
                    row["text_length"]
                ),
                row["text_sha256"],
            )
        )

    selected: list[
        dict[str, Any]
    ] = []

    source_names = sorted(
        by_source
    )

    while len(selected) < limit:
        progressed = False

        for source_name in source_names:
            source_rows = (
                by_source[source_name]
            )

            if not source_rows:
                continue

            selected.append(
                source_rows.pop(0)
            )
            progressed = True

            if len(selected) >= limit:
                break

        if not progressed:
            break

    return selected


def main() -> None:
    if not NORMALIZED_PATH.exists():
        raise FileNotFoundError(
            NORMALIZED_PATH
        )

    exclusion_paths = (
        discover_exclusion_paths()
    )

    print(
        "[info] exclusion files"
    )

    if exclusion_paths:
        for path in exclusion_paths:
            print(
                "  - "
                + str(
                    path.relative_to(
                        PROJECT_ROOT
                    )
                )
            )
    else:
        print(
            "  - none found"
        )

    excluded_hashes, exclusion_file_counts = (
        load_excluded_hashes(
            exclusion_paths
        )
    )

    rows = load_jsonl(
        NORMALIZED_PATH
    )

    candidates: list[
        dict[str, Any]
    ] = []

    seen_hashes: set[str] = set()

    exclusions: Counter[str] = (
        Counter()
    )

    source_counts: Counter[str] = (
        Counter()
    )

    feature_counts: Counter[str] = (
        Counter()
    )

    for index, row in enumerate(
        rows,
        start=1,
    ):
        if not is_malicious(row):
            exclusions[
                "not_malicious"
            ] += 1
            continue

        if is_mutated(row):
            exclusions["mutated"] += 1
            continue

        text = row_text(row)

        if not text:
            exclusions[
                "empty_text"
            ] += 1
            continue

        text_hash = sha256_text(
            text
        )

        if text_hash in excluded_hashes:
            exclusions[
                "already_used"
            ] += 1
            continue

        if text_hash in seen_hashes:
            exclusions[
                "duplicate"
            ] += 1
            continue

        parsed_result = (
            parse_yaml_candidate(
                text
            )
        )

        if parsed_result is None:
            exclusions[
                "not_yaml_structure"
            ] += 1
            continue

        parsed, root_type = (
            parsed_result
        )

        features = (
            yaml_structure_features(
                parsed,
                text,
            )
        )

        (
            structure_score,
            active_features,
        ) = yaml_structure_score(
            features,
            root_type,
        )

        (
            semantic_count,
            semantic_hits,
        ) = attack_semantic_signal(
            parsed
        )

        if structure_score < 6:
            exclusions[
                "low_structure_score"
            ] += 1
            continue

        has_substantive_structure = (
            features[
                "top_level_fields"
            ] >= 2
            or features[
                "nested_mappings"
            ] > 0
            or features[
                "sequences"
            ] > 0
            or features[
                "block_scalars"
            ] > 0
            or features[
                "anchors_or_aliases"
            ] > 0
            or features[
                "explicit_tags"
            ] > 0
        )

        if not has_substantive_structure:
            exclusions[
                "single_field_false_positive"
            ] += 1
            continue

        if semantic_count == 0:
            exclusions[
                "no_attack_semantic_signal"
            ] += 1
            continue

        current_source_id = (
            source_id(row)
        )

        candidate = {
            "candidate_id": (
                "YAML-RESCAN-V2-"
                f"{len(candidates) + 1:05d}"
            ),
            "source_id": (
                current_source_id
            ),
            "source_record_id": (
                source_record_id(
                    row,
                    index,
                )
            ),
            "text_sha256": (
                text_hash
            ),
            "scanner_input": text,
            "text_length": len(text),
            "candidate_structure_format": (
                "yaml"
            ),
            "yaml_root_type": (
                root_type
            ),
            "yaml_structure_score": (
                structure_score
            ),
            "yaml_features": (
                "|".join(
                    active_features
                )
            ),
            "semantic_signal_count": (
                semantic_count
            ),
            "semantic_signals": (
                "|".join(
                    semantic_hits
                )
            ),
            "top_level_fields": (
                features[
                    "top_level_fields"
                ]
            ),
            "nested_mappings": (
                features[
                    "nested_mappings"
                ]
            ),
            "sequence_count": (
                features[
                    "sequences"
                ]
            ),
            "block_scalar_count": (
                features[
                    "block_scalars"
                ]
            ),
            "document_marker_count": (
                features[
                    "document_markers"
                ]
            ),
            "anchor_alias_count": (
                features[
                    "anchors_or_aliases"
                ]
            ),
            "explicit_tag_count": (
                features[
                    "explicit_tags"
                ]
            ),
            "mapping_line_count": (
                features[
                    "mapping_lines"
                ]
            ),
            "sequence_line_count": (
                features[
                    "sequence_lines"
                ]
            ),
            "ground_truth_decision": (
                "malicious"
            ),
            "structure_origin": (
                "source_original"
            ),
            "provenance_status": (
                "traceable"
                if current_source_id
                != "UNKNOWN"
                else "review"
            ),
            "generation_method": (
                "normalized_source_original"
            ),
            "structure_valid": "",
            "attack_semantics_valid": "",
            "provenance_valid": "",
            "review_decision": "",
            "review_note": "",
        }

        candidates.append(
            candidate
        )

        seen_hashes.add(
            text_hash
        )

        source_counts[
            current_source_id
        ] += 1

        for feature in active_features:
            feature_counts[
                feature
            ] += 1

    candidates.sort(
        key=lambda row: (
            -int(
                row[
                    "semantic_signal_count"
                ]
            ),
            -int(
                row[
                    "yaml_structure_score"
                ]
            ),
            row["source_id"],
            int(
                row["text_length"]
            ),
            row["text_sha256"],
        )
    )

    audit_rows = (
        select_audit_rows(
            candidates,
            AUDIT_LIMIT,
        )
    )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
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
        "candidate_count": (
            len(candidates)
        ),
        "audit_count": (
            len(audit_rows)
        ),
        "audit_limit": (
            AUDIT_LIMIT
        ),
        "exclusion_file_count": (
            len(exclusion_paths)
        ),
        "excluded_hash_count": (
            len(excluded_hashes)
        ),
        "exclusion_files": [
            str(
                path.relative_to(
                    PROJECT_ROOT
                )
            )
            for path in exclusion_paths
        ],
        "excluded_hashes_by_file": (
            exclusion_file_counts
        ),
        "candidate_counts_by_source": dict(
            source_counts.most_common()
        ),
        "feature_counts": dict(
            feature_counts.most_common()
        ),
        "exclusion_counts": dict(
            exclusions.most_common()
        ),
        "all_output": (
            str(
                ALL_OUTPUT.relative_to(
                    PROJECT_ROOT
                )
            )
            if candidates
            else None
        ),
        "audit_output": (
            str(
                AUDIT_OUTPUT.relative_to(
                    PROJECT_ROOT
                )
            )
            if audit_rows
            else None
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
    print(
        "[done] normalized YAML "
        "expanded rescan v2"
    )
    print(
        f"input rows      : "
        f"{len(rows)}"
    )
    print(
        f"candidates      : "
        f"{len(candidates)}"
    )
    print(
        f"audit rows      : "
        f"{len(audit_rows)}"
    )
    print(
        f"exclusion files : "
        f"{len(exclusion_paths)}"
    )
    print(
        f"excluded hashes : "
        f"{len(excluded_hashes)}"
    )

    print(
        "\ncandidates by source"
    )

    if source_counts:
        for (
            current_source_id,
            count,
        ) in source_counts.most_common():
            print(
                f"  "
                f"{current_source_id:<48}"
                f": {count}"
            )
    else:
        print("  none")

    print(
        "\nexclusion counts"
    )

    for reason, count in (
        exclusions.most_common()
    ):
        print(
            f"  {reason:<36}"
            f": {count}"
        )

    print(
        f"\nall output  : "
        f"{ALL_OUTPUT}"
    )
    print(
        f"audit output: "
        f"{AUDIT_OUTPUT}"
    )
    print(
        f"summary     : "
        f"{SUMMARY_OUTPUT}"
    )
    print("=" * 72)


if __name__ == "__main__":
    main()