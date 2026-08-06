from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError


def find_project_root(start: Path) -> Path:
    current = start.resolve()

    for candidate in [current, *current.parents]:
        if (
            (candidate / "data").is_dir()
            and (candidate / "scripts").is_dir()
        ):
            return candidate

    raise FileNotFoundError(
        "프로젝트 루트를 찾지 못했습니다. "
        "data/와 scripts/가 함께 존재하는 상위 경로가 필요합니다."
    )


PROJECT_ROOT = find_project_root(
    Path(__file__).parent
)

SOURCE_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "src12_bordair_multimodal"
    / "payloads_v3"
    / "structured_data_injection"
    / "structured_data_injection_001.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "04_structure_intact"
    / "external_structure_candidates"
    / "src12_bordair_v1"
)

ALL_OUTPUT = (
    OUTPUT_DIR
    / "src12_bordair_yaml_candidates_all_v1.csv"
)

AUDIT_OUTPUT = (
    OUTPUT_DIR
    / "src12_bordair_yaml_audit_v1.csv"
)

SUMMARY_OUTPUT = (
    PROJECT_ROOT
    / "reports"
    / "src12_bordair_yaml_summary_v1.json"
)


class UniqueKeyLoader(yaml.SafeLoader):
    """
    PyYAML 기본 loader가 중복 key를 덮어쓰는 것을 방지한다.
    """


def construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(
            key_node,
            deep=deep,
        )

        try:
            hash(key)
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc

        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key: {key!r}",
                key_node.start_mark,
            )

        mapping[key] = loader.construct_object(
            value_node,
            deep=deep,
        )

    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def norm(value: Any) -> str:
    return str(value or "").strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def load_source_rows(
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
        for value in data.values():
            if (
                isinstance(value, list)
                and all(
                    isinstance(row, dict)
                    for row in value
                )
            ):
                return value

    raise ValueError(
        f"지원하지 않는 JSON 구조입니다: {path}"
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


def parse_strict_yaml(
    text: str,
) -> tuple[Any, str] | None:
    stripped = text.strip()

    if not stripped:
        return None

    # JSON은 YAML 문법상 유효하지만 JSON quota와 중복되므로 제외한다.
    if is_strict_json(stripped):
        return None

    try:
        parsed = yaml.load(
            stripped,
            Loader=UniqueKeyLoader,
        )
    except yaml.YAMLError:
        return None

    if isinstance(parsed, dict):
        return parsed, "mapping"

    if isinstance(parsed, list):
        return parsed, "sequence"

    return None


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


def yaml_features(
    parsed: Any,
    text: str,
) -> dict[str, int]:
    features = {
        "top_level_fields": 0,
        "nested_mapping_count": 0,
        "sequence_count": 0,
        "block_scalar_count": 0,
        "document_marker_count": 0,
        "anchor_alias_count": 0,
        "mapping_line_count": 0,
    }

    if isinstance(parsed, dict):
        features["top_level_fields"] = len(parsed)

    elif isinstance(parsed, list):
        features["top_level_fields"] = len(parsed)
        features["sequence_count"] = 1

    def walk(
        value: Any,
        depth: int = 0,
    ) -> None:
        if isinstance(value, dict):
            if depth > 0:
                features[
                    "nested_mapping_count"
                ] += 1

            for child in value.values():
                walk(
                    child,
                    depth + 1,
                )

        elif isinstance(value, list):
            if depth > 0:
                features[
                    "sequence_count"
                ] += 1

            for child in value:
                walk(
                    child,
                    depth + 1,
                )

    walk(parsed)

    features["block_scalar_count"] = len(
        re.findall(
            r"(?m)^\s*"
            r"[^#\n][^:\n]{0,100}"
            r":\s*[>|][-+]?\s*$",
            text,
        )
    )

    features["document_marker_count"] = len(
        re.findall(
            r"(?m)^\s*(?:---|\.\.\.)\s*$",
            text,
        )
    )

    features["anchor_alias_count"] = len(
        re.findall(
            r"(?<!\w)[&*][A-Za-z_][\w-]*",
            text,
        )
    )

    features["mapping_line_count"] = len(
        re.findall(
            r"(?m)^\s*"
            r"(?:-\s+)?"
            r"[^#\s][^:\n]{0,100}"
            r":(?:\s|$)",
            text,
        )
    )

    return features


def structure_is_substantive(
    parsed: Any,
    features: dict[str, int],
) -> bool:
    if isinstance(parsed, dict):
        if features["top_level_fields"] >= 2:
            return True

    if isinstance(parsed, list):
        if features["top_level_fields"] >= 2:
            return True

    return any(
        [
            features["nested_mapping_count"] > 0,
            features["sequence_count"] > 0,
            features["block_scalar_count"] > 0,
            features["anchor_alias_count"] > 0,
        ]
    )


def attack_semantic_signals(
    parsed: Any,
) -> list[str]:
    joined = "\n".join(
        scalar_texts(parsed)
    ).lower()

    patterns = {
        "instruction_override": (
            r"\b("
            r"ignore|disregard|override|forget|"
            r"replace|supersede"
            r")\b"
            r".{0,120}"
            r"\b("
            r"instruction|rules?|guidelines?|"
            r"system|previous|prior|above"
            r")\b"
        ),
        "system_prompt_extraction": (
            r"\b("
            r"output|reveal|show|print|return"
            r")\b"
            r".{0,100}"
            r"\b("
            r"system prompt|hidden prompt|"
            r"system message|configuration"
            r")\b"
        ),
        "safety_bypass": (
            r"\b("
            r"disable|remove|bypass|without|"
            r"ignore"
            r")\b"
            r".{0,100}"
            r"\b("
            r"safety|filter|guardrail|policy|"
            r"restriction"
            r")\b"
        ),
        "role_override": (
            r"\b("
            r"you are now|act as|become|"
            r"maintenance mode|dan"
            r")\b"
        ),
        "data_exfiltration": (
            r"\b("
            r"return|send|upload|reveal|show|"
            r"print|exfiltrat"
            r")\b"
            r".{0,120}"
            r"\b("
            r"user data|secret|password|token|"
            r"credential|config|database|"
            r"api key"
            r")\b"
        ),
        "fixed_malicious_output": (
            r"\bpwned\b"
            r"|unrestricted ai"
            r"|system override"
        ),
    }

    return [
        name
        for name, pattern in patterns.items()
        if re.search(
            pattern,
            joined,
            re.IGNORECASE
            | re.DOTALL,
        )
    ]


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "candidate_id",
        "source_id",
        "source_record_id",
        "text_sha256",
        "scanner_input",
        "category",
        "strategy",
        "attack_source",
        "attack_reference",
        "expected_detection",
        "modalities",
        "candidate_structure_format",
        "yaml_root_type",
        "top_level_fields",
        "nested_mapping_count",
        "sequence_count",
        "block_scalar_count",
        "document_marker_count",
        "anchor_alias_count",
        "mapping_line_count",
        "semantic_signal_count",
        "semantic_signals",
        "structure_origin",
        "generation_method",
        "provenance_status",
        "structure_valid",
        "attack_semantics_valid",
        "provenance_valid",
        "review_decision",
        "review_note",
        "quota_selection",
    ]

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
    if not SOURCE_PATH.exists():
        raise FileNotFoundError(
            SOURCE_PATH
        )

    source_rows = load_source_rows(
        SOURCE_PATH
    )

    candidates: list[
        dict[str, Any]
    ] = []

    exclusion_counts = {
        "empty_text": 0,
        "strict_json": 0,
        "not_strict_yaml": 0,
        "weak_yaml_structure": 0,
        "no_prompt_injection_semantics": 0,
    }

    for row in source_rows:
        text = norm(
            row.get("text")
        )

        if not text:
            exclusion_counts[
                "empty_text"
            ] += 1
            continue

        if is_strict_json(text):
            exclusion_counts[
                "strict_json"
            ] += 1
            continue

        parsed_result = parse_strict_yaml(
            text
        )

        if parsed_result is None:
            exclusion_counts[
                "not_strict_yaml"
            ] += 1
            continue

        parsed, root_type = (
            parsed_result
        )

        features = yaml_features(
            parsed,
            text,
        )

        if not structure_is_substantive(
            parsed,
            features,
        ):
            exclusion_counts[
                "weak_yaml_structure"
            ] += 1
            continue

        semantic_signals = (
            attack_semantic_signals(
                parsed
            )
        )

        if not semantic_signals:
            exclusion_counts[
                "no_prompt_injection_semantics"
            ] += 1
            continue

        candidate_id = (
            "SRC12-YAML-"
            f"{len(candidates) + 1:04d}"
        )

        source_record_id = norm(
            row.get("id")
        )

        candidates.append(
            {
                "candidate_id": candidate_id,
                "source_id": (
                    "SRC-12_bordair_multimodal"
                ),
                "source_record_id": (
                    source_record_id
                ),
                "text_sha256": (
                    sha256_text(text)
                ),
                "scanner_input": text,
                "category": norm(
                    row.get("category")
                ),
                "strategy": norm(
                    row.get("strategy")
                ),
                "attack_source": norm(
                    row.get("attack_source")
                ),
                "attack_reference": norm(
                    row.get(
                        "attack_reference"
                    )
                ),
                "expected_detection": norm(
                    row.get(
                        "expected_detection"
                    )
                ),
                "modalities": "|".join(
                    str(value)
                    for value in (
                        row.get("modalities")
                        or []
                    )
                ),
                "candidate_structure_format": (
                    "yaml"
                ),
                "yaml_root_type": (
                    root_type
                ),
                "top_level_fields": (
                    features[
                        "top_level_fields"
                    ]
                ),
                "nested_mapping_count": (
                    features[
                        "nested_mapping_count"
                    ]
                ),
                "sequence_count": (
                    features[
                        "sequence_count"
                    ]
                ),
                "block_scalar_count": (
                    features[
                        "block_scalar_count"
                    ]
                ),
                "document_marker_count": (
                    features[
                        "document_marker_count"
                    ]
                ),
                "anchor_alias_count": (
                    features[
                        "anchor_alias_count"
                    ]
                ),
                "mapping_line_count": (
                    features[
                        "mapping_line_count"
                    ]
                ),
                "semantic_signal_count": (
                    len(semantic_signals)
                ),
                "semantic_signals": (
                    "|".join(
                        semantic_signals
                    )
                ),
                "structure_origin": (
                    "synthetic_source_original"
                ),
                "generation_method": (
                    "public_source_generator"
                ),
                "provenance_status": (
                    "traceable"
                ),
                "structure_valid": "",
                "attack_semantics_valid": "",
                "provenance_valid": "",
                "review_decision": "",
                "review_note": "",
                "quota_selection": "",
            }
        )

    write_csv(
        ALL_OUTPUT,
        candidates,
    )

    write_csv(
        AUDIT_OUTPUT,
        candidates,
    )

    summary = {
        "source_id": (
            "SRC-12_bordair_multimodal"
        ),
        "input_rows": len(source_rows),
        "yaml_candidate_count": (
            len(candidates)
        ),
        "excluded": exclusion_counts,
        "source_path": str(
            SOURCE_PATH.relative_to(
                PROJECT_ROOT
            )
        ),
        "all_output": str(
            ALL_OUTPUT.relative_to(
                PROJECT_ROOT
            )
        ),
        "audit_output": str(
            AUDIT_OUTPUT.relative_to(
                PROJECT_ROOT
            )
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
    print("[done] SRC-12 Bordair YAML extraction")
    print(f"input rows      : {len(source_rows)}")
    print(f"yaml candidates : {len(candidates)}")
    print("\nexclusions")

    for reason, count in exclusion_counts.items():
        print(
            f"  {reason:<36}: {count}"
        )

    print(f"\nall output  : {ALL_OUTPUT}")
    print(f"audit output: {AUDIT_OUTPUT}")
    print(f"summary     : {SUMMARY_OUTPUT}")
    print("=" * 72)


if __name__ == "__main__":
    main()