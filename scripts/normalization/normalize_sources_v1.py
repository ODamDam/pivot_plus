from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


RAW_DIR = Path("data/raw")
OUT_DIR = Path("data/normalized")
REPORT_DIR = Path("reports")

OUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

JSONL_OUT = OUT_DIR / "all_sources_normalized_v1.jsonl"
CSV_OUT = OUT_DIR / "all_sources_normalized_v1.csv"
SUMMARY_CSV = REPORT_DIR / "normalization_summary_v1.csv"
SUMMARY_MD = REPORT_DIR / "normalization_summary_v1.md"


FIELDNAMES = [
    "normalized_record_id",
    "source_id",
    "source_name",
    "source_split",
    "source_path",
    "source_record_id",
    "raw_text",
    "scanner_input",
    "scanner_input_prompt_only",
    "scanner_input_with_context",
    "original_label",
    "normalized_label",
    "candidate_use",
    "attack_type",
    "is_structure_intact",
    "is_context_eval",
    "is_augmented",
    "group_id",
    "keep_or_drop",
    "drop_reason",
    "text_length",
    "text_sha256",
    "metadata_json",
]


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            yield idx, json.loads(line)


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False)

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def as_boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, float):
        return value != 0.0
    if value is None:
        return None

    s = str(value).strip().lower()

    if s in {"1", "true", "yes", "y", "malicious", "jailbreak", "injection", "prompt_injection"}:
        return True
    if s in {"0", "false", "no", "n", "benign", "regular", "safe"}:
        return False

    return None


def detect_split(path: Path) -> str:
    name = path.name.lower()
    if "train" in name:
        return "train"
    if "test" in name:
        return "test"
    if "validation" in name or "valid" in name:
        return "validation"
    return "unknown"


def detect_source_id(path: Path) -> str:
    rel = path.relative_to(RAW_DIR)
    return rel.parts[0]


def source_name_from_id(source_id: str) -> str:
    return source_id


def infer_attack_type(text: str, *, source_id: str = "", category: Any = None, is_structure: bool = False) -> str:
    t = text.lower()
    c = str(category or "").lower()

    if is_structure:
        return "indirect_injection"

    if any(k in c for k in ["exfil", "leak", "secret", "credential"]):
        return "data_exfiltration"

    if any(k in c for k in ["role", "persona", "dan", "jailbreak"]):
        return "role_play_bypass"

    if any(k in c for k in ["policy", "safety", "bypass"]):
        return "policy_bypass"

    if any(k in c for k in ["format", "json", "xml", "yaml", "markdown", "encoding"]):
        return "format_injection"

    data_exfil_keywords = [
        "secret", "password", "api key", "token", "credential",
        "system prompt", "hidden prompt", "confidential", "private",
        "reveal", "leak", "print the instructions", "show me your instructions",
    ]

    role_play_keywords = [
        "roleplay", "role play", "pretend", "act as", "you are now",
        "dan", "developer mode", "grandma", "simulation",
    ]

    policy_keywords = [
        "policy", "safety", "guidelines", "restriction", "filter",
        "censor", "uncensored", "bypass", "jailbreak",
    ]

    format_keywords = [
        "json", "xml", "yaml", "markdown", "html", "base64",
        "encode", "decode", "csv", "table", "schema",
    ]

    override_keywords = [
        "ignore", "disregard", "forget", "override", "bypass",
        "previous instructions", "prior instructions", "system instructions",
        "developer instructions", "do not follow",
    ]

    if any(k in t for k in data_exfil_keywords):
        return "data_exfiltration"

    if any(k in t for k in role_play_keywords):
        return "role_play_bypass"

    if any(k in t for k in policy_keywords):
        return "policy_bypass"

    if any(k in t for k in format_keywords):
        return "format_injection"

    if any(k in t for k in override_keywords):
        return "instruction_override"

    if "SRC-01" in source_id:
        return "instruction_override"

    if "SRC-06" in source_id:
        return "role_play_bypass"

    return "unspecified"


def base_record(
    *,
    source_id: str,
    source_path: Path,
    source_record_id: str,
    raw_text: str,
    scanner_input: str,
    scanner_input_prompt_only: str = "",
    scanner_input_with_context: str = "",
    original_label: Any = "",
    normalized_label: str = "unclear",
    candidate_use: str = "review_candidate",
    attack_type: str = "unspecified",
    is_structure_intact: bool = False,
    is_context_eval: bool = False,
    is_augmented: bool = False,
    group_id: Any = "",
    keep_or_drop: str = "review",
    drop_reason: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    text_for_hash = scanner_input or raw_text
    text_len = len(text_for_hash)

    if not text_for_hash:
        keep_or_drop = "drop"
        drop_reason = "empty_text"
    elif text_len < 10:
        keep_or_drop = "drop"
        drop_reason = "too_short"

    return {
        "normalized_record_id": "",  # filled later
        "source_id": source_id,
        "source_name": source_name_from_id(source_id),
        "source_split": detect_split(source_path),
        "source_path": str(source_path.as_posix()),
        "source_record_id": source_record_id,
        "raw_text": raw_text,
        "scanner_input": scanner_input,
        "scanner_input_prompt_only": scanner_input_prompt_only,
        "scanner_input_with_context": scanner_input_with_context,
        "original_label": "" if original_label is None else str(original_label),
        "normalized_label": normalized_label,
        "candidate_use": candidate_use,
        "attack_type": attack_type,
        "is_structure_intact": str(bool(is_structure_intact)).lower(),
        "is_context_eval": str(bool(is_context_eval)).lower(),
        "is_augmented": str(bool(is_augmented)).lower(),
        "group_id": "" if group_id is None else str(group_id),
        "keep_or_drop": keep_or_drop,
        "drop_reason": drop_reason,
        "text_length": text_len,
        "text_sha256": stable_hash(text_for_hash),
        "metadata_json": json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True),
    }


def normalize_src01(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any]:
    source_id = detect_source_id(path)
    text = clean_text(obj.get("text"))

    return base_record(
        source_id=source_id,
        source_path=path,
        source_record_id=f"{path.name}:{line_no}",
        raw_text=text,
        scanner_input=text,
        original_label="unlabeled",
        normalized_label="malicious_candidate",
        candidate_use="malicious_seed",
        attack_type="instruction_override",
        keep_or_drop="review",
        metadata={
            "similarity": obj.get("similarity"),
        },
    )


def normalize_src03(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any]:
    source_id = detect_source_id(path)

    system_prompt = clean_text(obj.get("System Prompt"))
    user_prompt = clean_text(obj.get("User Prompt"))
    original_label = obj.get("Prompt injection")
    degree = obj.get("Degree")

    is_malicious = as_boolish(original_label)

    if is_malicious is True:
        normalized_label = "malicious_candidate"
        candidate_use = "malicious_seed"
    elif is_malicious is False:
        normalized_label = "benign_candidate"
        candidate_use = "benign"
    else:
        normalized_label = "unclear"
        candidate_use = "review_candidate"

    if system_prompt:
        with_context = (
            "[System Prompt]\n"
            f"{system_prompt}\n\n"
            "[User Prompt]\n"
            f"{user_prompt}"
        )
    else:
        with_context = user_prompt

    return base_record(
        source_id=source_id,
        source_path=path,
        source_record_id=f"{path.name}:{line_no}",
        raw_text=user_prompt,
        scanner_input=user_prompt,
        scanner_input_prompt_only=user_prompt,
        scanner_input_with_context=with_context,
        original_label=original_label,
        normalized_label=normalized_label,
        candidate_use=candidate_use,
        attack_type=infer_attack_type(user_prompt, source_id=source_id),
        is_context_eval=True,
        keep_or_drop="review",
        metadata={
            "degree": degree,
            "source": obj.get("Source"),
            "system_prompt_present": bool(system_prompt),
        },
    )


def normalize_src04(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any]:
    source_id = detect_source_id(path)
    text = clean_text(obj.get("text"))
    label = obj.get("label")
    is_malicious = as_boolish(label)

    if is_malicious is True:
        normalized_label = "malicious_candidate"
        candidate_use = "malicious_seed"
    elif is_malicious is False:
        normalized_label = "benign_candidate"
        candidate_use = "benign"
    else:
        normalized_label = "unclear"
        candidate_use = "review_candidate"

    return base_record(
        source_id=source_id,
        source_path=path,
        source_record_id=f"{path.name}:{line_no}",
        raw_text=text,
        scanner_input=text,
        original_label=label,
        normalized_label=normalized_label,
        candidate_use=candidate_use,
        attack_type=infer_attack_type(text, source_id=source_id),
        keep_or_drop="review",
        metadata={},
    )


def normalize_src05(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any]:
    source_id = detect_source_id(path)
    text = clean_text(obj.get("text"))
    label = obj.get("label")
    label_s = str(label).strip().lower()

    if label_s == "benign":
        normalized_label = "benign_candidate"
        candidate_use = "hard_negative"
        attack_type = "none"
    elif label_s == "jailbreak":
        normalized_label = "malicious_candidate"
        candidate_use = "bypass_candidate"
        attack_type = infer_attack_type(text, source_id=source_id, category="jailbreak")
    else:
        normalized_label = "unclear"
        candidate_use = "review_candidate"
        attack_type = infer_attack_type(text, source_id=source_id)

    return base_record(
        source_id=source_id,
        source_path=path,
        source_record_id=f"{path.name}:{line_no}",
        raw_text=text,
        scanner_input=text,
        original_label=label,
        normalized_label=normalized_label,
        candidate_use=candidate_use,
        attack_type=attack_type,
        keep_or_drop="review",
        metadata={},
    )


def normalize_src06(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any]:
    source_id = detect_source_id(path)
    text = clean_text(obj.get("prompt"))

    jailbreak_field = obj.get("jailbreak")
    path_s = str(path.as_posix()).lower()

    is_jailbreak = as_boolish(jailbreak_field)
    if is_jailbreak is None:
        is_jailbreak = "jailbreak" in path_s and "regular" not in path_s

    if is_jailbreak:
        normalized_label = "malicious_candidate"
        candidate_use = "bypass_candidate"
        attack_type = infer_attack_type(text, source_id=source_id, category="jailbreak")
    else:
        normalized_label = "benign_candidate"
        candidate_use = "benign_candidate"
        attack_type = "none"

    return base_record(
        source_id=source_id,
        source_path=path,
        source_record_id=f"{path.name}:{line_no}",
        raw_text=text,
        scanner_input=text,
        original_label=jailbreak_field,
        normalized_label=normalized_label,
        candidate_use=candidate_use,
        attack_type=attack_type,
        keep_or_drop="review",
        metadata={
            "platform": obj.get("platform"),
            "source": obj.get("source"),
            "created_at": obj.get("created_at"),
            "date": obj.get("date"),
            "community_id": obj.get("community_id"),
            "community_name": obj.get("community_name"),
            "community": obj.get("community"),
            "previous_community_id": obj.get("previous_community_id"),
        },
    )


def normalize_src07(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any]:
    source_id = detect_source_id(path)
    text = clean_text(obj.get("text"))
    label = obj.get("label")
    is_malicious = as_boolish(label)

    wrapper = (
        "You are reviewing the following repository file content for possible prompt injection risk. "
        "Determine whether the file contains instructions that attempt to manipulate an AI assistant, "
        "override its instructions, or exfiltrate hidden information.\n\n"
        "[Repository File Content]\n"
        f"{text}"
    )

    if is_malicious is True:
        normalized_label = "malicious_candidate"
        candidate_use = "structure_intact_malicious"
    elif is_malicious is False:
        normalized_label = "benign_candidate"
        candidate_use = "benign_hard_negative"
    else:
        normalized_label = "unclear"
        candidate_use = "structure_intact_review"

    return base_record(
        source_id=source_id,
        source_path=path,
        source_record_id=f"{path.name}:{line_no}",
        raw_text=text,
        scanner_input=wrapper,
        original_label=label,
        normalized_label=normalized_label,
        candidate_use=candidate_use,
        attack_type="indirect_injection",
        is_structure_intact=True,
        keep_or_drop="review",
        metadata={
            "wrapper": "repository_file_review_v1",
        },
    )


def normalize_src09(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any]:
    source_id = detect_source_id(path)
    text = clean_text(obj.get("text"))

    label = obj.get("label")
    category = obj.get("category")
    severity = obj.get("severity")
    group_id = obj.get("group_id")
    augmented = as_boolish(obj.get("augmented")) or False

    is_malicious = as_boolish(label)

    if is_malicious is True:
        normalized_label = "malicious_candidate"
        candidate_use = "malicious_seed"
    elif is_malicious is False:
        normalized_label = "benign_candidate"
        candidate_use = "benign"
    else:
        normalized_label = "unclear"
        candidate_use = "review_candidate"

    return base_record(
        source_id=source_id,
        source_path=path,
        source_record_id=f"{path.name}:{line_no}",
        raw_text=text,
        scanner_input=text,
        original_label=label,
        normalized_label=normalized_label,
        candidate_use=candidate_use,
        attack_type=infer_attack_type(text, source_id=source_id, category=category),
        is_augmented=augmented,
        group_id=group_id,
        keep_or_drop="review",
        metadata={
            "category": category,
            "severity": severity,
            "source": obj.get("source"),
            "tags": obj.get("tags"),
        },
    )


def normalize_one(path: Path, line_no: int, obj: dict[str, Any]) -> dict[str, Any] | None:
    source_id = detect_source_id(path)

    if source_id.startswith("SRC-01"):
        return normalize_src01(path, line_no, obj)
    if source_id.startswith("SRC-03"):
        return normalize_src03(path, line_no, obj)
    if source_id.startswith("SRC-04"):
        return normalize_src04(path, line_no, obj)
    if source_id.startswith("SRC-05"):
        return normalize_src05(path, line_no, obj)
    if source_id.startswith("SRC-06"):
        return normalize_src06(path, line_no, obj)
    if source_id.startswith("SRC-07"):
        return normalize_src07(path, line_no, obj)
    if source_id.startswith("SRC-09"):
        return normalize_src09(path, line_no, obj)

    return None


def write_outputs(rows: list[dict[str, Any]]) -> None:
    with JSONL_OUT.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    with CSV_OUT.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def write_summary(rows: list[dict[str, Any]]) -> None:
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["source_id"]].append(row)

    summary_rows = []

    for source_id, group in sorted(grouped.items()):
        label_counts = Counter(r["normalized_label"] for r in group)
        use_counts = Counter(r["candidate_use"] for r in group)
        attack_counts = Counter(r["attack_type"] for r in group)
        keep_counts = Counter(r["keep_or_drop"] for r in group)
        split_counts = Counter(r["source_split"] for r in group)

        summary_rows.append({
            "source_id": source_id,
            "total": len(group),
            "splits": json.dumps(dict(split_counts), ensure_ascii=False, sort_keys=True),
            "normalized_label_counts": json.dumps(dict(label_counts), ensure_ascii=False, sort_keys=True),
            "candidate_use_counts": json.dumps(dict(use_counts), ensure_ascii=False, sort_keys=True),
            "attack_type_counts": json.dumps(dict(attack_counts), ensure_ascii=False, sort_keys=True),
            "keep_or_drop_counts": json.dumps(dict(keep_counts), ensure_ascii=False, sort_keys=True),
        })

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        fieldnames = [
            "source_id",
            "total",
            "splits",
            "normalized_label_counts",
            "candidate_use_counts",
            "attack_type_counts",
            "keep_or_drop_counts",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

    with SUMMARY_MD.open("w", encoding="utf-8") as f:
        f.write("# Normalization Summary v1\n\n")
        f.write(f"- total normalized rows: {len(rows)}\n")
        f.write(f"- output jsonl: `{JSONL_OUT.as_posix()}`\n")
        f.write(f"- output csv: `{CSV_OUT.as_posix()}`\n\n")

        f.write("| source_id | total | splits | labels | candidate_use | keep/drop |\n")
        f.write("| --- | ---: | --- | --- | --- | --- |\n")

        for r in summary_rows:
            f.write(
                f"| {r['source_id']} "
                f"| {r['total']} "
                f"| `{r['splits']}` "
                f"| `{r['normalized_label_counts']}` "
                f"| `{r['candidate_use_counts']}` "
                f"| `{r['keep_or_drop_counts']}` |\n"
            )


def main() -> None:
    target_files = sorted(
        p for p in RAW_DIR.rglob("*.jsonl")
        if "preview" not in p.name.lower()
    )

    rows: list[dict[str, Any]] = []

    for path in target_files:
        for line_no, obj in read_jsonl(path):
            if not isinstance(obj, dict):
                continue

            row = normalize_one(path, line_no, obj)
            if row is None:
                continue

            rows.append(row)

    for idx, row in enumerate(rows, start=1):
        row["normalized_record_id"] = f"NORM-{idx:07d}"

    write_outputs(rows)
    write_summary(rows)

    print(f"[OK] normalized rows: {len(rows)}")
    print(f"[OK] wrote {JSONL_OUT}")
    print(f"[OK] wrote {CSV_OUT}")
    print(f"[OK] wrote {SUMMARY_CSV}")
    print(f"[OK] wrote {SUMMARY_MD}")


if __name__ == "__main__":
    main()
