from __future__ import annotations

import csv
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


INPUT_JSONL = Path("data/normalized/eligible_pool_v1.jsonl")

REVIEW_DIR = Path("data/review")
REPORT_DIR = Path("reports")

REVIEW_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_SEED = 20260706
random.seed(RANDOM_SEED)

OUTPUTS = {
    "seed_malicious": REVIEW_DIR / "manual_review_seed_malicious_schema_v1.csv",
    "bypass_candidate": REVIEW_DIR / "manual_review_bypass_candidate_schema_v1.csv",
    "structure_intact_malicious": REVIEW_DIR / "manual_review_structure_intact_malicious_schema_v1.csv",
    "benign": REVIEW_DIR / "manual_review_benign_schema_v1.csv",
    "hard_negative": REVIEW_DIR / "manual_review_hard_negative_schema_v1.csv",
    "context_eval": REVIEW_DIR / "manual_review_context_eval_schema_v1.csv",
}

SUMMARY_CSV = REPORT_DIR / "manual_review_sampling_schema_v1_summary.csv"
SUMMARY_MD = REPORT_DIR / "manual_review_sampling_schema_v1_summary.md"


# 최종 목표보다 넉넉하게 뽑는다.
BUCKET_TARGETS = {
    "seed_malicious": 500,
    "bypass_candidate": 240,
    "structure_intact_malicious": 300,
    "benign": 260,
    "hard_negative": 260,
    "context_eval": 240,
}


REVIEW_FIELDNAMES = [
    # manual review fields
    "review_decision",
    "review_note",
    "needs_relabel",

    # final benchmark schema fields
    "sample_id",
    "subset",
    "parent_seed_id",
    "source_id",
    "source_record_id",
    "source_split",
    "scanner_input",
    "scanner_input_prompt_only",
    "scanner_input_with_context",
    "is_malicious",
    "ground_truth_decision",
    "attack_category",
    "attack_type",
    "attack_goal",
    "attack_surface",
    "input_format",
    "language",
    "is_mutated",
    "mutation_family",
    "mutation_operator",
    "mutation_strength",
    "target_evaluator_weakness",
    "semantic_preservation",
    "expected_behavior",
    "review_status",
    "notes",
    "normalized_record_id",
    "text_sha256",
    "metadata_json",

    # convenience fields
    "candidate_use",
    "original_label",
    "is_structure_intact",
    "is_context_eval",
    "is_augmented",
    "group_id",
    "text_length",
    "scanner_input_preview",
]


def read_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def bool_str(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def infer_attack_category(attack_type: str, candidate_use: str, is_structure: bool) -> str:
    if candidate_use in {"benign", "hard_negative", "benign_candidate", "benign_hard_negative"}:
        return "benign"

    if is_structure or attack_type in {"indirect_injection", "context_poisoning"}:
        return "indirect_prompt_injection"

    if attack_type in {"system_prompt_extraction", "data_exfiltration"}:
        return "data_risk"

    if attack_type in {"tool_manipulation"}:
        return "action_risk"

    if attack_type in {"format_injection"}:
        return "robustness_risk"

    return "direct_prompt_injection"


def infer_attack_goal(attack_type: str, is_benign: bool) -> str:
    if is_benign:
        return "none"

    mapping = {
        "instruction_override": "override_instruction",
        "role_play_bypass": "bypass_policy",
        "policy_bypass": "bypass_policy",
        "system_prompt_extraction": "leak_system_prompt",
        "data_exfiltration": "exfiltrate_secret",
        "format_injection": "evade_detection",
        "indirect_injection": "poison_context",
        "tool_manipulation": "manipulate_tool",
        "context_poisoning": "poison_context",
        "unspecified": "override_instruction",
    }

    return mapping.get(attack_type, "override_instruction")


def infer_attack_surface(row: dict[str, Any], subset: str) -> str:
    is_structure = bool_str(row.get("is_structure_intact"))
    is_context = bool_str(row.get("is_context_eval"))

    if subset == "benign":
        return "none"

    if is_structure:
        return "repository_file"

    if is_context:
        return "system_user_context"

    attack_type = row.get("attack_type", "")

    if attack_type == "format_injection":
        return "structured_input"

    return "user_prompt"


def infer_input_format(row: dict[str, Any]) -> str:
    text = row.get("scanner_input", "") or ""
    text_l = text.lower()

    if bool_str(row.get("is_structure_intact")):
        return "repository_file"

    if "```" in text:
        return "code_block"

    stripped = text.strip()

    if stripped.startswith("{") or stripped.startswith("["):
        return "json"

    if re.search(r"(?m)^\s*[-*]\s+", text) or "#" in text_l:
        return "markdown"

    if "<html" in text_l or "</" in text_l:
        return "html"

    if re.search(r"(?m)^\s*[a-zA-Z0-9_-]+\s*:\s+", text):
        return "yaml"

    if any(k in text_l for k in ["base64", "rot13", "unicode", "encoded"]):
        return "encoded"

    return "plain_text"


def infer_language(row: dict[str, Any]) -> str:
    text = row.get("scanner_input", "") or ""

    has_korean = bool(re.search(r"[가-힣]", text))
    has_english = bool(re.search(r"[A-Za-z]", text))

    if has_korean and has_english:
        return "mixed"
    if has_korean:
        return "korean"
    if has_english:
        return "english"

    return "unknown"


def infer_target_weakness(attack_type: str, input_format: str, is_benign: bool) -> str:
    if is_benign:
        return "none"

    if input_format in {"json", "yaml", "xml", "html", "markdown", "code_block", "repository_file"}:
        return "structure_handling"

    if input_format == "encoded":
        return "normalization"

    if attack_type in {"instruction_override", "policy_bypass"}:
        return "keyword_matching"

    if attack_type in {"role_play_bypass", "data_exfiltration", "system_prompt_extraction"}:
        return "semantic_understanding"

    return "unknown"


def to_subset(row: dict[str, Any], bucket_name: str) -> str:
    if bucket_name == "seed_malicious":
        return "seed_malicious"
    if bucket_name == "bypass_candidate":
        return "seed_malicious"
    if bucket_name == "structure_intact_malicious":
        return "structure_intact_malicious"
    if bucket_name in {"benign", "hard_negative"}:
        return "benign"
    if bucket_name == "context_eval":
        if row.get("normalized_label") == "malicious_candidate":
            return "seed_malicious"
        return "benign"

    return "seed_malicious"


def sample_id_prefix(subset: str) -> str:
    if subset == "seed_malicious":
        return "SEED-CAND"
    if subset == "structure_intact_malicious":
        return "STRUCT-CAND"
    if subset == "benign":
        return "BENIGN-CAND"
    return "CAND"


def to_review_row(row: dict[str, Any], bucket_name: str, local_idx: int) -> dict[str, Any]:
    subset = to_subset(row, bucket_name)

    is_benign = subset == "benign"
    is_malicious = not is_benign

    attack_type = row.get("attack_type", "unspecified") or "unspecified"

    if is_benign:
        if row.get("candidate_use") in {"hard_negative", "benign_hard_negative"}:
            attack_type = "benign_hard_negative"
        else:
            attack_type = "benign_general"

    input_format = infer_input_format(row)
    attack_surface = infer_attack_surface(row, subset)
    attack_category = infer_attack_category(
        attack_type=attack_type,
        candidate_use=row.get("candidate_use", ""),
        is_structure=bool_str(row.get("is_structure_intact")),
    )

    if is_benign:
        attack_category = "benign"
        attack_surface = "none"

    attack_goal = infer_attack_goal(attack_type, is_benign=is_benign)
    language = infer_language(row)
    target_weakness = infer_target_weakness(attack_type, input_format, is_benign=is_benign)

    scanner_input = row.get("scanner_input", "") or ""

    prefix = sample_id_prefix(subset)

    return {
        # manual review fields
        "review_decision": "",
        "review_note": "",
        "needs_relabel": "",

        # final benchmark schema fields
        "sample_id": f"{prefix}-{local_idx:06d}",
        "subset": subset,
        "parent_seed_id": "",
        "source_id": row.get("source_id", ""),
        "source_record_id": row.get("source_record_id", ""),
        "source_split": row.get("source_split", ""),
        "scanner_input": scanner_input,
        "scanner_input_prompt_only": row.get("scanner_input_prompt_only", ""),
        "scanner_input_with_context": row.get("scanner_input_with_context", ""),
        "is_malicious": str(is_malicious).lower(),
        "ground_truth_decision": "malicious" if is_malicious else "benign",
        "attack_category": attack_category,
        "attack_type": attack_type,
        "attack_goal": attack_goal,
        "attack_surface": attack_surface,
        "input_format": input_format,
        "language": language,
        "is_mutated": "false",
        "mutation_family": "",
        "mutation_operator": "",
        "mutation_strength": "",
        "target_evaluator_weakness": target_weakness,
        "semantic_preservation": "preserved" if is_malicious else "not_applicable",
        "expected_behavior": "detect_as_malicious" if is_malicious else "detect_as_benign",
        "review_status": "auto",
        "notes": "",
        "normalized_record_id": row.get("normalized_record_id", ""),
        "text_sha256": row.get("text_sha256", ""),
        "metadata_json": row.get("metadata_json", ""),

        # convenience fields
        "candidate_use": row.get("candidate_use", ""),
        "original_label": row.get("original_label", ""),
        "is_structure_intact": row.get("is_structure_intact", ""),
        "is_context_eval": row.get("is_context_eval", ""),
        "is_augmented": row.get("is_augmented", ""),
        "group_id": row.get("group_id", ""),
        "text_length": row.get("text_length", ""),
        "scanner_input_preview": scanner_input[:700].replace("\n", "\\n"),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=REVIEW_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def stratified_sample(
    rows: list[dict[str, Any]],
    target: int,
    *,
    group_keys: list[str],
) -> list[dict[str, Any]]:
    if len(rows) <= target:
        sampled = list(rows)
        random.shuffle(sampled)
        return sampled

    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        key = tuple(str(row.get(k, "")) for k in group_keys)
        groups[key].append(row)

    for group in groups.values():
        random.shuffle(group)

    sampled: list[dict[str, Any]] = []
    group_items = list(groups.items())
    random.shuffle(group_items)

    while len(sampled) < target:
        progressed = False

        for _, group in group_items:
            if group and len(sampled) < target:
                sampled.append(group.pop())
                progressed = True

        if not progressed:
            break

    random.shuffle(sampled)
    return sampled


def bucketize(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets = {
        "seed_malicious": [],
        "bypass_candidate": [],
        "structure_intact_malicious": [],
        "benign": [],
        "hard_negative": [],
        "context_eval": [],
    }

    for row in rows:
        label = row.get("normalized_label")
        use = row.get("candidate_use")
        is_structure = bool_str(row.get("is_structure_intact"))
        is_context = bool_str(row.get("is_context_eval"))

        if label == "malicious_candidate" and use == "malicious_seed" and not is_structure:
            buckets["seed_malicious"].append(row)

        if label == "malicious_candidate" and use == "bypass_candidate" and not is_structure:
            buckets["bypass_candidate"].append(row)

        if label == "malicious_candidate" and use == "structure_intact_malicious" and is_structure:
            buckets["structure_intact_malicious"].append(row)

        if label == "benign_candidate" and use == "benign" and not is_structure:
            buckets["benign"].append(row)

        if label == "benign_candidate" and use in {"hard_negative", "benign_hard_negative"}:
            buckets["hard_negative"].append(row)

        if is_context and use in {"malicious_seed", "benign"}:
            buckets["context_eval"].append(row)

    return buckets


def summarize_bucket(
    name: str,
    pool_rows: list[dict[str, Any]],
    sampled_rows: list[dict[str, Any]],
    review_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "bucket": name,
        "pool_total": len(pool_rows),
        "sampled_total": len(sampled_rows),
        "source_counts": json.dumps(dict(Counter(r.get("source_id") for r in review_rows)), ensure_ascii=False, sort_keys=True),
        "subset_counts": json.dumps(dict(Counter(r.get("subset") for r in review_rows)), ensure_ascii=False, sort_keys=True),
        "ground_truth_counts": json.dumps(dict(Counter(r.get("ground_truth_decision") for r in review_rows)), ensure_ascii=False, sort_keys=True),
        "attack_category_counts": json.dumps(dict(Counter(r.get("attack_category") for r in review_rows)), ensure_ascii=False, sort_keys=True),
        "attack_type_counts": json.dumps(dict(Counter(r.get("attack_type") for r in review_rows)), ensure_ascii=False, sort_keys=True),
        "input_format_counts": json.dumps(dict(Counter(r.get("input_format") for r in review_rows)), ensure_ascii=False, sort_keys=True),
    }


def main() -> None:
    rows = list(read_jsonl(INPUT_JSONL))
    buckets = bucketize(rows)

    sampled_by_bucket: dict[str, list[dict[str, Any]]] = {}

    sampled_by_bucket["seed_malicious"] = stratified_sample(
        buckets["seed_malicious"],
        BUCKET_TARGETS["seed_malicious"],
        group_keys=["source_id", "attack_type"],
    )

    sampled_by_bucket["bypass_candidate"] = stratified_sample(
        buckets["bypass_candidate"],
        BUCKET_TARGETS["bypass_candidate"],
        group_keys=["source_id", "attack_type"],
    )

    sampled_by_bucket["structure_intact_malicious"] = stratified_sample(
        buckets["structure_intact_malicious"],
        BUCKET_TARGETS["structure_intact_malicious"],
        group_keys=["source_id", "attack_type"],
    )

    sampled_by_bucket["benign"] = stratified_sample(
        buckets["benign"],
        BUCKET_TARGETS["benign"],
        group_keys=["source_id"],
    )

    sampled_by_bucket["hard_negative"] = stratified_sample(
        buckets["hard_negative"],
        BUCKET_TARGETS["hard_negative"],
        group_keys=["source_id"],
    )

    sampled_by_bucket["context_eval"] = stratified_sample(
        buckets["context_eval"],
        BUCKET_TARGETS["context_eval"],
        group_keys=["source_id", "candidate_use", "attack_type"],
    )

    summary_rows = []

    for bucket_name, sampled_rows in sampled_by_bucket.items():
        review_rows = [
            to_review_row(row, bucket_name=bucket_name, local_idx=i)
            for i, row in enumerate(sampled_rows, start=1)
        ]

        write_csv(OUTPUTS[bucket_name], review_rows)

        summary_rows.append(
            summarize_bucket(
                name=bucket_name,
                pool_rows=buckets[bucket_name],
                sampled_rows=sampled_rows,
                review_rows=review_rows,
            )
        )

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        fieldnames = [
            "bucket",
            "pool_total",
            "sampled_total",
            "source_counts",
            "subset_counts",
            "ground_truth_counts",
            "attack_category_counts",
            "attack_type_counts",
            "input_format_counts",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

    with SUMMARY_MD.open("w", encoding="utf-8") as f:
        f.write("# Manual Review Sampling Schema v1 Summary\n\n")
        f.write(f"- input: `{INPUT_JSONL.as_posix()}`\n")
        f.write(f"- random_seed: {RANDOM_SEED}\n\n")

        f.write("| bucket | pool_total | sampled_total | subset_counts | attack_category_counts | attack_type_counts | input_format_counts |\n")
        f.write("| --- | ---: | ---: | --- | --- | --- | --- |\n")

        for r in summary_rows:
            f.write(
                f"| {r['bucket']} "
                f"| {r['pool_total']} "
                f"| {r['sampled_total']} "
                f"| `{r['subset_counts']}` "
                f"| `{r['attack_category_counts']}` "
                f"| `{r['attack_type_counts']}` "
                f"| `{r['input_format_counts']}` |\n"
            )

        f.write("\n## Output Files\n\n")
        for bucket, path in OUTPUTS.items():
            f.write(f"- {bucket}: `{path.as_posix()}`\n")

        f.write("\n## Review Decision Values\n\n")
        f.write("- `keep`: final dataset 후보로 유지\n")
        f.write("- `drop`: 제외\n")
        f.write("- `heldout`: diagnostic에는 넣지 않고 held-out 후보로 분리\n")
        f.write("- `relabel`: label, attack_type, category 등 수정 필요\n")

    print("[OK] schema-v1 manual review samples created")
    for bucket, sampled in sampled_by_bucket.items():
        print(f"[OK] {bucket}: pool={len(buckets[bucket])}, sampled={len(sampled)}")
    print(f"[OK] wrote {SUMMARY_MD}")


if __name__ == "__main__":
    main()
