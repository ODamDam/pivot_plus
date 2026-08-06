from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def find_project_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "data").is_dir() and (candidate / "scripts").is_dir():
            return candidate
    raise FileNotFoundError("Could not find project root containing data/ and scripts/.")


PROJECT_ROOT = find_project_root(Path(__file__).parent)

BENIGN_PATH = (
    PROJECT_ROOT / "data" / "review" / "01_seed_review" / "benign"
    / "manual_review_benign_schema_v1.csv"
)
HARD_PATH = (
    PROJECT_ROOT / "data" / "review" / "01_seed_review" / "hard_negative"
    / "manual_review_hard_negative_schema_v1.csv"
)
SEED_PATH = (
    PROJECT_ROOT / "data" / "inputs" / "mutation"
    / "mutation_seeds_diagnostic_v1_seed250.jsonl"
)
MUTATED_PATH = PROJECT_ROOT / "data" / "final" / "mutated_malicious_500_v1.csv"
STRUCTURE_PATH = (
    PROJECT_ROOT / "data" / "review" / "04_structure_intact" / "final"
    / "structure_intact_dataset_150_v1.csv"
)

BENIGN_OUTPUT_DIR = PROJECT_ROOT / "data" / "review" / "05_benign" / "final"
FINAL_OUTPUT_DIR = PROJECT_ROOT / "data" / "final"
REPORTS_DIR = PROJECT_ROOT / "reports"

BENIGN_SELECTED_CSV = BENIGN_OUTPUT_DIR / "benign_dataset_100_v1.csv"
BENIGN_SELECTED_JSONL = BENIGN_OUTPUT_DIR / "benign_dataset_100_v1.jsonl"
BENIGN_COMPLETED_CSV = BENIGN_OUTPUT_DIR / "benign_candidates_520_reviewed_v1.csv"

FINAL_CSV = FINAL_OUTPUT_DIR / "prompt_injection_diagnostic_dataset_1000_v1.csv"
FINAL_JSONL = FINAL_OUTPUT_DIR / "prompt_injection_diagnostic_dataset_1000_v1.jsonl"
FINAL_MANIFEST = FINAL_OUTPUT_DIR / "prompt_injection_diagnostic_dataset_1000_manifest_v1.csv"
FINAL_SUMMARY = REPORTS_DIR / "prompt_injection_diagnostic_dataset_1000_summary_v1.json"


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"No rows to write: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                fields.append(key)
                seen.add(key)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def norm(value: Any) -> str:
    return str(value or "").strip()


def first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = norm(row.get(key))
        if value:
            return value
    return ""


def normalized_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


PI_PATTERN = re.compile(
    r"(?is)"
    r"\b(ignore|disregard|override|forget|supersede|bypass|disable)\b"
    r".{0,120}\b(previous|prior|above|system|instruction|policy|guardrail|filter)\b"
    r"|system\s+prompt"
    r"|developer\s+message"
    r"|\b(reveal|print|show|send|upload)\b.{0,80}"
    r"\b(secret|password|token|credential|api\s*key)\b"
    r"|exfiltrat"
)


def contains_prompt_injection(text: str) -> bool:
    return bool(PI_PATTERN.search(text))


def lexical_signature(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", text.lower()))


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def diverse_select(
    rows: list[dict[str, Any]],
    count: int,
    *,
    max_similarity: float = 0.82,
) -> list[dict[str, Any]]:
    ordered = sorted(
        rows,
        key=lambda r: (
            abs(len(normalized_space(first(r, "scanner_input"))) - 260),
            first(r, "text_sha256") or sha256_text(first(r, "scanner_input")),
        ),
    )
    selected: list[dict[str, Any]] = []
    signatures: list[set[str]] = []

    for row in ordered:
        sig = lexical_signature(first(row, "scanner_input"))
        if all(jaccard(sig, previous) < max_similarity for previous in signatures):
            selected.append(row)
            signatures.append(sig)
        if len(selected) == count:
            return selected

    selected_hashes = {
        first(row, "text_sha256") or sha256_text(first(row, "scanner_input"))
        for row in selected
    }
    for row in ordered:
        row_hash = first(row, "text_sha256") or sha256_text(first(row, "scanner_input"))
        if row_hash not in selected_hashes:
            selected.append(row)
            selected_hashes.add(row_hash)
        if len(selected) == count:
            break

    if len(selected) != count:
        raise ValueError(f"Could select only {len(selected)} of requested {count}")
    return selected


def common_row(
    *,
    dataset_id: str,
    sample_id: str,
    parent_seed_id: str,
    source_id: str,
    source_record_id: str,
    source_split: str,
    scanner_input: str,
    text_hash: str,
    ground_truth: str,
    subset: str,
    attack_category: str = "",
    attack_type: str = "",
    attack_goal: str = "",
    attack_surface: str = "",
    input_format: str = "plain_text",
    language: str = "english",
    is_mutated: bool = False,
    mutation_family: str = "",
    mutation_operator: str = "",
    mutation_strength: str = "",
    parent_record_id: str = "",
    structure_format: str = "",
    structure_origin: str = "",
    generation_method: str = "",
    provenance_status: str = "traceable",
    review_status: str = "final",
    candidate_use: str = "",
    expected_behavior: str = "",
    metadata_json: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": "dataset_schema_v1",
        "dataset_id": dataset_id,
        "sample_id": sample_id,
        "parent_seed_id": parent_seed_id,
        "source_id": source_id,
        "source_record_id": source_record_id,
        "source_split": source_split,
        "scanner_input": scanner_input,
        "scanner_input_prompt_only": scanner_input,
        "scanner_input_with_context": scanner_input,
        "text_sha256": text_hash,
        "ground_truth_decision": ground_truth,
        "is_malicious": ground_truth == "malicious",
        "dataset_subset": subset,
        "attack_category": attack_category,
        "attack_type": attack_type,
        "attack_goal": attack_goal,
        "attack_surface": attack_surface,
        "input_format": input_format,
        "language": language,
        "is_mutated": is_mutated,
        "mutation_family": mutation_family,
        "mutation_operator": mutation_operator,
        "mutation_strength": mutation_strength,
        "parent_record_id": parent_record_id,
        "structure_format": structure_format,
        "structure_origin": structure_origin,
        "generation_method": generation_method,
        "provenance_status": provenance_status,
        "review_decision": "keep",
        "review_status": review_status,
        "quota_selection": "yes",
        "candidate_use": candidate_use,
        "expected_behavior": expected_behavior,
        "metadata_json": metadata_json,
    }


def main() -> None:
    benign_candidates = read_csv(BENIGN_PATH)
    hard_candidates = read_csv(HARD_PATH)
    seed_rows = read_jsonl(SEED_PATH)
    mutated_rows = read_csv(MUTATED_PATH)
    structure_rows = read_csv(STRUCTURE_PATH)

    if (len(seed_rows), len(mutated_rows), len(structure_rows)) != (250, 500, 150):
        raise ValueError(
            f"Unexpected malicious subset counts: "
            f"{len(seed_rows)}, {len(mutated_rows)}, {len(structure_rows)}"
        )

    existing_hashes: set[str] = set()
    for row in seed_rows:
        text = first(row, "scanner_input", "mutation_target_text")
        existing_hashes.add(first(row, "text_sha256") or sha256_text(text))
    for row in mutated_rows:
        text = first(row, "child_text")
        existing_hashes.add(first(row, "child_sha256") or sha256_text(text))
    for row in structure_rows:
        text = first(row, "scanner_input")
        existing_hashes.add(first(row, "text_sha256") or sha256_text(text))

    general_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in benign_candidates:
        text = normalized_space(first(row, "scanner_input"))
        text_hash = first(row, "text_sha256") or sha256_text(text)
        eligible = (
            norm(row.get("is_malicious")).lower() in {"false", "0"}
            and norm(row.get("candidate_use")).lower() == "benign"
            and 35 <= len(text) <= 900
            and not contains_prompt_injection(text)
            and text_hash not in existing_hashes
        )
        row["_text_hash"] = text_hash
        if eligible:
            general_by_source[first(row, "source_id")].append(row)

    general_selected: list[dict[str, Any]] = []
    for source_id in sorted(general_by_source):
        general_selected.extend(diverse_select(general_by_source[source_id], 20))
    if len(general_selected) != 60:
        raise ValueError(f"General benign count mismatch: {len(general_selected)}")

    repo_candidates: list[dict[str, Any]] = []
    rogue_candidates: list[dict[str, Any]] = []

    for row in hard_candidates:
        text = first(row, "scanner_input")
        text_hash = first(row, "text_sha256") or sha256_text(text)
        source_id = first(row, "source_id")
        candidate_use = norm(row.get("candidate_use")).lower()

        base_eligible = (
            norm(row.get("is_malicious")).lower() in {"false", "0"}
            and candidate_use in {"hard_negative", "benign_hard_negative"}
            and 20 <= len(text) <= 1800
            and text_hash not in existing_hashes
        )
        row["_text_hash"] = text_hash

        if source_id.startswith("SRC-07"):
            marker = "[Repository File Content]"
            payload = text.split(marker, 1)[1].strip() if marker in text else text
            if (
                base_eligible
                and 15 <= len(payload) <= 800
                and not contains_prompt_injection(payload)
            ):
                repo_candidates.append(row)

        elif source_id.startswith("SRC-05"):
            if base_eligible and not contains_prompt_injection(text):
                rogue_candidates.append(row)

    repo_selected = diverse_select(repo_candidates, 20, max_similarity=0.72)

    challenge_terms = re.compile(
        r"(?i)\b(role|character|fictional|security|policy|guideline|assistant|"
        r"cyber|privacy|safety|ethical|restricted|controversial)\b"
    )
    rogue_candidates.sort(
        key=lambda row: (
            -len(challenge_terms.findall(first(row, "scanner_input"))),
            abs(len(normalized_space(first(row, "scanner_input"))) - 500),
            row["_text_hash"],
        )
    )

    rogue_selected: list[dict[str, Any]] = []
    signatures: list[set[str]] = []
    for row in rogue_candidates:
        sig = lexical_signature(first(row, "scanner_input"))
        if all(jaccard(sig, previous) < 0.78 for previous in signatures):
            rogue_selected.append(row)
            signatures.append(sig)
        if len(rogue_selected) == 20:
            break

    if len(rogue_selected) < 20:
        selected_hashes = {row["_text_hash"] for row in rogue_selected}
        for row in rogue_candidates:
            if row["_text_hash"] not in selected_hashes:
                rogue_selected.append(row)
                selected_hashes.add(row["_text_hash"])
            if len(rogue_selected) == 20:
                break

    selected_candidates = general_selected + repo_selected + rogue_selected
    if len(selected_candidates) != 100:
        raise ValueError(f"Benign selection count mismatch: {len(selected_candidates)}")

    selected_hashes = [row["_text_hash"] for row in selected_candidates]
    if len(selected_hashes) != len(set(selected_hashes)):
        raise ValueError("Duplicate hashes inside benign 100")
    if set(selected_hashes) & existing_hashes:
        raise ValueError("Benign 100 overlaps malicious 900")

    selected_hash_set = set(selected_hashes)
    reviewed_all: list[dict[str, Any]] = []

    for origin, rows in [
        ("general_benign_pool", benign_candidates),
        ("hard_negative_pool", hard_candidates),
    ]:
        for row in rows:
            out = {k: v for k, v in row.items() if not k.startswith("_")}
            text = first(row, "scanner_input")
            text_hash = first(row, "text_sha256") or sha256_text(text)
            selected = text_hash in selected_hash_set
            out["review_decision"] = "keep" if selected else "drop"
            out["review_status"] = "final_rule_based_quality_review"
            out["needs_relabel"] = "no"
            out["ground_truth_decision"] = "benign"
            out["is_malicious"] = "false"
            out["text_sha256"] = text_hash
            out["quota_selection"] = "yes" if selected else "no"
            out["selection_origin_pool"] = origin
            out["final_benign_subtype"] = (
                "benign_general"
                if selected and origin == "general_benign_pool"
                else "benign_hard_negative"
                if selected
                else ""
            )
            if selected:
                out["review_note"] = (
                    "Selected after deterministic validity, prompt-injection exclusion, "
                    "length, provenance, duplicate, and lexical-diversity checks."
                )
            elif not norm(out.get("review_note")):
                out["review_note"] = (
                    "Not selected because it was ineligible or a more diverse candidate "
                    "from the same source/bucket was selected."
                )
            reviewed_all.append(out)

    write_csv(BENIGN_COMPLETED_CSV, reviewed_all)

    benign_final: list[dict[str, Any]] = []
    for index, row in enumerate(selected_candidates, start=1):
        text = first(row, "scanner_input")
        subtype = "benign_general" if row in general_selected else "benign_hard_negative"
        benign_final.append(
            common_row(
                dataset_id=f"BENIGN-{index:04d}",
                sample_id=first(row, "sample_id"),
                parent_seed_id="",
                source_id=first(row, "source_id"),
                source_record_id=first(row, "source_record_id"),
                source_split=first(row, "source_split"),
                scanner_input=text,
                text_hash=row["_text_hash"],
                ground_truth="benign",
                subset=subtype,
                input_format=first(row, "input_format") or "plain_text",
                language=first(row, "language") or "english",
                structure_origin="source_original",
                generation_method="source_original",
                review_status="final_rule_based_quality_review",
                candidate_use=first(row, "candidate_use"),
                expected_behavior="detect_as_benign",
                metadata_json=first(row, "metadata_json"),
            )
        )

    write_csv(BENIGN_SELECTED_CSV, benign_final)
    write_jsonl(BENIGN_SELECTED_JSONL, benign_final)

    final_rows: list[dict[str, Any]] = []

    for index, row in enumerate(seed_rows, start=1):
        text = first(row, "scanner_input", "mutation_target_text")
        final_rows.append(
            common_row(
                dataset_id=f"SEED-{index:04d}",
                sample_id=first(row, "sample_id"),
                parent_seed_id=first(row, "parent_seed_id", "sample_id"),
                source_id=first(row, "source_id"),
                source_record_id=first(row, "source_record_id"),
                source_split=first(row, "source_split"),
                scanner_input=text,
                text_hash=first(row, "text_sha256") or sha256_text(text),
                ground_truth="malicious",
                subset="seed_malicious",
                attack_category=first(row, "attack_category"),
                attack_type=first(row, "attack_type"),
                attack_goal=first(row, "attack_goal"),
                attack_surface=first(row, "attack_surface"),
                input_format=first(row, "input_format") or "plain_text",
                language=first(row, "language") or "english",
                structure_origin="source_original",
                generation_method="source_original",
                review_status=first(row, "review_status") or "final_seed_curation",
                candidate_use="malicious_seed",
                expected_behavior="detect_as_malicious",
                metadata_json=first(row, "metadata_json"),
            )
        )

    for index, row in enumerate(mutated_rows, start=1):
        text = first(row, "child_text")
        final_rows.append(
            common_row(
                dataset_id=f"MUTATED-{index:04d}",
                sample_id=first(row, "final_sample_id"),
                parent_seed_id=first(row, "parent_record_id"),
                source_id="",
                source_record_id="",
                source_split="",
                scanner_input=text,
                text_hash=first(row, "child_sha256") or sha256_text(text),
                ground_truth="malicious",
                subset="mutated_malicious",
                attack_type=first(row, "attack_type"),
                input_format=first(row, "output_format", "input_format") or "plain_text",
                is_mutated=True,
                mutation_family=first(row, "operator_family"),
                mutation_operator=first(row, "selected_op_id"),
                parent_record_id=first(row, "parent_record_id"),
                structure_origin="mutation_generated",
                generation_method="mutation_engine_v1",
                review_status=first(row, "filter_decision") or "VALID",
                candidate_use="mutated_malicious",
                expected_behavior="detect_as_malicious",
                metadata_json=json.dumps(
                    {
                        "final_selection_index": first(row, "final_selection_index"),
                        "length_ratio": first(row, "length_ratio"),
                        "input_format": first(row, "input_format"),
                        "output_format": first(row, "output_format"),
                    },
                    ensure_ascii=False,
                ),
            )
        )

    for index, row in enumerate(structure_rows, start=1):
        text = first(row, "scanner_input")
        final_rows.append(
            common_row(
                dataset_id=f"STRUCTURE-{index:04d}",
                sample_id=first(row, "candidate_id", "dataset_id"),
                parent_seed_id="",
                source_id=first(row, "source_id"),
                source_record_id=first(row, "source_record_id"),
                source_split="",
                scanner_input=text,
                text_hash=first(row, "text_sha256") or sha256_text(text),
                ground_truth="malicious",
                subset="structure_intact_malicious",
                attack_type=first(row, "attack_type"),
                attack_goal=first(row, "attack_goal"),
                attack_surface=first(row, "attack_surface"),
                input_format=first(row, "structure_format") or "structured",
                structure_format=first(row, "structure_format"),
                structure_origin=first(row, "structure_origin"),
                generation_method=first(row, "generation_method"),
                provenance_status=first(row, "provenance_status") or "traceable",
                review_status="final_structure_intact_review",
                candidate_use="structure_intact_malicious",
                expected_behavior="detect_as_malicious",
                metadata_json=json.dumps(
                    {"review_note": first(row, "review_note")},
                    ensure_ascii=False,
                ),
            )
        )

    final_rows.extend(benign_final)

    if len(final_rows) != 1000:
        raise ValueError(f"Final dataset count is {len(final_rows)}, expected 1000")

    hashes = [row["text_sha256"] for row in final_rows]
    duplicate_hashes = [h for h, count in Counter(hashes).items() if count > 1]
    if duplicate_hashes:
        raise ValueError(f"Duplicate hashes in final dataset: {duplicate_hashes[:10]}")

    subset_counts = Counter(row["dataset_subset"] for row in final_rows)
    truth_counts = Counter(row["ground_truth_decision"] for row in final_rows)

    write_csv(FINAL_CSV, final_rows)
    write_jsonl(FINAL_JSONL, final_rows)

    manifest_rows = [
        {"dataset_subset": "seed_malicious", "target_count": 250,
         "actual_count": subset_counts["seed_malicious"],
         "ground_truth_decision": "malicious", "status": "complete"},
        {"dataset_subset": "mutated_malicious", "target_count": 500,
         "actual_count": subset_counts["mutated_malicious"],
         "ground_truth_decision": "malicious", "status": "complete"},
        {"dataset_subset": "structure_intact_malicious", "target_count": 150,
         "actual_count": subset_counts["structure_intact_malicious"],
         "ground_truth_decision": "malicious", "status": "complete"},
        {"dataset_subset": "benign_general", "target_count": 60,
         "actual_count": subset_counts["benign_general"],
         "ground_truth_decision": "benign", "status": "complete"},
        {"dataset_subset": "benign_hard_negative", "target_count": 40,
         "actual_count": subset_counts["benign_hard_negative"],
         "ground_truth_decision": "benign", "status": "complete"},
    ]
    write_csv(FINAL_MANIFEST, manifest_rows)

    summary = {
        "schema_version": "dataset_schema_v1",
        "dataset_name": "prompt_injection_diagnostic_dataset_1000_v1",
        "total_rows": len(final_rows),
        "ground_truth_counts": dict(truth_counts),
        "subset_counts": dict(subset_counts),
        "benign_source_counts": dict(Counter(row["source_id"] for row in benign_final)),
        "duplicate_text_hash_count": 0,
        "all_rows_reviewed_keep": all(row["review_decision"] == "keep" for row in final_rows),
        "all_rows_quota_selected": all(row["quota_selection"] == "yes" for row in final_rows),
        "outputs": {
            "benign_csv": str(BENIGN_SELECTED_CSV.relative_to(PROJECT_ROOT)),
            "benign_jsonl": str(BENIGN_SELECTED_JSONL.relative_to(PROJECT_ROOT)),
            "final_csv": str(FINAL_CSV.relative_to(PROJECT_ROOT)),
            "final_jsonl": str(FINAL_JSONL.relative_to(PROJECT_ROOT)),
            "manifest_csv": str(FINAL_MANIFEST.relative_to(PROJECT_ROOT)),
        },
    }
    FINAL_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    FINAL_SUMMARY.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("=" * 72)
    print("[done] benign 100 and dataset_schema_v1 merge")
    print(f"benign general       : {subset_counts['benign_general']}")
    print(f"benign hard-negative: {subset_counts['benign_hard_negative']}")
    print(f"final total          : {len(final_rows)}")
    print(f"malicious            : {truth_counts['malicious']}")
    print(f"benign               : {truth_counts['benign']}")
    print("duplicate hashes     : 0")
    print(f"final CSV            : {FINAL_CSV}")
    print(f"final JSONL          : {FINAL_JSONL}")
    print(f"manifest             : {FINAL_MANIFEST}")
    print(f"summary              : {FINAL_SUMMARY}")
    print("=" * 72)


if __name__ == "__main__":
    main()
