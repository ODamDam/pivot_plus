#!/usr/bin/env python3
"""Prepare a deterministic, blinded 200-record AI first-pass smoke set.

No API is called. The script selects proportionally by source and diversifies
each source across deterministic text-length buckets. Audit metadata and model
inputs are written separately to prevent label/source leakage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_INPUT = Path("data/dataset_a/candidate_pool/dataset_a_raw_candidate_pool_1500_v1.jsonl")
DEFAULT_OUTPUT = Path("data/dataset_a/adjudication/ai_first_pass_smoke_200_v1.jsonl")
DEFAULT_MANIFEST = Path("reports/dataset_a/ai_first_pass_smoke_200_v1_manifest.json")
DEFAULT_SCHEMA = Path("schemas/dataset_a_ai_first_pass_v1.schema.json")
DEFAULT_SAMPLE_SIZE = 200
DEFAULT_SEED = 20260806


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def allocate_proportional_quotas(capacities: dict[str, int], total: int) -> dict[str, int]:
    if total < 0 or total > sum(capacities.values()):
        raise ValueError("sample size must be between zero and total capacity")
    if not capacities:
        return {}

    population = sum(capacities.values())
    exact = {key: total * value / population for key, value in capacities.items()}
    quotas = {key: min(capacities[key], int(exact[key])) for key in capacities}
    remainder = total - sum(quotas.values())
    order = sorted(capacities, key=lambda key: (-(exact[key] - int(exact[key])), key))
    while remainder:
        progressed = False
        for key in order:
            if quotas[key] < capacities[key]:
                quotas[key] += 1
                remainder -= 1
                progressed = True
                if remainder == 0:
                    break
        if not progressed:
            raise ValueError("unable to allocate sample quota")
    return dict(sorted(quotas.items()))


def length_bucket(text: str) -> str:
    length = len(text)
    if length <= 79:
        return "short"
    if length <= 499:
        return "medium"
    return "long"


def _diverse_sample(records: list[dict[str, Any]], quota: int, rng: random.Random) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        buckets[length_bucket(record["content"]["raw_text"])].append(record)
    for bucket_records in buckets.values():
        bucket_records.sort(key=lambda row: row["candidate_id"])
        rng.shuffle(bucket_records)

    selected: list[dict[str, Any]] = []
    bucket_order = ["short", "medium", "long"]
    while len(selected) < quota:
        progressed = False
        for bucket in bucket_order:
            if buckets[bucket]:
                item = buckets[bucket].pop()
                item = {**item, "_sampling": {"length_bucket": bucket}}
                selected.append(item)
                progressed = True
                if len(selected) == quota:
                    break
        if not progressed:
            raise ValueError("source quota exceeds available records")
    return selected


def select_stratified_records(records: list[dict[str, Any]], sample_size: int, seed: int) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["source"]["source_id"]].append(record)
    quotas = allocate_proportional_quotas({key: len(value) for key, value in grouped.items()}, sample_size)
    rng = random.Random(seed)
    selected: list[dict[str, Any]] = []
    for source_id in sorted(grouped):
        selected.extend(_diverse_sample(grouped[source_id], quotas[source_id], rng))
    return sorted(selected, key=lambda row: row["candidate_id"])


def build_blinded_input(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": record["candidate_id"],
        "content": {
            "standalone_text": record["content"]["raw_text"],
            "trusted_instruction": None,
            "untrusted_input": None,
            "additional_context": None,
            "input_format_observed": record["content"].get("input_format_observed"),
        },
    }


def validate_annotation_schema(path: Path = DEFAULT_SCHEMA) -> dict[str, Any]:
    schema = json.loads(path.read_text(encoding="utf-8"))
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise ValueError("Structured Outputs schema must be a strict object")
    if set(schema.get("required", [])) != set(schema.get("properties", {})):
        raise ValueError("all Structured Outputs properties must be required")
    return schema


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    schema = validate_annotation_schema(args.schema)
    records = read_jsonl(args.input)
    selected = select_stratified_records(records, args.sample_size, args.seed)
    blinded = [build_blinded_input(record) for record in selected]
    write_jsonl(args.output, blinded)

    source_counts = Counter(row["source"]["source_id"] for row in selected)
    tier_counts = Counter(row["collection"]["eligibility_tier"] for row in selected)
    length_counts = Counter(row["_sampling"]["length_bucket"] for row in selected)
    manifest = {
        "manifest_version": "dataset_a_ai_first_pass_smoke_manifest_v1.0",
        "prompt_version": "dataset-a-ai-first-pass-v1.0",
        "policy_version": "pivot-dataset-a-spec-v1.0",
        "random_seed": args.seed,
        "record_count": len(blinded),
        "input_path": args.input.as_posix(),
        "input_sha256": sha256_file(args.input),
        "output_path": args.output.as_posix(),
        "output_sha256": sha256_file(args.output),
        "schema_path": args.schema.as_posix(),
        "schema_sha256": hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest(),
        "source_counts": dict(sorted(source_counts.items())),
        "eligibility_tier_counts": dict(sorted(tier_counts.items())),
        "length_bucket_counts": dict(sorted(length_counts.items())),
        "candidate_ids": [row["candidate_id"] for row in selected],
        "blinding": {
            "included": ["candidate_id", "content"],
            "withheld": ["source", "provenance", "collection", "prior_metadata", "case_gt", "cell_quotas", "other_annotator_results"]
        },
        "api_called": False
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": args.output.as_posix(), "records": len(blinded), "source_counts": dict(sorted(source_counts.items()))}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
