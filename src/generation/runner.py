from __future__ import annotations

import argparse
import json
import time
import uuid
import hashlib
from collections import Counter
from pathlib import Path

from src.common.jsonl import append_jsonl, write_jsonl
from src.dataset.loader import load_dataset_records
from src.generation.clients.base import GenerationClientError
from src.generation.clients.vulnerable_llm import VulnerableLLMClient
from src.generation.message_builder import MessageBuilder
from src.generation.models import ExcludedGenerationInput
from src.generation.result_models import (
    GenerationFailureRecord,
    GenerationRunRecord,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--input-view",
        choices=["prompt_only", "context_prompt"],
        required=True,
    )
    parser.add_argument(
        "--experiment-id",
        required=True,
    )
    parser.add_argument(
        "--generation-profile",
        default="high_yield_v1",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/outputs/generations"),
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=512,
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--sleep-sec",
        type=float,
        default=0.0,
    )

    return parser.parse_args()


def load_completed_dataset_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()

    completed: set[str] = set()

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()

            if not stripped:
                continue

            record = json.loads(stripped)

            dataset_id = record.get("dataset_id")
            execution_status = record.get("execution_status")

            if dataset_id and execution_status == "completed":
                completed.add(str(dataset_id))

    return completed

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def build_experiment_manifest(
    args: argparse.Namespace,
    *,
    dataset_sha256: str,
    server_health: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "generation_experiment_manifest.v1",
        "experiment_id": args.experiment_id,
        "dataset_path": str(args.dataset.resolve()),
        "dataset_sha256": dataset_sha256,
        "input_view": args.input_view,
        "generation_profile": args.generation_profile,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "base_url": args.base_url,
        "server": {
            "api_version": server_health.get("api_version"),
            "ollama_model": server_health.get("ollama_model"),
            "default_temperature": server_health.get(
                "default_temperature"
            ),
            "default_max_tokens": server_health.get(
                "default_max_tokens"
            ),
        },
    }


def validate_or_create_manifest(
    path: Path,
    expected_manifest: dict[str, object],
) -> None:
    if not path.exists():
        path.write_text(
            json.dumps(
                expected_manifest,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return

    existing_manifest = json.loads(
        path.read_text(encoding="utf-8")
    )

    if existing_manifest != expected_manifest:
        raise RuntimeError(
            "Experiment manifest mismatch. "
            "Do not reuse the same experiment_id with different "
            "dataset, input view, generation profile, model, or "
            "generation parameters.\n\n"
            f"Existing manifest:\n"
            f"{json.dumps(existing_manifest, ensure_ascii=False, indent=2)}"
            f"\n\nRequested manifest:\n"
            f"{json.dumps(expected_manifest, ensure_ascii=False, indent=2)}"
        )

def main() -> None:
    args = parse_args()

    run_id = f"run-{uuid.uuid4()}"

    experiment_dir = args.output_dir / args.experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=True)

    result_path = experiment_dir / "results.jsonl"
    failure_path = experiment_dir / "failures.jsonl"
    excluded_path = experiment_dir / "excluded.jsonl"
    summary_path = experiment_dir / "summary.json"
    manifest_path = experiment_dir / "manifest.json"

    records = load_dataset_records(args.dataset)
    builder = MessageBuilder()

    client = VulnerableLLMClient(
        base_url=args.base_url,
        timeout_sec=180.0,
        max_retries=3,
        retry_delay_sec=2.0,
    )

    health = client.health()

    dataset_sha256 = sha256_file(args.dataset)

    manifest = build_experiment_manifest(
        args,
        dataset_sha256=dataset_sha256,
        server_health=health,
    )

    validate_or_create_manifest(
        manifest_path,
        manifest,
    )

    completed_dataset_ids = load_completed_dataset_ids(
        result_path
    )

    print(
        json.dumps(
            {
                "server_health": health,
                "experiment_id": args.experiment_id,
                "run_id": run_id,
                "existing_completed": len(completed_dataset_ids),
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    counters: Counter[str] = Counter()

    excluded_records: list[dict[str, str]] = []
    candidates = []

    for record in records:
        built = builder.build(record, args.input_view)

        if isinstance(built, ExcludedGenerationInput):
            excluded_records.append(
                built.to_dict()
            )
            counters["excluded"] += 1
            continue

        if built.dataset_id in completed_dataset_ids:
            counters["skipped_completed"] += 1
            continue

        candidates.append(built)

    write_jsonl(
        excluded_path,
        excluded_records,
    )

    if args.limit is not None:
        candidates = candidates[: args.limit]

    total = len(candidates)

    for index, generation_input in enumerate(
        candidates,
        start=1,
    ):
        generation_id = (
            f"{args.experiment_id}-"
            f"{generation_input.dataset_id}"
        )

        print(
            f"[{index}/{total}] "
            f"{generation_input.dataset_id}"
        )

        try:
            result = client.generate(
                generation_input,
                experiment_id=args.experiment_id,
                generation_profile=args.generation_profile,
                generation_id=generation_id,
                run_id=run_id,
                temperature=args.temperature,
                max_tokens=args.max_tokens,
            )

            run_record = GenerationRunRecord(
                schema_version="generation_result.v1",
                experiment_id=args.experiment_id,
                run_id=run_id,
                generation_id=generation_id,
                dataset_id=generation_input.dataset_id,
                dataset_subset=(
                    generation_input.dataset_subset
                ),
                input_view=generation_input.input_view,
                generation_profile=(
                    args.generation_profile
                ),
                prompt_text=(
                    generation_input.prompt_text
                ),
                context_text=(
                    generation_input.context_text
                ),
                context_type=(
                    generation_input.context_type
                ),
                source_messages=[
                    message.to_dict()
                    for message in generation_input.messages
                ],
                attack_type=(
                    generation_input.attack_type
                ),
                is_malicious=(
                    generation_input.is_malicious
                ),
                execution_status=(
                    result.execution_status
                ),
                response_text=(
                    result.response_text
                ),
                request_id=result.request_id,
                server_generation_id=(
                    result.generation_id
                ),
                metadata=(
                    generation_input.metadata
                ),
                server_meta=result.meta,
            )

            append_jsonl(
                result_path,
                run_record.to_dict(),
            )

            completed_dataset_ids.add(
                generation_input.dataset_id
            )
            counters["completed"] += 1

        except Exception as exc:
            failure_record = GenerationFailureRecord(
                schema_version="generation_failure.v1",
                experiment_id=args.experiment_id,
                run_id=run_id,
                generation_id=generation_id,
                dataset_id=(
                    generation_input.dataset_id
                ),
                dataset_subset=(
                    generation_input.dataset_subset
                ),
                input_view=(
                    generation_input.input_view
                ),
                generation_profile=(
                    args.generation_profile
                ),
                error_type=type(exc).__name__,
                error_message=str(exc),
                metadata=(
                    generation_input.metadata
                ),
            )

            append_jsonl(
                failure_path,
                failure_record.to_dict(),
            )

            counters["failed"] += 1

            print(
                f"  failed: "
                f"{type(exc).__name__}: {exc}"
            )

        if args.sleep_sec > 0:
            time.sleep(args.sleep_sec)

    def count_jsonl_records(path: Path) -> int:
        if not path.exists():
            return 0

        count = 0

        with path.open("r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    count += 1

        return count

    cumulative_completed = count_jsonl_records(
        result_path
    )
    cumulative_failures = count_jsonl_records(
        failure_path
    )
    cumulative_excluded = count_jsonl_records(
        excluded_path
    )

    summary = {
        "schema_version": "generation_summary.v1",
        "experiment_id": args.experiment_id,
        "run_id": run_id,
        "dataset_path": str(args.dataset),
        "dataset_sha256": dataset_sha256,
        "input_view": args.input_view,
        "generation_profile": args.generation_profile,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "server_health": health,
        "current_run_counts": dict(counters),
        "cumulative_counts": {
            "completed": cumulative_completed,
            "failures": cumulative_failures,
            "excluded": cumulative_excluded,
        },
        "result_path": str(result_path),
        "failure_path": str(failure_path),
        "excluded_path": str(excluded_path),
        "manifest_path": str(manifest_path),
    }

    summary_path.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\nSummary:")
    print(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()