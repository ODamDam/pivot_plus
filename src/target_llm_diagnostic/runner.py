from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from pydantic import ValidationError

from src.common.jsonl import append_jsonl, iter_jsonl
from src.generation.clients.base import (
    CanonicalGenerationClient,
    ClientGenerationResult,
    GenerationHTTPError,
    GenerationResponseError,
)
from src.generation.clients.vulnerable_llm import CanonicalVulnerableLLMClient
from vulnerable_llm.canonical import (
    CanonicalGenerationRequest,
    build_canonical_messages,
)

from .schemas import (
    DiagnosticFailureRecord,
    DiagnosticInputRecord,
    DiagnosticResultRecord,
)


RUNNER_VERSION = "target_llm_canonical_diagnostic_runner.v1"
PLAN_SCHEMA_VERSION = "target_llm_diagnostic_execution_plan.v1"
MANIFEST_SCHEMA_VERSION = "target_llm_diagnostic_manifest.v1"
CHECKPOINT_SCHEMA_VERSION = "target_llm_diagnostic_checkpoint.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[2],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def write_json_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write("\n")


def write_jsonl_exclusive(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as file:
        for row in rows:
            file.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_diagnostic_cases(path: Path) -> list[DiagnosticInputRecord]:
    records: list[DiagnosticInputRecord] = []
    seen: set[str] = set()
    for line_number, value in enumerate(iter_jsonl(path), 1):
        try:
            record = DiagnosticInputRecord.model_validate(value)
        except ValidationError as exc:
            raise ValueError(f"invalid diagnostic input at line {line_number}: {exc}") from exc
        if record.diagnostic_case_id in seen:
            raise ValueError(
                f"duplicate diagnostic_case_id would create a duplicate generation key: "
                f"{record.diagnostic_case_id}"
            )
        seen.add(record.diagnostic_case_id)
        records.append(record)
    if not records:
        raise ValueError("diagnostic input must contain at least one record")

    first = records[0]
    for record in records[1:]:
        if record.provider != first.provider or record.model != first.model:
            raise ValueError("all diagnostic records must use one provider and model")
        if record.generation_config != first.generation_config:
            raise ValueError("all diagnostic records must use one generation config")
        if record.repetitions != first.repetitions:
            raise ValueError("all diagnostic records must use one repetition count")
    return records


@dataclass(frozen=True)
class ExecutionPlanItem:
    generation_key: str
    request: CanonicalGenerationRequest
    diagnostic_case_id: str
    source_candidate_id: str
    source_record_id: str | None
    source_file: str
    source_provenance: dict[str, Any]
    pair_id: str
    attacker_goal: dict[str, Any]
    objective_success_criterion: str
    transformation_notes: str
    execution_safety: dict[str, Any]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "execution_plan_schema_version": PLAN_SCHEMA_VERSION,
            "generation_key": self.generation_key,
            "diagnostic_case_id": self.diagnostic_case_id,
            "source_candidate_id": self.source_candidate_id,
            "source_record_id": self.source_record_id,
            "source_file": self.source_file,
            "source_provenance": self.source_provenance,
            "pair_id": self.pair_id,
            "attacker_goal": self.attacker_goal,
            "objective_success_criterion": self.objective_success_criterion,
            "transformation_notes": self.transformation_notes,
            "execution_safety": self.execution_safety,
            "canonical_request": self.request.model_dump(mode="json"),
        }


def expand_execution_plan(
    records: list[DiagnosticInputRecord], *, run_id: str, input_sha256: str
) -> list[ExecutionPlanItem]:
    plan: list[ExecutionPlanItem] = []
    seen_keys: set[str] = set()
    for record in records:
        for repetition_index in range(record.repetitions):
            for condition, untrusted_input in (
                ("control", record.control_input),
                ("attack", record.attack_input),
            ):
                generation_key = (
                    f"{record.diagnostic_case_id}:{condition}:{repetition_index}"
                )
                if generation_key in seen_keys:
                    raise ValueError(f"duplicate generation key: {generation_key}")
                seen_keys.add(generation_key)
                generation_suffix = sha256_text(generation_key)[:16]
                request = CanonicalGenerationRequest(
                    run_id=run_id,
                    generation_id=f"{run_id}-{generation_suffix}",
                    case_id=record.diagnostic_case_id,
                    scenario_id=record.scenario_id,
                    condition=condition,
                    repetition_index=repetition_index,
                    trusted_instruction=record.trusted_instruction,
                    normal_task=record.normal_task,
                    trust_boundary=record.trust_boundary,
                    trusted_context=record.trusted_context,
                    untrusted_input=untrusted_input,
                    injection_location=record.injection_location,
                    provider=record.provider,
                    model=record.model,
                    generation_config=record.generation_config,
                    dataset_sha256=input_sha256,
                    random_seed=record.generation_config.random_seed,
                    attack_method=",".join(record.attack_family),
                    seed_original=record.control_input,
                    attack_rendered=record.attack_input,
                    experiment_metadata={
                        "diagnostic_only": True,
                        "diagnostic_schema_version": record.diagnostic_schema_version,
                        "diagnostic_case_id": record.diagnostic_case_id,
                        "source_candidate_id": record.source_candidate_id,
                        "source_record_id": record.source_record_id,
                        "source_file": record.source_file,
                        "source_provenance": record.source_provenance,
                        "pair_id": record.pair_id,
                        "attacker_goal": record.attacker_goal,
                        "objective_success_criterion": record.objective_success_criterion,
                        "transformation_notes": record.transformation_notes,
                        "condition_input_information": record.condition_input_information,
                        "execution_safety": record.execution_safety.model_dump(mode="json"),
                    },
                )
                build_canonical_messages(request)
                plan.append(ExecutionPlanItem(
                    generation_key=generation_key,
                    request=request,
                    diagnostic_case_id=record.diagnostic_case_id,
                    source_candidate_id=record.source_candidate_id,
                    source_record_id=record.source_record_id,
                    source_file=record.source_file,
                    source_provenance=record.source_provenance,
                    pair_id=record.pair_id,
                    attacker_goal=record.attacker_goal,
                    objective_success_criterion=record.objective_success_criterion,
                    transformation_notes=record.transformation_notes,
                    execution_safety=record.execution_safety.model_dump(mode="json"),
                ))
    return plan


@dataclass(frozen=True)
class DiagnosticRunOptions:
    run_id: str
    output_root: Path
    seed: int
    dry_run: bool
    resume: bool = False
    max_attempts: int = 2
    retry_delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not self.run_id.strip():
            raise ValueError("run_id must not be blank")
        if self.max_attempts < 1 or self.retry_delay_seconds < 0:
            raise ValueError("invalid retry policy")
        if self.dry_run and self.resume:
            raise ValueError("dry-run cannot resume an execution run")


@dataclass(frozen=True)
class DiagnosticRunSummary:
    planned: int
    completed: int
    failed: int
    skipped_completed: int
    run_dir: Path


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, GenerationHTTPError):
        return 500 <= exc.status_code <= 599
    return isinstance(exc, (ConnectionError, TimeoutError))


def _manifest(
    records: list[DiagnosticInputRecord], input_path: Path, input_hash: str,
    options: DiagnosticRunOptions,
) -> dict[str, Any]:
    first = records[0]
    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "schema_versions": {
            "input": first.diagnostic_schema_version,
            "canonical_request": "canonical_generation_request.v1",
            "execution_plan": PLAN_SCHEMA_VERSION,
            "result": "target_llm_diagnostic_result.v1",
            "failure": "target_llm_diagnostic_failure.v1",
            "checkpoint": CHECKPOINT_SCHEMA_VERSION,
        },
        "runner_version": RUNNER_VERSION,
        "run_id": options.run_id,
        "dry_run": options.dry_run,
        "git_commit": git_commit(),
        "input_file": str(input_path.resolve()),
        "input_file_sha256": input_hash,
        "selected_diagnostic_ids": [x.diagnostic_case_id for x in records],
        "provider": first.provider,
        "model": first.model,
        "generation_config": first.generation_config.model_dump(mode="json"),
        "seed": options.seed,
        "repetition_count": first.repetitions,
        "generation_count": sum(x.repetitions * 2 for x in records),
        "retry_policy": {
            "max_attempts": options.max_attempts,
            "retry_delay_seconds": options.retry_delay_seconds,
            "retryable": ["connection_failure", "timeout", "http_5xx"],
            "non_retryable": [
                "validation", "configuration", "http_4xx", "provider_mismatch",
                "malformed_input", "malformed_response",
            ],
        },
        "created_at": utc_now(),
    }


def _load_checkpoint(path: Path) -> set[str]:
    if not path.exists():
        return set()
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("checkpoint_schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise ValueError("checkpoint schema version mismatch")
    completed = value.get("completed_generation_keys")
    if not isinstance(completed, list) or not all(isinstance(x, str) for x in completed):
        raise ValueError("invalid checkpoint completed_generation_keys")
    return set(completed)


def _write_checkpoint(path: Path, completed: set[str]) -> None:
    value = {
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "completed_generation_keys": sorted(completed),
        "updated_at": utc_now(),
    }
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


class CanonicalDiagnosticRunner:
    def __init__(
        self, *, client: CanonicalGenerationClient | None,
        options: DiagnosticRunOptions,
    ) -> None:
        self.client = client
        self.options = options

    def run(self, input_path: Path) -> DiagnosticRunSummary:
        records = load_diagnostic_cases(input_path)
        input_hash = sha256_file(input_path)
        plan = expand_execution_plan(
            records, run_id=self.options.run_id, input_sha256=input_hash
        )
        run_dir = self.options.output_root / self.options.run_id
        manifest_path = run_dir / "manifest.json"
        plan_path = run_dir / "execution_plan.jsonl"
        checkpoint_path = run_dir / "checkpoint.json"

        expected_manifest = _manifest(records, input_path, input_hash, self.options)
        if run_dir.exists():
            if not self.options.resume:
                raise FileExistsError(f"run directory already exists: {run_dir}")
            if not manifest_path.exists() or not plan_path.exists():
                raise ValueError("resume run is missing manifest or execution plan")
            existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            for field in (
                "run_id", "git_commit", "input_file_sha256", "selected_diagnostic_ids",
                "provider", "model", "generation_config", "seed", "repetition_count",
                "runner_version", "schema_versions",
            ):
                if existing.get(field) != expected_manifest.get(field):
                    raise ValueError(f"resume manifest mismatch: {field}")
            existing_plan = [value for value in iter_jsonl(plan_path)]
            if existing_plan != [item.to_mapping() for item in plan]:
                raise ValueError("resume execution plan mismatch")
        else:
            run_dir.mkdir(parents=True, exist_ok=False)
            write_json_exclusive(manifest_path, expected_manifest)
            write_jsonl_exclusive(plan_path, [item.to_mapping() for item in plan])

        if self.options.dry_run:
            return DiagnosticRunSummary(len(plan), 0, 0, 0, run_dir)
        if self.client is None:
            raise ValueError("execution mode requires a canonical client")

        completed_keys = _load_checkpoint(checkpoint_path) if self.options.resume else set()
        completed = failed = skipped = 0
        for item in plan:
            if item.generation_key in completed_keys:
                skipped += 1
                continue
            attempts = 0
            result: ClientGenerationResult | None = None
            last_error: Exception | None = None
            while attempts < self.options.max_attempts:
                attempts += 1
                try:
                    result = self.client.generate_canonical(item.request)
                    break
                except Exception as exc:
                    last_error = exc
                    if not _is_retryable(exc) or attempts >= self.options.max_attempts:
                        break
                    if self.options.retry_delay_seconds:
                        time.sleep(self.options.retry_delay_seconds)
            if result is None:
                assert last_error is not None
                status = (
                    last_error.status_code
                    if isinstance(last_error, GenerationHTTPError) else None
                )
                failure = DiagnosticFailureRecord(
                    generation_key=item.generation_key,
                    diagnostic_case_id=item.diagnostic_case_id,
                    source_candidate_id=item.source_candidate_id,
                    pair_id=item.pair_id,
                    condition=item.request.condition,
                    repetition_index=item.request.repetition_index,
                    generation_id=item.request.generation_id,
                    error_type=type(last_error).__name__,
                    error_message=str(last_error),
                    http_status=status,
                    retryable=_is_retryable(last_error),
                    attempts=attempts,
                    endpoint_response_body=(
                        last_error.response_body
                        if isinstance(last_error, GenerationHTTPError) else None
                    ),
                )
                append_jsonl(
                    run_dir / "failures.jsonl", failure.model_dump(mode="json")
                )
                failed += 1
                continue

            response_hash = result.meta.get("response_sha256")
            if not isinstance(response_hash, str) or not response_hash:
                response_hash = sha256_text(result.response_text)
            record = DiagnosticResultRecord(
                generation_key=item.generation_key,
                diagnostic_case_id=item.diagnostic_case_id,
                source_candidate_id=item.source_candidate_id,
                source_record_id=item.source_record_id,
                source_file=item.source_file,
                source_provenance=item.source_provenance,
                pair_id=item.pair_id,
                condition=item.request.condition,
                repetition_index=item.request.repetition_index,
                generation_id=item.request.generation_id,
                execution_status=result.execution_status,
                endpoint_response=result.raw_response,
                request_id=result.request_id,
                server_generation_id=result.generation_id,
                response_text=result.response_text,
                response_sha256=response_hash,
                model_metadata=result.meta,
            )
            append_jsonl(run_dir / "results.jsonl", record.model_dump(mode="json"))
            completed_keys.add(item.generation_key)
            _write_checkpoint(checkpoint_path, completed_keys)
            completed += 1
        return DiagnosticRunSummary(len(plan), completed, failed, skipped, run_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run canonical Target LLM diagnostic control/attack pairs."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--output-root", type=Path,
        default=Path("experiments/target_llm_diagnostic_v1/runs"),
    )
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--timeout-sec", type=float, default=180.0)
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--retry-delay-sec", type=float, default=0.0)
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        options = DiagnosticRunOptions(
            run_id=args.run_id,
            output_root=args.output_root,
            seed=args.seed,
            dry_run=args.dry_run,
            resume=args.resume,
            max_attempts=args.max_attempts,
            retry_delay_seconds=args.retry_delay_sec,
        )
        client: CanonicalGenerationClient | None = None
        if not args.dry_run:
            client = CanonicalVulnerableLLMClient(
                base_url=args.base_url,
                timeout_sec=args.timeout_sec,
                max_retries=1,
                retry_delay_sec=0,
            )
        summary = CanonicalDiagnosticRunner(client=client, options=options).run(
            args.input
        )
        print(json.dumps({
            "run_id": args.run_id,
            "dry_run": args.dry_run,
            "planned": summary.planned,
            "completed": summary.completed,
            "failed": summary.failed,
            "skipped_completed": summary.skipped_completed,
            "run_dir": str(summary.run_dir),
        }, ensure_ascii=False, indent=2))
        return 0 if summary.failed == 0 else 1
    except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(run_cli())
