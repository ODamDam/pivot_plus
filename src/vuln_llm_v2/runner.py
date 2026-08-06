from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable

from .builder import build_request
from .clients import ModelClient, RetryableModelError
from .evaluator import Evaluator
from .manifest import write_checkpoint
from .parser import parse_response
from .recorder import JsonlRecorder
from .schemas import CaseResult, EvaluationDecision, EvaluatorVerdict, InputRecord, validate_input_records


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    timeout_seconds: float = 30
    base_delay_seconds: float = 0

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.timeout_seconds <= 0 or self.base_delay_seconds < 0:
            raise ValueError("invalid retry policy")


@dataclass(frozen=True)
class RunnerOptions:
    run_id: str
    seed: int
    output_dir: Path | None = None
    resume: bool = False
    overwrite: bool = False
    retry: RetryPolicy = RetryPolicy()

    def with_resume(self, value: bool) -> "RunnerOptions":
        return replace(self, resume=value)


@dataclass(frozen=True)
class RunSummary:
    completed_sample_ids: list[str]
    processed_this_invocation: list[str]


class ExperimentRunner:
    def __init__(self, client: ModelClient, evaluator: Evaluator, options: RunnerOptions):
        self.client = client
        self.evaluator = evaluator
        self.options = options

    def process_one(self, record: InputRecord) -> CaseResult:
        request = build_request(record, model_name=self.client.name)
        response = None
        for attempt in range(1, self.options.retry.max_attempts + 1):
            try:
                response = self.client.generate(request)
                break
            except RetryableModelError:
                if attempt == self.options.retry.max_attempts:
                    raise
        assert response is not None
        parsed = parse_response(response)
        try:
            decision = self.evaluator.evaluate(record, parsed)
        except Exception as exc:
            decision = EvaluationDecision(
                EvaluatorVerdict.ERROR,
                ["evaluator_exception", type(exc).__name__],
                getattr(self.evaluator, "name", "unspecified"),
            )
        return CaseResult(record.sample_id, dict(record.raw_input), request, response, parsed, decision)

    def run(self, records: Iterable[InputRecord]) -> RunSummary:
        rows = list(records)
        validate_input_records(rows)
        if self.options.output_dir is None:
            return RunSummary([row.sample_id for row in rows], [row.sample_id for row in rows])
        output_dir = Path(self.options.output_dir)
        results_path = output_dir / "results.jsonl"
        checkpoint_path = output_dir / "checkpoint.json"
        if output_dir.exists() and not self.options.resume and not self.options.overwrite:
            existing = {path.name for path in output_dir.iterdir()}
            if existing - {"run_manifest.json"}:
                raise FileExistsError(f"output directory exists: {output_dir}")
        if self.options.overwrite:
            raise ValueError("overwrite is intentionally unsupported in v1")
        output_dir.mkdir(parents=True, exist_ok=True)
        recorder = JsonlRecorder(results_path)
        completed = recorder.completed_sample_ids() if self.options.resume else []
        completed_set = set(completed)
        processed: list[str] = []
        for row in rows:
            if row.sample_id in completed_set:
                continue
            recorder.append(self.process_one(row))
            completed.append(row.sample_id)
            completed_set.add(row.sample_id)
            processed.append(row.sample_id)
            write_checkpoint(checkpoint_path, completed)
        return RunSummary(completed, processed)
