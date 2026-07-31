from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.vuln_llm_v2.clients import (
    DeterministicMockClient,
    NonRetryableModelError,
    RetryableModelError,
    TimeoutModelError,
)
from src.vuln_llm_v2.evaluator import RuleBasedEvaluator
from src.vuln_llm_v2.runner import ExperimentRunner, RunnerOptions
from src.vuln_llm_v2.schemas import (
    BehaviorClass,
    EvaluationDecision,
    EvaluatorVerdict,
    InputDisposition,
    InputRecord,
    ParsedResponse,
    RawResponse,
    validate_input_records,
)


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixtures() -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / "input_cases.jsonl").read_text(encoding="utf-8").splitlines()]


def test_context_absent_serialization_is_distinct_from_null_and_empty():
    absent = InputRecord.from_mapping({"sample_id": "a", "input_disposition": "benign", "prompt": "hello"})
    null = InputRecord.from_mapping({"sample_id": "b", "input_disposition": "benign", "prompt": "hello", "context": None})
    empty = InputRecord.from_mapping({"sample_id": "c", "input_disposition": "benign", "prompt": "hello", "context": ""})
    assert "context" not in absent.to_mapping()["raw_input"]
    assert null.to_mapping()["raw_input"]["context"] is None
    assert empty.to_mapping()["raw_input"]["context"] == ""


def test_input_fixtures_cover_required_dispositions_and_preserve_ids():
    records = [InputRecord.from_mapping(row) for row in load_fixtures()]
    assert [r.sample_id for r in records] == [row["sample_id"] for row in load_fixtures()]
    assert {r.input_disposition for r in records} == {
        InputDisposition.CLEAR_MALICIOUS,
        InputDisposition.CONTEXT_DEPENDENT,
        InputDisposition.AMBIGUOUS_REVIEW,
        InputDisposition.STRUCTURE_INTACT,
        InputDisposition.BENIGN,
    }


def test_duplicate_sample_id_is_rejected():
    rows = [InputRecord.from_mapping({"sample_id": "dup", "input_disposition": "benign", "prompt": "one"}), InputRecord.from_mapping({"sample_id": "dup", "input_disposition": "benign", "prompt": "two"})]
    with pytest.raises(ValueError, match="duplicate sample_id"):
        validate_input_records(rows)


def test_stage_artifacts_are_separate_and_raw_values_are_preserved(tmp_path):
    record = InputRecord.from_mapping(load_fixtures()[1])
    runner = ExperimentRunner(DeterministicMockClient(seed=7), RuleBasedEvaluator(), RunnerOptions(run_id="stages", seed=7, output_dir=tmp_path))
    result = runner.process_one(record)
    assert result.raw_input == load_fixtures()[1]
    assert result.constructed_request["messages"]
    assert isinstance(result.raw_response, RawResponse)
    assert isinstance(result.parsed_response, ParsedResponse)
    assert result.raw_response.text == result.parsed_response.text
    assert result.raw_input is not result.constructed_request


@pytest.mark.parametrize("mode,expected", [("empty", BehaviorClass.MALFORMED_OR_IRRELEVANT), ("malformed", BehaviorClass.MALFORMED_OR_IRRELEVANT)])
def test_empty_and_malformed_responses_are_not_safe_completions(mode, expected):
    client = DeterministicMockClient(seed=1, response_mode=mode)
    runner = ExperimentRunner(client, RuleBasedEvaluator(), RunnerOptions(run_id=f"bad-{mode}", seed=1))
    result = runner.process_one(InputRecord.from_mapping(load_fixtures()[0]))
    assert result.parsed_response.behavior == expected


def test_error_taxonomy_distinguishes_timeout_retryable_and_terminal():
    assert issubclass(TimeoutModelError, RetryableModelError)
    assert not issubclass(NonRetryableModelError, RetryableModelError)


def test_timeout_and_retryable_errors_use_bounded_attempts():
    class CountingClient:
        name = "counting"
        def __init__(self, error):
            self.error, self.calls = error, 0
        def generate(self, request):
            self.calls += 1
            raise self.error("failure")
    record = InputRecord.from_mapping(load_fixtures()[0])
    for error in (TimeoutModelError, RetryableModelError):
        client = CountingClient(error)
        runner = ExperimentRunner(client, RuleBasedEvaluator(), RunnerOptions(run_id="retry", seed=1))
        with pytest.raises(error):
            runner.process_one(record)
        assert client.calls == 3
    terminal = CountingClient(NonRetryableModelError)
    with pytest.raises(NonRetryableModelError):
        ExperimentRunner(terminal, RuleBasedEvaluator(), RunnerOptions(run_id="terminal", seed=1)).process_one(record)
    assert terminal.calls == 1


def test_resume_skips_completed_samples_and_does_not_overwrite(tmp_path):
    records = [InputRecord.from_mapping(row) for row in load_fixtures()[:2]]
    options = RunnerOptions(run_id="resume", seed=3, output_dir=tmp_path / "run")
    first = ExperimentRunner(DeterministicMockClient(seed=3), RuleBasedEvaluator(), options)
    assert first.run(records[:1]).completed_sample_ids == ["clear-001"]
    with pytest.raises(FileExistsError):
        ExperimentRunner(DeterministicMockClient(seed=3), RuleBasedEvaluator(), options).run(records)
    resumed = ExperimentRunner(DeterministicMockClient(seed=3), RuleBasedEvaluator(), options.with_resume(True)).run(records)
    assert resumed.completed_sample_ids == ["clear-001", "context-001"]
    assert resumed.processed_this_invocation == ["context-001"]


def test_same_seed_produces_identical_result():
    record = InputRecord.from_mapping(load_fixtures()[4])
    def one():
        return ExperimentRunner(DeterministicMockClient(seed=42), RuleBasedEvaluator(), RunnerOptions(run_id="det", seed=42)).process_one(record).to_mapping()
    assert one() == one()


def test_evaluator_abstain_error_and_not_vulnerable_are_distinct():
    assert EvaluationDecision(EvaluatorVerdict.ABSTAIN, ["insufficient_evidence"]).verdict is EvaluatorVerdict.ABSTAIN
    assert EvaluationDecision(EvaluatorVerdict.ERROR, ["evaluator_failure"]).verdict is EvaluatorVerdict.ERROR
    assert EvaluationDecision(EvaluatorVerdict.NOT_VULNERABLE, ["boundary_preserved"]).verdict is EvaluatorVerdict.NOT_VULNERABLE


def test_runner_records_evaluator_error_separately_from_not_vulnerable():
    class ExplodingEvaluator:
        name = "exploding"
        def evaluate(self, record, response):
            raise RuntimeError("judge unavailable")
    record = InputRecord.from_mapping(load_fixtures()[4])
    result = ExperimentRunner(DeterministicMockClient(seed=4), ExplodingEvaluator(), RunnerOptions(run_id="eval-error", seed=4)).process_one(record)
    assert result.decision.verdict is EvaluatorVerdict.ERROR
    assert result.decision.verdict is not EvaluatorVerdict.NOT_VULNERABLE
