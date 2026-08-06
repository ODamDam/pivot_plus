from __future__ import annotations

import json
from pathlib import Path

from src.vuln_llm_v2 import cli
from src.vuln_llm_v2.recorder import validate_case_output


FIXTURES = Path(__file__).parent / "fixtures"


def test_dry_run_validates_and_never_calls_network(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr("socket.socket.connect", forbidden)
    rc = cli.main([
        "--config", str(FIXTURES / "dry_run_config.json"),
        "--input", str(FIXTURES / "input_cases.jsonl"),
        "--output-dir", str(tmp_path / "dry"),
        "--run-id", "dry-fixture",
        "--limit", "2",
        "--seed", "99",
        "--dry-run",
    ])
    assert rc == 0
    output = capsys.readouterr().out
    assert "request_count: 2" in output
    assert "clear-001" in output and "context-001" in output
    assert "deterministic-mock-v1" in output
    assert "VULN_LLM_API_KEY" in output
    assert "credential_value" not in output
    manifest = json.loads((tmp_path / "dry" / "run_manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["dataset_sha256"]) == 64
    assert manifest["git_commit"]
    assert manifest["dry_run"] is True
    assert "authorization" not in json.dumps(manifest).lower()


def test_cli_output_directory_is_not_overwritten_by_default(tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    rc = cli.main(["--config", str(FIXTURES / "dry_run_config.json"), "--input", str(FIXTURES / "input_cases.jsonl"), "--output-dir", str(output), "--run-id", "collision", "--seed", "1", "--dry-run"])
    assert rc == 2


def test_mock_execution_writes_valid_output_schema(tmp_path):
    output = tmp_path / "mock-run"
    rc = cli.main([
        "--config", str(FIXTURES / "dry_run_config.json"),
        "--input", str(FIXTURES / "input_cases.jsonl"),
        "--output-dir", str(output), "--run-id", "mock-run",
        "--limit", "2", "--seed", "11",
    ])
    assert rc == 0
    rows = [json.loads(line) for line in (output / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    validate_case_output(rows)
    assert [row["sample_id"] for row in rows] == ["clear-001", "context-001"]
