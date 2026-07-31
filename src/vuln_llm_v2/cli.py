from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .clients import AdapterSpec, DeterministicMockClient
from .evaluator import RuleBasedEvaluator
from .manifest import git_commit, sha256_file, write_json_exclusive
from .runner import ExperimentRunner, RetryPolicy, RunnerOptions
from .schemas import InputRecord, validate_input_records


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Independent Vuln LLM v2 runner (mock-only until an adapter is implemented).")
    parser.add_argument("--config", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--overwrite", action="store_true", default=False)
    return parser


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("config must be a JSON object")
    return value


def _load_input(path: Path) -> list[InputRecord]:
    records: list[InputRecord] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(InputRecord.from_mapping(json.loads(line)))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"invalid input at line {line_number}: {exc}") from exc
    validate_input_records(records)
    return records


def _validated_model(config: dict[str, Any]) -> tuple[AdapterSpec, str]:
    model = config.get("model")
    if not isinstance(model, dict):
        raise ValueError("config.model must be an object")
    adapter = str(model.get("adapter", ""))
    name = str(model.get("name", ""))
    env_name = str(model.get("credential_env_var", ""))
    parameters = model.get("parameters", {})
    if not name or not isinstance(parameters, dict):
        raise ValueError("model name and parameter object are required")
    if adapter != "mock":
        raise ValueError("only the mock adapter is enabled")
    return AdapterSpec(name, env_name, parameters), adapter


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config_path, input_path, output_dir = Path(args.config), Path(args.input), Path(args.output_dir)
        config = _load_json(config_path)
        spec, _ = _validated_model(config)
        records = _load_input(input_path)
        if args.limit < 0:
            raise ValueError("limit cannot be negative")
        selected = records[: args.limit] if args.limit else records
        if output_dir.exists() and not args.resume and not args.overwrite:
            raise FileExistsError(f"output directory exists: {output_dir}")
        if args.overwrite:
            raise ValueError("--overwrite is reserved but intentionally unsupported")
        retry_cfg = config.get("retry", {})
        retry = RetryPolicy(
            max_attempts=int(retry_cfg.get("max_attempts", 3)),
            timeout_seconds=float(retry_cfg.get("timeout_seconds", 30)),
            base_delay_seconds=float(retry_cfg.get("base_delay_seconds", 0)),
        )
        manifest = {
            "schema_version": "vuln_llm_run_manifest.v1",
            "run_id": args.run_id,
            "dry_run": bool(args.dry_run),
            "resume": bool(args.resume),
            "seed": args.seed,
            "dataset_path": str(input_path),
            "dataset_sha256": sha256_file(input_path),
            "git_commit": git_commit(PROJECT_ROOT),
            "request_count": len(selected),
            "selected_sample_ids": [record.sample_id for record in selected],
            "model": spec.sanitized_mapping(),
            "retry": {"max_attempts": retry.max_attempts, "timeout_seconds": retry.timeout_seconds, "base_delay_seconds": retry.base_delay_seconds},
        }
        output_dir.mkdir(parents=True, exist_ok=args.resume)
        manifest_path = output_dir / "run_manifest.json"
        if not args.resume:
            write_json_exclusive(manifest_path, manifest)
        print(f"run_id: {args.run_id}")
        print(f"dry_run: {bool(args.dry_run)}")
        print(f"request_count: {len(selected)}")
        print(f"selected_sample_ids: {', '.join(record.sample_id for record in selected)}")
        print(f"model: {spec.name}")
        print(f"model_parameters: {json.dumps(spec.parameters, sort_keys=True)}")
        print(f"credential_env_var: {spec.credential_env_var}")
        print(f"dataset_sha256: {manifest['dataset_sha256']}")
        print(f"git_commit: {manifest['git_commit']}")
        if args.dry_run:
            print("validation: OK; network_calls: 0")
            return 0
        runner = ExperimentRunner(
            DeterministicMockClient(seed=args.seed), RuleBasedEvaluator(),
            RunnerOptions(args.run_id, args.seed, output_dir, args.resume, False, retry),
        )
        summary = runner.run(selected)
        print(f"processed: {len(summary.processed_this_invocation)}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
