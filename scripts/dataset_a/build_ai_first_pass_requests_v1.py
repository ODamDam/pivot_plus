#!/usr/bin/env python3
"""Build deterministic Responses API request envelopes without calling the API."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

try:
    from scripts.dataset_a.ai_first_pass_api_common_v1 import (
        DEFAULT_MAX_OUTPUT_TOKENS,
        DEFAULT_MODEL,
        DEFAULT_REASONING_EFFORT,
        PROMPT_VERSION,
        RUN_SCHEMA_VERSION,
        build_request_envelope,
        extract_system_instructions,
        read_jsonl,
        sha256_file,
        write_jsonl,
    )
except ModuleNotFoundError:  # Support direct ``python scripts/.../file.py`` execution.
    from ai_first_pass_api_common_v1 import (
        DEFAULT_MAX_OUTPUT_TOKENS,
        DEFAULT_MODEL,
        DEFAULT_REASONING_EFFORT,
        PROMPT_VERSION,
        RUN_SCHEMA_VERSION,
        build_request_envelope,
        extract_system_instructions,
        read_jsonl,
        sha256_file,
        write_jsonl,
    )


DEFAULT_INPUT = Path("data/dataset_a/adjudication/ai_first_pass_smoke_200_v1.jsonl")
DEFAULT_PROMPT = Path("docs/dataset_a/annotation/dataset_a_ai_first_pass_prompt_v1.md")
DEFAULT_SCHEMA = Path("schemas/dataset_a_ai_first_pass_v1.schema.json")
DEFAULT_OUTPUT = Path("data/dataset_a/adjudication/api_requests/ai_first_pass_smoke_200_requests_v1.jsonl")
DEFAULT_MANIFEST = Path("reports/dataset_a/ai_first_pass_smoke_200_api_request_manifest_v1.json")
DEFAULT_RUN_ID = "dataset-a-ai-first-pass-smoke-200-v1"
DEFAULT_RANDOM_SEED = 20260806


def git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--prompt", type=Path, default=DEFAULT_PROMPT)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--reasoning-effort", default=DEFAULT_REASONING_EFFORT)
    parser.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--random-seed", type=int, default=DEFAULT_RANDOM_SEED)
    args = parser.parse_args()

    cases = read_jsonl(args.input)
    ids = [row.get("candidate_id") for row in cases]
    if not cases or len(ids) != len(set(ids)) or not all(isinstance(value, str) for value in ids):
        raise ValueError("input must contain non-empty, unique candidate_id values")
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    if schema.get("additionalProperties") is not False:
        raise ValueError("schema must set additionalProperties=false")
    if set(schema.get("required", [])) != set(schema.get("properties", {})):
        raise ValueError("all schema properties must be required for strict outputs")
    instructions = extract_system_instructions(args.prompt.read_text(encoding="utf-8-sig"))
    requests = [
        build_request_envelope(
            case,
            instructions,
            schema,
            args.model,
            args.reasoning_effort,
            args.max_output_tokens,
        )
        for case in cases
    ]
    write_jsonl(args.output, requests)

    manifest = {
        "schema_version": RUN_SCHEMA_VERSION,
        "stage": "request_generation",
        "dry_run": True,
        "api_called": False,
        "record_count": len(requests),
        "run_id": args.run_id,
        "random_seed": args.random_seed,
        "prompt_version": PROMPT_VERSION,
        "git_commit": git_commit(),
        "configuration": {
            "model": args.model,
            "reasoning_effort": args.reasoning_effort,
            "max_output_tokens": args.max_output_tokens,
            "endpoint": "/v1/responses",
            "structured_outputs_strict": True,
        },
        "artifacts": {
            "input": {"path": args.input.as_posix(), "sha256": sha256_file(args.input)},
            "prompt": {"path": args.prompt.as_posix(), "sha256": sha256_file(args.prompt)},
            "schema": {"path": args.schema.as_posix(), "sha256": sha256_file(args.schema)},
            "requests": {"path": args.output.as_posix(), "sha256": sha256_file(args.output)},
        },
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"requests": len(requests), "output": args.output.as_posix(), "api_called": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
