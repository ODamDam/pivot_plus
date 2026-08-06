#!/usr/bin/env python3
"""Validate raw Responses API envelopes and extract annotation JSONL."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from scripts.dataset_a.ai_first_pass_api_common_v1 import (
        RUN_SCHEMA_VERSION,
        extract_structured_output,
        read_jsonl,
        sha256_file,
        validate_annotation_semantics,
        validate_schema_subset,
        write_jsonl,
    )
except ModuleNotFoundError:  # Support direct ``python scripts/.../file.py`` execution.
    from ai_first_pass_api_common_v1 import (
        RUN_SCHEMA_VERSION,
        extract_structured_output,
        read_jsonl,
        sha256_file,
        validate_annotation_semantics,
        validate_schema_subset,
        write_jsonl,
    )


DEFAULT_REQUESTS = Path("data/dataset_a/adjudication/api_requests/ai_first_pass_smoke_200_requests_v1.jsonl")
DEFAULT_RESPONSES = Path("data/dataset_a/adjudication/api_responses/ai_first_pass_smoke_200_raw_dry_run_v1.jsonl")
DEFAULT_SCHEMA = Path("schemas/dataset_a_ai_first_pass_v1.schema.json")
DEFAULT_OUTPUT = Path("data/dataset_a/adjudication/api_responses/ai_first_pass_smoke_200_parsed_dry_run_v1.jsonl")
DEFAULT_REPORT = Path("reports/dataset_a/ai_first_pass_smoke_200_api_validation_dry_run_v1.json")
DEFAULT_RUN_ID = "dataset-a-ai-first-pass-smoke-200-v1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=Path, default=DEFAULT_REQUESTS)
    parser.add_argument("--responses", type=Path, default=DEFAULT_RESPONSES)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--allow-errors", action="store_true")
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    args = parser.parse_args()

    requests = read_jsonl(args.requests)
    responses = read_jsonl(args.responses)
    request_ids = [row.get("custom_id") for row in requests]
    response_ids = [row.get("custom_id") for row in responses]
    request_set, response_set = set(request_ids), set(response_ids)
    errors: list[dict[str, Any]] = []

    if len(request_ids) != len(request_set):
        errors.append({"scope": "file", "message": "duplicate request custom_id"})
    if len(response_ids) != len(response_set):
        errors.append({"scope": "file", "message": "duplicate response custom_id"})
    for candidate_id in sorted(request_set - response_set):
        errors.append({"scope": "file", "candidate_id": candidate_id, "message": "missing response"})
    for candidate_id in sorted(response_set - request_set):
        errors.append({"scope": "file", "candidate_id": candidate_id, "message": "unexpected response"})

    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    try:
        from jsonschema import Draft202012Validator

        validator = Draft202012Validator(schema)
    except ModuleNotFoundError:
        validator = None
    parsed_by_id: dict[str, dict[str, Any]] = {}
    for raw in responses:
        candidate_id = raw.get("custom_id")
        try:
            annotation = extract_structured_output(raw)
            if validator is not None:
                schema_messages = [
                    error.message
                    for error in sorted(
                        validator.iter_errors(annotation), key=lambda item: list(item.path)
                    )
                ]
            else:
                schema_messages = validate_schema_subset(annotation, schema)
            for message in schema_messages:
                errors.append({"scope": "schema", "candidate_id": candidate_id, "message": message})
            semantic_messages = validate_annotation_semantics(candidate_id, annotation)
            for message in semantic_messages:
                errors.append({"scope": "semantic", "candidate_id": candidate_id, "message": message})
            if not schema_messages and not semantic_messages:
                parsed_by_id[candidate_id] = annotation
        except ValueError as exc:
            errors.append({"scope": "response", "candidate_id": candidate_id, "message": str(exc)})

    parsed = [parsed_by_id[candidate_id] for candidate_id in request_ids if candidate_id in parsed_by_id]
    write_jsonl(args.output, parsed)
    dry_run_count = sum(
        bool((row.get("response") or {}).get("body", {}).get("_dry_run")) for row in responses
    )
    error_counts = Counter(error["scope"] for error in errors)
    report = {
        "schema_version": RUN_SCHEMA_VERSION,
        "stage": "response_validation",
        "run_id": args.run_id,
        "passed": not errors,
        "request_count": len(requests),
        "response_count": len(responses),
        "valid_annotation_count": len(parsed),
        "dry_run_response_count": dry_run_count,
        "error_count": len(errors),
        "error_counts_by_scope": dict(sorted(error_counts.items())),
        "errors": errors,
        "artifacts": {
            "requests": {"path": args.requests.as_posix(), "sha256": sha256_file(args.requests)},
            "responses": {"path": args.responses.as_posix(), "sha256": sha256_file(args.responses)},
            "schema": {"path": args.schema.as_posix(), "sha256": sha256_file(args.schema)},
            "parsed": {"path": args.output.as_posix(), "sha256": sha256_file(args.output)},
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "valid": len(parsed), "errors": len(errors), "report": args.report.as_posix()}))
    return 0 if not errors or args.allow_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
