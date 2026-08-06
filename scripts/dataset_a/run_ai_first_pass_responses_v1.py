#!/usr/bin/env python3
"""Execute Responses API requests or produce deterministic dry-run responses.

Dry-run is the default and does not import the OpenAI SDK or inspect API keys.
Real execution requires both --execute and an exact --confirm-record-count value.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from scripts.dataset_a.ai_first_pass_api_common_v1 import (
        make_dry_run_response,
        read_jsonl,
        sha256_file,
        write_jsonl,
    )
except ModuleNotFoundError:  # Support direct ``python scripts/.../file.py`` execution.
    from ai_first_pass_api_common_v1 import (
        make_dry_run_response,
        read_jsonl,
        sha256_file,
        write_jsonl,
    )


DEFAULT_INPUT = Path("data/dataset_a/adjudication/api_requests/ai_first_pass_smoke_200_requests_v1.jsonl")
DEFAULT_DRY_OUTPUT = Path("data/dataset_a/adjudication/api_responses/ai_first_pass_smoke_200_raw_dry_run_v1.jsonl")
DEFAULT_LIVE_OUTPUT = Path("data/dataset_a/adjudication/api_responses/ai_first_pass_smoke_200_raw_v1.jsonl")
DEFAULT_DRY_MANIFEST = Path("reports/dataset_a/ai_first_pass_smoke_200_api_execution_dry_run_v1.json")
DEFAULT_LIVE_MANIFEST = Path("reports/dataset_a/ai_first_pass_smoke_200_api_execution_v1.json")
DEFAULT_RUN_ID = "dataset-a-ai-first-pass-smoke-200-v1"


def _live_record(client: Any, request: dict[str, Any]) -> dict[str, Any]:
    candidate_id = request["custom_id"]
    try:
        response = client.responses.create(**request["body"])
        return {
            "custom_id": candidate_id,
            "response": {
                "status_code": 200,
                "request_id": getattr(response, "_request_id", None),
                "body": response.model_dump(mode="json"),
            },
            "error": None,
        }
    except Exception as exc:  # Preserve per-record failure without losing checkpoint.
        return {
            "custom_id": candidate_id,
            "response": None,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--execute", action="store_true", help="Perform real API calls.")
    parser.add_argument("--confirm-record-count", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    args = parser.parse_args()

    requests = read_jsonl(args.input)
    ids = [row.get("custom_id") for row in requests]
    if not requests or len(ids) != len(set(ids)):
        raise ValueError("request file must contain unique custom_id values")

    output = args.output or (DEFAULT_LIVE_OUTPUT if args.execute else DEFAULT_DRY_OUTPUT)
    manifest_path = args.manifest or (DEFAULT_LIVE_MANIFEST if args.execute else DEFAULT_DRY_MANIFEST)
    if not args.execute:
        if args.resume:
            raise ValueError("--resume is only supported with --execute")
        write_jsonl(output, [make_dry_run_response(request) for request in requests])
        manifest = {
            "run_id": args.run_id,
            "mode": "dry-run",
            "api_called": False,
            "record_count": len(requests),
            "requests": {"path": args.input.as_posix(), "sha256": sha256_file(args.input)},
            "responses": {"path": output.as_posix(), "sha256": sha256_file(output)},
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"mode": "dry-run", "responses": len(requests), "output": output.as_posix(), "api_called": False}))
        return 0

    if args.confirm_record_count != len(requests):
        raise ValueError(
            "real execution requires --confirm-record-count equal to the request count"
        )
    if output.exists() and not args.resume:
        raise FileExistsError(f"refusing to overwrite existing live output: {output}")

    completed: set[str] = set()
    if args.resume and output.exists():
        completed = {row["custom_id"] for row in read_jsonl(output)}
        unknown = completed - set(ids)
        if unknown:
            raise ValueError(f"resume output contains unknown custom_id values: {sorted(unknown)}")

    from openai import OpenAI  # Deliberately unavailable to dry-run execution.

    client = OpenAI()
    written = 0
    for request in requests:
        if request["custom_id"] in completed:
            continue
        _append_jsonl(output, _live_record(client, request))
        written += 1
    manifest = {
        "run_id": args.run_id,
        "mode": "execute",
        "api_called": True,
        "record_count": len(requests),
        "written_this_invocation": written,
        "requests": {"path": args.input.as_posix(), "sha256": sha256_file(args.input)},
        "responses": {"path": output.as_posix(), "sha256": sha256_file(output)},
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"mode": "execute", "written": written, "output": output.as_posix(), "api_called": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
