#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
from pathlib import Path
from typing import Any

import jsonschema

import run_outcome_gt_judge_v1 as base
from outcome_gt_annotation_common_v1 import (
    EXPECTED_ROWS,
    ROOT,
    canonical_json,
    canonical_jsonl_bytes,
    read_jsonl,
    sha256_bytes,
    sha256_file,
)

PROMPT_PATH = ROOT / "docs/outcome_gt/OUTCOME_GT_JUDGE_SYSTEM_PROMPT_v2.txt"
PROMPT_VERSION = "outcome-gt-judge-system-prompt-v2"
PROMPT_SHA256 = "80a7a218bf34ccbf33a9aa936ac9f2926184be55acd0327fa3b93617e9435ad2"
REQUEST_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_requests"
RUN_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_runs"
SEMANTIC_SCHEMA_PATH = ROOT / "schemas/outcome_gt_judge_semantic_response_v1.schema.json"
RAW_SCHEMA_PATH = ROOT / "schemas/outcome_gt_judge_raw_result_v1.schema.json"
PROVENANCE_SCHEMA_PATH = ROOT / "schemas/outcome_gt_annotator_provenance_v2.schema.json"
STRUCTURED_OUTPUT_SCHEMA_SHA256 = "d821c295054a0a5a1a8c8df6eb631f8cb0a5d5fb5e680f7d6af840dff0a1bf1f"


def load_validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def structured_output_schema() -> dict[str, Any]:
    if sha256_file(SEMANTIC_SCHEMA_PATH) != STRUCTURED_OUTPUT_SCHEMA_SHA256:
        raise ValueError("structured-output semantic schema SHA-256 mismatch")
    schema = json.loads(SEMANTIC_SCHEMA_PATH.read_text(encoding="utf-8"))
    # Ollama's structured-output `format` accepts the JSON-Schema body. Metadata
    # fields are not needed for generation and are removed without changing the
    # validator used after generation.
    return {key: value for key, value in schema.items() if key not in {"$schema", "$id", "title"}}


def stable_run_id(
    pass_id: str,
    request_sha256: str,
    model: str,
    model_digest: str | None,
    provider_version: str,
    runner_commit: str,
    seed: int,
    max_tokens: int,
    limit: int | None,
) -> str:
    letter = "A" if pass_id == "pass_a" else "B"
    material = canonical_json({
        "runner_version": "outcome-gt-judge-runner-v2",
        "pass_id": pass_id,
        "request_sha256": request_sha256,
        "model": model,
        "model_digest": model_digest,
        "provider_version": provider_version,
        "runner_commit": runner_commit,
        "prompt_sha256": PROMPT_SHA256,
        "structured_output_schema_sha256": STRUCTURED_OUTPUT_SCHEMA_SHA256,
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": seed,
        "max_tokens": max_tokens,
        "limit": limit,
    })
    suffix = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"OGTJRUN-V2-{letter}-{suffix}"


def load_request_manifest(pass_id: str) -> tuple[Path, dict[str, Any]]:
    path = REQUEST_ROOT / pass_id / "judge_requests_1746_v2_manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != "outcome_gt_judge_request_manifest.v2":
        raise ValueError(f"{pass_id}: judge request manifest version mismatch")
    if value.get("pass_id") != pass_id or value.get("rows") != EXPECTED_ROWS:
        raise ValueError(f"{pass_id}: judge request manifest mismatch")
    request_path = ROOT / value["request_path"]
    if sha256_file(request_path) != value["request_sha256"]:
        raise ValueError(f"{pass_id}: judge request SHA-256 mismatch")
    if sha256_file(PROMPT_PATH) != PROMPT_SHA256 or value.get("prompt_sha256") != PROMPT_SHA256:
        raise ValueError("frozen judge prompt v2 SHA-256 mismatch")
    return request_path, value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-id", choices=["pass_a", "pass_b"], required=True)
    parser.add_argument("--provider", choices=["ollama"], default="ollama")
    parser.add_argument("--model", required=True)
    parser.add_argument("--annotator-id", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-tokens", type=int, default=768)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-transport-retries", type=int, default=1)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    if not 0 <= args.max_transport_retries <= 3:
        raise ValueError("--max-transport-retries must be between 0 and 3")
    if args.limit is not None and not 1 <= args.limit <= EXPECTED_ROWS:
        raise ValueError("--limit must be between 1 and 1746")

    request_path, request_manifest = load_request_manifest(args.pass_id)
    all_requests = read_jsonl(request_path)
    requests = all_requests[: args.limit] if args.limit else all_requests
    if len(all_requests) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} judge requests")

    provider_version, model_digest = base.ollama_metadata(args.base_url, args.model, args.timeout)
    runner_commit = base.git_head()
    run_id = stable_run_id(
        args.pass_id,
        request_manifest["request_sha256"],
        args.model,
        model_digest,
        provider_version,
        runner_commit,
        args.seed,
        args.max_tokens,
        args.limit,
    )
    run_dir = RUN_ROOT / args.pass_id / run_id
    raw_path = run_dir / "raw_results.jsonl"
    decisions_path = run_dir / "decisions_v1.jsonl"
    checkpoint_path = run_dir / "checkpoint_v2.json"
    provenance_path = run_dir / "annotator_provenance_v2.json"

    semantic_validator = load_validator(SEMANTIC_SCHEMA_PATH)
    raw_validator = load_validator(RAW_SCHEMA_PATH)
    provenance_validator = load_validator(PROVENANCE_SCHEMA_PATH)
    format_schema = structured_output_schema()
    prompt_text = PROMPT_PATH.read_text(encoding="utf-8")

    existing_raw = read_jsonl(raw_path) if raw_path.exists() else []
    terminal_by_id = {row["judge_request_id"]: row for row in existing_raw}
    success_by_id = base.raw_success_by_request(existing_raw)
    started_at = base.utc_now()
    if provenance_path.exists():
        prior = json.loads(provenance_path.read_text(encoding="utf-8"))
        started_at = prior["started_at"]
        immutable = {
            "run_id": run_id,
            "pass_id": args.pass_id,
            "annotator_id": args.annotator_id,
            "model_id": args.model,
            "model_digest": model_digest,
            "prompt_sha256": PROMPT_SHA256,
            "request_sha256": request_manifest["request_sha256"],
            "structured_output_schema_sha256": STRUCTURED_OUTPUT_SCHEMA_SHA256,
        }
        for key, expected in immutable.items():
            if prior.get(key) != expected:
                raise ValueError(f"resume provenance mismatch: {key}")

    base_provenance = {
        "schema_version": "outcome_gt_annotator_provenance.v2",
        "run_id": run_id,
        "pass_id": args.pass_id,
        "annotator_id": args.annotator_id,
        "provider": "ollama",
        "provider_version": provider_version,
        "model_id": args.model,
        "model_digest": model_digest,
        "runner_version": "outcome-gt-judge-runner-v2",
        "runner_commit": runner_commit,
        "prompt_version": PROMPT_VERSION,
        "prompt_path": str(PROMPT_PATH.relative_to(ROOT)).replace("\\", "/"),
        "prompt_sha256": PROMPT_SHA256,
        "assignment_sha256": request_manifest["source_assignment_sha256"],
        "request_sha256": request_manifest["request_sha256"],
        "structured_output_schema_sha256": STRUCTURED_OUTPUT_SCHEMA_SHA256,
        "sampling": {"temperature": 0.0, "top_p": 1.0, "seed": args.seed, "max_tokens": args.max_tokens},
        "retry_policy": {"max_transport_retries": args.max_transport_retries, "semantic_retry": False, "parse_retry": False},
        "started_at": started_at,
        "finished_at": None,
        "status": "RUNNING",
        "rows_target": len(requests),
        "rows_completed": len([r for r in requests if r["judge_request_id"] in success_by_id]),
        "rows_failed": len([r for r in requests if r["judge_request_id"] in terminal_by_id and terminal_by_id[r["judge_request_id"]].get("status") != "success"]),
    }
    errors = list(provenance_validator.iter_errors(base_provenance))
    if errors:
        raise ValueError(f"provenance schema failure: {errors[0].message}")
    base.write_json_replace(provenance_path, base_provenance)

    failures = 0
    for index, request_row in enumerate(requests, 1):
        request_id = request_row["judge_request_id"]
        if request_id in terminal_by_id:
            continue

        assignment = request_row["assignment"]
        user_payload = canonical_json({"schema_version": "outcome_gt_judge_input.v1", "assignment": assignment})
        payload = {
            "model": args.model,
            "messages": [{"role": "system", "content": prompt_text}, {"role": "user", "content": user_payload}],
            "stream": False,
            "format": format_schema,
            "options": {"temperature": 0.0, "top_p": 1.0, "seed": args.seed, "num_predict": args.max_tokens},
        }

        status = "transport_error"
        raw_content = None
        semantic = None
        error_message = None
        attempts = 0
        for attempt in range(args.max_transport_retries + 1):
            attempts = attempt + 1
            try:
                _, response_obj = base.http_json("POST", f"{args.base_url.rstrip('/')}/api/chat", payload, timeout=args.timeout)
                raw_content = base.model_content(response_obj)
                try:
                    semantic = base.parse_json_object(raw_content)
                except Exception as exc:
                    status = "parse_error"
                    error_message = str(exc)
                    break
                schema_errors = list(semantic_validator.iter_errors(semantic))
                if schema_errors:
                    status = "schema_error"
                    error_message = "; ".join(item.message for item in schema_errors[:5])
                    break
                try:
                    base.validate_semantic_evidence(semantic, assignment)
                except Exception as exc:
                    status = "evidence_error"
                    error_message = str(exc)
                    break
                status = "success"
                error_message = None
                break
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
                error_message = str(exc)
                if attempt < args.max_transport_retries:
                    time.sleep(min(2 ** attempt, 4))
                    continue
                status = "transport_error"

        raw_row = {
            "schema_version": "outcome_gt_judge_raw_result.v1",
            "judge_request_id": request_id,
            "assignment_item_id": request_row["assignment_item_id"],
            "pass_id": args.pass_id,
            "status": status,
            "attempts": attempts,
            "completed_at": base.utc_now(),
            "raw_content": raw_content,
            "raw_content_sha256": hashlib.sha256(raw_content.encode("utf-8")).hexdigest() if isinstance(raw_content, str) else None,
            "semantic": semantic if status == "success" else None,
            "error": error_message,
        }
        raw_errors = list(raw_validator.iter_errors(raw_row))
        if raw_errors:
            raise ValueError(f"raw result schema failure: {raw_errors[0].message}")
        base.append_jsonl(raw_path, raw_row)
        terminal_by_id[request_id] = raw_row
        if status == "success":
            success_by_id[request_id] = raw_row
        else:
            failures += 1

        if index % 10 == 0 or index == len(requests):
            base.write_json_replace(checkpoint_path, {
                "schema_version": "outcome_gt_judge_checkpoint.v2",
                "run_id": run_id,
                "pass_id": args.pass_id,
                "rows_target": len(requests),
                "rows_completed": sum(r["judge_request_id"] in success_by_id for r in requests),
                "rows_failed_this_invocation": failures,
                "updated_at": base.utc_now(),
            })

    decisions = [base.wrap_decision(success_by_id[row["judge_request_id"]], args.annotator_id) for row in requests if row["judge_request_id"] in success_by_id]
    decision_bytes = canonical_jsonl_bytes(decisions)
    decisions_path.parent.mkdir(parents=True, exist_ok=True)
    decisions_path.write_bytes(decision_bytes)

    completed = len(decisions)
    total_failed = len(requests) - completed
    final_status = "CANARY_COMPLETE" if args.limit is not None and completed == len(requests) else "COMPLETE" if completed == EXPECTED_ROWS else "INCOMPLETE"
    provenance = dict(base_provenance)
    provenance.update({"finished_at": base.utc_now(), "status": final_status, "rows_completed": completed, "rows_failed": total_failed})
    errors = list(provenance_validator.iter_errors(provenance))
    if errors:
        raise ValueError(f"final provenance schema failure: {errors[0].message}")
    base.write_json_replace(provenance_path, provenance)
    base.write_json_replace(checkpoint_path, {
        "schema_version": "outcome_gt_judge_checkpoint.v2",
        "run_id": run_id,
        "pass_id": args.pass_id,
        "rows_target": len(requests),
        "rows_completed": completed,
        "rows_failed": total_failed,
        "decision_sha256": sha256_bytes(decision_bytes),
        "updated_at": base.utc_now(),
        "status": final_status,
    })

    print(json.dumps({
        "status": final_status,
        "run_id": run_id,
        "pass_id": args.pass_id,
        "runner_version": "outcome-gt-judge-runner-v2",
        "prompt_version": PROMPT_VERSION,
        "structured_output": True,
        "model": args.model,
        "model_digest": model_digest,
        "rows_target": len(requests),
        "rows_completed": completed,
        "rows_failed": total_failed,
        "raw_results_path": str(raw_path.relative_to(ROOT)).replace("\\", "/"),
        "decisions_path": str(decisions_path.relative_to(ROOT)).replace("\\", "/"),
        "decision_sha256": sha256_bytes(decision_bytes),
        "provenance_path": str(provenance_path.relative_to(ROOT)).replace("\\", "/"),
    }, ensure_ascii=False, indent=2))
    return 0 if final_status in {"COMPLETE", "CANARY_COMPLETE"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
