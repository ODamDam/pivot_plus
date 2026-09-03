#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

from outcome_gt_annotation_common_v1 import (
    EXPECTED_ROWS,
    ROOT,
    canonical_json,
    canonical_jsonl_bytes,
    derive_outcome_label,
    flatten_strings,
    read_jsonl,
    sha256_bytes,
    sha256_file,
)

PROMPT_PATH = ROOT / "docs/outcome_gt/OUTCOME_GT_JUDGE_SYSTEM_PROMPT_v1.txt"
PROMPT_VERSION = "outcome-gt-judge-system-prompt-v1"
PROMPT_SHA256 = "a6cb893ef69ad4b688505da6a4511182f88d42956119db9af78a4b940837d64c"
REQUEST_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_requests"
RUN_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_runs"
SEMANTIC_SCHEMA_PATH = ROOT / "schemas/outcome_gt_judge_semantic_response_v1.schema.json"
RAW_SCHEMA_PATH = ROOT / "schemas/outcome_gt_judge_raw_result_v1.schema.json"
PROVENANCE_SCHEMA_PATH = ROOT / "schemas/outcome_gt_annotator_provenance_v1.schema.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_validator(path: Path) -> jsonschema.Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def git_head() -> str:
    try:
        value = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception as exc:
        raise RuntimeError("unable to resolve git HEAD for judge provenance") from exc
    if len(value) != 40:
        raise RuntimeError("invalid git HEAD")
    return value


def http_json(method: str, url: str, payload: dict[str, Any] | None = None, *, timeout: float) -> tuple[int, dict[str, Any]]:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return int(response.status), json.loads(response.read().decode("utf-8"))


def ollama_metadata(base_url: str, model: str, timeout: float) -> tuple[str, str | None]:
    _, version_obj = http_json("GET", f"{base_url.rstrip('/')}/api/version", timeout=timeout)
    version = str(version_obj.get("version") or "unknown")
    _, tags = http_json("GET", f"{base_url.rstrip('/')}/api/tags", timeout=timeout)
    digest = None
    for item in tags.get("models", []):
        if item.get("name") == model or item.get("model") == model:
            value = item.get("digest")
            if isinstance(value, str):
                digest = value.removeprefix("sha256:")
            break
    if digest is None:
        raise ValueError(f"Ollama model is not installed or digest is unavailable: {model}")
    return version, digest


def model_content(response_obj: dict[str, Any]) -> str:
    message = response_obj.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise ValueError("Ollama response missing message.content")
    return message["content"]


def parse_json_object(text: str) -> dict[str, Any]:
    candidate = text.strip()
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError:
        if candidate.startswith("```") and candidate.endswith("```"):
            lines = candidate.splitlines()
            if len(lines) < 3:
                raise
            candidate = "\n".join(lines[1:-1]).strip()
            value = json.loads(candidate)
        else:
            raise
    if not isinstance(value, dict):
        raise ValueError("judge output is not a JSON object")
    return value


def validate_semantic_evidence(semantic: dict[str, Any], assignment: dict[str, Any]) -> None:
    response_text = assignment["response_text"]
    request_text = "\n".join(flatten_strings(assignment["request_context"]))
    rule_text = "\n".join(flatten_strings(assignment["rule"]))
    for evidence in semantic["evidence"]:
        source = evidence["source"]
        quote = evidence["quote"]
        haystack = response_text if source == "response" else request_text if source == "request" else rule_text
        if quote not in haystack:
            raise ValueError(f"evidence quote is not literal in {source}")
        supports = evidence["supports"]
        if supports == "boundary_violated" and semantic["boundary_violated"] is not True:
            raise ValueError("boundary_violated evidence contradicts semantic decision")
        if supports == "boundary_preserved" and semantic["boundary_violated"] is not False:
            raise ValueError("boundary_preserved evidence contradicts semantic decision")
        if supports == "attacker_goal_achieved" and semantic["attacker_goal_achieved"] is not True:
            raise ValueError("attacker_goal_achieved evidence contradicts semantic decision")
        if supports == "attacker_goal_not_achieved" and semantic["attacker_goal_achieved"] is not False:
            raise ValueError("attacker_goal_not_achieved evidence contradicts semantic decision")
        if supports == "normal_task_completed" and semantic["normal_task_completed"] is not True:
            raise ValueError("normal_task_completed evidence contradicts semantic decision")
        if supports == "refusal" and semantic["refusal"] is not True:
            raise ValueError("refusal evidence contradicts semantic decision")
    if derive_outcome_label(semantic) == "indeterminate" and not any(item["supports"] == "indeterminate" for item in semantic["evidence"]):
        raise ValueError("indeterminate semantic decision requires indeterminate evidence")


def stable_run_id(pass_id: str, request_sha256: str, model: str, model_digest: str | None, provider_version: str, runner_commit: str, seed: int, max_tokens: int, limit: int | None) -> str:
    letter = "A" if pass_id == "pass_a" else "B"
    material = canonical_json({
        "pass_id": pass_id,
        "request_sha256": request_sha256,
        "model": model,
        "model_digest": model_digest,
        "provider_version": provider_version,
        "runner_commit": runner_commit,
        "prompt_sha256": PROMPT_SHA256,
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": seed,
        "max_tokens": max_tokens,
        "limit": limit,
    })
    suffix = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16].upper()
    return f"OGTJRUN-V1-{letter}-{suffix}"


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json(row) + "\n")
        handle.flush()


def write_json_replace(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_request_manifest(pass_id: str) -> tuple[Path, dict[str, Any]]:
    path = REQUEST_ROOT / pass_id / "judge_requests_1746_v1_manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("pass_id") != pass_id or value.get("rows") != EXPECTED_ROWS:
        raise ValueError(f"{pass_id}: judge request manifest mismatch")
    request_path = ROOT / value["request_path"]
    if sha256_file(request_path) != value["request_sha256"]:
        raise ValueError(f"{pass_id}: judge request SHA-256 mismatch")
    if sha256_file(PROMPT_PATH) != PROMPT_SHA256 or value.get("prompt_sha256") != PROMPT_SHA256:
        raise ValueError("frozen judge prompt SHA-256 mismatch")
    return request_path, value


def raw_success_by_request(raw_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["judge_request_id"]: row for row in raw_rows if row.get("status") == "success"}


def wrap_decision(raw: dict[str, Any], annotator_id: str) -> dict[str, Any]:
    semantic = raw["semantic"]
    return {
        "schema_version": "outcome_gt_independent_decision.v1",
        "assignment_item_id": raw["assignment_item_id"],
        "pass_id": raw["pass_id"],
        "normal_task_completed": semantic["normal_task_completed"],
        "attacker_goal_achieved": semantic["attacker_goal_achieved"],
        "boundary_violated": semantic["boundary_violated"],
        "refusal": semantic["refusal"],
        "execution_failure": False,
        "evidence": semantic["evidence"],
        "rationale": semantic["rationale"],
        "annotator": annotator_id,
        "decision_status": "independent_complete",
    }


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

    provider_version, model_digest = ollama_metadata(args.base_url, args.model, args.timeout)
    runner_commit = git_head()
    run_id = stable_run_id(args.pass_id, request_manifest["request_sha256"], args.model, model_digest, provider_version, runner_commit, args.seed, args.max_tokens, args.limit)
    run_dir = RUN_ROOT / args.pass_id / run_id
    raw_path = run_dir / "raw_results.jsonl"
    decisions_path = run_dir / "decisions_v1.jsonl"
    checkpoint_path = run_dir / "checkpoint.json"
    provenance_path = run_dir / "annotator_provenance_v1.json"

    semantic_validator = load_validator(SEMANTIC_SCHEMA_PATH)
    raw_validator = load_validator(RAW_SCHEMA_PATH)
    provenance_validator = load_validator(PROVENANCE_SCHEMA_PATH)
    prompt_text = PROMPT_PATH.read_text(encoding="utf-8")

    existing_raw = read_jsonl(raw_path) if raw_path.exists() else []
    terminal_by_id = {row["judge_request_id"]: row for row in existing_raw}
    success_by_id = raw_success_by_request(existing_raw)
    started_at = utc_now()
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
        }
        for key, expected in immutable.items():
            if prior.get(key) != expected:
                raise ValueError(f"resume provenance mismatch: {key}")

    base_provenance = {
        "schema_version": "outcome_gt_annotator_provenance.v1",
        "run_id": run_id,
        "pass_id": args.pass_id,
        "annotator_id": args.annotator_id,
        "provider": "ollama",
        "provider_version": provider_version,
        "model_id": args.model,
        "model_digest": model_digest,
        "runner_version": "outcome-gt-judge-runner-v1",
        "runner_commit": runner_commit,
        "prompt_version": PROMPT_VERSION,
        "prompt_path": str(PROMPT_PATH.relative_to(ROOT)).replace("\\", "/"),
        "prompt_sha256": PROMPT_SHA256,
        "assignment_sha256": request_manifest["source_assignment_sha256"],
        "request_sha256": request_manifest["request_sha256"],
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
    write_json_replace(provenance_path, base_provenance)

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
            "format": "json",
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
                _, response_obj = http_json("POST", f"{args.base_url.rstrip('/')}/api/chat", payload, timeout=args.timeout)
                raw_content = model_content(response_obj)
                try:
                    semantic = parse_json_object(raw_content)
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
                    validate_semantic_evidence(semantic, assignment)
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
            "completed_at": utc_now(),
            "raw_content": raw_content,
            "raw_content_sha256": hashlib.sha256(raw_content.encode("utf-8")).hexdigest() if isinstance(raw_content, str) else None,
            "semantic": semantic if status == "success" else None,
            "error": error_message,
        }
        raw_errors = list(raw_validator.iter_errors(raw_row))
        if raw_errors:
            raise ValueError(f"raw result schema failure: {raw_errors[0].message}")
        append_jsonl(raw_path, raw_row)
        terminal_by_id[request_id] = raw_row
        if status == "success":
            success_by_id[request_id] = raw_row
        else:
            failures += 1

        if index % 10 == 0 or index == len(requests):
            write_json_replace(checkpoint_path, {
                "schema_version": "outcome_gt_judge_checkpoint.v1",
                "run_id": run_id,
                "pass_id": args.pass_id,
                "rows_target": len(requests),
                "rows_completed": sum(r["judge_request_id"] in success_by_id for r in requests),
                "rows_failed_this_invocation": failures,
                "updated_at": utc_now(),
            })

    decisions = [wrap_decision(success_by_id[row["judge_request_id"]], args.annotator_id) for row in requests if row["judge_request_id"] in success_by_id]
    decision_bytes = canonical_jsonl_bytes(decisions)
    decisions_path.parent.mkdir(parents=True, exist_ok=True)
    decisions_path.write_bytes(decision_bytes)

    completed = len(decisions)
    total_failed = len(requests) - completed
    final_status = "CANARY_COMPLETE" if args.limit is not None and completed == len(requests) else "COMPLETE" if completed == EXPECTED_ROWS else "INCOMPLETE"
    provenance = dict(base_provenance)
    provenance.update({"finished_at": utc_now(), "status": final_status, "rows_completed": completed, "rows_failed": total_failed})
    errors = list(provenance_validator.iter_errors(provenance))
    if errors:
        raise ValueError(f"final provenance schema failure: {errors[0].message}")
    write_json_replace(provenance_path, provenance)
    write_json_replace(checkpoint_path, {
        "schema_version": "outcome_gt_judge_checkpoint.v1",
        "run_id": run_id,
        "pass_id": args.pass_id,
        "rows_target": len(requests),
        "rows_completed": completed,
        "rows_failed": total_failed,
        "decision_sha256": sha256_bytes(decision_bytes),
        "updated_at": utc_now(),
        "status": final_status,
    })

    print(json.dumps({
        "status": final_status,
        "run_id": run_id,
        "pass_id": args.pass_id,
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
