from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]

RUN_DIR = (
    ROOT
    / "experiments"
    / "target_llm_production_v1"
    / "runs"
    / "target-llm-production-smoke-v1"
)

PLAN = RUN_DIR / "execution_plan.jsonl"
RESULTS = RUN_DIR / "results.jsonl"
CHECKPOINT = RUN_DIR / "checkpoint.json"
RECOVERY_LOG = RUN_DIR / "direct_recovery_attempts.jsonl"
SUMMARY = RUN_DIR / "run_summary.json"

DIRECT_URL = "http://localhost:8000/direct-generate"

EXPECTED_MODEL = "qwen2.5:7b"
EXPECTED_DIRECT_COUNT = 6


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def append_jsonl(path: Path, row: dict):
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(
            json.dumps(
                row,
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n"
        )


def write_json_atomic(path: Path, obj: dict):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(
            obj,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def response_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def replicate_to_index(value: str) -> int:
    mapping = {
        "r1": 0,
        "r2": 1,
        "r3": 2,
    }
    if value not in mapping:
        raise ValueError(f"unexpected replicate_index: {value}")
    return mapping[value]


def dataset_sha(row: dict):
    return (
        row.get("expected_source_artifact_sha256")
        or row.get("expected_source_artifact_sha")
        or row.get("dataset_sha256")
    )


def build_direct_payload(row: dict) -> dict:
    if row["mode"] != "direct":
        raise ValueError("non-direct row passed to direct payload builder")

    messages = row["materialized_request"]["model_visible_messages"]

    if len(messages) != 2:
        raise ValueError(
            f"{row['generation_id']}: expected exactly 2 direct messages"
        )

    if messages[0]["role"] != "system":
        raise ValueError(
            f"{row['generation_id']}: first message must be system"
        )

    if messages[1]["role"] != "user":
        raise ValueError(
            f"{row['generation_id']}: second message must be user"
        )

    options = row["generation_options"]

    return {
        "schema_version": "direct_generation_request.v1",
        "run_id": "target-llm-production-smoke-v1",
        "generation_id": row["generation_id"],
        "case_id": row["production_case_id"],
        "repetition_index": replicate_to_index(
            row["replicate_index"]
        ),
        "provider": row["provider"],
        "model": row["model"],
        "messages": messages,
        "generation_config": {
            "temperature": options["temperature"],
            "max_tokens": options["max_tokens"],
            "random_seed": options["seed"],
            "provider_options": {
                "top_p": options["top_p"],
            },
        },
        "dataset_sha256": dataset_sha(row),
    }


def post_with_one_technical_retry(payload: dict):
    last_exc = None

    for attempt in (1, 2):
        try:
            response = requests.post(
                DIRECT_URL,
                json=payload,
                timeout=180,
            )

            # 4xx means the request itself is wrong. Do not retry.
            if 400 <= response.status_code < 500:
                raise RuntimeError(
                    f"direct endpoint returned {response.status_code}: "
                    f"{response.text}"
                )

            # One technical retry is permitted for server/provider failure.
            if response.status_code >= 500:
                if attempt == 1:
                    time.sleep(1)
                    continue
                response.raise_for_status()

            response.raise_for_status()
            return response.json(), attempt

        except (
            requests.ConnectionError,
            requests.Timeout,
        ) as exc:
            last_exc = exc

            if attempt == 1:
                time.sleep(1)
                continue

            raise

    if last_exc:
        raise last_exc

    raise RuntimeError("direct request failed without response")


def main():
    plan = read_jsonl(PLAN)

    checkpoint = json.loads(
        CHECKPOINT.read_text(encoding="utf-8")
    )

    completed = set(
        checkpoint.get("completed_generation_ids", [])
    )

    missing_direct = [
        row
        for row in plan
        if row["mode"] == "direct"
        and row["generation_id"] not in completed
    ]

    print("=== DIRECT RECOVERY PREFLIGHT ===")
    print("checkpoint completed:", len(completed))
    print("missing direct:", len(missing_direct))

    if len(completed) != 12:
        raise RuntimeError(
            f"expected 12 completed generations before recovery, "
            f"found {len(completed)}"
        )

    if len(missing_direct) != EXPECTED_DIRECT_COUNT:
        raise RuntimeError(
            f"expected exactly {EXPECTED_DIRECT_COUNT} missing direct rows, "
            f"found {len(missing_direct)}"
        )

    if any(row["model"] != EXPECTED_MODEL for row in missing_direct):
        raise RuntimeError("direct recovery contains unexpected model")

    recovered = 0
    new_failures = 0

    for i, row in enumerate(missing_direct, 1):
        gid = row["generation_id"]

        print(f"[{i:02d}/06] direct {gid}")

        payload = build_direct_payload(row)

        started = time.perf_counter()

        try:
            endpoint_response, attempt_number = (
                post_with_one_technical_retry(payload)
            )

            text = endpoint_response.get("response")

            if not isinstance(text, str) or not text.strip():
                raise RuntimeError(
                    "direct endpoint returned empty response"
                )

            if endpoint_response.get("model") != EXPECTED_MODEL:
                raise RuntimeError(
                    "endpoint response model identity mismatch"
                )

            meta = endpoint_response.get("meta") or {}

            if meta.get("model_identity") not in (
                None,
                EXPECTED_MODEL,
            ):
                raise RuntimeError(
                    f"provider model identity mismatch: "
                    f"{meta.get('model_identity')}"
                )

            result_record = {
                "generation_id": gid,
                "production_case_id": row["production_case_id"],
                "source_pool": row["source_pool"],
                "mode": "direct",
                "replicate_index": row["replicate_index"],
                "seed": row["seed"],
                "generation_options": row["generation_options"],
                "execution_status": "completed",
                "response_text": text,
                "response_sha256": response_sha(text),
                "endpoint_response": endpoint_response,
                "latency_seconds": (
                    time.perf_counter() - started
                ),
                "recovery": {
                    "recovered_from_initial_404": True,
                    "technical_attempt_number": attempt_number,
                    "endpoint": "/direct-generate",
                },
            }

            append_jsonl(RESULTS, result_record)

            append_jsonl(
                RECOVERY_LOG,
                {
                    "generation_id": gid,
                    "status": "completed",
                    "attempt_number": attempt_number,
                    "endpoint": "/direct-generate",
                    "model": endpoint_response.get("model"),
                    "model_identity": meta.get("model_identity"),
                    "model_digest": meta.get("model_digest"),
                },
            )

            completed.add(gid)

            write_json_atomic(
                CHECKPOINT,
                {
                    "completed_generation_ids": sorted(completed),
                },
            )

            recovered += 1

        except Exception as exc:
            append_jsonl(
                RECOVERY_LOG,
                {
                    "generation_id": gid,
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            )

            new_failures += 1
            print(
                f"FAILED {gid}: "
                f"{type(exc).__name__}: {exc}"
            )

    final_results = read_jsonl(RESULTS)
    unique_completed = {
        row["generation_id"]
        for row in final_results
        if row.get("execution_status") == "completed"
    }

    summary = {
        "run_id": "target-llm-production-smoke-v1",
        "planned": 18,
        "completed": len(unique_completed),
        "failed": 18 - len(unique_completed),
        "attack_completed": len(
            {
                row["generation_id"]
                for row in final_results
                if row["mode"] == "attack"
                and row.get("execution_status") == "completed"
            }
        ),
        "direct_completed": len(
            {
                row["generation_id"]
                for row in final_results
                if row["mode"] == "direct"
                and row.get("execution_status") == "completed"
            }
        ),
        "historical_failed_attempts": 6,
        "recovered_direct_this_run": recovered,
        "new_recovery_failures": new_failures,
        "historical_failure_file": "failures.jsonl",
        "recovery_audit_file": "direct_recovery_attempts.jsonl",
        "run_dir": str(RUN_DIR.relative_to(ROOT)),
    }

    write_json_atomic(SUMMARY, summary)

    print()
    print("=== DIRECT RECOVERY SUMMARY ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if summary["completed"] != 18:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
