from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

import requests
from vulnerable_llm.canonical import CanonicalGenerationRequest
from src.generation.clients.vulnerable_llm import CanonicalVulnerableLLMClient

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "experiments/target_llm_production_v1/inputs/production_main_execution_plan_2661_v1_1.jsonl"
MANIFEST = ROOT / "experiments/target_llm_production_v1/inputs/production_generation_manifest_1207_v1_1.jsonl"
RUN_ID = "target-llm-production-smoke-v1"
RUN_DIR = ROOT / "experiments/target_llm_production_v1/runs" / RUN_ID

CANONICAL_URL = "http://localhost:8000"
OLLAMA_URL = "http://localhost:11434/api/chat"
SELECTION_SEED = "target-llm-production-smoke-v1"

def read_jsonl(path):
    with path.open(encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]

def append_jsonl(path, row):
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def rank(case_id):
    return hashlib.sha256(
        f"{SELECTION_SEED}:{case_id}".encode()
    ).hexdigest()

def select_smoke(plan, manifests):
    meta = {m["production_case_id"]: m for m in manifests}

    attack_cases = sorted(
        {r["production_case_id"] for r in plan if r["mode"] == "attack"},
        key=rank,
    )[:4]

    benign = sorted(
        {
            r["production_case_id"] for r in plan
            if r["mode"] == "direct"
            and meta[r["production_case_id"]]["source_case_gt"]["derived_class"] == "non_pi_non_malicious"
        },
        key=rank,
    )[0]

    malicious = sorted(
        {
            r["production_case_id"] for r in plan
            if r["mode"] == "direct"
            and meta[r["production_case_id"]]["source_case_gt"]["derived_class"] == "non_pi_malicious"
        },
        key=rank,
    )[0]

    chosen = set(attack_cases + [benign, malicious])
    selected = [r for r in plan if r["production_case_id"] in chosen]

    if len(selected) != 18:
        raise RuntimeError(f"expected 18 rows, got {len(selected)}")

    return selected

def direct_generate(row):
    payload = {
        "model": row["model"],
        "messages": row["materialized_request"]["model_visible_messages"],
        "stream": False,
        "options": {
            "temperature": row["generation_options"]["temperature"],
            "top_p": row["generation_options"]["top_p"],
            "seed": row["generation_options"]["seed"],
            "num_predict": row["generation_options"]["max_tokens"],
        },
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=180)
    response.raise_for_status()
    body = response.json()

    text = (body.get("message") or {}).get("content")
    if not isinstance(text, str):
        raise RuntimeError("direct Ollama response missing message.content")

    return text, body

def main():
    if RUN_DIR.exists():
        raise FileExistsError(f"run already exists: {RUN_DIR}")

    plan = read_jsonl(PLAN)
    manifests = read_jsonl(MANIFEST)
    selected = select_smoke(plan, manifests)

    RUN_DIR.mkdir(parents=True)

    with (RUN_DIR / "execution_plan.jsonl").open(
        "w", encoding="utf-8", newline="\n"
    ) as f:
        for row in selected:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    manifest = {
        "run_id": RUN_ID,
        "selection_seed": SELECTION_SEED,
        "git_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "source_plan_sha256": sha256_file(PLAN),
        "planned": 18,
        "attack": 12,
        "direct": 6,
        "model": "qwen2.5:7b",
    }

    (RUN_DIR / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    client = CanonicalVulnerableLLMClient(
        base_url=CANONICAL_URL,
        timeout_sec=180,
        max_retries=1,
        retry_delay_sec=0,
    )

    completed = []
    failures = []

    for i, row in enumerate(selected, 1):
        gid = row["generation_id"]
        started = time.perf_counter()
        print(f"[{i:02d}/18] {row['mode']} {gid}")

        try:
            if row["mode"] == "attack":
                req = CanonicalGenerationRequest.model_validate(
                    row["materialized_request"]["canonical_request"]
                )
                result = client.generate_canonical(req)
                response_text = result.response_text
                raw_response = result.raw_response
                execution_status = result.execution_status
            else:
                response_text, raw_response = direct_generate(row)
                execution_status = "completed"

            record = {
                "generation_id": gid,
                "production_case_id": row["production_case_id"],
                "source_pool": row["source_pool"],
                "mode": row["mode"],
                "replicate_index": row["replicate_index"],
                "seed": row["seed"],
                "generation_options": row["generation_options"],
                "execution_status": execution_status,
                "response_text": response_text,
                "response_sha256": hashlib.sha256(
                    response_text.encode("utf-8")
                ).hexdigest(),
                "endpoint_response": raw_response,
                "latency_seconds": time.perf_counter() - started,
            }

            append_jsonl(RUN_DIR / "results.jsonl", record)
            completed.append(gid)

            tmp = RUN_DIR / "checkpoint.json.tmp"
            tmp.write_text(
                json.dumps(
                    {"completed_generation_ids": sorted(completed)},
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
            tmp.replace(RUN_DIR / "checkpoint.json")

        except Exception as exc:
            failure = {
                "generation_id": gid,
                "mode": row["mode"],
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            }
            append_jsonl(RUN_DIR / "failures.jsonl", failure)
            failures.append(failure)

    summary = {
        "run_id": RUN_ID,
        "planned": 18,
        "completed": len(completed),
        "failed": len(failures),
        "run_dir": str(RUN_DIR.relative_to(ROOT)),
    }

    (RUN_DIR / "run_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()

