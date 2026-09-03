#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from outcome_gt_annotation_common_v1 import ROOT, read_jsonl

RUN_ROOT = ROOT / "data/outcome_gt/adjudication_v1/judge_runs"


def normalized_error_key(row: dict[str, Any]) -> str:
    status = str(row.get("status") or "unknown")
    error = row.get("error")
    if not isinstance(error, str) or not error.strip():
        return status
    text = " ".join(error.strip().split())
    if len(text) > 180:
        text = text[:177] + "..."
    return f"{status}: {text}"


def summarize(pass_id: str, run_id: str) -> dict[str, Any]:
    run_dir = RUN_ROOT / pass_id / run_id
    raw_path = run_dir / "raw_results.jsonl"
    provenance_path = run_dir / "annotator_provenance_v2.json"
    checkpoint_path = run_dir / "checkpoint_v2.json"
    if not raw_path.exists():
        raise FileNotFoundError(raw_path)

    rows = read_jsonl(raw_path)
    status_counts = Counter(str(row.get("status") or "unknown") for row in rows)
    attempt_counts = Counter(int(row.get("attempts") or 0) for row in rows)
    error_counts = Counter(normalized_error_key(row) for row in rows if row.get("status") != "success")
    request_ids_by_status: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        status = str(row.get("status") or "unknown")
        if len(request_ids_by_status[status]) < 10:
            request_ids_by_status[status].append(str(row.get("judge_request_id")))

    provenance = json.loads(provenance_path.read_text(encoding="utf-8")) if provenance_path.exists() else None
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8")) if checkpoint_path.exists() else None
    return {
        "schema_version": "outcome_gt_judge_run_diagnostic.v2",
        "pass_id": pass_id,
        "run_id": run_id,
        "raw_rows": len(rows),
        "status_counts": dict(sorted(status_counts.items())),
        "attempt_counts": {str(k): v for k, v in sorted(attempt_counts.items())},
        "failure_error_counts": dict(sorted(error_counts.items(), key=lambda item: (-item[1], item[0]))),
        "request_ids_by_status": dict(sorted(request_ids_by_status.items())),
        "provenance_status": provenance.get("status") if isinstance(provenance, dict) else None,
        "runner_version": provenance.get("runner_version") if isinstance(provenance, dict) else None,
        "prompt_version": provenance.get("prompt_version") if isinstance(provenance, dict) else None,
        "rows_target": provenance.get("rows_target") if isinstance(provenance, dict) else None,
        "rows_completed": provenance.get("rows_completed") if isinstance(provenance, dict) else None,
        "rows_failed": provenance.get("rows_failed") if isinstance(provenance, dict) else None,
        "checkpoint_status": checkpoint.get("status") if isinstance(checkpoint, dict) else None,
        "raw_content_included": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize Outcome GT judge v2 operational failures without printing response-bearing raw content.")
    parser.add_argument("--pass-id", choices=["pass_a", "pass_b"], required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.pass_id, args.run_id), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
