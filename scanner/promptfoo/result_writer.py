import json
import os
from datetime import datetime

_report_filename: str = ""
_hitlogfile: str = ""


def init_result_files(report_dir: str = "./promptfoo_reports", report_prefix: str = "promptfoo_run") -> dict:
    global _report_filename, _hitlogfile

    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    _report_filename = os.path.join(report_dir, f"{report_prefix}.{timestamp}.report.jsonl")
    _hitlogfile = os.path.join(report_dir, f"{report_prefix}.{timestamp}.hitlog.jsonl")

    with open(_report_filename, "w", encoding="utf-8") as f:
        header = {
            "entry_type": "start_run",
            "report_prefix": report_prefix,
            "timestamp": timestamp,
        }
        f.write(json.dumps(header) + "\n")

    return {
        "report_filename": _report_filename,
        "hitlogfile": _hitlogfile,
    }


def write_result(record: dict, scorer_result: dict) -> None:
    entry = {
        "entry_type": "attempt",
        "seed_id": record.get("seed_id", ""),
        "prompt": record.get("mutated_prompt", ""),
        "response": record.get("model_output", ""),
        "goal": record.get("bucket_id", ""),
        "scorer": "promptfoo_llm_rubric",
        "passed": scorer_result.get("passed", True),
        "reason": scorer_result.get("reason", ""),
        "judge_response": scorer_result.get("judge_response", ""),
        "result": "PASS" if scorer_result.get("passed", True) else "FAIL",
    }

    with open(_report_filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    if not scorer_result.get("passed", True):
        with open(_hitlogfile, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")