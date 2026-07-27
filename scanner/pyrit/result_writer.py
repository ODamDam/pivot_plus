import json
import os
from datetime import datetime


_report_filename: str = ""
_hitlogfile: str = ""


def init_result_files(report_dir: str = "./pyrit_reports", report_prefix: str = "pyrit_run") -> dict:
    """
    결과 저장 경로 초기화. main.py에서 시작 시 1회 호출.
    garak의 init_garak_config()에 대응하는 역할.
    """
    global _report_filename, _hitlogfile

    os.makedirs(report_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    _report_filename = os.path.join(report_dir, f"{report_prefix}.{timestamp}.report.jsonl")
    _hitlogfile = os.path.join(report_dir, f"{report_prefix}.{timestamp}.hitlog.jsonl")

    # 헤더 기록
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


def write_result(input_data: dict, scorer_result: dict) -> None:
    """
    단일 레코드의 scorer 결과를 JSONL로 저장.
    FAIL(취약점 감지)인 경우 hitlog에도 추가 기록.
    """
    entry = {
        "entry_type": "attempt",
        "seed_id": input_data.get("seed_id", ""),
        "prompt": input_data.get("prompt", ""),
        "response": input_data.get("response", ""),
        "goal": input_data.get("goal", ""),
        "scorer": "SelfAskTrueFalseScorer",
        "score": scorer_result.get("score"),
        "score_rationale": scorer_result.get("score_rationale", ""),
        "passed": scorer_result.get("passed", True),
        "result": "PASS" if scorer_result.get("passed", True) else "FAIL",
    }

    with open(_report_filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    if not scorer_result.get("passed", True):
        with open(_hitlogfile, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")