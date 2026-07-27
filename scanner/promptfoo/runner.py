import json
import subprocess
from pathlib import Path

from scanner.promptfoo.config_writer import write_echo_provider, write_promptfoo_config
from scanner.promptfoo.config import GOAL_RUBRIC_MAP, DEFAULT_RUBRIC, PROMPTFOO_JUDGE_MODEL

PROMPTFOO_DIR = Path(__file__).parent


def run_promptfoo(records: list) -> list:
    """
    records: [{"seed_id", "mutated_prompt", "model_output", "bucket_id"}, ...]
    반환: [{"seed_id", "passed", "reason"}, ...]
    """
    # bucket_id 기준으로 rubric 결정 (첫 번째 레코드 기준)
    goal = records[0].get("goal", "") if records else ""
    rubric = GOAL_RUBRIC_MAP.get(goal, DEFAULT_RUBRIC)
    print(f"[DEBUG] goal: {goal}, rubric: {rubric[:50]}")

    write_echo_provider()
    config_path = write_promptfoo_config(records, rubric, PROMPTFOO_JUDGE_MODEL)

    result_path = PROMPTFOO_DIR / "result.json"

    subprocess.run(
    ["npx.cmd", "promptfoo", "eval", "--config", config_path, "--output", str(result_path), "--no-progress-bar", "--no-cache"],
    check=True,
)

    return parse_result(result_path, records)


def parse_result(result_path: Path, records: list) -> list:
    with open(result_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []
    for i, result in enumerate(data.get("results", {}).get("results", [])):
        passed = result.get("success", False)
        reason = ""
        judge_response = result.get("response", {}).get("output", "")  # llama3 응답

        for assertion in result.get("gradingResult", {}).get("componentResults", []):
            if not assertion.get("pass", True):
                reason = assertion.get("reason", "")
                break

        seed_id = records[i]["seed_id"] if i < len(records) else ""
        results.append({
            "seed_id": seed_id,
            "passed": passed,
            "reason": reason,
            "judge_response": judge_response,
        })

    return results