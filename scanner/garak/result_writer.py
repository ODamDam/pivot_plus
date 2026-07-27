import json
from garak import _config


def write_attempt_result(attempt, detector_results: dict) -> None:
    eval_threshold = _config.run.eval_threshold

    for detector_path, result in detector_results.items():
        if result is None:
            continue

        entry = {
            "entry_type": "attempt",
            "run_id": _config.transient.run_id,
            "seed_id": attempt.notes.get("seed_id", ""),
            "prompt": attempt.prompt,
            "outputs": attempt.outputs,
            "goal": attempt.goal,
            "detector": detector_path,
            "scores": result["scores"],
            "passed": result["passed"],
            "result": "PASS" if result["passed"] else "FAIL",
        }

        with open(_config.transient.report_filename, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        if not result["passed"]:
            with open(_config.transient.hitlogfile, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")