import json
from pathlib import Path


def write_result(result: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False) + "\n")


def make_result_path(scanner_name: str, result_type: str, timestamp: str) -> Path:
    return (
        Path(__file__).parent.parent
        / "results"
        / f"{scanner_name}_{result_type}_{timestamp}.jsonl"
    )