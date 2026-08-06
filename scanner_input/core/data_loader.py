import json
from pathlib import Path
from typing import Generator

from scanner_input.core.data_models import VulnRecord
from scanner_input.config import VULN_RESULT_PATH


def iter_vuln_records(path: Path = VULN_RESULT_PATH) -> Generator[VulnRecord, None, None]:
    if not path.exists():
        raise FileNotFoundError(f"vuln_results.jsonl 파일을 찾을 수 없습니다: {path}")

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            yield VulnRecord( # 수정 필요
                seed_id=raw["seed_id"],
                mutated_prompt=raw["mutated_prompt"],
                model_output=raw["model_output"],
                bucket_id=raw["bucket_id"],
                triggers=raw.get("triggers"),  
            )