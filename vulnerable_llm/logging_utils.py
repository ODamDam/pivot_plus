import json
import os
import time
from typing import Any, Dict


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def append_jsonl(log_dir: str, filename: str, record: Dict[str, Any]) -> str:
    ensure_dir(log_dir)
    path = os.path.join(log_dir, filename)

    record.setdefault("ts", int(time.time()))

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return path
