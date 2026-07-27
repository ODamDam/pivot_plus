from typing import Generator
from datetime import datetime

from scanner_input.core.data_loader import iter_vuln_records
from scanner_input.core.result_writer import make_result_path
from scanner_input.config import SUPPORTED_SCANNERS


def select_scanner() -> str:
    print(f"사용 가능한 스캐너: {', '.join(SUPPORTED_SCANNERS)}")
    scanner = input("스캐너를 선택하세요: ").strip().lower()
    if scanner not in SUPPORTED_SCANNERS:
        raise ValueError(f"지원하지 않는 스캐너입니다: {scanner}")
    return scanner


def get_builder(scanner: str):
    builders = {
        "garak": lambda: __import__(
            "scanner_input.integrations.garak.input_builder", fromlist=["build_attempt"]
        ).build_attempt,
        "pyrit": lambda: __import__(
            "scanner_input.integrations.pyrit.input_builder", fromlist=["build_input"]
        ).build_input,
        "promptfoo": lambda: __import__(
            "scanner_input.integrations.pyrit.input_builder", fromlist=["build_input"]
        ).build_input,
    }
    if scanner not in builders:
        raise ValueError(f"지원하지 않는 스캐너입니다: {scanner}")
    return builders[scanner]()


def run() -> tuple[str, Generator]:
    scanner = select_scanner()
    build = get_builder(scanner)

    def generate():
        for record in iter_vuln_records():
            yield build(record)

    return scanner, generate()


if __name__ == "__main__":
    scanner, attempts = run()
    for attempt in attempts:
        print(f"[{attempt.notes['seed_id']}] Attempt 생성 완료 / 스캐너: {scanner}")
        