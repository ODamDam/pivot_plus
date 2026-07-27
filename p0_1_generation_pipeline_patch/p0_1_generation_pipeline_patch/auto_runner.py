import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, Optional, Tuple
import uuid

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


WATCH_DIR = Path("mutation/data")
OUTPUT_DIR = Path("vulnerable_llm/data")
API_URL = "http://localhost:8000/generate"
PROGRESS_FILE = OUTPUT_DIR / "progress.json"
RESULT_FILE = OUTPUT_DIR / "vuln_results.jsonl"
FAILURE_FILE = OUTPUT_DIR / "generation_failures.jsonl"
AUTO_RUN_ID = f"run-{uuid.uuid4()}"


def _ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    _ensure_output_dir()
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_progress() -> Dict[str, int]:
    if not PROGRESS_FILE.exists():
        return {}
    try:
        with PROGRESS_FILE.open("r", encoding="utf-8") as file:
            raw = json.load(file)
        # Backward-compatible with the original {path: byte_offset} format.
        return {str(key): int(value) for key, value in raw.items()}
    except (json.JSONDecodeError, TypeError, ValueError):
        print("[경고] progress.json 파일이 손상되었습니다. 초기화합니다.")
        return {}


def save_progress(positions: Dict[str, int]) -> None:
    _ensure_output_dir()
    with PROGRESS_FILE.open("w", encoding="utf-8") as file:
        json.dump(positions, file, ensure_ascii=False, indent=2)


file_positions = load_progress()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stable_ids(file_path: Path, line_start: int, raw_line: str) -> Tuple[str, str]:
    identity = f"{file_path.resolve()}|{line_start}|{_sha256_text(raw_line)}"
    case_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"case|{identity}")
    generation_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"generation|{identity}")
    return f"case-{case_uuid}", f"gen-{generation_uuid}"


def _first_value(data: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None:
            return value
    return None


def _normalise_markers(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def build_request_payload(
    original_data: Dict[str, Any],
    prompt_text: str,
    *,
    case_id: str,
    generation_id: str,
) -> Dict[str, Any]:
    benchmark_category = _first_value(
        original_data,
        "benchmark_category",
        "bucket_id",
    )
    triggers = _normalise_markers(
        _first_value(original_data, "expected_markers", "triggers")
    )

    return {
        "prompt": prompt_text,
        "case_id": case_id,
        "generation_id": generation_id,
        "testcase_id": _first_value(original_data, "testcase_id", "input_id"),
        "seed_id": original_data.get("seed_id"),
        "mutation_id": _first_value(original_data, "mutation_id", "child_id"),
        "run_id": original_data.get("run_id") or AUTO_RUN_ID,
        "benchmark_category": benchmark_category,
        "delivery_channel": original_data.get("delivery_channel"),
        "attack_type": original_data.get("attack_type"),
        "primary_objective_id": original_data.get("primary_objective_id"),
        "objective_text": original_data.get("objective_text"),
        "triggers": triggers,
        "context": original_data.get("context"),
        # Preserve the full original mutation record without inventing missing
        # objective labels. Later pipeline stages can migrate it losslessly.
        "metadata": original_data,
        "params": original_data.get("generation_params") or {},
    }


def query_vulnerable_llm(
    payload: Dict[str, Any],
    max_retries: int = 3,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    headers = {"Content-Type": "application/json"}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                API_URL,
                json=payload,
                headers=headers,
                timeout=120,
            )
            response.raise_for_status()
            try:
                body = response.json()
            except ValueError as exc:
                return False, None, {
                    "type": "InvalidJSONResponse",
                    "message": str(exc),
                    "attempt": attempt,
                }
            return True, body, None
        except requests.exceptions.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            error = {
                "type": "HTTPError",
                "message": str(exc),
                "status_code": status_code,
                "attempt": attempt,
            }
            # Retrying a validation/policy 4xx response does not help.
            if status_code is not None and 400 <= status_code < 500:
                return False, None, error
            print(f" API 호출 에러 (시도 {attempt}/{max_retries}): {exc}")
        except requests.exceptions.RequestException as exc:
            error = {
                "type": type(exc).__name__,
                "message": str(exc),
                "attempt": attempt,
            }
            print(f" API 호출 에러 (시도 {attempt}/{max_retries}): {exc}")

        if attempt < max_retries:
            time.sleep(2)

    return False, None, error


def build_generated_case(
    original_data: Dict[str, Any],
    prompt_text: str,
    request_payload: Dict[str, Any],
    server_body: Dict[str, Any],
    *,
    source_file: Path,
    line_start: int,
) -> Dict[str, Any]:
    response_text = str(server_body.get("response") or "")
    meta = server_body.get("meta") or {}
    benchmark_category = request_payload.get("benchmark_category")
    triggers = request_payload.get("triggers") or []

    record = {
        "schema_version": "generated_case.v0.2",
        "case_id": server_body.get("case_id") or request_payload["case_id"],
        "generation_id": server_body.get("generation_id") or request_payload["generation_id"],
        "request_id": server_body.get("request_id"),
        "testcase_id": request_payload.get("testcase_id"),
        "run_id": request_payload.get("run_id"),
        "lineage": {
            "seed_id": request_payload.get("seed_id"),
            "mutation_id": request_payload.get("mutation_id"),
            "operator_id": _first_value(original_data, "operator_id", "operator"),
            "parent_id": _first_value(original_data, "parent_id", "parent_case_id"),
            "source_schema_version": original_data.get("schema_version"),
            "trace": original_data.get("trace") or [],
        },
        "benchmark_category": benchmark_category,
        "attack": {
            "delivery_channel": request_payload.get("delivery_channel"),
            "attack_type": request_payload.get("attack_type"),
            "primary_objective_id": request_payload.get("primary_objective_id"),
            "objective_text": request_payload.get("objective_text"),
            "expected_markers": triggers,
            "metadata_status": (
                "complete"
                if request_payload.get("primary_objective_id")
                and request_payload.get("objective_text")
                else "objective_metadata_missing"
            ),
        },
        "context": {
            "raw": request_payload.get("context"),
            "system_prompt": original_data.get("system_prompt"),
            "developer_prompt": original_data.get("developer_prompt"),
            "protected_assets": original_data.get("protected_assets") or [],
            "expected_output_contract": original_data.get("expected_output_contract"),
        },
        "prompt": prompt_text,
        "response": response_text,
        "target_generation": meta,
        "execution_status": server_body.get("execution_status") or "completed",
        "error": None,
        "source": {
            "input_file": str(source_file),
            "byte_offset": line_start,
        },
        # Temporary aliases keep the current scanner_input v0.1 usable until
        # the next patch replaces it with EvaluationCase.
        "seed_id": request_payload.get("seed_id"),
        "mutation_id": request_payload.get("mutation_id"),
        "mutated_prompt": prompt_text,
        "model_output": response_text,
        "bucket_id": benchmark_category,
        "triggers": triggers,
    }
    return record


def _record_local_failure(
    *,
    file_path: Path,
    line_start: int,
    case_id: Optional[str],
    generation_id: Optional[str],
    original_data: Optional[Dict[str, Any]],
    error: Dict[str, Any],
) -> None:
    _append_jsonl(
        FAILURE_FILE,
        {
            "schema_version": "generation_failure.v0.2",
            "case_id": case_id,
            "generation_id": generation_id,
            "source": {
                "input_file": str(file_path),
                "byte_offset": line_start,
            },
            "seed_id": (original_data or {}).get("seed_id"),
            "testcase_id": (original_data or {}).get("testcase_id"),
            "execution_status": "failed",
            "error": error,
        },
    )


def process_new_lines(file_path: str) -> None:
    global file_positions

    path = Path(file_path)
    progress_key = os.path.normpath(str(path))
    last_position = int(file_positions.get(progress_key, 0))
    processed_count = 0

    try:
        with path.open("r", encoding="utf-8") as file:
            file.seek(last_position)

            while True:
                line_start = file.tell()
                raw_line = file.readline()
                if raw_line == "":
                    break
                line_end = file.tell()

                # A writer may still be appending the last JSONL record. Wait
                # for the next filesystem event rather than discarding it.
                is_complete_line = raw_line.endswith("\n")
                stripped = raw_line.strip()
                if not stripped:
                    file_positions[progress_key] = line_end
                    save_progress(file_positions)
                    continue

                try:
                    original_data = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    if not is_complete_line:
                        break
                    _record_local_failure(
                        file_path=path,
                        line_start=line_start,
                        case_id=None,
                        generation_id=None,
                        original_data=None,
                        error={"type": "JSONDecodeError", "message": str(exc)},
                    )
                    print(f"[경고] 올바르지 않은 JSONL 형식: {stripped[:100]}")
                    file_positions[progress_key] = line_end
                    save_progress(file_positions)
                    continue

                prompt_text = _first_value(original_data, "child_text", "prompt", "mutated_prompt")
                if not isinstance(prompt_text, str) or not prompt_text.strip():
                    _record_local_failure(
                        file_path=path,
                        line_start=line_start,
                        case_id=None,
                        generation_id=None,
                        original_data=original_data,
                        error={"type": "MissingPrompt", "message": "No prompt field found."},
                    )
                    file_positions[progress_key] = line_end
                    save_progress(file_positions)
                    continue

                prompt_text = prompt_text.strip()
                case_id, generation_id = _stable_ids(path, line_start, stripped)
                payload = build_request_payload(
                    original_data,
                    prompt_text,
                    case_id=case_id,
                    generation_id=generation_id,
                )

                success, server_body, error = query_vulnerable_llm(payload)
                if not success or server_body is None:
                    _record_local_failure(
                        file_path=path,
                        line_start=line_start,
                        case_id=case_id,
                        generation_id=generation_id,
                        original_data=original_data,
                        error=error or {"type": "UnknownError", "message": "No server response."},
                    )
                    print(f"  -> [실패] 서버 응답 없음: {prompt_text[:40]}...")
                    # Do not advance past the failed line. It will be retried on
                    # the next modification event or process restart.
                    break

                generated_case = build_generated_case(
                    original_data,
                    prompt_text,
                    payload,
                    server_body,
                    source_file=path,
                    line_start=line_start,
                )
                _append_jsonl(RESULT_FILE, generated_case)

                file_positions[progress_key] = line_end
                save_progress(file_positions)
                processed_count += 1
                print(f"  -> 생성 및 canonical 로깅 완료: {prompt_text[:40]}...")
                time.sleep(0.5)

    except FileNotFoundError:
        print(f"파일을 찾을 수 없습니다: {path}")
    except Exception as exc:
        print(f"파일 처리 에러: {type(exc).__name__}: {exc}")

    if processed_count:
        print(f"[완료] '{path.name}'에서 {processed_count}개 case를 처리했습니다.")


class MutationFileHandler(FileSystemEventHandler):
    @staticmethod
    def _eligible(path: str) -> bool:
        return path.endswith(".jsonl") and Path(path).name != RESULT_FILE.name

    def on_created(self, event) -> None:
        if event.is_directory:
            return
        file_path = os.path.normpath(event.src_path)
        if self._eligible(file_path):
            print(f"\n[새 파일 감지 (생성)] '{file_path}'")
            process_new_lines(file_path)

    def on_modified(self, event) -> None:
        if event.is_directory:
            return
        file_path = os.path.normpath(event.src_path)
        if self._eligible(file_path):
            process_new_lines(file_path)

    def on_moved(self, event) -> None:
        if event.is_directory:
            return
        file_path = os.path.normpath(event.dest_path)
        if self._eligible(file_path):
            print(f"\n[새 파일 감지 (이동/복사)] '{file_path}'")
            process_new_lines(file_path)


if __name__ == "__main__":
    WATCH_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_output_dir()

    print(f"'{WATCH_DIR}' 폴더 내의 기존 파일들을 초기 스캔합니다...")
    for candidate in sorted(WATCH_DIR.iterdir()):
        if candidate.suffix == ".jsonl" and candidate.name != RESULT_FILE.name:
            process_new_lines(str(candidate))
    print("기존 파일 확인 완료.\n")

    event_handler = MutationFileHandler()
    observer = Observer()
    observer.schedule(event_handler, str(WATCH_DIR), recursive=False)
    observer.start()
    print(f"'{WATCH_DIR}' 폴더 실시간 감시 대기 중... (서버가 켜져 있는지 확인하세요!)")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n감시를 종료합니다.")
        observer.stop()

    observer.join()
