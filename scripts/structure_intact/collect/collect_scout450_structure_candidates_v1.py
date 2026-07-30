from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SEED_250_PATH = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "batches"
    / "seed_curation_250_v1.csv"
)

EXISTING_COMPLETED_PATHS = [
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_audit_v1"
    / "structure_audit_json_v1_completed.csv",
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_audit_v1"
    / "structure_audit_code_block_v1_completed.csv",
    PROJECT_ROOT
    / "data"
    / "review"
    / "structure_intact_audit_v1"
    / "structure_audit_markdown_v1_completed.csv",
]

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "review"
    / "external_structure_candidates"
    / "src10_scout450_v1"
)

RAW_OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "src10_scout450"
    / "scout450_test_v1.jsonl"
)

SUMMARY_PATH = (
    PROJECT_ROOT
    / "reports"
    / "src10_scout450_structure_candidate_summary_v1.json"
)

SOURCE_ID = "SRC-10_SCOUT_450"
DATASET_NAME = "sullivanUCSD/SCOUT-450"


def norm(value: Any) -> str:
    return str(value or "").strip()


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8", errors="replace")
    ).hexdigest()


def load_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def load_existing_hashes() -> set[str]:
    hashes: set[str] = set()

    for row in load_csv(SEED_250_PATH):
        text = norm(
            row.get("scanner_input")
            or row.get("mutation_target_text")
        )

        text_hash = norm(row.get("text_sha256"))

        if not text_hash and text:
            text_hash = sha256_text(text)

        if text_hash:
            hashes.add(text_hash)

    for path in EXISTING_COMPLETED_PATHS:
        for row in load_csv(path):
            if norm(row.get("review_decision")).lower() != "keep":
                continue

            text = norm(row.get("scanner_input"))
            text_hash = norm(row.get("text_sha256"))

            if not text_hash and text:
                text_hash = sha256_text(text)

            if text_hash:
                hashes.add(text_hash)

    return hashes


def load_scout_rows() -> list[dict[str, Any]]:
    """
    Hugging Face datasets-server API를 이용해 SCOUT-450 test split을
    페이지 단위로 내려받는다.

    datasets.load_dataset()이 Hub metadata를 찾지 못하는 환경에서도
    동작하도록 한 fallback이 아니라 기본 수집 경로로 사용한다.
    """
    from urllib.parse import urlencode
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError

    endpoint = "https://datasets-server.huggingface.co/rows"

    dataset_name = DATASET_NAME
    config_name = "default"
    split_name = "test"
    page_size = 100

    rows: list[dict[str, Any]] = []
    offset = 0
    expected_total: int | None = None

    while True:
        query = urlencode(
            {
                "dataset": dataset_name,
                "config": config_name,
                "split": split_name,
                "offset": offset,
                "length": page_size,
            }
        )

        url = f"{endpoint}?{query}"

        request = Request(
            url,
            headers={
                "User-Agent": (
                    "llm-prompt-injection-diagnostic-benchmark/1.0"
                ),
                "Accept": "application/json",
            },
        )

        try:
            with urlopen(request, timeout=60) as response:
                payload = json.loads(
                    response.read().decode("utf-8")
                )
        except HTTPError as exc:
            error_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            raise RuntimeError(
                "SCOUT-450 Dataset Server 요청 실패\n"
                f"HTTP status: {exc.code}\n"
                f"URL: {url}\n"
                f"Response: {error_body[:1000]}"
            ) from exc

        except URLError as exc:
            raise RuntimeError(
                "SCOUT-450 Dataset Server에 연결하지 못했습니다.\n"
                f"URL: {url}\n"
                f"Reason: {exc.reason}"
            ) from exc

        page_rows = payload.get("rows", [])

        if expected_total is None:
            features = payload.get("features", [])
            expected_total = payload.get(
                "num_rows_total",
            )

            print(
                "[info] SCOUT-450 schema fields:",
                len(features),
            )
            print(
                "[info] expected rows:",
                expected_total,
            )

        if not page_rows:
            break

        for item in page_rows:
            row = item.get("row")

            if isinstance(row, dict):
                rows.append(row)

        offset += len(page_rows)

        print(
            f"[info] downloaded {len(rows)} rows"
        )

        if expected_total is not None:
            if len(rows) >= expected_total:
                break

        if len(page_rows) < page_size:
            break

    if not rows:
        raise RuntimeError(
            "SCOUT-450에서 행을 가져오지 못했습니다."
        )

    if expected_total is not None:
        if len(rows) != expected_total:
            raise RuntimeError(
                "SCOUT-450 행 수가 예상과 다릅니다.\n"
                f"expected={expected_total}, actual={len(rows)}"
            )

    return rows

def save_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        for row in rows:
            file.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )


def is_attack(row: dict[str, Any]) -> bool:
    value = row.get("is_attack")

    if isinstance(value, bool):
        return value

    return norm(value).lower() in {
        "true",
        "1",
        "yes",
    }


def is_substantive_markdown(
    text: str,
) -> tuple[bool, str]:
    features = {
        "heading": bool(
            re.search(
                r"(?m)^\s{0,3}#{1,6}\s+\S",
                text,
            )
        ),
        "list": bool(
            re.search(
                r"(?m)^\s*(?:[-*+]|\d+\.)\s+\S",
                text,
            )
        ),
        "blockquote": bool(
            re.search(
                r"(?m)^\s*>\s+\S",
                text,
            )
        ),
        "fence": bool(
            re.search(
                r"```[\s\S]+?```",
                text,
            )
        ),
        "table": bool(
            re.search(
                r"(?m)^\s*\|.+\|\s*$",
                text,
            )
        ),
        "link": bool(
            re.search(
                r"\[[^\]]+\]\([^)]+\)",
                text,
            )
        ),
    }

    active = [
        name
        for name, matched in features.items()
        if matched
    ]

    if len(active) >= 2:
        return (
            True,
            "markdown_features:"
            + ",".join(active),
        )

    if (
        "heading" in active
        and len(text.splitlines()) >= 4
    ):
        return True, "markdown_heading_document"

    return False, "insufficient_markdown_structure"


def is_code_structure(
    text: str,
) -> tuple[bool, str]:
    fenced = re.search(
        r"```(?:python|py|javascript|js|typescript|ts|"
        r"bash|sh|shell|powershell|ps1|java|c|cpp|"
        r"csharp|cs|go|rust|ruby|php|sql|html|xml)?"
        r"\s*\n[\s\S]+?\n```",
        text,
        flags=re.IGNORECASE,
    )

    if fenced:
        return True, "fenced_code_block"

    code_patterns = [
        r"(?m)^\s*(def|class|function)\s+\w+",
        r"(?m)^\s*(import|from)\s+[\w.]+",
        r"(?m)^\s*(const|let|var)\s+\w+\s*=",
        r"(?m)^\s*#include\s*[<\"]",
        r"(?m)^\s*(if|for|while)\s*\(.+\)",
        r"(?m)^\s*#!/(?:usr/)?bin/",
        r"(?m)^\s*(SELECT|INSERT|UPDATE|DELETE)\s+",
        r"(?m)^\s*(#|//|/\*|\*)\s*"
        r"(ignore|disregard|override|reveal|execute)",
    ]

    hits = sum(
        bool(re.search(pattern, text, re.IGNORECASE))
        for pattern in code_patterns
    )

    if hits >= 2:
        return True, "source_code_multi_pattern"

    return False, "insufficient_code_structure"


def parse_json_structure(
    text: str,
) -> tuple[bool, str]:
    stripped = text.strip()

    try:
        parsed = json.loads(stripped)

        if isinstance(parsed, dict):
            return True, "strict_json_object"

        if isinstance(parsed, list):
            return True, "strict_json_array"

    except json.JSONDecodeError:
        pass

    # Tool output 앞뒤에 설명이 붙은 경우 JSON 블록을 추출합니다.
    decoder = json.JSONDecoder()

    for match in re.finditer(r"[\{\[]", stripped):
        try:
            parsed, end_index = decoder.raw_decode(
                stripped[match.start():]
            )
        except json.JSONDecodeError:
            continue

        if isinstance(parsed, dict):
            return True, "embedded_json_object"

        if isinstance(parsed, list):
            return True, "embedded_json_array"

    return False, "json_parse_failed"


def generation_origin(
    generation_method: str,
) -> tuple[str, str]:
    method = generation_method.lower()

    if any(
        token in method
        for token in {
            "synthetic",
            "generated",
            "template",
            "llm",
        }
    ):
        return (
            "synthetic_source_original",
            "open_source_synthetic",
        )

    return (
        "natural_original",
        "open_source_traceable",
    )


def classify_candidate(
    row: dict[str, Any],
) -> tuple[str, str] | None:
    carrier = norm(
        row.get("carrier_type")
    ).lower()

    text = norm(row.get("eval_content"))

    if not text:
        return None

    if carrier == "markdown":
        valid, reason = is_substantive_markdown(text)

        if valid:
            return "markdown", reason

        return None

    if carrier == "code":
        valid, reason = is_code_structure(text)

        if valid:
            return "code_block", reason

        return None

    if carrier in {
        "tool_output",
        "tool_description",
        "browser_trace",
        "agent_memory",
    }:
        valid, reason = parse_json_structure(text)

        if valid:
            return "json", reason

    # carrier label이 달라도 실제 전체 payload가 JSON이면 후보로 둡니다.
    valid_json, json_reason = parse_json_structure(text)

    if valid_json:
        return "json", json_reason

    return None


def main() -> None:
    existing_hashes = load_existing_hashes()
    scout_rows = load_scout_rows()

    save_jsonl(
        RAW_OUTPUT_PATH,
        scout_rows,
    )

    candidates: list[dict[str, Any]] = []
    seen_hashes: set[str] = set()

    exclusion_counts: Counter[str] = Counter()
    format_counts: Counter[str] = Counter()
    carrier_counts: Counter[str] = Counter()
    generation_counts: Counter[str] = Counter()

    for row in scout_rows:
        if not is_attack(row):
            exclusion_counts["benign"] += 1
            continue

        classified = classify_candidate(row)

        if classified is None:
            exclusion_counts[
                "not_target_structure"
            ] += 1
            continue

        structure_format, detection_reason = classified
        text = norm(row.get("eval_content"))
        text_hash = sha256_text(text)

        if text_hash in existing_hashes:
            exclusion_counts[
                "overlap_existing_dataset"
            ] += 1
            continue

        if text_hash in seen_hashes:
            exclusion_counts["duplicate"] += 1
            continue

        seen_hashes.add(text_hash)

        method = norm(
            row.get("generation_method")
        )
        structure_origin, provenance_type = (
            generation_origin(method)
        )

        candidate = {
            "candidate_id": (
                f"SRC10-STRUCT-{len(candidates) + 1:04d}"
            ),
            "source_id": SOURCE_ID,
            "source_record_id": norm(row.get("id")),
            "source_dataset": norm(
                row.get("source_dataset")
            ),
            "source_license": "MIT",
            "text_sha256": text_hash,
            "scanner_input": text,
            "clean_content": norm(
                row.get("clean_content")
            ),
            "goal_text": norm(
                row.get("goal_text")
            ),
            "policy_text": norm(
                row.get("policy_text")
            ),
            "carrier_type": norm(
                row.get("carrier_type")
            ),
            "category": norm(row.get("category")),
            "attack_type_original": norm(
                row.get("attack_type")
            ),
            "hiding_strategy": norm(
                row.get("hiding_strategy")
            ),
            "difficulty": norm(
                row.get("difficulty")
            ),
            "candidate_structure_format": (
                structure_format
            ),
            "structure_detection_reason": (
                detection_reason
            ),
            "generation_method": method,
            "structure_origin": structure_origin,
            "provenance_type": provenance_type,
            "provenance_status": "traceable",
            "injection_span_start": row.get(
                "injection_span_start"
            ),
            "injection_span_end": row.get(
                "injection_span_end"
            ),
            "text_length": len(text),
            "ground_truth_decision": "malicious",
            "structure_valid": "",
            "attack_semantics_valid": "",
            "provenance_valid": "",
            "review_decision": "",
            "review_note": "",
        }

        candidates.append(candidate)
        format_counts[structure_format] += 1
        carrier_counts[
            norm(row.get("carrier_type")) or "unknown"
        ] += 1
        generation_counts[
            method or "unknown"
        ] += 1

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )
    SUMMARY_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = list(candidates[0].keys())

    combined_path = (
        OUTPUT_DIR
        / "src10_scout450_structure_candidates_all_v1.csv"
    )

    with combined_path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(candidates)

    for format_name in [
        "json",
        "code_block",
        "markdown",
    ]:
        rows_for_format = [
            row
            for row in candidates
            if row["candidate_structure_format"]
            == format_name
        ]

        path = (
            OUTPUT_DIR
            / f"src10_scout450_{format_name}_candidates_v1.csv"
        )

        with path.open(
            "w",
            encoding="utf-8-sig",
            newline="",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
            )
            writer.writeheader()
            writer.writerows(rows_for_format)

    summary = {
        "source_id": SOURCE_ID,
        "dataset_name": DATASET_NAME,
        "dataset_rows": len(scout_rows),
        "attack_rows": sum(
            1 for row in scout_rows
            if is_attack(row)
        ),
        "candidate_count": len(candidates),
        "candidate_counts_by_format": dict(
            sorted(format_counts.items())
        ),
        "carrier_counts": dict(
            carrier_counts.most_common()
        ),
        "generation_method_counts": dict(
            generation_counts.most_common()
        ),
        "exclusion_counts": dict(
            exclusion_counts.most_common()
        ),
        "existing_hash_count": len(existing_hashes),
        "raw_output": str(
            RAW_OUTPUT_PATH.relative_to(
                PROJECT_ROOT
            )
        ),
        "candidate_output": str(
            combined_path.relative_to(
                PROJECT_ROOT
            )
        ),
    }

    SUMMARY_PATH.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 72)
    print("[done] SCOUT-450 structure candidate collection")
    print(f"dataset rows : {len(scout_rows)}")
    print(
        "attack rows  : "
        f"{summary['attack_rows']}"
    )
    print(f"candidates   : {len(candidates)}")

    for format_name in [
        "json",
        "code_block",
        "markdown",
    ]:
        print(
            f"  {format_name:<12}: "
            f"{format_counts[format_name]}"
        )

    print(f"raw output   : {RAW_OUTPUT_PATH}")
    print(f"candidates   : {combined_path}")
    print(f"summary      : {SUMMARY_PATH}")
    print("=" * 72)


if __name__ == "__main__":
    main()