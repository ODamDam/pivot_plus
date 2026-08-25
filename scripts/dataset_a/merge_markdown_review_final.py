"""Merge the two reviewed Markdown representation decisions into a final artifact."""

from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl, write_jsonl


ROOT = _PROJECT_ROOT
RESOLUTION_SOURCE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_markdown_resolution_105_v1.jsonl")
QUEUE_SOURCE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_markdown_human_review_queue_v1.jsonl")
OUTPUT = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_markdown_resolution_105_v1_reviewed_final.jsonl")
REVIEWER = "ChatGPT-human-review-2026-08-20"


DECISIONS = {
    "DA-RAW-000866": {
        "representation_decision": "MARKDOWN",
        "observed_format": "markdown",
        "rationale": "Whole record is organized as a Markdown-style instructional document using a heading, repeated numbered procedures, bullet lists, and multiple consistently structured example sections.",
        "resolution_status": "MARKDOWN_HUMAN_CONFIRMED",
        "proposed_corrected_format": "markdown",
        "proposed_corrected_scenario": "SCN-REMAIN-DOC-001",
    },
    "DA-RAW-000970": {
        "representation_decision": "CODE",
        "observed_format": "code",
        "rationale": "The whole record is a Python-like source-code artifact with imports, assignments, function definitions, control flow, and code comments. Hash-prefixed lines function as source-code comments rather than Markdown headings.",
        "resolution_status": "CODE_HUMAN_CONFIRMED",
        "proposed_corrected_format": "code",
        "proposed_corrected_scenario": "SCN-REMAIN-CODE-001",
    },
}


def merge_markdown_review(
    root: Path = ROOT, reviewed_at: str | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    source_records = read_jsonl(root / RESOLUTION_SOURCE)
    queue = read_jsonl(root / QUEUE_SOURCE)
    records = copy.deepcopy(source_records)
    if reviewed_at is None:
        reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    assert len(source_records) == 105
    assert [row["candidate_id"] for row in queue] == list(DECISIONS)
    assert all(row["resolution_status"] == "HUMAN_REVIEW_REQUIRED" for row in queue)
    assert all(all(value is None for value in row["review"].values()) for row in queue)

    by_id = {row["candidate_id"]: row for row in records}
    for candidate_id, decision in DECISIONS.items():
        record = by_id[candidate_id]
        assert record["resolution_status"] == "HUMAN_REVIEW_REQUIRED"
        record["resolution_status"] = decision["resolution_status"]
        record["proposed_corrected_format"] = decision["proposed_corrected_format"]
        record["proposed_corrected_scenario"] = decision["proposed_corrected_scenario"]
        record["human_review"] = {
            "representation_decision": decision["representation_decision"],
            "observed_format": decision["observed_format"],
            "rationale": decision["rationale"],
            "reviewer": REVIEWER,
            "reviewed_at": reviewed_at,
            "source_queue": QUEUE_SOURCE.as_posix(),
        }

    return records, source_records, queue


def main() -> None:
    output = ROOT / OUTPUT
    if output.exists():
        raise FileExistsError("final Markdown resolution already exists; refusing overwrite")
    reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    records, _, _ = merge_markdown_review(ROOT, reviewed_at)
    write_jsonl(output, records)
    print(f"reviewed_at={reviewed_at}")
    print(f"output={OUTPUT.as_posix()} count={len(records)}")


if __name__ == "__main__":
    main()
