"""Merge the supplied Dataset A structure-only Batch 1 human decisions.

The source queue and source resolution artifact are read-only. New reviewed
versions are written only when the destination paths do not already exist.
"""

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
QUEUE_SOURCE = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_human_review_queue_v2.jsonl"
)
RESOLUTION_SOURCE = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_resolution_299_v2.jsonl"
)
QUEUE_OUTPUT = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_human_review_queue_v2_reviewed_batch01.jsonl"
)
RESOLUTION_OUTPUT = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_resolution_299_v2_reviewed_batch01.jsonl"
)
REVIEWER = "ChatGPT-human-review-2026-08-20"


BATCH01_DECISIONS: dict[str, dict[str, str]] = {
    "DA-RAW-000499": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Natural-language prompt with incidental colon; no whole-record structured representation.",
    },
    "DA-RAW-000772": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Natural-language classification task containing lists and an output-format example; whole record is not structured data.",
    },
    "DA-RAW-000801": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Premise/Hypothesis labels are prose task formatting rather than YAML structure.",
    },
    "DA-RAW-000806": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Prose document with dialogue examples and numbered instructions; no structured data representation.",
    },
    "DA-RAW-000807": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Email-style prose with subject/header labels; not YAML structured data.",
    },
    "DA-RAW-000811": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Natural-language question and multiple-choice options.",
    },
    "DA-RAW-000862": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Student/Teacher dialogue formatting, not structured data.",
    },
    "DA-RAW-000880": {
        "structure_decision": "STRUCT",
        "observed_format": "json",
        "rationale": "Whole record is clearly intended as a nested JSON object representation. Although syntactically incomplete/malformed, observable JSON hierarchy is unambiguous.",
    },
    "DA-RAW-000901": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Role description followed by chat-history prose.",
    },
    "DA-RAW-000906": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Long moderator/expert dialogue and natural-language question; no structured representation.",
    },
    "DA-RAW-000912": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Natural-language reasoning text with an answer label; not structured data.",
    },
    "DA-RAW-000920": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Rewrite instruction followed by article prose.",
    },
    "DA-RAW-000923": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Student/Teacher and Premise/Hypothesis labels are prose formatting.",
    },
    "DA-RAW-000954": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Contains a JSON block but is followed by separate natural-language instructions; whole record is mixed prose rather than a JSON document.",
    },
    "DA-RAW-000960": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Classification instruction with class list and output-format example; whole record is prose.",
    },
    "DA-RAW-000977": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Heading-style labels such as MAIN DIRECTIVE and SUMMARY are natural-language prompt structure, not YAML data.",
    },
    "DA-RAW-000989": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Natural-language role prompt containing an advertisement template example; no whole-record structured representation.",
    },
    "DA-RAW-000995": {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": "Initial [] is only an isolated JSON fragment; the remainder of the record is prose.",
    },
}


def merge_batch01(
    root: Path = ROOT,
    reviewed_at: str | None = None,
    *,
    apply: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    queue = copy.deepcopy(read_jsonl(root / QUEUE_SOURCE))
    resolutions = copy.deepcopy(read_jsonl(root / RESOLUTION_SOURCE))
    if not apply:
        return queue, resolutions

    if reviewed_at is None:
        reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    queue_ids = [record["candidate_id"] for record in queue]
    assert queue_ids[:18] == list(BATCH01_DECISIONS)
    assert len(queue) == 69 and len(set(queue_ids)) == 69
    assert all(all(value is None for value in row["review"].values()) for row in queue)

    for record in queue:
        decision = BATCH01_DECISIONS.get(record["candidate_id"])
        if decision is None:
            continue
        record["review"] = {
            **decision,
            "reviewer": REVIEWER,
            "reviewed_at": reviewed_at,
        }

    resolution_by_id = {record["candidate_id"]: record for record in resolutions}
    assert len(resolutions) == 299 and len(resolution_by_id) == 299
    for candidate_id, decision in BATCH01_DECISIONS.items():
        record = resolution_by_id[candidate_id]
        assert record["resolution_status"] == "HUMAN_REVIEW_REQUIRED"
        is_struct = decision["structure_decision"] == "STRUCT"
        record["resolution_status"] = (
            "STRUCT_HUMAN_CONFIRMED" if is_struct else "TEXT_HUMAN_CONFIRMED"
        )
        record["proposed_corrected_format"] = decision["observed_format"]
        record["proposed_corrected_scenario"] = (
            "SCN-REMAIN-STRUCT-001" if is_struct else "SCN-REMAIN-TEXT-001"
        )
        record["human_resolution_issue"] = None
        record["batch_human_review"] = {
            **decision,
            "reviewer": REVIEWER,
            "reviewed_at": reviewed_at,
            "source_queue": QUEUE_OUTPUT.as_posix(),
        }

    return queue, resolutions


def main() -> None:
    queue_output = ROOT / QUEUE_OUTPUT
    resolution_output = ROOT / RESOLUTION_OUTPUT
    if queue_output.exists() or resolution_output.exists():
        raise FileExistsError("reviewed Batch 1 output already exists; refusing overwrite")
    reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    queue, resolutions = merge_batch01(ROOT, reviewed_at)
    write_jsonl(queue_output, queue)
    write_jsonl(resolution_output, resolutions)
    print(f"reviewed_at={reviewed_at}")
    print(f"reviewed_queue={QUEUE_OUTPUT.as_posix()}")
    print(f"reviewed_resolution={RESOLUTION_OUTPUT.as_posix()}")


if __name__ == "__main__":
    main()
