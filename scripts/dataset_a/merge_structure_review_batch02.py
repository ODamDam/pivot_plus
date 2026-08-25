"""Merge supplied structure-only Batch 2 decisions into new reviewed artifacts."""

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
from scripts.dataset_a.merge_structure_review_batch01 import REVIEWER


ROOT = _PROJECT_ROOT
QUEUE_SOURCE = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_human_review_queue_v2_reviewed_batch01.jsonl"
)
RESOLUTION_SOURCE = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_resolution_299_v2_reviewed_batch01.jsonl"
)
QUEUE_OUTPUT = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_human_review_queue_v2_reviewed_batch02.jsonl"
)
RESOLUTION_OUTPUT = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_structure_resolution_299_v2_reviewed_batch02.jsonl"
)


def _text(rationale: str) -> dict[str, str]:
    return {
        "structure_decision": "TEXT",
        "observed_format": "plain_text",
        "rationale": rationale,
    }


BATCH02_DECISIONS = {
    "DA-RAW-000997": _text("Character-role prompt containing many profile-style labels, but natural-language instructions and prose are mixed throughout; not a whole-record YAML or JSON representation."),
    "DA-RAW-000998": _text("Character-role prompt with profile-style labels embedded in mixed prose; not a whole-record structured data representation."),
    "DA-RAW-001012": _text("Natural-language persona instruction with dialogue examples."),
    "DA-RAW-001014": _text("Natural-language role instruction with an incidental Prompt label."),
    "DA-RAW-001016": _text("Natural-language instruction containing an INFO block and Markdown guidance; not JSON/YAML structured data."),
    "DA-RAW-001018": _text("Persona description, dialogue examples, and policy prose; not a structured serialization."),
    "DA-RAW-001037": _text("Natural-language role prompt containing dialogue and policy lists; not whole-record structured data."),
    "DA-RAW-001040": _text("Name/Input/Output/Condition labels form a prompt template, but values and layout are natural-language prose rather than consistent YAML/config representation."),
    "DA-RAW-001044": _text("Natural-language DAN role prompt."),
    "DA-RAW-001046": _text("Translator-role prose containing a response-format example; whole record is not structured data."),
    "DA-RAW-001049": _text("Uses Task/Objectives/Rules/Roles/Strategy headings, but their contents are prose and do not form consistent YAML mapping or sequence syntax."),
    "DA-RAW-001052": _text("Persona instruction with response-format labels; not structured data."),
    "DA-RAW-001069": _text("Natural-language fiction-writing instruction with incidental empty Summary and Direction labels."),
    "DA-RAW-001077": _text("Natural-language character backstory and numbered rule list; not JSON/YAML representation."),
    "DA-RAW-001078": _text("Natural-language persona instruction with dialogue examples and policy prose."),
    "DA-RAW-001083": _text("Contains a custom ENVVAR/assert pseudo-config block, but it is neither JSON nor YAML and the whole record is a natural-language prompt."),
    "DA-RAW-001094": _text("Two YAML-like variable lines are embedded inside a larger natural-language instruction; they are only a structured fragment."),
    "DA-RAW-001095": _text("Few-shot natural-language prompt using Question/Thought/Response labels; not structured data."),
}


def merge_batch02(
    root: Path = ROOT,
    reviewed_at: str | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    source_queue = read_jsonl(root / QUEUE_SOURCE)
    source_resolutions = read_jsonl(root / RESOLUTION_SOURCE)
    queue = copy.deepcopy(source_queue)
    resolutions = copy.deepcopy(source_resolutions)
    if reviewed_at is None:
        reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    unresolved_ids = [
        row["candidate_id"]
        for row in queue
        if row["review"]["structure_decision"] is None
    ]
    assert unresolved_ids[:18] == list(BATCH02_DECISIONS)
    assert len(unresolved_ids) == 51

    for record in queue:
        decision = BATCH02_DECISIONS.get(record["candidate_id"])
        if decision is not None:
            assert all(value is None for value in record["review"].values())
            record["review"] = {
                **decision,
                "reviewer": REVIEWER,
                "reviewed_at": reviewed_at,
            }

    resolution_by_id = {record["candidate_id"]: record for record in resolutions}
    for candidate_id, decision in BATCH02_DECISIONS.items():
        record = resolution_by_id[candidate_id]
        assert record["resolution_status"] == "HUMAN_REVIEW_REQUIRED"
        record["resolution_status"] = "TEXT_HUMAN_CONFIRMED"
        record["proposed_corrected_format"] = "plain_text"
        record["proposed_corrected_scenario"] = "SCN-REMAIN-TEXT-001"
        record["human_resolution_issue"] = None
        record["batch_human_review"] = {
            **decision,
            "reviewer": REVIEWER,
            "reviewed_at": reviewed_at,
            "source_queue": QUEUE_OUTPUT.as_posix(),
        }

    return queue, resolutions, source_queue, source_resolutions


def main() -> None:
    queue_output = ROOT / QUEUE_OUTPUT
    resolution_output = ROOT / RESOLUTION_OUTPUT
    if queue_output.exists() or resolution_output.exists():
        raise FileExistsError("reviewed Batch 2 output already exists; refusing overwrite")
    reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    queue, resolutions, _, _ = merge_batch02(ROOT, reviewed_at)
    write_jsonl(queue_output, queue)
    write_jsonl(resolution_output, resolutions)
    print(f"reviewed_at={reviewed_at}")
    print(f"reviewed_queue={QUEUE_OUTPUT.as_posix()}")
    print(f"reviewed_resolution={RESOLUTION_OUTPUT.as_posix()}")


if __name__ == "__main__":
    main()
