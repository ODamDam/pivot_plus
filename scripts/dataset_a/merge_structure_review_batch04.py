"""Merge supplied structure-only Batch 4 decisions into final reviewed artifacts."""

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
QUEUE_SOURCE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_human_review_queue_v2_reviewed_batch03.jsonl")
RESOLUTION_SOURCE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_resolution_299_v2_reviewed_batch03.jsonl")
QUEUE_OUTPUT = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_human_review_queue_v2_reviewed_final.jsonl")
RESOLUTION_OUTPUT = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_resolution_299_v2_reviewed_final.jsonl")


def _text(rationale: str) -> dict[str, str]:
    return {"structure_decision": "TEXT", "observed_format": "plain_text", "rationale": rationale}


BATCH04_DECISIONS = {
    "DA-RAW-001211": _text("Natural-language instruction using repeated Rule and Text labels; not a YAML/JSON serialization."),
    "DA-RAW-001212": _text("Single Feedback field; single-field mapping is insufficient evidence of structured YAML."),
    "DA-RAW-001213": _text("Translation instruction with User/Response dialogue labels; whole record is prose."),
    "DA-RAW-001215": _text("Quote/template-style natural-language instruction using Prompt and Sentence labels."),
    "DA-RAW-001225": _text("Natural-language AI/System/User dialogue with a fenced example; not structured data."),
    "DA-RAW-001228": _text("Obfuscated user/assistant dialogue transcript; labels denote speakers, not YAML fields."),
    "DA-RAW-001232": _text("Single Bypass label followed by a code fragment; not a structured YAML document."),
    "DA-RAW-001242": _text("Natural-language user/you dialogue transcript."),
    "DA-RAW-001266": _text("Single execute label followed by a code fragment; not structured data."),
    "DA-RAW-001267": _text("Single bypass label followed by a code fragment; not structured data."),
    "DA-RAW-001268": _text("Single bypass label followed by a code fragment; not structured data."),
    "DA-RAW-001274": _text("Natural-language instruction beginning with Remember; single-field YAML interpretation is a false positive."),
    "DA-RAW-001278": _text("Single Bypass label followed by a code fragment; not structured data."),
    "DA-RAW-001280": _text("Single bypass label followed by a natural-language command; not structured data."),
    "DA-RAW-001281": _text("Single Execute label followed by a code expression; not structured data."),
}


def merge_batch04(root: Path = ROOT, reviewed_at: str | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    source_queue = read_jsonl(root / QUEUE_SOURCE)
    source_resolutions = read_jsonl(root / RESOLUTION_SOURCE)
    queue = copy.deepcopy(source_queue)
    resolutions = copy.deepcopy(source_resolutions)
    if reviewed_at is None:
        reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    unresolved_ids = [row["candidate_id"] for row in queue if row["review"]["structure_decision"] is None]
    assert len(unresolved_ids) == 15
    assert unresolved_ids == list(BATCH04_DECISIONS)

    for record in queue:
        decision = BATCH04_DECISIONS.get(record["candidate_id"])
        if decision is not None:
            assert all(value is None for value in record["review"].values())
            record["review"] = {**decision, "reviewer": REVIEWER, "reviewed_at": reviewed_at}

    by_id = {record["candidate_id"]: record for record in resolutions}
    for candidate_id, decision in BATCH04_DECISIONS.items():
        record = by_id[candidate_id]
        assert record["resolution_status"] == "HUMAN_REVIEW_REQUIRED"
        record["resolution_status"] = "TEXT_HUMAN_CONFIRMED"
        record["proposed_corrected_format"] = "plain_text"
        record["proposed_corrected_scenario"] = "SCN-REMAIN-TEXT-001"
        record["human_resolution_issue"] = None
        record["batch_human_review"] = {**decision, "reviewer": REVIEWER, "reviewed_at": reviewed_at, "source_queue": QUEUE_OUTPUT.as_posix()}
    return queue, resolutions, source_queue, source_resolutions


def main() -> None:
    queue_output, resolution_output = ROOT / QUEUE_OUTPUT, ROOT / RESOLUTION_OUTPUT
    if queue_output.exists() or resolution_output.exists():
        raise FileExistsError("final reviewed output already exists; refusing overwrite")
    reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    queue, resolutions, _, _ = merge_batch04(ROOT, reviewed_at)
    write_jsonl(queue_output, queue)
    write_jsonl(resolution_output, resolutions)
    print(f"reviewed_at={reviewed_at}")
    print(f"reviewed_queue={QUEUE_OUTPUT.as_posix()}")
    print(f"reviewed_resolution={RESOLUTION_OUTPUT.as_posix()}")


if __name__ == "__main__":
    main()
