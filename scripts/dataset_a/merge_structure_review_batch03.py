"""Merge supplied structure-only Batch 3 decisions into new reviewed artifacts."""

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
QUEUE_SOURCE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_human_review_queue_v2_reviewed_batch02.jsonl")
RESOLUTION_SOURCE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_resolution_299_v2_reviewed_batch02.jsonl")
QUEUE_OUTPUT = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_human_review_queue_v2_reviewed_batch03.jsonl")
RESOLUTION_OUTPUT = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_structure_resolution_299_v2_reviewed_batch03.jsonl")


def _text(rationale: str) -> dict[str, str]:
    return {"structure_decision": "TEXT", "observed_format": "plain_text", "rationale": rationale}


BATCH03_DECISIONS = {
    "DA-RAW-001102": _text("Email headers and body form an ordinary email document, not a JSON/YAML structured data representation."),
    "DA-RAW-001108": _text("Prompt template using quote delimiters and Rules/Title/Return/Ignore labels; not whole-record structured data."),
    "DA-RAW-001111": _text("Natural-language translation instruction ending with an incidental colon."),
    "DA-RAW-001112": _text("Single Story field followed by a long natural-language instruction; single-field YAML parse is not sufficient structural evidence."),
    "DA-RAW-001117": _text("Natural-language instruction with translation and User/Bot dialogue examples."),
    "DA-RAW-001118": _text("Few-shot natural-language prompt using title and sentence labels."),
    "DA-RAW-001130": _text("Natural-language tutor prompt with User/Response examples."),
    "DA-RAW-001137": _text("Natural-language question/answer prompt using labels."),
    "DA-RAW-001144": _text("Short prose example using Answer and Conclusion labels."),
    "DA-RAW-001149": _text("Single Bypass label followed by a code fragment; not a structured YAML document."),
    "DA-RAW-001150": _text("Single Run label followed by a shell fragment; not structured data."),
    "DA-RAW-001167": _text("Single Execute label followed by a natural-language command; single-field mapping false positive."),
    "DA-RAW-001173": _text("Single Execute label with a code-like fragment; not a JSON/YAML representation."),
    "DA-RAW-001194": _text("Natural-language few-shot example using Feedback and Text labels."),
    "DA-RAW-001201": _text("SYSTEM is a role-style prompt prefix followed by natural-language instructions, not a YAML field representation."),
    "DA-RAW-001207": _text("Code-like expression enclosed in braces, but it is neither JSON nor YAML structured data."),
    "DA-RAW-001209": _text("Single repeat field followed by a natural-language instruction; insufficient evidence for structured YAML."),
    "DA-RAW-001210": _text("Natural-language instruction using Response and Sentence labels."),
}


def merge_batch03(root: Path = ROOT, reviewed_at: str | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    source_queue = read_jsonl(root / QUEUE_SOURCE)
    source_resolutions = read_jsonl(root / RESOLUTION_SOURCE)
    queue = copy.deepcopy(source_queue)
    resolutions = copy.deepcopy(source_resolutions)
    if reviewed_at is None:
        reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    unresolved_ids = [row["candidate_id"] for row in queue if row["review"]["structure_decision"] is None]
    assert len(unresolved_ids) == 33
    assert unresolved_ids[:18] == list(BATCH03_DECISIONS)

    for record in queue:
        decision = BATCH03_DECISIONS.get(record["candidate_id"])
        if decision is not None:
            assert all(value is None for value in record["review"].values())
            record["review"] = {**decision, "reviewer": REVIEWER, "reviewed_at": reviewed_at}

    by_id = {record["candidate_id"]: record for record in resolutions}
    for candidate_id, decision in BATCH03_DECISIONS.items():
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
        raise FileExistsError("reviewed Batch 3 output already exists; refusing overwrite")
    reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    queue, resolutions, _, _ = merge_batch03(ROOT, reviewed_at)
    write_jsonl(queue_output, queue)
    write_jsonl(resolution_output, resolutions)
    print(f"reviewed_at={reviewed_at}")
    print(f"reviewed_queue={QUEUE_OUTPUT.as_posix()}")
    print(f"reviewed_resolution={RESOLUTION_OUTPUT.as_posix()}")


if __name__ == "__main__":
    main()
