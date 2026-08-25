"""Create the reviewed ENCODED/HTML representation resolution artifact."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl, write_jsonl


ROOT = _PROJECT_ROOT
SOURCE = Path("data/dataset_a/adjudication/scenario_binding_v1/dataset_a_remaining_bound_1050_v1.jsonl")
OUTPUT = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_small_format_resolution_6_v2.jsonl")
REVIEWER = "ChatGPT-human-review-2026-08-20"


DECISIONS = {
    "DA-RAW-000576": "Natural-language prompt requesting ROT-13 output; the payload itself is not an encoded representation.",
    "DA-RAW-000595": "Natural-language prompt requesting ROT-13 output; no whole-record encoded payload is present.",
    "DA-RAW-000659": "Natural-language instruction mentioning ROT-13 as an output operation; the record itself is plain prose.",
    "DA-RAW-001058": "Mixed natural-language jailbreak transcript containing custom alien/human wrappers and embedded Base64-like fragments; neither a whole-record encoded representation nor a conventional HTML document.",
    "DA-RAW-001067": "Natural-language persona prompt wrapped with im_start/im_end-like chat sentinels; these are not HTML elements and the record is not an HTML document.",
    "DA-RAW-001244": "Natural-language instruction containing custom begin/end wrappers and an ASCII-decoding fragment; not HTML and not a whole-record encoded representation.",
}


def build_resolution(root: Path = ROOT, reviewed_at: str | None = None) -> list[dict[str, Any]]:
    if reviewed_at is None:
        reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    source = read_jsonl(root / SOURCE)
    selected = [
        row for row in source
        if row["input_format_observed"] in {"encoded", "html"}
    ]
    assert len(selected) == 6
    assert [row["candidate_id"] for row in selected] == list(DECISIONS)
    assert [row["input_format_observed"] for row in selected] == [
        "encoded", "encoded", "encoded", "html", "html", "html"
    ]

    return [
        {
            "candidate_id": row["candidate_id"],
            "previous_input_format": row["input_format_observed"],
            "previous_scenario_ref": row["scenario_ref"],
            "representation_decision": "TEXT",
            "observed_format": "plain_text",
            "rationale": DECISIONS[row["candidate_id"]],
            "reviewer": REVIEWER,
            "reviewed_at": reviewed_at,
            "proposed_corrected_scenario": "SCN-REMAIN-TEXT-001",
        }
        for row in selected
    ]


def main() -> None:
    output = ROOT / OUTPUT
    if output.exists():
        raise FileExistsError("small-format resolution already exists; refusing overwrite")
    reviewed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    records = build_resolution(ROOT, reviewed_at)
    write_jsonl(output, records)
    print(f"reviewed_at={reviewed_at}")
    print(f"output={OUTPUT.as_posix()} count={len(records)}")


if __name__ == "__main__":
    main()
