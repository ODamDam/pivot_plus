from collections import Counter
from pathlib import Path

from scripts.dataset_a.merge_structure_review_batch01 import (
    BATCH01_DECISIONS,
    merge_batch01,
)


ROOT = Path(__file__).resolve().parents[2]


def test_batch01_merge_updates_only_supplied_ids():
    reviewed_at = "2026-08-20T00:00:00Z"
    queue, resolutions = merge_batch01(ROOT, reviewed_at)
    decisions = set(BATCH01_DECISIONS)

    assert len(queue) == 69
    assert len(resolutions) == 299
    assert len({row["candidate_id"] for row in queue}) == 69
    assert len({row["candidate_id"] for row in resolutions}) == 299
    assert {row["candidate_id"] for row in queue if row["review"]["reviewer"]} == decisions
    assert sum(all(value is None for value in row["review"].values()) for row in queue) == 51
    assert all(
        row["review"]["reviewed_at"] == reviewed_at
        for row in queue
        if row["candidate_id"] in decisions
    )


def test_batch01_resolution_distribution_and_expected_formats():
    _, resolutions = merge_batch01(ROOT, "2026-08-20T00:00:00Z")
    counts = Counter(row["resolution_status"] for row in resolutions)

    assert counts == {
        "STRUCT_AUTO": 9,
        "TEXT_AUTO": 201,
        "STRUCT_HUMAN_CONFIRMED": 3,
        "TEXT_HUMAN_CONFIRMED": 35,
        "HUMAN_REVIEW_REQUIRED": 51,
    }
    by_id = {row["candidate_id"]: row for row in resolutions}
    assert by_id["DA-RAW-000880"]["proposed_corrected_format"] == "json"
    assert by_id["DA-RAW-000880"]["proposed_corrected_scenario"] == "SCN-REMAIN-STRUCT-001"
    assert by_id["DA-RAW-000499"]["proposed_corrected_format"] == "plain_text"
    assert by_id["DA-RAW-000499"]["proposed_corrected_scenario"] == "SCN-REMAIN-TEXT-001"


def test_batch01_merge_preserves_raw_text_and_input_order():
    queue, _ = merge_batch01(ROOT, "2026-08-20T00:00:00Z")
    source_queue, _ = merge_batch01(ROOT, "2026-08-20T00:00:00Z", apply=False)

    assert [row["candidate_id"] for row in queue] == [
        row["candidate_id"] for row in source_queue
    ]
    assert [row["untrusted_input"] for row in queue] == [
        row["untrusted_input"] for row in source_queue
    ]
