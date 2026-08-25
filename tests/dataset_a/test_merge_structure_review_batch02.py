from collections import Counter
from pathlib import Path

from scripts.dataset_a.merge_structure_review_batch01 import BATCH01_DECISIONS
from scripts.dataset_a.merge_structure_review_batch02 import (
    BATCH02_DECISIONS,
    merge_batch02,
)


ROOT = Path(__file__).resolve().parents[2]


def test_batch02_merge_preserves_batch01_and_adds_exact_ids():
    queue, resolutions, source_queue, _ = merge_batch02(
        ROOT, "2026-08-20T00:00:00Z"
    )
    by_id = {row["candidate_id"]: row for row in queue}
    source_by_id = {row["candidate_id"]: row for row in source_queue}

    assert len(queue) == 69
    assert len(resolutions) == 299
    assert all(
        by_id[candidate_id]["review"] == source_by_id[candidate_id]["review"]
        for candidate_id in BATCH01_DECISIONS
    )
    assert {
        row["candidate_id"]
        for row in queue
        if row["review"]["reviewed_at"] == "2026-08-20T00:00:00Z"
    } == set(BATCH02_DECISIONS)
    assert sum(all(value is None for value in row["review"].values()) for row in queue) == 33


def test_batch02_resolution_distribution_and_raw_preservation():
    queue, resolutions, source_queue, _ = merge_batch02(
        ROOT, "2026-08-20T00:00:00Z"
    )

    assert Counter(row["resolution_status"] for row in resolutions) == {
        "STRUCT_AUTO": 9,
        "TEXT_AUTO": 201,
        "STRUCT_HUMAN_CONFIRMED": 3,
        "TEXT_HUMAN_CONFIRMED": 53,
        "HUMAN_REVIEW_REQUIRED": 33,
    }
    assert [row["candidate_id"] for row in queue] == [
        row["candidate_id"] for row in source_queue
    ]
    assert [row["untrusted_input"] for row in queue] == [
        row["untrusted_input"] for row in source_queue
    ]
