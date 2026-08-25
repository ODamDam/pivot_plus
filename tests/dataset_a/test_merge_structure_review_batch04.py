from collections import Counter
from pathlib import Path

from scripts.dataset_a.merge_structure_review_batch01 import BATCH01_DECISIONS
from scripts.dataset_a.merge_structure_review_batch02 import BATCH02_DECISIONS
from scripts.dataset_a.merge_structure_review_batch03 import BATCH03_DECISIONS
from scripts.dataset_a.merge_structure_review_batch04 import (
    BATCH04_DECISIONS,
    merge_batch04,
)


ROOT = Path(__file__).resolve().parents[2]


def test_batch04_preserves_prior_reviews_and_closes_exact_ids():
    queue, resolutions, source_queue, _ = merge_batch04(
        ROOT, "2026-08-20T00:00:00Z"
    )
    by_id = {row["candidate_id"]: row for row in queue}
    source_by_id = {row["candidate_id"]: row for row in source_queue}
    prior_ids = set(BATCH01_DECISIONS) | set(BATCH02_DECISIONS) | set(BATCH03_DECISIONS)

    assert len(queue) == 69
    assert len(resolutions) == 299
    assert len({row["candidate_id"] for row in resolutions}) == 299
    assert all(by_id[cid]["review"] == source_by_id[cid]["review"] for cid in prior_ids)
    assert {
        row["candidate_id"]
        for row in queue
        if row["review"]["reviewed_at"] == "2026-08-20T00:00:00Z"
    } == set(BATCH04_DECISIONS)
    assert all(all(value is not None for value in row["review"].values()) for row in queue)


def test_batch04_distribution_consistency_and_raw_preservation():
    queue, resolutions, source_queue, _ = merge_batch04(
        ROOT, "2026-08-20T00:00:00Z"
    )

    assert Counter(row["resolution_status"] for row in resolutions) == {
        "STRUCT_AUTO": 9,
        "TEXT_AUTO": 201,
        "STRUCT_HUMAN_CONFIRMED": 3,
        "TEXT_HUMAN_CONFIRMED": 86,
    }
    assert [row["candidate_id"] for row in queue] == [row["candidate_id"] for row in source_queue]
    assert [row["untrusted_input"] for row in queue] == [row["untrusted_input"] for row in source_queue]
    assert all(row["proposed_corrected_scenario"] is not None for row in resolutions)

    dispositions = Counter()
    for row in resolutions:
        status = row["resolution_status"]
        if status.startswith("STRUCT_"):
            assert row["proposed_corrected_scenario"] == "SCN-REMAIN-STRUCT-001"
            dispositions["STRUCT"] += 1
        elif status.startswith("TEXT_"):
            assert row["proposed_corrected_format"] == "plain_text"
            assert row["proposed_corrected_scenario"] == "SCN-REMAIN-TEXT-001"
            dispositions["TEXT"] += 1
        else:
            raise AssertionError(f"unresolved status: {status}")
    assert dispositions == {"STRUCT": 12, "TEXT": 287}
