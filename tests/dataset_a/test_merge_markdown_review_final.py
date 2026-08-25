from collections import Counter
from pathlib import Path

from scripts.dataset_a.merge_markdown_review_final import (
    DECISIONS,
    QUEUE_SOURCE,
    merge_markdown_review,
)
from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl


ROOT = Path(__file__).resolve().parents[2]


def test_final_markdown_review_merges_exact_decisions_and_statuses():
    records, source_records, queue = merge_markdown_review(
        ROOT, "2026-08-20T00:00:00Z"
    )
    by_id = {row["candidate_id"]: row for row in records}

    assert len(records) == len({row["candidate_id"] for row in records}) == 105
    assert [row["candidate_id"] for row in records] == [
        row["candidate_id"] for row in source_records
    ]
    assert set(DECISIONS) == {row["candidate_id"] for row in queue}
    assert by_id["DA-RAW-000866"]["resolution_status"] == "MARKDOWN_HUMAN_CONFIRMED"
    assert by_id["DA-RAW-000866"]["proposed_corrected_format"] == "markdown"
    assert by_id["DA-RAW-000866"]["proposed_corrected_scenario"] == "SCN-REMAIN-DOC-001"
    assert by_id["DA-RAW-000970"]["resolution_status"] == "CODE_HUMAN_CONFIRMED"
    assert by_id["DA-RAW-000970"]["proposed_corrected_format"] == "code"
    assert by_id["DA-RAW-000970"]["proposed_corrected_scenario"] == "SCN-REMAIN-CODE-001"


def test_final_markdown_distribution_is_closed_and_deterministic():
    first, _, queue = merge_markdown_review(ROOT, "2026-08-20T00:00:00Z")
    second, _, _ = merge_markdown_review(ROOT, "2026-08-20T00:00:00Z")

    assert first == second
    assert Counter(row["proposed_corrected_format"] for row in first) == {
        "markdown": 12,
        "plain_text": 92,
        "code": 1,
    }
    assert not any(row["proposed_corrected_scenario"] is None for row in first)
    assert [row["raw_text"] for row in queue] == [
        row["raw_text"] for row in read_jsonl(ROOT / QUEUE_SOURCE)
    ]
    assert {row["human_review"]["reviewed_at"] for row in first if row["candidate_id"] in DECISIONS} == {
        "2026-08-20T00:00:00Z"
    }
