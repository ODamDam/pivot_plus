from collections import Counter
from pathlib import Path

from scripts.dataset_a.build_small_format_resolution_v2 import (
    DECISIONS,
    build_resolution,
)


ROOT = Path(__file__).resolve().parents[2]


def test_small_format_resolution_closes_exact_source_order():
    records = build_resolution(ROOT, "2026-08-20T00:00:00Z")

    assert [row["candidate_id"] for row in records] == list(DECISIONS)
    assert len(records) == len({row["candidate_id"] for row in records}) == 6
    assert Counter(row["previous_input_format"] for row in records) == {
        "encoded": 3,
        "html": 3,
    }
    assert {row["representation_decision"] for row in records} == {"TEXT"}
    assert {row["observed_format"] for row in records} == {"plain_text"}
    assert {row["proposed_corrected_scenario"] for row in records} == {
        "SCN-REMAIN-TEXT-001"
    }
    assert {row["reviewed_at"] for row in records} == {"2026-08-20T00:00:00Z"}


def test_small_format_resolution_is_deterministic_and_source_derived():
    first = build_resolution(ROOT, "2026-08-20T00:00:00Z")
    second = build_resolution(ROOT, "2026-08-20T00:00:00Z")

    assert first == second
    assert all(row["previous_scenario_ref"] for row in first)
    assert not any(value is None for row in first for value in row.values())
