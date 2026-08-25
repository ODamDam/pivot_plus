import json
from collections import Counter
from pathlib import Path

from scripts.dataset_a.build_structure_resolution_v2 import (
    build_resolution_records,
    make_review_queue,
    representation_resolution_from_audits,
    write_jsonl,
)


ROOT = Path(__file__).resolve().parents[2]


def test_review_decision_drop_does_not_override_valid_structure_axis():
    status, valid, reason = representation_resolution_from_audits(
        [
            {
                "structure_valid": "true",
                "review_decision": "drop",
                "review_note": "Drop because attack semantics are duplicated.",
            }
        ]
    )

    assert status == "STRUCT_HUMAN_CONFIRMED"
    assert valid is True
    assert reason is None


def test_invalid_structure_requires_representation_specific_reason():
    reusable = representation_resolution_from_audits(
        [
            {
                "structure_valid": "false",
                "review_decision": "drop",
                "review_note": "Plain sentence colon created a parser false positive.",
            }
        ]
    )
    mixed_only = representation_resolution_from_audits(
        [
            {
                "structure_valid": "false",
                "review_decision": "drop",
                "review_note": "Drop because attack semantics are duplicated.",
            }
        ]
    )

    assert reusable[:2] == ("TEXT_HUMAN_CONFIRMED", False)
    assert mixed_only[0] == "HUMAN_REVIEW_REQUIRED"


def test_conflicting_structure_axes_require_conflict_review():
    status, valid, reason = representation_resolution_from_audits(
        [
            {"structure_valid": "true", "review_note": "Valid YAML mapping."},
            {
                "structure_valid": "false",
                "review_note": "No observable structure; parser false positive.",
            },
        ]
    )

    assert status == "HUMAN_REVIEW_CONFLICT"
    assert valid is None
    assert reason == "conflicting_reusable_structure_valid_results"


def test_repository_resolution_is_complete_and_queue_contains_only_unresolved():
    resolutions, source_rows = build_resolution_records(ROOT)
    queue = make_review_queue(resolutions, source_rows)
    counts = Counter(record["resolution_status"] for record in resolutions)

    assert len(resolutions) == 299
    assert len({record["candidate_id"] for record in resolutions}) == 299
    assert counts == {
        "STRUCT_AUTO": 9,
        "TEXT_AUTO": 201,
        "STRUCT_HUMAN_CONFIRMED": 2,
        "TEXT_HUMAN_CONFIRMED": 18,
        "HUMAN_REVIEW_REQUIRED": 69,
    }
    assert len(queue) == 69
    assert all(record["proposed_corrected_format"] is None for record in queue)
    assert all(record["proposed_corrected_scenario"] is None for record in queue)
    assert all(all(value is None for value in record["review"].values()) for record in queue)
    assert all(
        record["untrusted_input"] == source_rows[record["candidate_id"]]["untrusted_input"]
        for record in queue
    )


def test_jsonl_output_is_deterministic(tmp_path):
    resolutions, _ = build_resolution_records(ROOT)
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"

    write_jsonl(first, resolutions)
    write_jsonl(second, resolutions)

    assert first.read_bytes() == second.read_bytes()
    assert len([json.loads(line) for line in first.read_bytes().split(b"\n") if line]) == 299
