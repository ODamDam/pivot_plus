import json
from pathlib import Path

import pytest

from scripts.dataset_a.merge_code_review_proposals_v1 import (
    _validate_proposal,
    merge_approved_proposals,
    read_jsonl,
)


ROOT = Path(__file__).resolve().parents[2]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    batch = tmp_path / "batch.jsonl"
    proposals = tmp_path / "proposals.jsonl"
    approvals = tmp_path / "approvals.jsonl"
    resolution = tmp_path / "resolution.jsonl"
    _write_jsonl(batch, [{"candidate_id": "A"}, {"candidate_id": "B"}])
    _write_jsonl(
        proposals,
        [
            {
                "candidate_id": "A",
                "proposed_representation_decision": "CODE",
                "proposed_observed_format": "code",
                "rationale": "Whole record is source code.",
                "confidence": "high",
                "policy_basis": "whole-record code carrier",
                "morphology_basis": "code dominant",
                "requires_human_attention": False,
                "attention_reason": "",
            },
            {
                "candidate_id": "B",
                "proposed_representation_decision": "TEXT",
                "proposed_observed_format": "plain_text",
                "rationale": "Whole record is prose.",
                "confidence": "medium",
                "policy_basis": "whole-record prose carrier",
                "morphology_basis": "text dominant",
                "requires_human_attention": True,
                "attention_reason": "Competing fence.",
            },
        ],
    )
    _write_jsonl(
        resolution,
        [
            {"candidate_id": "A", "resolution_status": "HUMAN_REVIEW_REQUIRED", "proposed_corrected_format": None, "proposed_corrected_scenario": None},
            {"candidate_id": "B", "resolution_status": "HUMAN_REVIEW_REQUIRED", "proposed_corrected_format": None, "proposed_corrected_scenario": None},
            {"candidate_id": "C", "resolution_status": "CODE_AUTO", "proposed_corrected_format": "code", "proposed_corrected_scenario": "SCN-REMAIN-CODE-001"},
        ],
    )
    return batch, proposals, approvals, resolution


def test_only_explicitly_approved_candidates_are_merged(tmp_path):
    batch, proposals, approvals, resolution = _fixture(tmp_path)
    _write_jsonl(
        approvals,
        [{"candidate_id": "A", "approved": True, "reviewer": "human-1", "reviewed_at": "2026-08-25T00:00:00Z"}],
    )

    merged = merge_approved_proposals(batch, proposals, approvals, resolution)

    by_id = {row["candidate_id"]: row for row in merged}
    assert by_id["A"]["resolution_status"] == "CODE_HUMAN_CONFIRMED"
    assert by_id["A"]["human_representation_decision"] == "CODE"
    assert by_id["A"]["human_review"]["representation_decision"] == "CODE"
    assert by_id["B"]["resolution_status"] == "HUMAN_REVIEW_REQUIRED"
    assert "human_review" not in by_id["B"]
    assert by_id["C"]["resolution_status"] == "CODE_AUTO"


@pytest.mark.parametrize(
    "target,rows,error",
    [
        ("approvals", [{"candidate_id": "A", "approved": True, "reviewer": "h", "reviewed_at": "t"}, {"candidate_id": "A", "approved": True, "reviewer": "h", "reviewed_at": "t"}], "duplicate"),
        ("approvals", [{"candidate_id": "MISSING", "approved": True, "reviewer": "h", "reviewed_at": "t"}], "missing"),
    ],
)
def test_rejects_duplicate_or_missing_approval_ids(tmp_path, target, rows, error):
    batch, proposals, approvals, resolution = _fixture(tmp_path)
    _write_jsonl(approvals, rows)
    with pytest.raises(ValueError, match=error):
        merge_approved_proposals(batch, proposals, approvals, resolution)


def test_rejects_invalid_taxonomy_and_empty_rationale(tmp_path):
    batch, proposals, approvals, resolution = _fixture(tmp_path)
    _write_jsonl(approvals, [{"candidate_id": "A", "approved": True, "reviewer": "h", "reviewed_at": "t"}])
    rows = [json.loads(line) for line in proposals.read_text(encoding="utf-8").splitlines()]
    rows[0]["proposed_representation_decision"] = "NEW_TAXONOMY"
    rows[0]["rationale"] = ""
    _write_jsonl(proposals, rows)
    with pytest.raises(ValueError, match="invalid taxonomy|empty rationale"):
        merge_approved_proposals(batch, proposals, approvals, resolution)


def test_rejects_incomplete_proposal_set(tmp_path):
    batch, proposals, approvals, resolution = _fixture(tmp_path)
    _write_jsonl(approvals, [])
    rows = [json.loads(proposals.read_text(encoding="utf-8").splitlines()[0])]
    _write_jsonl(proposals, rows)
    with pytest.raises(ValueError, match="missing proposal"):
        merge_approved_proposals(batch, proposals, approvals, resolution)


def test_batch01_proposal_artifact_is_complete_and_taxonomy_valid():
    base = ROOT / "data/dataset_a/adjudication/scenario_binding_v2"
    batch = read_jsonl(base / "dataset_a_code_human_review_batch01_25_v1.jsonl")
    proposals = read_jsonl(
        base / "dataset_a_code_human_review_batch01_25_v1_codex_proposals.jsonl"
    )
    resolution = read_jsonl(base / "dataset_a_code_resolution_233_v1.jsonl")
    assert len(batch) == len(proposals) == 25
    assert len(resolution) == len({row["candidate_id"] for row in resolution}) == 233
    assert [row["candidate_id"] for row in proposals] == [
        row["candidate_id"] for row in batch
    ]
    assert {row["candidate_id"] for row in batch} <= {
        row["candidate_id"] for row in resolution
    }
    for proposal in proposals:
        _validate_proposal(proposal)


def test_reviewed_batch01_artifact_is_reproducible_and_non_batch_unchanged():
    base = ROOT / "data/dataset_a/adjudication/scenario_binding_v2"
    batch_path = base / "dataset_a_code_human_review_batch01_25_v1.jsonl"
    proposal_path = base / "dataset_a_code_human_review_batch01_25_v1_codex_proposals.jsonl"
    approval_path = Path(
        "data/dataset_a/adjudication/scenario_binding_v2/"
        "dataset_a_code_human_review_batch01_25_v1_approvals.jsonl"
    )
    resolution_path = base / "dataset_a_code_resolution_233_v1.jsonl"
    output_path = base / "dataset_a_code_resolution_233_v1_reviewed_batch01.jsonl"

    expected = merge_approved_proposals(
        batch_path, proposal_path, approval_path, resolution_path
    )
    actual = read_jsonl(output_path)
    assert actual == expected
    assert len(actual) == len({row["candidate_id"] for row in actual}) == 233

    batch_ids = {row["candidate_id"] for row in read_jsonl(batch_path)}
    source_by_id = {
        row["candidate_id"]: row for row in read_jsonl(resolution_path)
    }
    actual_by_id = {row["candidate_id"]: row for row in actual}
    assert all(
        actual_by_id[candidate_id] == source
        for candidate_id, source in source_by_id.items()
        if candidate_id not in batch_ids
    )


def test_remaining199_proposal_artifact_matches_unapproved_queue_exactly():
    base = ROOT / "data/dataset_a/adjudication/scenario_binding_v2"
    queue = read_jsonl(base / "dataset_a_code_human_review_queue_v1.jsonl")
    approvals = read_jsonl(
        base / "dataset_a_code_human_review_batch01_25_v1_approvals.jsonl"
    )
    proposals = read_jsonl(
        base / "dataset_a_code_remaining199_codex_proposals_v1.jsonl"
    )
    approved_ids = {row["candidate_id"] for row in approvals}
    remaining_ids = [
        row["candidate_id"]
        for row in queue
        if row["candidate_id"] not in approved_ids
    ]

    assert len(queue) == 224
    assert len(approved_ids) == 25
    assert len(proposals) == len({row["candidate_id"] for row in proposals}) == 199
    assert [row["candidate_id"] for row in proposals] == remaining_ids
    assert not (approved_ids & set(remaining_ids))
    for proposal in proposals:
        _validate_proposal(proposal)


def test_complete_code_review_artifact_is_reproducible_and_preserves_prior_records():
    base = Path("data/dataset_a/adjudication/scenario_binding_v2")
    proposal_path = base / "dataset_a_code_remaining199_codex_proposals_v1.jsonl"
    approval_path = base / "dataset_a_code_remaining199_approvals_v1.jsonl"
    resolution_path = base / "dataset_a_code_resolution_233_v1_reviewed_batch01.jsonl"
    output_path = ROOT / base / "dataset_a_code_resolution_233_v1_reviewed_complete.jsonl"

    expected = merge_approved_proposals(
        proposal_path, proposal_path, approval_path, resolution_path
    )
    actual = read_jsonl(output_path)
    assert actual == expected
    assert len(actual) == len({row["candidate_id"] for row in actual}) == 233

    remaining_ids = {
        row["candidate_id"] for row in read_jsonl(ROOT / proposal_path)
    }
    prior_by_id = {
        row["candidate_id"]: row for row in read_jsonl(ROOT / resolution_path)
    }
    actual_by_id = {row["candidate_id"]: row for row in actual}
    assert all(
        actual_by_id[candidate_id] == row
        for candidate_id, row in prior_by_id.items()
        if candidate_id not in remaining_ids
    )
    assert all(
        actual_by_id[candidate_id]["resolution_status"]
        == "MARKDOWN_HUMAN_CONFIRMED"
        for candidate_id in remaining_ids
    )
