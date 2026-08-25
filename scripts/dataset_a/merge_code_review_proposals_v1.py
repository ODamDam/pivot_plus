"""Merge human-approved CODE review proposals into a new resolution artifact."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BATCH = ROOT / "data/dataset_a/adjudication/scenario_binding_v2/dataset_a_code_human_review_batch01_25_v1.jsonl"
DEFAULT_PROPOSALS = ROOT / "data/dataset_a/adjudication/scenario_binding_v2/dataset_a_code_human_review_batch01_25_v1_codex_proposals.jsonl"
DEFAULT_RESOLUTION = ROOT / "data/dataset_a/adjudication/scenario_binding_v2/dataset_a_code_resolution_233_v1.jsonl"

TAXONOMY = {
    ("TEXT", "plain_text"): ("TEXT_HUMAN_CONFIRMED", "SCN-REMAIN-TEXT-001"),
    ("STRUCT", "json"): ("STRUCT_HUMAN_CONFIRMED", "SCN-REMAIN-STRUCT-001"),
    ("STRUCT", "yaml"): ("STRUCT_HUMAN_CONFIRMED", "SCN-REMAIN-STRUCT-001"),
    ("MARKDOWN", "markdown"): ("MARKDOWN_HUMAN_CONFIRMED", "SCN-REMAIN-DOC-001"),
    ("CODE", "code"): ("CODE_HUMAN_CONFIRMED", "SCN-REMAIN-CODE-001"),
}
CONFIDENCE = {"high", "medium", "low"}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _index_unique(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    ids = [str(row.get("candidate_id") or "").strip() for row in rows]
    if any(not candidate_id for candidate_id in ids):
        raise ValueError(f"missing candidate_id in {label}")
    duplicates = sorted({candidate_id for candidate_id in ids if ids.count(candidate_id) > 1})
    if duplicates:
        raise ValueError(f"duplicate candidate_id in {label}: {duplicates}")
    return dict(zip(ids, rows))


def _validate_proposal(row: dict[str, Any]) -> tuple[str, str, str, str]:
    decision = str(row.get("proposed_representation_decision") or "").strip()
    observed = str(row.get("proposed_observed_format") or "").strip()
    rationale = str(row.get("rationale") or "").strip()
    confidence = str(row.get("confidence") or "").strip()
    if (decision, observed) not in TAXONOMY:
        raise ValueError(f"invalid taxonomy for {row.get('candidate_id')}: {decision}/{observed}")
    if not rationale:
        raise ValueError(f"empty rationale for {row.get('candidate_id')}")
    if confidence not in CONFIDENCE:
        raise ValueError(f"invalid confidence for {row.get('candidate_id')}: {confidence}")
    for field in ("policy_basis", "morphology_basis"):
        if not str(row.get(field) or "").strip():
            raise ValueError(f"empty {field} for {row.get('candidate_id')}")
    if not isinstance(row.get("requires_human_attention"), bool):
        raise ValueError(f"invalid requires_human_attention for {row.get('candidate_id')}")
    return decision, observed, rationale, confidence


def merge_approved_proposals(
    batch_path: Path,
    proposals_path: Path,
    approvals_path: Path,
    resolution_path: Path,
) -> list[dict[str, Any]]:
    batch = _index_unique(read_jsonl(batch_path), "batch")
    proposals = _index_unique(read_jsonl(proposals_path), "proposals")
    approvals = _index_unique(read_jsonl(approvals_path), "approvals")
    resolutions = read_jsonl(resolution_path)
    resolution_index = _index_unique(resolutions, "resolution")

    missing_proposals = sorted(set(batch) - set(proposals))
    extra_proposals = sorted(set(proposals) - set(batch))
    if missing_proposals:
        raise ValueError(f"missing proposal candidate_id: {missing_proposals}")
    if extra_proposals:
        raise ValueError(f"proposal candidate_id not in batch: {extra_proposals}")
    for proposal in proposals.values():
        _validate_proposal(proposal)

    missing_approval_ids = sorted(set(approvals) - set(batch))
    if missing_approval_ids:
        raise ValueError(f"missing candidate_id from batch/proposals: {missing_approval_ids}")
    if missing_resolution_ids := sorted(set(batch) - set(resolution_index)):
        raise ValueError(f"missing candidate_id from resolution: {missing_resolution_ids}")

    merged = copy.deepcopy(resolutions)
    merged_by_id = {row["candidate_id"]: row for row in merged}
    for candidate_id, approval in approvals.items():
        if approval.get("approved") is not True:
            raise ValueError(f"approval must set approved=true for {candidate_id}")
        reviewer = str(approval.get("reviewer") or "").strip()
        reviewed_at = str(approval.get("reviewed_at") or "").strip()
        if not reviewer or not reviewed_at:
            raise ValueError(f"approval reviewer/reviewed_at required for {candidate_id}")
        proposal = proposals[candidate_id]
        decision, observed, rationale, confidence = _validate_proposal(proposal)
        status, scenario = TAXONOMY[(decision, observed)]
        record = merged_by_id[candidate_id]
        if record.get("resolution_status") not in {"HUMAN_REVIEW_REQUIRED", "HUMAN_REVIEW_CONFLICT"}:
            raise ValueError(f"candidate is not unresolved: {candidate_id}")
        record["human_representation_decision"] = decision
        record["resolution_status"] = status
        record["proposed_corrected_format"] = observed
        record["proposed_corrected_scenario"] = scenario
        record["human_resolution_issue"] = None
        record["human_review"] = {
            "representation_decision": decision,
            "observed_format": observed,
            "rationale": rationale,
            "confidence": confidence,
            "reviewer": reviewer,
            "reviewed_at": reviewed_at,
            "approval_source": approvals_path.as_posix(),
            "proposal_source": proposals_path.as_posix(),
        }
    return merged


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=Path, default=DEFAULT_BATCH)
    parser.add_argument("--proposals", type=Path, default=DEFAULT_PROPOSALS)
    parser.add_argument("--approvals", type=Path, required=True)
    parser.add_argument("--resolution", type=Path, default=DEFAULT_RESOLUTION)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"output already exists; refusing overwrite: {args.output}")
    rows = merge_approved_proposals(args.batch, args.proposals, args.approvals, args.resolution)
    write_jsonl(args.output, rows)
    print(f"output={args.output.as_posix()} count={len(rows)} approvals={len(read_jsonl(args.approvals))}")


if __name__ == "__main__":
    main()
