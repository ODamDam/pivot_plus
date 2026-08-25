"""Reuse completed representation audits for Dataset A structure correction v2.

The script never edits v1 coverage, binding, or adjudication artifacts. Matching
uses provenance identifiers only; text similarity and label semantics are not
used.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.dataset_a.structure_classifier_v2 import (
    classify_observable_structure,
)


ROOT = _PROJECT_ROOT
POOL = Path("data/dataset_a/candidate_pool/dataset_a_raw_candidate_pool_1500_v1_2_parse_fixed.jsonl")
BOUND = Path(
    "data/dataset_a/adjudication/scenario_binding_v1/"
    "dataset_a_remaining_bound_1050_v1.jsonl"
)
AUDIT_ROOT = Path(
    "data/archive/pre_monorepo_data_pipeline_20260730/review/"
    "04_structure_intact"
)
OUTPUT_DIR = Path("data/dataset_a/adjudication/scenario_binding_v2")
RESOLUTION_OUTPUT = OUTPUT_DIR / "dataset_a_structure_resolution_299_v2.jsonl"
QUEUE_OUTPUT = OUTPUT_DIR / "dataset_a_structure_human_review_queue_v2.jsonl"


_REPRESENTATION_INVALID_REASON_MARKERS = (
    "does not parse",
    "fails the structure",
    "fails structure",
    "plain sentence",
    "plain prose",
    "parser false positive",
    "parse false positive",
    "no observable structure",
    "not structurally",
    "structure is not",
    "structure does not",
    "not intact",
    "invalid structure",
    "not valid yaml",
    "not valid json",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_bytes().split(b"\n") if line.strip()]


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(
                json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            )


def completed_audit_paths(root: Path) -> list[Path]:
    completed = []
    for path in sorted((root / AUDIT_ROOT).rglob("*.csv")):
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
        except (UnicodeDecodeError, csv.Error):
            continue
        if not rows or "structure_valid" not in rows[0]:
            continue
        if all(
            str(record.get("structure_valid") or "").strip().lower()
            in {"true", "false"}
            and bool(str(record.get("review_decision") or "").strip())
            and bool(str(record.get("review_note") or "").strip())
            for record in rows
        ):
            completed.append(path)
    return completed


def load_completed_audits(root: Path) -> list[dict[str, Any]]:
    audits: list[dict[str, Any]] = []
    for path in completed_audit_paths(root):
        relative = path.relative_to(root).as_posix()
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for line_number, record in enumerate(csv.DictReader(handle), start=2):
                if "structure_valid" not in record:
                    continue
                record["_audit_source"] = relative
                record["_audit_line"] = line_number
                audits.append(record)
    return audits


def _parse_bool(value: Any) -> bool | None:
    normalized = str(value or "").strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def _explicit_representation_invalidity(record: dict[str, Any]) -> bool:
    note = str(record.get("review_note") or "").strip().lower()
    return any(marker in note for marker in _REPRESENTATION_INVALID_REASON_MARKERS)


def representation_resolution_from_audits(
    audits: list[dict[str, Any]],
) -> tuple[str, bool | None, str | None]:
    """Resolve only the explicit representation axis from matched audits."""

    reusable: set[bool] = set()
    for audit in audits:
        structure_valid = _parse_bool(audit.get("structure_valid"))
        if structure_valid is True:
            reusable.add(True)
        elif structure_valid is False and _explicit_representation_invalidity(audit):
            reusable.add(False)

    if reusable == {True, False}:
        return (
            "HUMAN_REVIEW_CONFLICT",
            None,
            "conflicting_reusable_structure_valid_results",
        )
    if reusable == {True}:
        return "STRUCT_HUMAN_CONFIRMED", True, None
    if reusable == {False}:
        return "TEXT_HUMAN_CONFIRMED", False, None
    return "HUMAN_REVIEW_REQUIRED", None, "no_reusable_representation_axis"


def _build_audit_index(
    pool: list[dict[str, Any]], audits: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    by_normalized: dict[str, list[str]] = defaultdict(list)
    by_source_record: dict[tuple[str, str], list[str]] = defaultdict(list)
    for record in pool:
        candidate_id = record["candidate_id"]
        normalized = record["provenance"].get("normalized_record_id")
        if normalized:
            by_normalized[normalized].append(candidate_id)
        key = (
            record["provenance"].get("raw_source_id") or "",
            record["source"].get("source_record_id") or "",
        )
        if all(key):
            by_source_record[key].append(candidate_id)

    matches: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for audit in audits:
        candidate_ids: list[str] = []
        match_method: str | None = None
        normalized = str(audit.get("normalized_record_id") or "").strip()
        if normalized and normalized in by_normalized:
            candidate_ids = by_normalized[normalized]
            match_method = "normalized_record_id"
        else:
            key = (
                str(audit.get("source_id") or "").strip(),
                str(audit.get("source_record_id") or "").strip(),
            )
            if all(key) and key in by_source_record:
                candidate_ids = by_source_record[key]
                match_method = "source_id+source_record_id"

        for candidate_id in candidate_ids:
            matched = dict(audit)
            matched["_match_method"] = match_method
            matches[candidate_id].append(matched)
    return matches


def _audit_formats(audits: list[dict[str, Any]]) -> set[str]:
    return {
        str(record.get("candidate_structure_format") or "").strip()
        for record in audits
        if _parse_bool(record.get("structure_valid")) is True
        and str(record.get("candidate_structure_format") or "").strip()
    }


def build_resolution_records(
    root: Path = ROOT,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    pool = read_jsonl(root / POOL)
    bound = [
        record
        for record in read_jsonl(root / BOUND)
        if record["scenario_ref"] == "SCN-REMAIN-STRUCT-001"
    ]
    assert len(bound) == 299
    pool_by_id = {record["candidate_id"]: record for record in pool}
    bound_by_id = {record["candidate_id"]: record for record in bound}
    assert len(bound_by_id) == 299

    audits = load_completed_audits(root)
    audit_matches = _build_audit_index(pool, audits)
    resolutions: list[dict[str, Any]] = []

    for bound_record in bound:
        candidate_id = bound_record["candidate_id"]
        pool_record = pool_by_id[candidate_id]
        classification = classify_observable_structure(bound_record["untrusted_input"])
        matched = audit_matches.get(candidate_id, [])
        human_status, human_valid, human_issue = representation_resolution_from_audits(
            matched
        )

        if classification.structure_strength == "clear_structured":
            resolution_status = "STRUCT_AUTO"
            corrected_format = classification.observed_format
            corrected_scenario = "SCN-REMAIN-STRUCT-001"
        elif classification.structure_strength == "plain_text_like":
            resolution_status = "TEXT_AUTO"
            corrected_format = "plain_text"
            corrected_scenario = "SCN-REMAIN-TEXT-001"
        elif human_status == "STRUCT_HUMAN_CONFIRMED":
            formats = _audit_formats(matched)
            if len(formats) == 1:
                resolution_status = human_status
                corrected_format = next(iter(formats))
                corrected_scenario = "SCN-REMAIN-STRUCT-001"
            else:
                resolution_status = "HUMAN_REVIEW_CONFLICT"
                corrected_format = None
                corrected_scenario = None
                human_issue = "confirmed_structure_format_missing_or_conflicting"
        elif human_status == "TEXT_HUMAN_CONFIRMED":
            resolution_status = human_status
            corrected_format = "plain_text"
            corrected_scenario = "SCN-REMAIN-TEXT-001"
        else:
            resolution_status = human_status
            corrected_format = None
            corrected_scenario = None

        sources = sorted({record["_audit_source"] for record in matched})
        reasons = [
            str(record.get("review_note") or "").strip()
            for record in matched
            if str(record.get("review_note") or "").strip()
        ]
        resolutions.append(
            {
                "candidate_id": candidate_id,
                "normalized_record_id": pool_record["provenance"].get(
                    "normalized_record_id"
                ),
                "source_id": pool_record["source"].get("source_id"),
                "source_record_id": pool_record["source"].get("source_record_id"),
                "previous_input_format": bound_record["input_format_observed"],
                "previous_scenario_ref": bound_record["scenario_ref"],
                "classifier_observed_format": classification.observed_format,
                "classifier_structure_strength": classification.structure_strength,
                "classifier_reason": classification.detection_reason,
                "classifier_requires_human_review": classification.requires_human_review,
                "human_audit_match": bool(matched),
                "human_structure_valid": human_valid,
                "human_audit_source": sources,
                "human_audit_reason": reasons,
                "human_audit_match_method": sorted(
                    {record["_match_method"] for record in matched}
                ),
                "human_audit_axis_reusable": human_status
                in {"STRUCT_HUMAN_CONFIRMED", "TEXT_HUMAN_CONFIRMED"},
                "human_resolution_issue": human_issue,
                "resolution_status": resolution_status,
                "proposed_corrected_format": corrected_format,
                "proposed_corrected_scenario": corrected_scenario,
            }
        )

    assert {record["candidate_id"] for record in resolutions} == set(bound_by_id)
    return resolutions, bound_by_id


def make_review_queue(
    resolutions: list[dict[str, Any]], source_rows: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    queue = []
    for resolution in resolutions:
        if resolution["resolution_status"] not in {
            "HUMAN_REVIEW_REQUIRED",
            "HUMAN_REVIEW_CONFLICT",
        }:
            continue
        assert resolution["proposed_corrected_format"] is None
        assert resolution["proposed_corrected_scenario"] is None
        source = source_rows[resolution["candidate_id"]]
        queue.append(
            {
                **resolution,
                "untrusted_input": source["untrusted_input"],
                "review": {
                    "structure_decision": None,
                    "observed_format": None,
                    "rationale": None,
                    "reviewer": None,
                    "reviewed_at": None,
                },
            }
        )
    return queue


def main() -> None:
    resolutions, source_rows = build_resolution_records(ROOT)
    queue = make_review_queue(resolutions, source_rows)
    write_jsonl(ROOT / RESOLUTION_OUTPUT, resolutions)
    write_jsonl(ROOT / QUEUE_OUTPUT, queue)
    print(f"resolution_records={len(resolutions)}")
    print(f"human_review_queue={len(queue)}")
    print(f"resolution_output={RESOLUTION_OUTPUT.as_posix()}")
    print(f"queue_output={QUEUE_OUTPUT.as_posix()}")


if __name__ == "__main__":
    main()
