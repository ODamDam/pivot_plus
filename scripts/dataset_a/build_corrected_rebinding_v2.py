"""Apply canonical representation resolutions to the 1,050 original bindings.

Observed input format and untrusted content are provenance and remain unchanged.
The corrected canonical representation and format are stored separately.
"""

from __future__ import annotations

import copy
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl, write_jsonl


ROOT = _PROJECT_ROOT
BASE_BINDING = Path(
    "data/dataset_a/adjudication/scenario_binding_v1/"
    "dataset_a_remaining_bound_1050_v1.jsonl"
)
CATALOG = Path("data/dataset_a/scenarios/scenario_catalog_remaining_v1.jsonl")
RESOLUTION_PATHS = {
    "STRUCT": Path(
        "data/dataset_a/adjudication/scenario_binding_v2/"
        "dataset_a_structure_resolution_299_v2_reviewed_final.jsonl"
    ),
    "MARKDOWN": Path(
        "data/dataset_a/adjudication/scenario_binding_v2/"
        "dataset_a_markdown_resolution_105_v1_reviewed_final.jsonl"
    ),
    "SMALL": Path(
        "data/dataset_a/adjudication/scenario_binding_v2/"
        "dataset_a_small_format_resolution_6_v2.jsonl"
    ),
    "CODE": Path(
        "data/dataset_a/adjudication/scenario_binding_v2/"
        "dataset_a_code_resolution_233_v1_reviewed_complete.jsonl"
    ),
}
OUTPUT = Path(
    "data/dataset_a/adjudication/scenario_binding_v2/"
    "dataset_a_remaining_corrected_rebinding_1050_v2.jsonl"
)

EXPECTED_TRACK_COUNTS = {"STRUCT": 299, "MARKDOWN": 105, "SMALL": 6, "CODE": 233}
EXPECTED_REPRESENTATIONS = {"TEXT": 809, "MARKDOWN": 220, "STRUCT": 12, "CODE": 9}
EXPECTED_FORMATS = {"plain_text": 809, "markdown": 220, "json": 9, "yaml": 3, "code": 9}
EXPECTED_SCENARIOS = {
    "SCN-REMAIN-TEXT-001": 809,
    "SCN-REMAIN-DOC-001": 220,
    "SCN-REMAIN-STRUCT-001": 12,
    "SCN-REMAIN-CODE-001": 9,
}
ALLOWED_STATUSES = {
    "STRUCT_AUTO",
    "STRUCT_HUMAN_CONFIRMED",
    "TEXT_AUTO",
    "TEXT_HUMAN_CONFIRMED",
    "MARKDOWN_AUTO",
    "MARKDOWN_HUMAN_CONFIRMED",
    "CODE_AUTO",
    "CODE_HUMAN_CONFIRMED",
}
VALID_MAPPINGS = {
    ("TEXT", "plain_text", "SCN-REMAIN-TEXT-001"),
    ("STRUCT", "json", "SCN-REMAIN-STRUCT-001"),
    ("STRUCT", "yaml", "SCN-REMAIN-STRUCT-001"),
    ("MARKDOWN", "markdown", "SCN-REMAIN-DOC-001"),
    ("CODE", "code", "SCN-REMAIN-CODE-001"),
}
SCENARIO_DERIVED_FIELDS = (
    "normal_task",
    "trusted_instruction",
    "trust_boundary",
    "injection_location",
)


def load_canonical_inputs(root: Path = ROOT) -> dict[str, Any]:
    return {
        "base": read_jsonl(root / BASE_BINDING),
        "catalog": read_jsonl(root / CATALOG),
        "resolutions": {
            track: read_jsonl(root / path)
            for track, path in RESOLUTION_PATHS.items()
        },
    }


def _normalize_standard(rows: list[dict[str, Any]], track: str) -> list[dict[str, Any]]:
    normalized = []
    for row in rows:
        status = str(row.get("resolution_status") or "").strip()
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"unresolved or invalid status in {track}: {row.get('candidate_id')} {status}")
        decision = status.split("_", 1)[0]
        normalized.append(
            {
                "candidate_id": row["candidate_id"],
                "representation_decision": decision,
                "corrected_format": row.get("proposed_corrected_format"),
                "corrected_scenario_ref": row.get("proposed_corrected_scenario"),
                "resolution_status": status,
                "resolution_source_track": track,
            }
        )
    return normalized


def _normalize_small(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": row["candidate_id"],
            "representation_decision": row.get("representation_decision"),
            "corrected_format": row.get("observed_format"),
            "corrected_scenario_ref": row.get("proposed_corrected_scenario"),
            "resolution_status": "TEXT_HUMAN_CONFIRMED",
            "resolution_source_track": "SMALL",
        }
        for row in rows
    ]


def normalize_resolution_tracks(
    resolution_rows: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    if set(resolution_rows) != set(RESOLUTION_PATHS):
        raise ValueError("resolution tracks must be exactly STRUCT, MARKDOWN, SMALL, CODE")
    normalized = {
        track: (
            _normalize_small(rows)
            if track == "SMALL"
            else _normalize_standard(rows, track)
        )
        for track, rows in resolution_rows.items()
    }
    for track, rows in normalized.items():
        ids = [row["candidate_id"] for row in rows]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate candidate_id within {track}")
        for row in rows:
            mapping = (
                row["representation_decision"],
                row["corrected_format"],
                row["corrected_scenario_ref"],
            )
            if mapping not in VALID_MAPPINGS:
                raise ValueError(f"invalid canonical representation mapping: {row['candidate_id']} {mapping}")
    return normalized


def combine_normalized_tracks(
    normalized_tracks: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    combined: dict[str, dict[str, Any]] = {}
    for track, rows in normalized_tracks.items():
        for row in rows:
            candidate_id = row["candidate_id"]
            if candidate_id in combined:
                previous = combined[candidate_id]["resolution_source_track"]
                raise ValueError(
                    f"resolution track overlap for {candidate_id}: {previous} and {track}"
                )
            combined[candidate_id] = row
    return combined


def apply_resolution_map(
    base_rows: list[dict[str, Any]],
    catalog_rows: list[dict[str, Any]],
    resolution_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    base_ids = [row["candidate_id"] for row in base_rows]
    if len(base_ids) != len(set(base_ids)):
        raise ValueError("duplicate candidate_id in base binding")
    unknown = sorted(set(resolution_map) - set(base_ids))
    if unknown:
        raise ValueError(f"unknown resolution candidate IDs: {unknown}")
    catalog = {row["scenario_id"]: row for row in catalog_rows}
    if len(catalog) != len(catalog_rows):
        raise ValueError("duplicate scenario_id in catalog")

    output = copy.deepcopy(base_rows)
    for row in output:
        resolution = resolution_map.get(row["candidate_id"])
        if resolution is None:
            if row.get("input_format_observed") != "plain_text":
                raise ValueError(
                    f"non-plain pass-through candidate: {row['candidate_id']}"
                )
            row["representation_decision"] = "TEXT"
            row["input_format_corrected"] = "plain_text"
            continue

        scenario_id = resolution["corrected_scenario_ref"]
        if scenario_id not in catalog:
            raise ValueError(f"unknown corrected scenario_ref: {scenario_id}")
        scenario = catalog[scenario_id]
        scenario_changed = row["scenario_ref"] != scenario_id
        row["scenario_ref"] = scenario_id
        row["representation_decision"] = resolution["representation_decision"]
        row["input_format_corrected"] = resolution["corrected_format"]
        if scenario_changed:
            for field in SCENARIO_DERIVED_FIELDS:
                row[field] = scenario[field]
            if "untrusted_input_role" in row:
                row["untrusted_input_role"] = scenario["untrusted_input_role"]
    return output


def build_corrected_rebinding(root: Path = ROOT) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    inputs = load_canonical_inputs(root)
    if len(inputs["base"]) != 1050:
        raise ValueError(f"base binding count must be 1050, got {len(inputs['base'])}")
    actual_track_counts = {
        track: len(rows) for track, rows in inputs["resolutions"].items()
    }
    if actual_track_counts != EXPECTED_TRACK_COUNTS:
        raise ValueError(f"unexpected resolution track counts: {actual_track_counts}")

    normalized = normalize_resolution_tracks(inputs["resolutions"])
    resolution_map = combine_normalized_tracks(normalized)
    if len(resolution_map) != 643:
        raise ValueError(f"resolution union must be 643, got {len(resolution_map)}")
    output = apply_resolution_map(inputs["base"], inputs["catalog"], resolution_map)

    representation_counts = Counter(row["representation_decision"] for row in output)
    format_counts = Counter(row["input_format_corrected"] for row in output)
    scenario_counts = Counter(row["scenario_ref"] for row in output)
    if representation_counts != EXPECTED_REPRESENTATIONS:
        raise ValueError(f"unexpected representation distribution: {representation_counts}")
    if format_counts != EXPECTED_FORMATS:
        raise ValueError(f"unexpected corrected-format distribution: {format_counts}")
    if scenario_counts != EXPECTED_SCENARIOS:
        raise ValueError(f"unexpected scenario distribution: {scenario_counts}")

    audit = {
        "resolution_union_count": len(resolution_map),
        "resolution_ids": list(resolution_map),
        "pass_through_count": len(output) - len(resolution_map),
        "overlap_count": 0,
        "unresolved_count": 0,
        "representation_counts": dict(representation_counts),
        "corrected_format_counts": dict(format_counts),
        "scenario_counts": dict(scenario_counts),
    }
    return output, audit


def main() -> None:
    output_path = ROOT / OUTPUT
    if output_path.exists():
        raise FileExistsError(f"corrected rebinding output exists; refusing overwrite: {output_path}")
    rows, audit = build_corrected_rebinding(ROOT)
    write_jsonl(output_path, rows)
    print(f"output={OUTPUT.as_posix()} count={len(rows)}")
    print(
        f"resolution_union={audit['resolution_union_count']} "
        f"pass_through={audit['pass_through_count']} overlap={audit['overlap_count']}"
    )


if __name__ == "__main__":
    main()
