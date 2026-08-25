from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.dataset_a.build_corrected_rebinding_v2 import (
    BASE_BINDING,
    CATALOG,
    OUTPUT,
    RESOLUTION_PATHS,
    apply_resolution_map,
    build_corrected_rebinding,
    combine_normalized_tracks,
    load_canonical_inputs,
)
from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl


ROOT = Path(__file__).resolve().parents[2]


def test_corrected_rebinding_exact_population_and_distribution():
    output, audit = build_corrected_rebinding(ROOT)

    assert len(output) == len({row["candidate_id"] for row in output}) == 1050
    assert audit["resolution_union_count"] == 643
    assert audit["pass_through_count"] == 407
    assert audit["overlap_count"] == 0
    assert audit["unresolved_count"] == 0
    assert Counter(row["representation_decision"] for row in output) == {
        "TEXT": 809,
        "MARKDOWN": 220,
        "STRUCT": 12,
        "CODE": 9,
    }
    assert Counter(row["input_format_corrected"] for row in output) == {
        "plain_text": 809,
        "markdown": 220,
        "json": 9,
        "yaml": 3,
        "code": 9,
    }


def test_corrected_rebinding_preserves_id_order_raw_and_observed_format():
    inputs = load_canonical_inputs(ROOT)
    output, _ = build_corrected_rebinding(ROOT)

    assert [row["candidate_id"] for row in output] == [
        row["candidate_id"] for row in inputs["base"]
    ]
    for source, corrected in zip(inputs["base"], output):
        assert corrected["untrusted_input"] == source["untrusted_input"]
        assert corrected["input_format_observed"] == source["input_format_observed"]
        for field in (
            "candidate_id",
            "source_id",
            "binding_origin",
            "source_original",
            "source_context_recovered",
            "binding_status",
        ):
            assert corrected[field] == source[field]


def test_pass_through_407_preserves_every_original_field():
    inputs = load_canonical_inputs(ROOT)
    output, audit = build_corrected_rebinding(ROOT)
    corrected_by_id = {row["candidate_id"]: row for row in output}
    resolution_ids = set(audit["resolution_ids"])
    pass_through = [
        row for row in inputs["base"] if row["candidate_id"] not in resolution_ids
    ]

    assert len(pass_through) == 407
    for source in pass_through:
        corrected = corrected_by_id[source["candidate_id"]]
        assert {field: corrected[field] for field in source} == source
        assert corrected["representation_decision"] == "TEXT"
        assert corrected["input_format_corrected"] == "plain_text"


def test_code_keeps_code_block_observation_and_uses_code_canonical_format():
    output, _ = build_corrected_rebinding(ROOT)
    code = [row for row in output if row["representation_decision"] == "CODE"]

    assert len(code) == 9
    assert {row["input_format_observed"] for row in code} == {
        "code_block",
        "markdown",
    }
    assert {row["input_format_corrected"] for row in code} == {"code"}
    assert {row["scenario_ref"] for row in code} == {"SCN-REMAIN-CODE-001"}


def test_all_scenario_derived_fields_match_selected_catalog():
    inputs = load_canonical_inputs(ROOT)
    output, _ = build_corrected_rebinding(ROOT)
    catalog = {row["scenario_id"]: row for row in inputs["catalog"]}

    for row in output:
        scenario = catalog[row["scenario_ref"]]
        for field in (
            "normal_task",
            "trusted_instruction",
            "trust_boundary",
            "injection_location",
        ):
            assert row[field] == scenario[field]


def test_resolution_tracks_are_disjoint_and_exact_canonical_inputs_exist():
    inputs = load_canonical_inputs(ROOT)
    assert len(inputs["base"]) == 1050
    assert len(inputs["catalog"]) == 4
    assert {track: len(rows) for track, rows in inputs["resolutions"].items()} == {
        "STRUCT": 299,
        "MARKDOWN": 105,
        "SMALL": 6,
        "CODE": 233,
    }
    assert all((ROOT / path).exists() for path in RESOLUTION_PATHS.values())
    assert (ROOT / BASE_BINDING).exists()
    assert (ROOT / CATALOG).exists()


def test_combine_tracks_fails_closed_on_overlap():
    row = {
        "candidate_id": "A",
        "representation_decision": "TEXT",
        "corrected_format": "plain_text",
        "corrected_scenario_ref": "SCN-REMAIN-TEXT-001",
        "resolution_status": "TEXT_AUTO",
        "resolution_source_track": "STRUCT",
    }
    duplicate = {**row, "resolution_source_track": "CODE"}
    with pytest.raises(ValueError, match="overlap"):
        combine_normalized_tracks({"STRUCT": [row], "CODE": [duplicate]})


def test_apply_fails_closed_on_unknown_resolution_id():
    inputs = load_canonical_inputs(ROOT)
    unknown = {
        "DA-RAW-999999": {
            "candidate_id": "DA-RAW-999999",
            "representation_decision": "TEXT",
            "corrected_format": "plain_text",
            "corrected_scenario_ref": "SCN-REMAIN-TEXT-001",
            "resolution_status": "TEXT_AUTO",
            "resolution_source_track": "STRUCT",
        }
    }
    with pytest.raises(ValueError, match="unknown resolution candidate"):
        apply_resolution_map(inputs["base"], inputs["catalog"], unknown)


def test_apply_does_not_mutate_inputs():
    inputs = load_canonical_inputs(ROOT)
    source = deepcopy(inputs["base"])
    build_corrected_rebinding(ROOT)
    assert inputs["base"] == source


def test_written_corrected_rebinding_artifact_is_exactly_reproducible():
    expected, _ = build_corrected_rebinding(ROOT)
    assert read_jsonl(ROOT / OUTPUT) == expected
