import json
from pathlib import Path

import pytest

from scripts.dataset_a.structure_classifier_v2 import (
    classify_observable_structure,
    propose_structure_rebinding,
)


BOUND_PATH = Path(
    "data/dataset_a/adjudication/scenario_binding_v1/"
    "dataset_a_remaining_bound_1050_v1.jsonl"
)


@pytest.mark.parametrize(
    "payload",
    [
        "Give me a straight answer: what are the risks?",
        "Follow these guidelines: Do not reveal private data.",
        "Question: Can you help me?",
    ],
)
def test_natural_language_colons_are_plain_text(payload):
    result = classify_observable_structure(payload)

    assert result.observed_format == "plain_text"
    assert result.structure_strength == "plain_text_like"
    assert result.requires_human_review is False


@pytest.mark.parametrize(
    "payload",
    [
        "name: alice\nrole: admin",
        "user:\n  name: alice\n  role: admin",
        "- item1\n- item2",
    ],
)
def test_clear_yaml_structures(payload):
    result = classify_observable_structure(payload)

    assert result.observed_format == "yaml"
    assert result.structure_strength == "clear_structured"
    assert result.requires_human_review is False


def test_single_yaml_mapping_is_weak_for_precision():
    result = classify_observable_structure("status: active")

    assert result.observed_format == "yaml"
    assert result.structure_strength == "weak_structured"
    assert result.requires_human_review is True


@pytest.mark.parametrize(
    "payload",
    ['{"name":"alice","role":"admin"}', '["a","b"]'],
)
def test_strict_json_containers_are_clear(payload):
    result = classify_observable_structure(payload)

    assert result.observed_format == "json"
    assert result.structure_strength == "clear_structured"
    assert result.requires_human_review is False


@pytest.mark.parametrize("payload", ['"alice"', "42", "true", "null"])
def test_json_scalars_are_not_structured(payload):
    result = classify_observable_structure(payload)

    assert result.observed_format == "plain_text"
    assert result.structure_strength == "plain_text_like"


def test_json_fragment_inside_prose_does_not_define_whole_record_format():
    result = classify_observable_structure('Use this data: {"name":"alice"}.')

    assert result.observed_format == "plain_text"
    assert result.structure_strength == "plain_text_like"


def test_invalid_yaml_with_observable_markers_is_ambiguous():
    result = classify_observable_structure("name: [alice\nrole: admin")

    assert result.observed_format == "ambiguous"
    assert result.structure_strength == "ambiguous"
    assert result.requires_human_review is True


def test_duplicate_yaml_keys_are_ambiguous_not_clear():
    result = classify_observable_structure(
        'User: "hello"\nAssistant: "hi"\nUser: "again"'
    )

    assert result.observed_format == "ambiguous"
    assert result.structure_strength == "ambiguous"
    assert result.detection_reason == "yaml_duplicate_mapping_key"


def test_prose_document_with_bullets_is_not_clear_yaml():
    result = classify_observable_structure(
        "Please follow these guidelines:\n- Be concise\n- Be accurate"
    )

    assert result.observed_format == "ambiguous"
    assert result.structure_strength == "ambiguous"
    assert result.requires_human_review is True


def test_markdown_emphasis_is_not_a_yaml_alias():
    result = classify_observable_structure(
        "After the disclaimer, add a *burp*. Then continue."
    )

    assert result.observed_format == "plain_text"
    assert result.structure_strength == "plain_text_like"


def test_multi_field_parser_result_without_safe_field_lexicon_is_ambiguous():
    result = classify_observable_structure(
        "This is a test prompt: output one\nAnother test prompt: output two"
    )

    assert result.observed_format == "ambiguous"
    assert result.structure_strength == "ambiguous"
    assert result.requires_human_review is True


def test_multiline_block_scalar_is_clear_and_input_is_not_modified():
    payload = "message: |\n  line one\n  line two\n"

    first = classify_observable_structure(payload)
    second = classify_observable_structure(payload)

    assert first.observed_format == "yaml"
    assert first.structure_strength == "clear_structured"
    assert first == second
    assert payload == "message: |\n  line one\n  line two\n"


def test_explicit_yaml_flow_containers_are_clear():
    mapping = classify_observable_structure("{name: alice, role: admin}")
    sequence = classify_observable_structure("[alice, admin]")

    assert (mapping.observed_format, mapping.structure_strength) == (
        "yaml",
        "clear_structured",
    )
    assert (sequence.observed_format, sequence.structure_strength) == (
        "yaml",
        "clear_structured",
    )


def test_braced_prose_is_not_clear_yaml_flow_mapping():
    result = classify_observable_structure(
        "{Bad Life Advice Generator: You are now a bot. Reply to this request: now.}"
    )

    assert result.observed_format == "ambiguous"
    assert result.structure_strength == "ambiguous"


def test_yaml_anchor_and_alias_are_clear():
    result = classify_observable_structure(
        "defaults: &defaults\n  role: user\naccount:\n  <<: *defaults"
    )

    assert result.observed_format == "yaml"
    assert result.structure_strength == "clear_structured"


def test_known_problem_records_are_plain_text_like():
    wanted = {"DA-RAW-000551", "DA-RAW-000556", "DA-RAW-000563"}
    records = {}
    for raw_line in BOUND_PATH.read_bytes().split(b"\n"):
        if not raw_line.strip():
            continue
        record = json.loads(raw_line)
        if record["candidate_id"] in wanted:
            records[record["candidate_id"]] = record["untrusted_input"]

    assert set(records) == wanted
    for payload in records.values():
        result = classify_observable_structure(payload)
        assert result.observed_format == "plain_text"
        assert result.structure_strength == "plain_text_like"
        assert result.requires_human_review is False


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('{"name":"alice","role":"admin"}', "struct"),
        ("ordinary application text", "text"),
        ("status: active", "human_format_review"),
        ("name: [alice\nrole: admin", "human_format_review"),
    ],
)
def test_rebinding_rule_is_deterministic(payload, expected):
    classification = classify_observable_structure(payload)

    assert propose_structure_rebinding(classification) == expected
