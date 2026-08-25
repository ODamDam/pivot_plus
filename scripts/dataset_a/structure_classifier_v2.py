"""High-precision observable JSON/YAML structure classifier for Dataset A.

This module is intentionally independent from the historical structure-intact
extractor.  It classifies representation only; payload meaning, PI status, and
maliciousness are outside its scope.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

import yaml
from yaml.nodes import MappingNode


ObservedFormat = Literal["json", "yaml", "plain_text", "ambiguous"]
StructureStrength = Literal[
    "clear_structured",
    "weak_structured",
    "plain_text_like",
    "ambiguous",
]
StructureRebinding = Literal["struct", "text", "human_format_review"]


@dataclass(frozen=True)
class StructureClassification:
    observed_format: ObservedFormat
    structure_strength: StructureStrength
    detection_reason: str
    requires_human_review: bool


_MAPPING_LINE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<key>"
    r"[A-Za-z_][\w.-]*|<<|['\"][^'\"\r\n]+['\"]"
    r")\s*:\s*(?P<value>.*)$"
)
_SEQUENCE_LINE = re.compile(r"^(?P<indent>[ \t]*)-\s+\S.*$")
_DOCUMENT_MARKER = re.compile(r"^\s*(?:---|\.\.\.)\s*(?:#.*)?$")
_BLOCK_SCALAR = re.compile(
    r"^\s*(?:[A-Za-z_][\w.-]*|['\"][^'\"\r\n]+['\"]|<<)"
    r"\s*:\s*[>|][+-]?\d?\s*(?:#.*)?$"
)
_ANCHOR_OR_ALIAS = re.compile(r"(?<!\S)(?:&|\*)[A-Za-z_][\w.-]*(?=\s|$)")
_EXPLICIT_TAG = re.compile(r"(?<!\S)(?:!![A-Za-z_][\w:/.+-]*|!<[^>]+>)(?=\s|$)")


class _DuplicateKeyError(yaml.YAMLError):
    pass


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    if not isinstance(node, MappingNode):
        return loader.construct_mapping(node, deep=deep)
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        marker = repr(key)
        if marker in seen:
            raise _DuplicateKeyError("duplicate mapping key")
        seen.add(marker)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _plain(reason: str) -> StructureClassification:
    return StructureClassification(
        observed_format="plain_text",
        structure_strength="plain_text_like",
        detection_reason=reason,
        requires_human_review=False,
    )


def _ambiguous(reason: str) -> StructureClassification:
    return StructureClassification(
        observed_format="ambiguous",
        structure_strength="ambiguous",
        detection_reason=reason,
        requires_human_review=True,
    )


def _looks_like_inline_prose_mapping(match: re.Match[str], line: str) -> bool:
    """Reject the common ``Question: natural sentence?`` YAML false positive.

    This is deliberately lexical. It does not inspect what the words mean.
    A single unindented line whose value is sentence-length and ends in question
    or exclamation punctuation is treated as prose rather than configuration.
    """

    value = match.group("value").strip()
    return (
        "\n" not in line
        and not match.group("indent")
        and len(value.split()) >= 3
        and value.endswith(("?", "!"))
    )


def classify_observable_structure(payload: str) -> StructureClassification:
    """Classify whole-record observable JSON/YAML representation.

    Precision is preferred over recall. Only ``clear_structured`` records are
    eligible for automatic STRUCT rebinding; weak and ambiguous results require
    human format review.
    """

    if not isinstance(payload, str):
        raise TypeError("payload must be a string")

    stripped = payload.strip()
    if not stripped:
        return _plain("empty_or_whitespace_only")

    json_scalar = False
    try:
        parsed_json = json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        parsed_json = None
    else:
        if isinstance(parsed_json, (dict, list)):
            return StructureClassification(
                observed_format="json",
                structure_strength="clear_structured",
                detection_reason="strict_json_top_level_container",
                requires_human_review=False,
            )
        json_scalar = True

    lines = stripped.splitlines()
    mapping_matches = [
        match
        for line in lines
        if (match := _MAPPING_LINE.match(line)) is not None
    ]
    sequence_matches = [
        match
        for line in lines
        if (match := _SEQUENCE_LINE.match(line)) is not None
    ]
    document_marker_count = sum(bool(_DOCUMENT_MARKER.match(line)) for line in lines)
    block_scalar_count = sum(bool(_BLOCK_SCALAR.match(line)) for line in lines)
    anchor_alias_count = len(_ANCHOR_OR_ALIAS.findall(stripped))
    explicit_tag_count = len(_EXPLICIT_TAG.findall(stripped))
    explicit_flow = (
        len(lines) == 1
        and (
            (stripped.startswith("{") and stripped.endswith("}"))
            or (stripped.startswith("[") and stripped.endswith("]"))
        )
    )

    has_lexical_evidence = any(
        (
            mapping_matches,
            sequence_matches,
            document_marker_count,
            block_scalar_count,
            anchor_alias_count,
            explicit_tag_count,
            explicit_flow,
        )
    )
    if not has_lexical_evidence:
        try:
            parser_only_yaml = yaml.load(stripped, Loader=_UniqueKeySafeLoader)
        except _DuplicateKeyError:
            return _ambiguous("yaml_duplicate_mapping_key")
        except yaml.YAMLError:
            parser_only_yaml = None
        if isinstance(parser_only_yaml, (dict, list)) and len(parser_only_yaml) >= 2:
            return _ambiguous("yaml_multifield_without_high_precision_lexical_evidence")
        reason = "json_scalar_not_container" if json_scalar else "no_observable_structure"
        return _plain(reason)

    try:
        parsed_yaml = yaml.load(stripped, Loader=_UniqueKeySafeLoader)
    except _DuplicateKeyError:
        return _ambiguous("yaml_duplicate_mapping_key")
    except yaml.YAMLError:
        return _ambiguous("yaml_lexical_evidence_parse_failure")

    if not isinstance(parsed_yaml, (dict, list)):
        return _ambiguous("yaml_markers_without_top_level_container")

    if explicit_flow and len(parsed_yaml) >= 2:
        simple_flow_mapping = not isinstance(parsed_yaml, dict) or all(
            isinstance(key, str)
            and re.fullmatch(r"[A-Za-z_][\w.-]{0,63}", key) is not None
            for key in parsed_yaml
        )
        if simple_flow_mapping:
            return StructureClassification(
                observed_format="yaml",
                structure_strength="clear_structured",
                detection_reason="explicit_yaml_flow_container",
                requires_human_review=False,
            )
        return _ambiguous("flow_mapping_with_non_field_keys")

    if (
        len(lines) == 1
        and len(mapping_matches) == 1
        and _looks_like_inline_prose_mapping(mapping_matches[0], lines[0])
    ):
        return _plain("single_line_sentence_colon")

    structural_line_numbers = {
        index
        for index, line in enumerate(lines)
        if (
            _MAPPING_LINE.match(line)
            or _SEQUENCE_LINE.match(line)
            or _DOCUMENT_MARKER.match(line)
            or not line.strip()
            or line.lstrip().startswith("#")
            or line[:1].isspace()
        )
    }
    unframed_prose = len(structural_line_numbers) != len(lines)
    if unframed_prose and (mapping_matches or sequence_matches):
        return _ambiguous("mixed_prose_and_yaml_markers")

    indentation_levels = {
        len(match.group("indent").replace("\t", "    "))
        for match in mapping_matches + sequence_matches
    }
    nested = any(level > 0 for level in indentation_levels)
    clear = any(
        (
            len(mapping_matches) >= 2,
            len(sequence_matches) >= 2,
            nested,
            block_scalar_count > 0,
            anchor_alias_count > 0,
            explicit_tag_count > 0 and bool(mapping_matches or sequence_matches),
            document_marker_count > 0
            and bool(mapping_matches or sequence_matches),
        )
    )

    if clear:
        features = []
        if len(mapping_matches) >= 2:
            features.append("multi_key_mapping")
        if len(sequence_matches) >= 2:
            features.append("multi_item_sequence")
        if nested:
            features.append("nested_structure")
        if block_scalar_count:
            features.append("block_scalar")
        if anchor_alias_count:
            features.append("anchor_or_alias")
        if explicit_tag_count:
            features.append("explicit_tag")
        if document_marker_count:
            features.append("document_marker")
        return StructureClassification(
            observed_format="yaml",
            structure_strength="clear_structured",
            detection_reason="yaml_" + "+".join(features),
            requires_human_review=False,
        )

    return StructureClassification(
        observed_format="yaml",
        structure_strength="weak_structured",
        detection_reason="single_yaml_mapping_or_sequence",
        requires_human_review=True,
    )


def propose_structure_rebinding(
    classification: StructureClassification,
) -> StructureRebinding:
    """Map a v2 result to the correction action without changing artifacts."""

    if classification.structure_strength == "clear_structured":
        return "struct"
    if classification.structure_strength == "plain_text_like":
        return "text"
    return "human_format_review"
