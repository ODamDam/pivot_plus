#!/usr/bin/env python3
"""Shared, side-effect-free helpers for Dataset A AI first-pass API tooling."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


PROMPT_VERSION = "dataset-a-ai-first-pass-v1.0"
RUN_SCHEMA_VERSION = "dataset_a_ai_first_pass_api_run_v1.0"
DEFAULT_MODEL = "gpt-5.6-terra"
DEFAULT_REASONING_EFFORT = "medium"
DEFAULT_MAX_OUTPUT_TOKENS = 2000


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
    return records


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_system_instructions(prompt_markdown: str) -> str:
    marker = "## System instructions"
    next_marker = "## Per-record user input template"
    if marker not in prompt_markdown or next_marker not in prompt_markdown:
        raise ValueError("prompt document is missing required section markers")
    section = prompt_markdown.split(marker, 1)[1].split(next_marker, 1)[0].strip()
    if not section:
        raise ValueError("system instructions section is empty")
    return section


def build_request_envelope(
    case: dict[str, Any],
    system_instructions: str,
    schema: dict[str, Any],
    model: str,
    reasoning_effort: str,
    max_output_tokens: int,
) -> dict[str, Any]:
    candidate_id = case["candidate_id"]
    user_text = (
        f"Annotate this blinded candidate under {PROMPT_VERSION}.\n\n"
        "<CASE_JSON>\n"
        f"{json.dumps(case, ensure_ascii=False, separators=(',', ':'))}\n"
        "</CASE_JSON>"
    )
    return {
        "custom_id": candidate_id,
        "method": "POST",
        "url": "/v1/responses",
        "body": {
            "model": model,
            "reasoning": {"effort": reasoning_effort},
            "input": [
                {
                    "role": "system",
                    "content": [{"type": "input_text", "text": system_instructions}],
                },
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": user_text}],
                },
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "dataset_a_ai_first_pass_v1",
                    "strict": True,
                    "schema": schema,
                }
            },
            "max_output_tokens": max_output_tokens,
            "store": False,
        },
    }


def _mock_annotation(candidate_id: str) -> dict[str, Any]:
    """Return a schema-valid neutral annotation for transport-only dry runs."""
    return {
        "candidate_id": candidate_id,
        "record_validity": "valid",
        "instruction_present": True,
        "boundary_evaluable_from_record": False,
        "curation_recommendation": "needs_scenario_binding",
        "pi_assessment": "not_assignable",
        "maliciousness": "uncertain",
        "injection_mode": "ambiguous",
        "context_dependent": True,
        "attack_techniques": [],
        "risk_patterns": [],
        "hard_negative_type": "none",
        "attacker_goal_summary": "",
        "missing_information": ["Dry-run mock; no model judgment was performed."],
        "evidence_spans": [],
        "brief_rationale": "Synthetic dry-run output used only to validate the pipeline.",
        "confidence": "low",
        "human_review_required": True,
        "human_review_reason": "Dry-run mock; replace with an actual API response.",
    }


def make_dry_run_response(request: dict[str, Any]) -> dict[str, Any]:
    candidate_id = request["custom_id"]
    annotation = _mock_annotation(candidate_id)
    output_text = json.dumps(annotation, ensure_ascii=False, separators=(",", ":"))
    return {
        "custom_id": candidate_id,
        "response": {
            "status_code": 200,
            "request_id": f"dryrun-{candidate_id}",
            "body": {
                "id": f"dryrun_{candidate_id}",
                "object": "response",
                "created_at": 0,
                "status": "completed",
                "model": request["body"]["model"],
                "output": [
                    {
                        "type": "message",
                        "id": f"dryrun_message_{candidate_id}",
                        "status": "completed",
                        "role": "assistant",
                        "content": [
                            {
                                "type": "output_text",
                                "text": output_text,
                                "annotations": [],
                            }
                        ],
                    }
                ],
                "usage": {
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                },
                "_dry_run": True,
            },
        },
        "error": None,
    }


def extract_structured_output(raw_record: dict[str, Any]) -> dict[str, Any]:
    if raw_record.get("error"):
        raise ValueError(f"API error: {raw_record['error']}")
    response = raw_record.get("response")
    if not isinstance(response, dict):
        raise ValueError("missing response envelope")
    if response.get("status_code") != 200:
        raise ValueError(f"non-200 response: {response.get('status_code')}")
    body = response.get("body")
    if not isinstance(body, dict):
        raise ValueError("missing response body")
    if body.get("status") != "completed":
        raise ValueError(f"response status is {body.get('status')!r}, not 'completed'")

    texts: list[str] = []
    refusals: list[str] = []
    for item in body.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                texts.append(content["text"])
            elif content.get("type") == "refusal":
                refusals.append(str(content.get("refusal", "")))
    if refusals:
        raise ValueError(f"model refusal: {'; '.join(refusals)}")
    if len(texts) != 1:
        raise ValueError(f"expected exactly one output_text item, found {len(texts)}")
    try:
        parsed = json.loads(texts[0])
    except json.JSONDecodeError as exc:
        raise ValueError(f"output_text is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("structured output must be a JSON object")
    return parsed


def validate_annotation_semantics(candidate_id: str, annotation: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if annotation.get("candidate_id") != candidate_id:
        errors.append("candidate_id does not match request custom_id")
    if annotation.get("pi_assessment") == "not_assignable" and annotation.get(
        "boundary_evaluable_from_record"
    ) is not False:
        errors.append("not_assignable requires boundary_evaluable_from_record=false")
    if annotation.get("record_validity") == "invalid":
        if annotation.get("pi_assessment") != "invalid":
            errors.append("record_validity=invalid requires pi_assessment=invalid")
        if annotation.get("curation_recommendation") != "exclude_invalid":
            errors.append("record_validity=invalid requires exclude_invalid")
    if annotation.get("maliciousness") == "uncertain" and not annotation.get(
        "missing_information", ["not-present-in-test-schema"]
    ):
        errors.append("maliciousness=uncertain requires missing_information")
    if annotation.get("human_review_required") and not annotation.get("human_review_reason"):
        errors.append("human_review_required=true requires human_review_reason")
    return errors


def validate_schema_subset(instance: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Validate the JSON Schema keywords used by the first-pass schema.

    This fallback keeps dry-run verification usable in minimal Python environments.
    Full validation still uses ``jsonschema`` when that package is available.
    """
    errors: list[str] = []
    expected = schema.get("type")
    type_map = {
        "object": dict,
        "array": list,
        "string": str,
        "boolean": bool,
        "number": (int, float),
        "integer": int,
        "null": type(None),
    }
    if expected in type_map:
        valid_type = isinstance(instance, type_map[expected])
        if expected in {"number", "integer"} and isinstance(instance, bool):
            valid_type = False
        if not valid_type:
            return [f"{path}: expected {expected}"]

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value is not in enum")
    if isinstance(instance, str):
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            errors.append(f"{path}: string does not match pattern")
        if len(instance) > schema.get("maxLength", len(instance)):
            errors.append(f"{path}: string exceeds maxLength")
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required property {key}")
        if schema.get("additionalProperties") is False:
            for key in instance.keys() - properties.keys():
                errors.append(f"{path}: unexpected property {key}")
        for key, value in instance.items():
            if key in properties:
                errors.extend(validate_schema_subset(value, properties[key], f"{path}.{key}"))
    if isinstance(instance, list):
        if len(instance) > schema.get("maxItems", len(instance)):
            errors.append(f"{path}: array exceeds maxItems")
        if schema.get("uniqueItems"):
            serialized = [json.dumps(item, sort_keys=True, ensure_ascii=False) for item in instance]
            if len(serialized) != len(set(serialized)):
                errors.append(f"{path}: array items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, value in enumerate(instance):
                errors.extend(validate_schema_subset(value, item_schema, f"{path}[{index}]"))
    return errors
