"""Read-only morphology analysis for unresolved Dataset A code-block candidates."""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import scripts.dataset_a.code_classifier_v1 as code_classifier
from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl, write_jsonl
from scripts.dataset_a.markdown_classifier_v1 import classify_observable_markdown


ROOT = _PROJECT_ROOT
QUEUE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_code_human_review_queue_v1.jsonl")
RESOLUTION = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_code_resolution_233_v1.jsonl")
BOUND = Path("data/dataset_a/adjudication/scenario_binding_v1/dataset_a_remaining_bound_1050_v1.jsonl")
MARKDOWN_QUEUE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_markdown_human_review_queue_v1.jsonl")
OUTPUT = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_code_morphology_224_v1.jsonl")

_FENCE_RE = re.compile(r"(?m)^\s{0,3}(`{3,}|~{3,})([^\n\r]*)\r?$")
_HEADING_RE = re.compile(r"(?m)^\s{0,3}#{1,6}[ \t]+\S")
_LIST_RE = re.compile(r"(?m)^\s{0,6}(?:[-+*][ \t]+|\d+[.)][ \t]+)\S")
_LABEL_RE = re.compile(r"^\s*[A-Za-z][A-Za-z0-9 _/-]{0,40}:\s*$")
_INSTRUCTION_RE = re.compile(r"^\s*(?:please\b|use\b|run\b|execute\b|answer\b|write\b|review\b|print\b|now\b|then\b|return\b|output\b)", re.I)


def _line_content_start(text: str, match: re.Match[str]) -> int:
    newline = text.find("\n", match.end())
    return len(text) if newline == -1 else newline + 1


def _parse_fences(text: str) -> dict[str, Any]:
    delimiters = list(_FENCE_RE.finditer(text))
    blocks: list[dict[str, Any]] = []
    used: set[int] = set()
    unbalanced = 0
    for index, opener in enumerate(delimiters):
        if index in used:
            continue
        token = opener.group(1)
        close_index = None
        for candidate_index in range(index + 1, len(delimiters)):
            if candidate_index in used:
                continue
            candidate = delimiters[candidate_index].group(1)
            if candidate[0] == token[0] and len(candidate) >= len(token):
                close_index = candidate_index
                break
        content_start = _line_content_start(text, opener)
        language = opener.group(2).strip().split(maxsplit=1)[0] if opener.group(2).strip() else None
        used.add(index)
        if close_index is None:
            unbalanced += 1
            blocks.append({
                "open_start": opener.start(), "open_end": content_start,
                "close_start": len(text), "close_end": len(text),
                "content": text[content_start:], "language": language,
                "balanced": False,
            })
        else:
            closer = delimiters[close_index]
            used.add(close_index)
            blocks.append({
                "open_start": opener.start(), "open_end": content_start,
                "close_start": closer.start(), "close_end": _line_content_start(text, closer),
                "content": text[content_start:closer.start()], "language": language,
                "balanced": True,
            })

    outside_parts: list[str] = []
    cursor = 0
    for block in blocks:
        outside_parts.append(text[cursor:block["open_start"]])
        cursor = block["close_end"] if block["balanced"] else len(text)
    outside_parts.append(text[cursor:])
    return {
        "delimiters": delimiters,
        "blocks": blocks,
        "outside": "".join(outside_parts),
        "inside": "".join(block["content"] for block in blocks),
        "unbalanced": unbalanced,
    }


def _nonblank_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def _sentence_like(line: str) -> bool:
    stripped = line.strip()
    words = re.findall(r"[A-Za-zÀ-ž]+", stripped)
    return len(words) >= 5 or (len(words) >= 3 and stripped.endswith((".", "?", "!")))


def _inside_features(text: str) -> dict[str, Any]:
    counts, family, density = code_classifier._signal_counts(text)
    nonblank = _nonblank_lines(text)
    return {
        "imports": counts.get("python_import", 0),
        "definitions": counts.get("python_def_class", 0) + counts.get("javascript_function", 0) + counts.get("c_include_main", 0),
        "assignments": counts.get("assignment", 0) + counts.get("javascript_decl", 0),
        "control_flow": counts.get("python_control", 0),
        "calls": counts.get("function_call", 0),
        "source_comments": counts.get("source_comment", 0),
        "shell_syntax": counts.get("shell_shebang", 0) + counts.get("shell_syntax", 0) + counts.get("powershell", 0) + counts.get("batch", 0),
        "sql_syntax": counts.get("sql_select", 0) + counts.get("sql_from", 0) + counts.get("sql_clause", 0),
        "code_signal_count": sum(counts.values()),
        "code_line_count": round(density * len(nonblank)),
        "code_density": round(density, 6),
        "language_family": family,
    }


def analyze_code_morphology(text: str) -> dict[str, Any]:
    parsed = _parse_fences(text)
    blocks, outside, inside = parsed["blocks"], parsed["outside"], parsed["inside"]
    balanced_blocks = [block for block in blocks if block["balanced"]]
    outside_lines = _nonblank_lines(outside)
    inside_lines = _nonblank_lines(inside)
    total_lines = _nonblank_lines(text)
    fenced_chars = sum(len(block["content"]) for block in blocks)
    outside_chars = len(outside)
    meaningful_chars = fenced_chars + outside_chars
    fenced_char_ratio = fenced_chars / max(1, meaningful_chars)
    fenced_line_ratio = len(inside_lines) / max(1, len(inside_lines) + len(outside_lines))
    inside_features = _inside_features(inside)
    outside_features = _inside_features(outside)
    outside_heading_lines = len(_HEADING_RE.findall(outside))
    outside_list_lines = len(_LIST_RE.findall(outside))
    outside_sentence_lines = sum(_sentence_like(line) for line in outside_lines)
    outside_instruction_lines = sum(bool(_INSTRUCTION_RE.match(line)) for line in outside_lines)
    outside_label_lines = sum(bool(_LABEL_RE.fullmatch(line)) for line in outside_lines)
    markdown = classify_observable_markdown(outside)

    if parsed["unbalanced"]:
        topology = "UNBALANCED_OR_MALFORMED"
    elif not balanced_blocks:
        topology = "NO_VALID_FENCE"
    elif len(balanced_blocks) >= 2:
        topology = "MULTI_BLOCK_DOCUMENT"
    elif not outside.strip():
        topology = "WHOLE_RECORD_FENCE"
    elif len(outside_lines) <= 2:
        topology = "CODE_WITH_SHORT_WRAPPER"
    else:
        topology = "PROSE_WITH_CODE_EXAMPLE"

    whole_classification = code_classifier.classify_observable_code(text)
    if topology == "NO_VALID_FENCE" and whole_classification.code_strength == "clear_code":
        dominance = "CODE_DOMINANT_HIGH"
        reason = "whole_record_language_consistent_source_without_fence"
    elif (
        balanced_blocks
        and fenced_char_ratio >= 0.90
        and len(outside_lines) <= 2
        and inside_features["code_signal_count"] >= 2
        and inside_features["code_density"] >= 0.35
        and outside_heading_lines < 2
    ):
        dominance = "CODE_DOMINANT_HIGH"
        reason = "balanced_high_ratio_high_density_fenced_source"
    elif (
        topology == "MULTI_BLOCK_DOCUMENT"
        and (outside_heading_lines >= 2 or markdown.markdown_strength == "clear_markdown")
    ):
        dominance = "MARKDOWN_DOMINANT_HIGH"
        reason = "multi_block_markdown_document_organization"
    elif (
        whole_classification.competing_format == "markdown"
        and topology in {"UNBALANCED_OR_MALFORMED", "NO_VALID_FENCE"}
    ):
        dominance = "MIXED"
        reason = "malformed_or_inline_markdown_code_wrapper_competition"
    elif (
        fenced_char_ratio <= 0.30
        and len(outside_lines) >= 4
        and inside_features["code_signal_count"] < 2
        and outside_sentence_lines >= 2
    ):
        dominance = "TEXT_DOMINANT_HIGH"
        reason = "substantial_outside_prose_with_small_low_signal_fence"
    elif balanced_blocks and topology in {"PROSE_WITH_CODE_EXAMPLE", "MULTI_BLOCK_DOCUMENT"}:
        dominance = "MIXED"
        reason = "fenced_content_and_outside_document_compete"
    else:
        dominance = "UNCERTAIN"
        reason = "insufficient_or_malformed_dominance_evidence"

    languages = [block["language"] for block in blocks if block["language"]]
    result = {
        "fence_topology": topology,
        "fence_count": len(parsed["delimiters"]),
        "fenced_block_count": len(blocks),
        "balanced_fence_count": len(balanced_blocks),
        "unbalanced_fence_count": parsed["unbalanced"],
        "fence_languages": languages,
        "first_fence_start_offset": parsed["delimiters"][0].start() if parsed["delimiters"] else None,
        "last_fence_end_offset": parsed["delimiters"][-1].end() if parsed["delimiters"] else None,
        "total_chars": len(text),
        "total_nonblank_lines": len(total_lines),
        "fenced_chars": fenced_chars,
        "outside_fence_chars": outside_chars,
        "fenced_char_ratio": round(fenced_char_ratio, 6),
        "fenced_lines": len(inside_lines),
        "outside_fence_lines": len(outside_lines),
        "fenced_line_ratio": round(fenced_line_ratio, 6),
        "outside_prose_ratio": round(outside_chars / max(1, meaningful_chars), 6),
        "outside_nonblank_lines": len(outside_lines),
        "outside_sentence_like_lines": outside_sentence_lines,
        "outside_instruction_like_lines": outside_instruction_lines,
        "outside_markdown_heading_lines": outside_heading_lines,
        "outside_list_lines": outside_list_lines,
        "outside_label_lines": outside_label_lines,
        "inside_imports": inside_features["imports"],
        "inside_definitions": inside_features["definitions"],
        "inside_assignments": inside_features["assignments"],
        "inside_control_flow": inside_features["control_flow"],
        "inside_calls": inside_features["calls"],
        "inside_source_comments": inside_features["source_comments"],
        "inside_shell_syntax": inside_features["shell_syntax"],
        "inside_sql_syntax": inside_features["sql_syntax"],
        "code_signal_count_inside": inside_features["code_signal_count"],
        "code_line_count_inside": inside_features["code_line_count"],
        "code_density_inside": inside_features["code_density"],
        "code_signal_count_outside": outside_features["code_signal_count"],
        "code_density_whole": round(code_classifier._signal_counts(text)[2], 6),
        "natural_language_density_whole": round(outside_sentence_lines / max(1, len(total_lines)), 6),
        "markdown_document_signals_outside": list(markdown.markdown_signals),
        "detected_language_inside": inside_features["language_family"],
        "provisional_dominance_class": dominance,
        "provisional_reason": reason,
    }
    return result


def calibration_anchors(root: Path = ROOT) -> dict[str, dict[str, Any]]:
    resolutions = read_jsonl(root / RESOLUTION)
    bound = {row["candidate_id"]: row for row in read_jsonl(root / BOUND)}
    anchors: dict[str, dict[str, Any]] = {}
    for row in resolutions:
        decision = row.get("human_representation_decision")
        if decision not in {"CODE", "MARKDOWN"}:
            continue
        morphology = analyze_code_morphology(bound[row["candidate_id"]]["untrusted_input"])
        morphology["anchor_type"] = f"REUSABLE_{decision}"
        anchors[row["candidate_id"]] = morphology
    markdown_queue = read_jsonl(root / MARKDOWN_QUEUE)
    external = next(row for row in markdown_queue if row["candidate_id"] == "DA-RAW-000970")
    morphology = analyze_code_morphology(external["raw_text"])
    morphology["anchor_type"] = "EXTERNAL_MARKDOWN_ORIGIN_CODE"
    anchors["DA-RAW-000970"] = morphology
    return anchors


def build_morphology_artifact(root: Path = ROOT) -> list[dict[str, Any]]:
    queue = read_jsonl(root / QUEUE)
    assert len(queue) == len({row["candidate_id"] for row in queue}) == 224
    records = []
    for source in queue:
        assert source["resolution_status"] == "HUMAN_REVIEW_REQUIRED"
        morphology = analyze_code_morphology(source["raw_text"])
        records.append({
            "candidate_id": source["candidate_id"],
            **morphology,
            "existing_classifier_observed_format": source["classifier_observed_format"],
            "existing_classifier_code_strength": source["classifier_code_strength"],
            "existing_classifier_reason": source["classifier_reason"],
            "existing_detected_language": source["detected_language_family"],
            "existing_competing_format": source["competing_format"],
            "existing_resolution_status": source["resolution_status"],
        })
    return records


def main() -> None:
    output = ROOT / OUTPUT
    if output.exists():
        raise FileExistsError("CODE morphology output already exists; refusing overwrite")
    records = build_morphology_artifact(ROOT)
    write_jsonl(output, records)
    print(f"output={OUTPUT.as_posix()} count={len(records)}")


if __name__ == "__main__":
    main()
