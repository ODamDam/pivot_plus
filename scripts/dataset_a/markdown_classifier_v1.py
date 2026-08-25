"""High-precision whole-record Markdown representation classifier for Dataset A."""

from __future__ import annotations

import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import scripts.dataset_a.build_structure_resolution_v2 as structure_audit
from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl, write_jsonl


ROOT = _PROJECT_ROOT
POOL = Path("data/dataset_a/candidate_pool/dataset_a_raw_candidate_pool_1500_v1_2_parse_fixed.jsonl")
BOUND = Path("data/dataset_a/adjudication/scenario_binding_v1/dataset_a_remaining_bound_1050_v1.jsonl")
OUTPUT_DIR = Path("data/dataset_a/adjudication/scenario_binding_v2")
RESOLUTION_OUTPUT = OUTPUT_DIR / "dataset_a_markdown_resolution_105_v1.jsonl"
QUEUE_OUTPUT = OUTPUT_DIR / "dataset_a_markdown_human_review_queue_v1.jsonl"

_HEADING_RE = re.compile(r"(?m)^ {0,3}(#{1,6})[ \t]+\S.*$")
_BULLET_RE = re.compile(r"(?m)^\s{0,6}[-+*][ \t]+\S.*$")
_NUMBERED_RE = re.compile(r"(?m)^\s{0,6}\d+[.)][ \t]+\S.*$")
_BLOCKQUOTE_RE = re.compile(r"(?m)^\s{0,3}>[ \t]+\S.*$")
_LINK_RE = re.compile(r"!?\[[^\]\n]+\]\([^\s)]+(?:\s+[^)]*)?\)")
_HR_RE = re.compile(r"(?m)^\s{0,3}(?:-{3,}|\*{3,}|_{3,})\s*$")
_FENCE_RE = re.compile(r"(?m)^\s{0,3}(`{3,}|~{3,})([^\n]*)$")
_HTML_TAG_RE = re.compile(r"</?(?:html|body|div|p|section|article|table|script|style|ul|ol|li|h[1-6])(?:\s[^>]*)?>", re.I)
_TABLE_SEPARATOR_RE = re.compile(
    r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$"
)


@dataclass(frozen=True)
class MarkdownClassification:
    observed_format: str
    markdown_strength: str
    detection_reason: str
    markdown_signals: tuple[str, ...]
    competing_format: str | None
    precedence_review_required: bool
    requires_human_review: bool


def _has_markdown_table(lines: list[str]) -> bool:
    for index in range(len(lines) - 1):
        if "|" in lines[index] and _TABLE_SEPARATOR_RE.fullmatch(lines[index + 1]):
            return True
    return False


def _fence_analysis(text: str) -> tuple[int, float, bool]:
    matches = list(_FENCE_RE.finditer(text))
    if len(matches) < 2:
        return len(matches), 0.0, False
    first, second = matches[0], matches[1]
    content_length = max(0, second.start() - first.end())
    ratio = content_length / max(1, len(text))
    outside = (text[: first.start()] + text[second.end() :]).strip()
    return len(matches), ratio, not outside


def classify_observable_markdown(text: str) -> MarkdownClassification:
    lines = text.splitlines()
    headings = _HEADING_RE.findall(text)
    heading_levels = {len(marker) for marker in headings}
    bullet_count = len(_BULLET_RE.findall(text))
    numbered_count = len(_NUMBERED_RE.findall(text))
    blockquote_count = len(_BLOCKQUOTE_RE.findall(text))
    link_count = len(_LINK_RE.findall(text))
    hr_count = len(_HR_RE.findall(text))
    table = _has_markdown_table(lines)
    fence_count, fence_ratio, code_only_fence = _fence_analysis(text)
    paired_fence = fence_count >= 2
    inline_fence_runs = len(re.findall(r"`{3,}|~{3,}", text))
    malformed_inline_fence = not paired_fence and inline_fence_runs >= 2
    html_tag_count = len(_HTML_TAG_RE.findall(text))

    signals: list[str] = []
    if headings:
        signals.append(f"headings:{len(headings)}")
    if len(heading_levels) >= 2:
        signals.append(f"heading_hierarchy:{len(heading_levels)}")
    if bullet_count:
        signals.append(f"bullet_items:{bullet_count}")
    if numbered_count:
        signals.append(f"numbered_items:{numbered_count}")
    if table:
        signals.append("markdown_table")
    if paired_fence:
        signals.append(f"fenced_blocks:{fence_count // 2}")
    elif fence_count:
        signals.append("unpaired_fence")
    if malformed_inline_fence:
        signals.append(f"inline_or_malformed_fence_runs:{inline_fence_runs}")
    if blockquote_count:
        signals.append(f"blockquotes:{blockquote_count}")
    if link_count:
        signals.append(f"links_or_images:{link_count}")
    if hr_count:
        signals.append(f"horizontal_rules:{hr_count}")
    if html_tag_count:
        signals.append(f"html_elements:{html_tag_count}")

    competing_format: str | None = None
    precedence_review = False
    if code_only_fence or (paired_fence and fence_ratio >= 0.65):
        competing_format = "code"
        precedence_review = True
    elif html_tag_count and (headings or table or paired_fence):
        competing_format = "html"
        precedence_review = True

    signal_tuple = tuple(signals)
    if competing_format is not None:
        return MarkdownClassification(
            "ambiguous",
            "ambiguous",
            "competing_whole_record_representation",
            signal_tuple,
            competing_format,
            precedence_review,
            True,
        )

    if table:
        return MarkdownClassification(
            "markdown", "clear_markdown", "markdown_table_whole_record_evidence",
            signal_tuple, None, False, False
        )

    list_signal = bullet_count >= 2 or numbered_count >= 2
    organizational_signals = sum(
        [
            len(headings) >= 2,
            list_signal,
            paired_fence,
            blockquote_count >= 2,
            link_count >= 1,
            hr_count >= 1,
        ]
    )
    if len(headings) >= 2 and organizational_signals >= 2:
        return MarkdownClassification(
            "markdown", "clear_markdown", "multiple_markdown_document_signals",
            signal_tuple, None, False, False
        )
    if len(headings) >= 3 and len(heading_levels) >= 2:
        return MarkdownClassification(
            "markdown", "clear_markdown", "multi_level_heading_hierarchy",
            signal_tuple, None, False, False
        )

    if paired_fence:
        return MarkdownClassification(
            "ambiguous", "ambiguous", "fenced_fragment_with_surrounding_prose",
            signal_tuple, None, False, True
        )
    if fence_count == 1:
        return MarkdownClassification(
            "ambiguous", "ambiguous", "truncated_or_unpaired_fence",
            signal_tuple, None, False, True
        )
    if malformed_inline_fence:
        return MarkdownClassification(
            "ambiguous", "ambiguous", "inline_or_malformed_fenced_fragment",
            signal_tuple, None, False, True
        )
    if len(headings) >= 2 or (headings and list_signal) or blockquote_count >= 2:
        return MarkdownClassification(
            "ambiguous", "weak_markdown", "limited_markdown_organization",
            signal_tuple, None, False, True
        )

    return MarkdownClassification(
        "plain_text", "plain_text_like", "no_whole_record_markdown_document_evidence",
        signal_tuple, None, False, False
    )


def build_markdown_artifacts(root: Path = ROOT) -> dict[str, list[dict[str, Any]]]:
    pool = read_jsonl(root / POOL)
    pool_by_id = {row["candidate_id"]: row for row in pool}
    bound = [
        row for row in read_jsonl(root / BOUND)
        if row["input_format_observed"] == "markdown"
    ]
    assert len(bound) == len({row["candidate_id"] for row in bound}) == 105
    audits = structure_audit.load_completed_audits(root)
    audit_index = structure_audit._build_audit_index(pool, audits)

    resolutions: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []
    for source in bound:
        candidate_id = source["candidate_id"]
        pool_record = pool_by_id[candidate_id]
        assert source["untrusted_input"] == pool_record["content"]["raw_text"]
        matched = audit_index.get(candidate_id, [])
        human_status, human_valid, human_issue = (
            structure_audit.representation_resolution_from_audits(matched)
        )
        classification = classify_observable_markdown(source["untrusted_input"])

        classifier_clear = classification.markdown_strength == "clear_markdown"
        classifier_plain = classification.markdown_strength == "plain_text_like"
        if (classifier_clear and human_valid is False) or (classifier_plain and human_valid is True):
            resolution_status = "HUMAN_REVIEW_CONFLICT"
            corrected_format = corrected_scenario = None
        elif classifier_clear:
            resolution_status = "MARKDOWN_AUTO"
            corrected_format = "markdown"
            corrected_scenario = "SCN-REMAIN-DOC-001"
        elif classifier_plain:
            resolution_status = "TEXT_AUTO"
            corrected_format = "plain_text"
            corrected_scenario = "SCN-REMAIN-TEXT-001"
        elif human_status == "STRUCT_HUMAN_CONFIRMED":
            resolution_status = "MARKDOWN_HUMAN_CONFIRMED"
            corrected_format = "markdown"
            corrected_scenario = "SCN-REMAIN-DOC-001"
        elif human_status == "TEXT_HUMAN_CONFIRMED":
            resolution_status = "TEXT_HUMAN_CONFIRMED"
            corrected_format = "plain_text"
            corrected_scenario = "SCN-REMAIN-TEXT-001"
        elif human_status == "HUMAN_REVIEW_CONFLICT":
            resolution_status = "HUMAN_REVIEW_CONFLICT"
            corrected_format = corrected_scenario = None
        else:
            resolution_status = "HUMAN_REVIEW_REQUIRED"
            corrected_format = corrected_scenario = None

        audit_sources = sorted({row["_audit_source"] for row in matched})
        audit_reasons = [
            str(row.get("review_note") or "").strip()
            for row in matched if str(row.get("review_note") or "").strip()
        ]
        resolution = {
            "candidate_id": candidate_id,
            "source_id": pool_record["source"].get("source_id"),
            "source_record_id": pool_record["source"].get("source_record_id"),
            "normalized_record_id": pool_record["provenance"].get("normalized_record_id"),
            "previous_input_format": source["input_format_observed"],
            "previous_scenario_ref": source["scenario_ref"],
            "classifier_observed_format": classification.observed_format,
            "classifier_markdown_strength": classification.markdown_strength,
            "classifier_reason": classification.detection_reason,
            "markdown_signals": list(classification.markdown_signals),
            "competing_format": classification.competing_format,
            "precedence_review_required": classification.precedence_review_required,
            "classifier_requires_human_review": classification.requires_human_review,
            "human_audit_match": bool(matched),
            "human_representation_valid": human_valid,
            "human_audit_source": audit_sources,
            "human_audit_reason": audit_reasons,
            "human_audit_axis_reusable": human_status in {
                "STRUCT_HUMAN_CONFIRMED", "TEXT_HUMAN_CONFIRMED"
            },
            "human_resolution_issue": human_issue,
            "resolution_status": resolution_status,
            "proposed_corrected_format": corrected_format,
            "proposed_corrected_scenario": corrected_scenario,
        }
        resolutions.append(resolution)

        if resolution_status in {"HUMAN_REVIEW_REQUIRED", "HUMAN_REVIEW_CONFLICT"}:
            queue.append(
                {
                    **resolution,
                    "raw_text": source["untrusted_input"],
                    "review": {
                        "representation_decision": None,
                        "observed_format": None,
                        "rationale": None,
                        "reviewer": None,
                        "reviewed_at": None,
                    },
                }
            )

    assert len(resolutions) == 105
    assert [row["candidate_id"] for row in resolutions] == [row["candidate_id"] for row in bound]
    return {"resolutions": resolutions, "queue": queue}


def main() -> None:
    resolution_path = ROOT / RESOLUTION_OUTPUT
    queue_path = ROOT / QUEUE_OUTPUT
    if resolution_path.exists() or queue_path.exists():
        raise FileExistsError("Markdown audit output already exists; refusing overwrite")
    artifacts = build_markdown_artifacts(ROOT)
    write_jsonl(resolution_path, artifacts["resolutions"])
    write_jsonl(queue_path, artifacts["queue"])
    print(f"resolution={RESOLUTION_OUTPUT.as_posix()} count={len(artifacts['resolutions'])}")
    print(f"queue={QUEUE_OUTPUT.as_posix()} count={len(artifacts['queue'])}")


if __name__ == "__main__":
    main()
