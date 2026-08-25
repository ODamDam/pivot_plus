"""High-precision whole-record source-code representation classifier."""

from __future__ import annotations

import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import scripts.dataset_a.build_structure_resolution_v2 as audit_tools
from scripts.dataset_a.build_structure_resolution_v2 import read_jsonl, write_jsonl
from scripts.dataset_a.structure_classifier_v2 import classify_observable_structure


ROOT = _PROJECT_ROOT
POOL = Path("data/dataset_a/candidate_pool/dataset_a_raw_candidate_pool_1500_v1_2_parse_fixed.jsonl")
BOUND = Path("data/dataset_a/adjudication/scenario_binding_v1/dataset_a_remaining_bound_1050_v1.jsonl")
MARKDOWN_QUEUE = Path("data/dataset_a/adjudication/scenario_binding_v2/dataset_a_markdown_human_review_queue_v1.jsonl")
OUTPUT_DIR = Path("data/dataset_a/adjudication/scenario_binding_v2")
RESOLUTION_OUTPUT = OUTPUT_DIR / "dataset_a_code_resolution_233_v1.jsonl"
QUEUE_OUTPUT = OUTPUT_DIR / "dataset_a_code_human_review_queue_v1.jsonl"

_FENCE_RE = re.compile(r"(?m)^\s{0,3}(`{3,}|~{3,})([^\n]*)$")
_LABEL_WRAPPER_RE = re.compile(r"^\s*(?:run|execute|bypass)\s*:\s*", re.I)
_HTML_RE = re.compile(r"</?(?:html|body|div|p|section|article|table|script|style|ul|ol|li|h[1-6])(?:\s[^>]*)?>", re.I)
_ENCODED_RE = re.compile(r"^(?:[A-Za-z0-9+/]{4}){4,}(?:==|=)?$")


@dataclass(frozen=True)
class CodeClassification:
    observed_format: str
    code_strength: str
    detection_reason: str
    code_signals: tuple[str, ...]
    detected_language_family: str | None
    competing_format: str | None
    requires_human_review: bool


def _signal_counts(text: str) -> tuple[dict[str, int], str | None, float]:
    patterns: dict[str, tuple[str, str]] = {
        "python_import": ("python", r"(?m)^\s*(?:from\s+[A-Za-z_][\w.]*\s+import|import\s+[A-Za-z_][\w.]*)\b"),
        "python_def_class": ("python", r"(?m)^\s*(?:async\s+def|def|class)\s+[A-Za-z_]\w*\s*(?:\([^\n]*\))?\s*:"),
        "python_control": ("python", r"(?m)^\s*(?:if|elif|else|for|while|try|except|with)\b[^\n]*:\s*$"),
        "javascript_decl": ("javascript", r"(?m)^\s*(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*="),
        "javascript_function": ("javascript", r"(?m)^\s*(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(|=>"),
        "c_include_main": ("c_cpp", r"(?m)^\s*#include\s*[<\"]|\b(?:int|void)\s+main\s*\("),
        "powershell": ("powershell", r"(?m)^\s*\$[A-Za-z_]\w*\s*=|\b(?:Get|Set|New|Remove|Invoke|Start|Stop)-[A-Za-z]+\b"),
        "batch": ("batch", r"(?im)^\s*(?:@echo\s+off|set\s+\w+=|if\s+exist\b|for\s+%%?\w\s+in\b)"),
        "assignment": ("generic", r"(?m)^\s*[A-Za-z_$][\w.$\[\]'\"]*\s*=\s*[^=\n].*$"),
        "function_call": ("generic", r"(?m)^\s*[A-Za-z_$][\w.$]*\s*\([^\n]*\)\s*;?\s*$"),
        "source_comment": ("generic", r"(?m)^\s*(?:#(?!\s*#)|//|/\*|\*)\s*\S.*$"),
    }
    counts = {name: len(re.findall(pattern, text)) for name, (_, pattern) in patterns.items()}
    sql = {
        "sql_select": len(re.findall(r"(?im)^\s*SELECT\b", text)),
        "sql_from": len(re.findall(r"(?im)^\s*FROM\b", text)),
        "sql_clause": len(re.findall(r"(?im)^\s*(?:WHERE|GROUP\s+BY|ORDER\s+BY|JOIN|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b", text)),
    }
    counts.update(sql)
    shell_shebang = len(re.findall(r"(?m)^#!\s*(?:/usr/bin/env\s+|/(?:usr/)?bin/)(?:ba|z|k)?sh\b", text))
    shell_syntax = len(re.findall(r"(?m)^\s*(?:set\s+-[a-z]+|echo\b|whoami\s*$|export\s+\w+=|\w+=\S+|if\s+\[|for\s+\w+\s+in\b|while\s+|case\s+).*$", text))
    counts["shell_shebang"] = shell_shebang
    counts["shell_syntax"] = shell_syntax

    language_scores = Counter()
    for name, count in counts.items():
        if not count:
            continue
        if name.startswith("python_"):
            language_scores["python"] += count
        elif name.startswith("javascript_"):
            language_scores["javascript"] += count
        elif name.startswith("c_"):
            language_scores["c_cpp"] += count
        elif name == "powershell":
            language_scores["powershell"] += count
        elif name == "batch":
            language_scores["batch"] += count
        elif name.startswith("sql_"):
            language_scores["sql"] += count
        elif name.startswith("shell_"):
            language_scores["shell"] += count
    family = language_scores.most_common(1)[0][0] if language_scores else None

    nonempty = [line for line in text.splitlines() if line.strip()]
    code_line_patterns = [pattern for _, pattern in patterns.values()] + [
        r"(?i)^\s*(?:SELECT|FROM|WHERE|GROUP\s+BY|ORDER\s+BY|JOIN|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b",
        r"^#!",
        r"^\s*(?:set\s+-[a-z]+|echo\b|whoami\s*$|export\s+\w+=)",
        r"[{};]\s*$",
    ]
    code_lines = sum(any(re.search(pattern, line) for pattern in code_line_patterns) for line in nonempty)
    return counts, family, code_lines / max(1, len(nonempty))


def classify_observable_code(text: str) -> CodeClassification:
    stripped = text.strip()
    structure = classify_observable_structure(text)
    if structure.structure_strength == "clear_structured":
        return CodeClassification(
            "ambiguous", "ambiguous", "whole_record_structured_data_competition",
            (), structure.observed_format, "struct", True
        )
    if _HTML_RE.search(text):
        return CodeClassification(
            "ambiguous", "ambiguous", "document_markup_competition",
            (), None, "doc", True
        )
    compact = re.sub(r"\s+", "", stripped)
    if len(compact) >= 24 and _ENCODED_RE.fullmatch(compact):
        return CodeClassification(
            "ambiguous", "ambiguous", "encoded_representation_competition",
            (), None, "encoded", True
        )

    counts, family, code_ratio = _signal_counts(text)
    signals = tuple(f"{name}:{count}" for name, count in counts.items() if count)
    fences = list(_FENCE_RE.finditer(text))
    if len(fences) >= 2:
        first, second = fences[0], fences[1]
        outside = (text[: first.start()] + text[second.end() :]).strip()
        return CodeClassification(
            "ambiguous", "ambiguous",
            "fenced_code_or_text_with_markdown_wrapper" if outside else "fenced_block_representation_competition",
            signals, family, "markdown", True
        )
    if len(fences) == 1 or len(re.findall(r"`{3,}|~{3,}", text)) >= 2:
        return CodeClassification(
            "ambiguous", "ambiguous", "malformed_or_inline_fence_competition",
            signals, family, "markdown", True
        )

    wrapper = bool(_LABEL_WRAPPER_RE.match(stripped))
    python_groups = sum(bool(counts.get(name)) for name in ("python_import", "python_def_class", "python_control"))
    js_groups = sum(bool(counts.get(name)) for name in ("javascript_decl", "javascript_function"))
    sql_groups = sum(bool(counts.get(name)) for name in ("sql_select", "sql_from", "sql_clause"))
    shell_groups = sum(bool(counts.get(name)) for name in ("shell_shebang", "shell_syntax"))
    generic_groups = sum(bool(counts.get(name)) for name in ("assignment", "function_call"))
    strong_groups = max(python_groups, js_groups, sql_groups, shell_groups)
    if counts.get("c_include_main"):
        strong_groups = max(strong_groups, 2)
    if counts.get("powershell", 0) >= 2 or counts.get("batch", 0) >= 2:
        strong_groups = max(strong_groups, 2)
    if family == "python" and python_groups >= 1 and generic_groups >= 1:
        strong_groups = max(strong_groups, 2)
    if family == "javascript" and js_groups >= 1 and (counts.get("function_call") or counts.get("assignment")):
        strong_groups = max(strong_groups, 2)

    if not wrapper and strong_groups >= 2 and code_ratio >= 0.30:
        return CodeClassification(
            "code", "clear_code", "multiple_language_consistent_code_signals",
            signals, family, None, False
        )

    any_code_signal = any(counts.values())
    if wrapper and any_code_signal:
        return CodeClassification(
            "ambiguous", "weak_code", "natural_language_label_with_code_fragment",
            signals, family, None, True
        )
    if any_code_signal and (len(stripped.splitlines()) <= 3 or code_ratio < 0.30):
        return CodeClassification(
            "ambiguous", "weak_code", "isolated_or_limited_code_syntax",
            signals, family, None, True
        )
    if any_code_signal:
        return CodeClassification(
            "ambiguous", "ambiguous", "mixed_prose_and_code_like_syntax",
            signals, family, None, True
        )
    return CodeClassification(
        "plain_text", "plain_text_like", "no_whole_record_source_code_evidence",
        signals, None, None, False
    )


def _human_representation_decision(matched: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    decisions: set[str] = set()
    for audit in matched:
        valid = str(audit.get("structure_valid") or "").strip().lower() == "true"
        note = str(audit.get("review_note") or "").strip().lower()
        fmt = str(audit.get("candidate_structure_format") or "").strip().lower()
        if valid and "genuine source-code structure" in note:
            decisions.add("CODE")
        elif valid and fmt == "markdown":
            decisions.add("MARKDOWN")
    if len(decisions) > 1:
        return None, "conflicting_explicit_whole_record_representation_audits"
    return (next(iter(decisions)), None) if decisions else (None, "no_reusable_whole_record_code_axis")


def markdown_code_anchor(root: Path = ROOT) -> CodeClassification:
    queue = read_jsonl(root / MARKDOWN_QUEUE)
    anchor = next(row for row in queue if row["candidate_id"] == "DA-RAW-000970")
    return classify_observable_code(anchor["raw_text"])


def build_code_artifacts(root: Path = ROOT) -> dict[str, list[dict[str, Any]]]:
    pool = read_jsonl(root / POOL)
    pool_by_id = {row["candidate_id"]: row for row in pool}
    bound = [row for row in read_jsonl(root / BOUND) if row["input_format_observed"] == "code_block"]
    assert len(bound) == len({row["candidate_id"] for row in bound}) == 233
    audits = audit_tools.load_completed_audits(root)
    audit_index = audit_tools._build_audit_index(pool, audits)
    resolutions: list[dict[str, Any]] = []
    queue: list[dict[str, Any]] = []

    for source in bound:
        candidate_id = source["candidate_id"]
        pool_record = pool_by_id[candidate_id]
        assert source["untrusted_input"] == pool_record["content"]["raw_text"]
        matched = audit_index.get(candidate_id, [])
        human_decision, human_issue = _human_representation_decision(matched)
        classification = classify_observable_code(source["untrusted_input"])
        clear = classification.code_strength == "clear_code"
        plain = classification.code_strength == "plain_text_like"
        if (clear and human_decision not in {None, "CODE"}) or (plain and human_decision == "CODE"):
            status = "HUMAN_REVIEW_CONFLICT"
            corrected_format = corrected_scenario = None
        elif clear:
            status, corrected_format, corrected_scenario = "CODE_AUTO", "code", "SCN-REMAIN-CODE-001"
        elif plain:
            status, corrected_format, corrected_scenario = "TEXT_AUTO", "plain_text", "SCN-REMAIN-TEXT-001"
        elif human_decision == "CODE":
            status, corrected_format, corrected_scenario = "CODE_HUMAN_CONFIRMED", "code", "SCN-REMAIN-CODE-001"
        elif human_decision == "MARKDOWN":
            status, corrected_format, corrected_scenario = "MARKDOWN_HUMAN_CONFIRMED", "markdown", "SCN-REMAIN-DOC-001"
        elif human_issue and human_issue.startswith("conflicting_"):
            status = "HUMAN_REVIEW_CONFLICT"
            corrected_format = corrected_scenario = None
        else:
            status = "HUMAN_REVIEW_REQUIRED"
            corrected_format = corrected_scenario = None

        audit_sources = sorted({row["_audit_source"] for row in matched})
        audit_reasons = [str(row.get("review_note") or "").strip() for row in matched if str(row.get("review_note") or "").strip()]
        resolution = {
            "candidate_id": candidate_id,
            "source_id": pool_record["source"].get("source_id"),
            "source_record_id": pool_record["source"].get("source_record_id"),
            "normalized_record_id": pool_record["provenance"].get("normalized_record_id"),
            "previous_input_format": source["input_format_observed"],
            "previous_scenario_ref": source["scenario_ref"],
            "classifier_observed_format": classification.observed_format,
            "classifier_code_strength": classification.code_strength,
            "classifier_reason": classification.detection_reason,
            "code_signals": list(classification.code_signals),
            "detected_language_family": classification.detected_language_family,
            "competing_format": classification.competing_format,
            "classifier_requires_human_review": classification.requires_human_review,
            "human_audit_match": bool(matched),
            "human_representation_decision": human_decision,
            "human_audit_source": audit_sources,
            "human_audit_reason": audit_reasons,
            "human_audit_axis_reusable": human_decision is not None,
            "human_resolution_issue": human_issue,
            "resolution_status": status,
            "proposed_corrected_format": corrected_format,
            "proposed_corrected_scenario": corrected_scenario,
        }
        resolutions.append(resolution)
        if status in {"HUMAN_REVIEW_REQUIRED", "HUMAN_REVIEW_CONFLICT"}:
            queue.append({
                **resolution,
                "raw_text": source["untrusted_input"],
                "review": {
                    "representation_decision": None,
                    "observed_format": None,
                    "rationale": None,
                    "reviewer": None,
                    "reviewed_at": None,
                },
            })

    assert [row["candidate_id"] for row in resolutions] == [row["candidate_id"] for row in bound]
    return {"resolutions": resolutions, "queue": queue}


def main() -> None:
    resolution_path, queue_path = ROOT / RESOLUTION_OUTPUT, ROOT / QUEUE_OUTPUT
    if resolution_path.exists() or queue_path.exists():
        raise FileExistsError("CODE audit output already exists; refusing overwrite")
    artifacts = build_code_artifacts(ROOT)
    write_jsonl(resolution_path, artifacts["resolutions"])
    write_jsonl(queue_path, artifacts["queue"])
    print(f"resolution={RESOLUTION_OUTPUT.as_posix()} count={len(artifacts['resolutions'])}")
    print(f"queue={QUEUE_OUTPUT.as_posix()} count={len(artifacts['queue'])}")


if __name__ == "__main__":
    main()
