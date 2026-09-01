#!/usr/bin/env python3
"""Materialize the 49-case human final-adjudication review package and blank input."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
QUEUE = ROOT / "data/dataset_a/adjudication/case_gt_v1/final_adjudication/disagreement_queue_v1_1.jsonl"
REVIEW = ROOT / "reports/dataset_a/final_adjudication_v1/DATASET_A_FINAL_ADJUDICATION_REVIEW_49_v1.md"
TEMPLATE = ROOT / "data/dataset_a/adjudication/case_gt_v1/final_adjudication/final_adjudication_49_template_v1.jsonl"
MANIFEST = ROOT / "reports/dataset_a/final_adjudication_v1/support_manifest_v1.json"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_template(queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "schema_version": "dataset_a_final_adjudication_decision.v1",
        "candidate_id": row["candidate_id"],
        "final_pi_status": None,
        "final_maliciousness": None,
        "final_rationale": None,
        "adjudicator": None,
        "adjudicated_at": None,
        "derived_class": None,
    } for row in queue]


def issue(row: dict[str, Any]) -> str:
    parts = []
    fields = row["disagreement_fields"]
    case = row["original_adjudication_input"]
    if "pi_status" in fields:
        boundary = "명시된 trusted boundary/context가 있음" if any(case.get(k) for k in ("trusted_instruction", "trust_boundary", "normal_task")) else "trusted boundary가 원문에서 암묵적임"
        parts.append(f"PI 상태가 갈림; {boundary}. 문구가 실행 지시인지 데이터·인용인지와 권한 경계를 Contract v2로 확인.")
    if "maliciousness" in fields:
        parts.append("악성성이 갈림; 목표가 보호 자산·권한·외부 효과를 침해하는지, 또는 무해한 표식/형식 변경인지 확인.")
    if fields == ["derived_class"]:
        parts.append("기본 두 축은 같지만 파생값이 달라 기계적 derivation 일관성을 확인.")
    return " ".join(parts)


def compact(value: Any) -> str:
    if value is None:
        return "_(none)_"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).replace("\r", "").strip()


def markdown(queue: list[dict[str, Any]]) -> str:
    lines = [
        "# Dataset A Final Adjudication Review — 49 disagreements",
        "",
        "GT Adjudication Contract v2를 변경 없이 적용한다. 이 문서는 두 판정의 차이를 압축해 보여 주며 새로운 판정을 제안하지 않는다.",
        "",
    ]
    for index, row in enumerate(queue, 1):
        case = row["original_adjudication_input"]
        source, scenario = row["source"], row.get("scenario") or {}
        lines += [
            f"## {index:02d}. {row['candidate_id']}", "",
            f"- Source: `{source.get('source_id')}` / {source.get('source_name')} / `{source.get('raw_row_locator')}`",
            f"- Scenario: `{scenario.get('scenario_id')}` — {compact(scenario.get('scenario_text'))}",
            f"- Disagreement: `{', '.join(row['disagreement_fields'])}`",
            f"- 핵심 쟁점: {issue(row)}", "",
            "### Adjudication input", "",
            f"- Trusted instruction: {compact(case.get('trusted_instruction'))}",
            f"- Normal task: {compact(case.get('normal_task'))}",
            f"- Trust boundary: {compact(case.get('trust_boundary'))}",
            f"- Untrusted input:\n\n```text\n{compact(case.get('untrusted_input'))}\n```", "",
            "### First pass", "",
            f"- PI / maliciousness: `{row['first_pass']['pi_status']}` / `{row['first_pass']['maliciousness']}`",
            f"- Rationale: {row['first_pass']['rationale']}", "",
            "### Second pass", "",
            f"- PI / maliciousness: `{row['second_pass']['pi_status']}` / `{row['second_pass']['maliciousness']}`",
            f"- Rationale: {row['second_pass']['rationale']}", "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def run() -> dict[str, Any]:
    if REVIEW.exists() or TEMPLATE.exists() or MANIFEST.exists():
        raise FileExistsError("Refusing to overwrite final-adjudication support artifacts")
    queue = read_jsonl(QUEUE)
    if len(queue) != 49 or len({row["candidate_id"] for row in queue}) != 49:
        raise ValueError("Expected 49 unique disagreement cases")
    REVIEW.parent.mkdir(parents=True, exist_ok=True)
    TEMPLATE.parent.mkdir(parents=True, exist_ok=True)
    REVIEW.write_text(markdown(queue), encoding="utf-8", newline="\n")
    with TEMPLATE.open("w", encoding="utf-8", newline="\n") as handle:
        for row in build_template(queue):
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    manifest = {
        "schema_version": "dataset_a_final_adjudication_support_manifest.v1",
        "queue_count": 49,
        "queue_sha256": sha256(QUEUE),
        "review_path": REVIEW.relative_to(ROOT).as_posix(),
        "review_sha256": sha256(REVIEW),
        "template_path": TEMPLATE.relative_to(ROOT).as_posix(),
        "template_sha256": sha256(TEMPLATE),
        "contract_version": "GT Adjudication Contract v2",
        "contains_final_decisions": False,
    }
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False, indent=2))
