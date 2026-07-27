from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st


INPUT_PATH = Path(
    "data/evaluation/annotations/"
    "response_annotation_pilot_50_v1.jsonl"
)

OUTPUT_PATH = Path(
    "data/evaluation/annotations/"
    "response_annotation_pilot_50_v1_labeled.jsonl"
)


HARM_LABELS = [
    "",
    "safe",
    "borderline",
    "partial_harm",
    "harmful",
    "unclear",
]

ATTACK_GOAL_LABELS = [
    "",
    "true",
    "partial",
    "false",
    "unclear",
    "not_applicable",
]

COMPLIANCE_LABELS = [
    "",
    "refusal",
    "noncompliance",
    "partial_compliance",
    "full_compliance",
    "irrelevant",
    "unclear",
]

JUDGABILITY_LABELS = [
    "",
    "judgable",
    "judgable_with_caution",
    "unclear_due_to_truncation",
    "unclear_due_to_generation_anomaly",
]

GROUND_TRUTH_LABELS = [
    "",
    "positive",
    "negative",
    "abstain",
]

CONFIDENCE_LABELS = [
    "",
    "high",
    "medium",
    "low",
]

REVIEW_STATUS_LABELS = [
    "unreviewed",
    "reviewed",
    "needs_second_review",
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line {line_number}: {exc}"
                ) from exc

            if not isinstance(row, dict):
                raise ValueError(
                    f"Expected JSON object at line {line_number}"
                )

            rows.append(row)

    return rows


def write_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_suffix(path.suffix + ".tmp")

    with temp_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        for row in rows:
            file.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    temp_path.replace(path)


def load_annotation_rows() -> list[dict[str, Any]]:
    input_rows = read_jsonl(INPUT_PATH)

    if not OUTPUT_PATH.exists():
        return input_rows

    output_rows = read_jsonl(OUTPUT_PATH)

    output_index = {
        row["annotation_id"]: row
        for row in output_rows
        if row.get("annotation_id")
    }

    merged_rows: list[dict[str, Any]] = []

    for row in input_rows:
        annotation_id = row.get("annotation_id")

        if annotation_id in output_index:
            merged_rows.append(output_index[annotation_id])
        else:
            merged_rows.append(row)

    return merged_rows


def group_pairs(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}

    for row in rows:
        dataset_id = str(row.get("dataset_id") or "")
        grouped.setdefault(dataset_id, []).append(row)

    pairs: list[dict[str, Any]] = []

    for dataset_id, pair_rows in grouped.items():
        prompt_row = next(
            (
                row
                for row in pair_rows
                if row.get("input_view") == "prompt_only"
            ),
            None,
        )

        context_row = next(
            (
                row
                for row in pair_rows
                if row.get("input_view") == "context_prompt"
            ),
            None,
        )

        if prompt_row is None or context_row is None:
            continue

        pair_number = prompt_row.get(
            "pilot_pair_number",
            context_row.get("pilot_pair_number"),
        )

        pairs.append(
            {
                "dataset_id": dataset_id,
                "pair_number": pair_number,
                "prompt_only": prompt_row,
                "context_prompt": context_row,
            }
        )

    pairs.sort(
        key=lambda pair: (
            pair.get("pair_number") is None,
            pair.get("pair_number") or 0,
            pair["dataset_id"],
        )
    )

    return pairs


def is_reviewed(row: dict[str, Any]) -> bool:
    return row.get("review_status") in {
        "reviewed",
        "needs_second_review",
    }


def pair_review_state(pair: dict[str, Any]) -> str:
    prompt_reviewed = is_reviewed(pair["prompt_only"])
    context_reviewed = is_reviewed(pair["context_prompt"])

    if prompt_reviewed and context_reviewed:
        return "completed"

    if prompt_reviewed or context_reviewed:
        return "partial"

    return "unreviewed"


def safe_index(options: list[str], value: Any) -> int:
    value = str(value or "")

    try:
        return options.index(value)
    except ValueError:
        return 0


def render_text_block(
    title: str,
    text: Any,
    height: int = 220,
) -> None:
    st.markdown(f"**{title}**")

    st.text_area(
        label=title,
        value=str(text or ""),
        height=height,
        disabled=True,
        label_visibility="collapsed",
    )


def render_metadata(row: dict[str, Any]) -> None:
    badges = [
        f"subset: `{row.get('dataset_subset')}`",
        f"attack: `{row.get('attack_type')}`",
        f"context: `{row.get('context_type')}`",
        f"done: `{row.get('done')}`",
        f"reason: `{row.get('done_reason')}`",
        f"truncated: `{row.get('generation_truncated')}`",
    ]

    st.caption(" · ".join(badges))


def annotation_form(
    row: dict[str, Any],
    key_prefix: str,
) -> dict[str, Any]:
    st.markdown("#### 라벨")

    harm = st.selectbox(
        "응답 위험성",
        HARM_LABELS,
        index=safe_index(
            HARM_LABELS,
            row.get("response_harm_label"),
        ),
        key=f"{key_prefix}_harm",
    )

    attack_goal = st.selectbox(
        "공격 목표 달성",
        ATTACK_GOAL_LABELS,
        index=safe_index(
            ATTACK_GOAL_LABELS,
            row.get("attack_goal_achieved"),
        ),
        key=f"{key_prefix}_attack_goal",
    )

    compliance = st.selectbox(
        "응답 순응 수준",
        COMPLIANCE_LABELS,
        index=safe_index(
            COMPLIANCE_LABELS,
            row.get("response_compliance_level"),
        ),
        key=f"{key_prefix}_compliance",
    )

    judgability = st.selectbox(
        "판정 가능성",
        JUDGABILITY_LABELS,
        index=safe_index(
            JUDGABILITY_LABELS,
            row.get("response_judgability"),
        ),
        key=f"{key_prefix}_judgability",
    )

    ground_truth = st.selectbox(
        "최종 Ground Truth",
        GROUND_TRUTH_LABELS,
        index=safe_index(
            GROUND_TRUTH_LABELS,
            row.get("ground_truth_decision"),
        ),
        key=f"{key_prefix}_ground_truth",
    )

    evidence = st.text_area(
        "근거가 되는 응답 부분",
        value=str(row.get("evidence_span") or ""),
        height=100,
        key=f"{key_prefix}_evidence",
    )

    rationale = st.text_area(
        "판정 근거",
        value=str(row.get("rationale") or ""),
        height=130,
        key=f"{key_prefix}_rationale",
    )

    confidence = st.selectbox(
        "판정 확신도",
        CONFIDENCE_LABELS,
        index=safe_index(
            CONFIDENCE_LABELS,
            row.get("reviewer_confidence"),
        ),
        key=f"{key_prefix}_confidence",
    )

    review_status = st.selectbox(
        "검토 상태",
        REVIEW_STATUS_LABELS,
        index=safe_index(
            REVIEW_STATUS_LABELS,
            row.get("review_status"),
        ),
        key=f"{key_prefix}_review_status",
    )

    return {
        "response_harm_label": harm,
        "attack_goal_achieved": attack_goal,
        "response_compliance_level": compliance,
        "response_judgability": judgability,
        "ground_truth_decision": ground_truth,
        "evidence_span": evidence,
        "rationale": rationale,
        "reviewer_confidence": confidence,
        "review_status": review_status,
    }


def validate_annotation(
    annotation: dict[str, Any],
) -> list[str]:
    required_fields = [
        "response_harm_label",
        "attack_goal_achieved",
        "response_compliance_level",
        "response_judgability",
        "ground_truth_decision",
        "reviewer_confidence",
    ]

    missing = [
        field
        for field in required_fields
        if not annotation.get(field)
    ]

    return missing


def save_pair(
    rows: list[dict[str, Any]],
    prompt_id: str,
    context_id: str,
    prompt_annotation: dict[str, Any],
    context_annotation: dict[str, Any],
) -> None:
    for row in rows:
        annotation_id = row.get("annotation_id")

        if annotation_id == prompt_id:
            row.update(prompt_annotation)

        if annotation_id == context_id:
            row.update(context_annotation)

    write_jsonl(OUTPUT_PATH, rows)


def main() -> None:
    st.set_page_config(
        page_title="LLM Response Annotation",
        layout="wide",
    )

    st.title("LLM 응답 위험성 라벨링 도구")
    st.caption(
        "Prompt-only와 Context+Prompt 응답을 쌍으로 비교하고 "
        "Ground Truth를 기록합니다."
    )

    try:
        rows = load_annotation_rows()
    except Exception as exc:
        st.error(str(exc))
        st.stop()

    pairs = group_pairs(rows)

    if not pairs:
        st.error("라벨링 가능한 paired sample이 없습니다.")
        st.stop()

    if "pair_index" not in st.session_state:
        st.session_state.pair_index = 0

    review_filter = st.sidebar.selectbox(
        "표시 대상",
        [
            "전체",
            "미검토",
            "부분 검토",
            "검토 완료",
            "재검토 필요",
        ],
    )

    filtered_pairs: list[dict[str, Any]] = []

    for pair in pairs:
        state = pair_review_state(pair)

        has_second_review = any(
            row.get("review_status")
            == "needs_second_review"
            for row in [
                pair["prompt_only"],
                pair["context_prompt"],
            ]
        )

        if review_filter == "전체":
            filtered_pairs.append(pair)
        elif review_filter == "미검토" and state == "unreviewed":
            filtered_pairs.append(pair)
        elif review_filter == "부분 검토" and state == "partial":
            filtered_pairs.append(pair)
        elif review_filter == "검토 완료" and state == "completed":
            filtered_pairs.append(pair)
        elif review_filter == "재검토 필요" and has_second_review:
            filtered_pairs.append(pair)

    if not filtered_pairs:
        st.warning("현재 필터에 해당하는 표본이 없습니다.")
        st.stop()

    st.session_state.pair_index = min(
        st.session_state.pair_index,
        len(filtered_pairs) - 1,
    )

    completed_pairs = sum(
        pair_review_state(pair) == "completed"
        for pair in pairs
    )

    st.sidebar.metric(
        "완료 Pair",
        f"{completed_pairs} / {len(pairs)}",
    )

    st.sidebar.progress(
        completed_pairs / len(pairs)
        if pairs
        else 0.0
    )

    pair_labels = [
        (
            f"{pair.get('pair_number', '-')}. "
            f"{pair['dataset_id']} "
            f"[{pair_review_state(pair)}]"
        )
        for pair in filtered_pairs
    ]

    selected_index = st.sidebar.selectbox(
        "Pair 선택",
        range(len(filtered_pairs)),
        index=st.session_state.pair_index,
        format_func=lambda index: pair_labels[index],
    )

    st.session_state.pair_index = selected_index
    pair = filtered_pairs[selected_index]

    prompt_row = pair["prompt_only"]
    context_row = pair["context_prompt"]

    st.markdown(
        f"### Pair {pair.get('pair_number', '-')} · "
        f"`{pair['dataset_id']}`"
    )

    st.caption(
        f"subset: `{prompt_row.get('dataset_subset')}` · "
        f"attack type: `{prompt_row.get('attack_type')}` · "
        f"context type: `{context_row.get('context_type')}` · "
        f"mutation: `{prompt_row.get('mutation_operator')}`"
    )

    with st.expander("원본 입력 정보", expanded=True):
        if str(context_row.get("context_text") or "").strip():
            render_text_block(
                "System / Repository Context",
                context_row.get("context_text"),
                height=220,
            )

        render_text_block(
            "User Prompt",
            prompt_row.get("prompt_text"),
            height=220,
        )

    left, right = st.columns(2)

    with left:
        st.subheader("Prompt-only")
        render_metadata(prompt_row)

        render_text_block(
            "모델 응답",
            prompt_row.get("response_text"),
            height=350,
        )

        prompt_annotation = annotation_form(
            prompt_row,
            f"prompt_{pair['dataset_id']}",
        )

    with right:
        st.subheader("Context + Prompt")
        render_metadata(context_row)

        render_text_block(
            "모델 응답",
            context_row.get("response_text"),
            height=350,
        )

        context_annotation = annotation_form(
            context_row,
            f"context_{pair['dataset_id']}",
        )

    st.divider()

    missing_prompt = validate_annotation(
        prompt_annotation
    )
    missing_context = validate_annotation(
        context_annotation
    )

    if missing_prompt:
        st.warning(
            "Prompt-only 미입력 필드: "
            + ", ".join(missing_prompt)
        )

    if missing_context:
        st.warning(
            "Context+Prompt 미입력 필드: "
            + ", ".join(missing_context)
        )

    nav_left, nav_center, nav_right = st.columns(
        [1, 2, 1]
    )

    with nav_left:
        previous_clicked = st.button(
            "← 이전",
            use_container_width=True,
            disabled=selected_index == 0,
        )

    with nav_center:
        save_clicked = st.button(
            "저장 후 다음",
            type="primary",
            use_container_width=True,
        )

    with nav_right:
        next_clicked = st.button(
            "다음 →",
            use_container_width=True,
            disabled=selected_index
            >= len(filtered_pairs) - 1,
        )

    if previous_clicked:
        st.session_state.pair_index = max(
            selected_index - 1,
            0,
        )
        st.rerun()

    if next_clicked:
        st.session_state.pair_index = min(
            selected_index + 1,
            len(filtered_pairs) - 1,
        )
        st.rerun()

    if save_clicked:
        if missing_prompt or missing_context:
            st.error(
                "필수 라벨을 모두 입력한 뒤 저장해주세요."
            )
        else:
            save_pair(
                rows=rows,
                prompt_id=prompt_row["annotation_id"],
                context_id=context_row["annotation_id"],
                prompt_annotation=prompt_annotation,
                context_annotation=context_annotation,
            )

            st.success("저장되었습니다.")

            st.session_state.pair_index = min(
                selected_index + 1,
                len(filtered_pairs) - 1,
            )

            st.rerun()

    st.sidebar.divider()

    st.sidebar.caption(f"입력: {INPUT_PATH}")
    st.sidebar.caption(f"저장: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()