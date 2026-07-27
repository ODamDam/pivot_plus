
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

INPUT_PATH = Path(
    "data/evaluation/input_revalidation/"
    "input_revalidation_pilot_200_v1.jsonl"
)
OUTPUT_PATH = Path(
    "data/evaluation/input_revalidation/"
    "input_revalidation_pilot_200_v1_labeled.jsonl"
)

STANDALONE = ["", "malicious", "benign", "ambiguous", "not_applicable"]
CONTEXTUAL = ["", "injection", "non_injection", "ambiguous", "not_applicable"]
GOAL = ["", "true", "false", "unclear"]
ELIGIBILITY = [
    "",
    "eligible_positive",
    "eligible_negative",
    "ambiguous_exclude",
    "context_only",
]
ISSUE = [
    "",
    "none",
    "standalone_only",
    "context_dependent",
    "ordinary_request_mislabeled",
    "attack_goal_unclear",
    "synthetic_incoherence",
    "insufficient_context",
    "other",
]
CONFIDENCE = ["", "high", "medium", "low"]
STATUS = ["unreviewed", "reviewed", "needs_second_review"]

def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    tmp.replace(path)

def safe_index(options: list[str], value: Any) -> int:
    value = str(value or "")
    return options.index(value) if value in options else 0

def load_rows() -> list[dict[str, Any]]:
    base = read_jsonl(INPUT_PATH)
    if not OUTPUT_PATH.exists():
        return base
    saved = {
        row["dataset_id"]: row
        for row in read_jsonl(OUTPUT_PATH)
    }
    return [saved.get(row["dataset_id"], row) for row in base]

def reviewed(row: dict[str, Any]) -> bool:
    return row.get("review_status_v2") in {"reviewed", "needs_second_review"}

st.set_page_config(page_title="Input Revalidation", layout="wide")
st.title("Prompt Injection 입력 재검증")
st.caption("기존 라벨을 정답으로 간주하지 않고 prompt 단독 악성 여부와 context 의존 공격 여부를 다시 판정합니다.")

try:
    rows = load_rows()
except Exception as exc:
    st.error(str(exc))
    st.stop()

if "index" not in st.session_state:
    st.session_state.index = 0

mode = st.sidebar.selectbox("표시 대상", ["전체", "미검토", "재검토 필요"])
filtered = []
for row in rows:
    if mode == "전체":
        filtered.append(row)
    elif mode == "미검토" and not reviewed(row):
        filtered.append(row)
    elif mode == "재검토 필요" and row.get("review_status_v2") == "needs_second_review":
        filtered.append(row)

if not filtered:
    st.warning("해당 표본이 없습니다.")
    st.stop()

done = sum(reviewed(r) for r in rows)
st.sidebar.metric("완료", f"{done} / {len(rows)}")
st.sidebar.progress(done / len(rows))

st.session_state.index = min(st.session_state.index, len(filtered) - 1)
selected = st.sidebar.selectbox(
    "표본 선택",
    range(len(filtered)),
    index=st.session_state.index,
    format_func=lambda i: (
        f"{filtered[i].get('pilot_order', '-')}. "
        f"{filtered[i]['dataset_id']} "
        f"[{filtered[i].get('review_status_v2', 'unreviewed')}]"
    ),
)
st.session_state.index = selected
row = filtered[selected]

st.markdown(f"### {row.get('pilot_order', '-')} · `{row['dataset_id']}`")
st.caption(
    f"subset: `{row.get('dataset_subset')}` · "
    f"existing label: `{row.get('is_malicious')}` · "
    f"attack: `{row.get('attack_type')}` · "
    f"context dependency: `{row.get('context_dependency')}` · "
    f"context type: `{row.get('context_type')}`"
)

left, right = st.columns(2)
with left:
    st.subheader("Prompt 단독")
    st.text_area(
        "Prompt",
        value=str(row.get("prompt_text") or row.get("scanner_input_prompt_only") or ""),
        height=420,
        disabled=True,
    )
with right:
    st.subheader("Context + Prompt")
    context = str(row.get("context_text") or "")
    prompt = str(row.get("prompt_text") or "")
    st.text_area("Context", value=context, height=210, disabled=True)
    st.text_area("Prompt", value=prompt, height=210, disabled=True)

st.divider()
c1, c2 = st.columns(2)

with c1:
    standalone = st.selectbox(
        "Prompt 단독 악성 여부",
        STANDALONE,
        index=safe_index(STANDALONE, row.get("adjudicated_standalone_prompt_label")),
    )
    contextual = st.selectbox(
        "Context 결합 시 injection 여부",
        CONTEXTUAL,
        index=safe_index(CONTEXTUAL, row.get("adjudicated_contextual_injection_label")),
    )
    goal = st.selectbox(
        "공격 목표가 명확한가",
        GOAL,
        index=safe_index(GOAL, row.get("attack_goal_specified")),
    )
    eligibility = st.selectbox(
        "Scanner 평가 적격성",
        ELIGIBILITY,
        index=safe_index(ELIGIBILITY, row.get("evaluation_eligibility")),
    )

with c2:
    issue = st.selectbox(
        "기존 라벨 문제 유형",
        ISSUE,
        index=safe_index(ISSUE, row.get("label_issue_type")),
    )
    confidence = st.selectbox(
        "확신도",
        CONFIDENCE,
        index=safe_index(CONFIDENCE, row.get("reviewer_confidence_v2")),
    )
    status = st.selectbox(
        "검토 상태",
        STATUS,
        index=safe_index(STATUS, row.get("review_status_v2")),
    )
    evidence = st.text_area(
        "판정 근거 구간",
        value=str(row.get("review_evidence") or ""),
        height=100,
    )
    rationale = st.text_area(
        "판정 이유",
        value=str(row.get("review_rationale") or ""),
        height=140,
    )

required = {
    "adjudicated_standalone_prompt_label": standalone,
    "adjudicated_contextual_injection_label": contextual,
    "attack_goal_specified": goal,
    "evaluation_eligibility": eligibility,
    "label_issue_type": issue,
    "reviewer_confidence_v2": confidence,
}
missing = [k for k, v in required.items() if not v]
if missing:
    st.warning("미입력: " + ", ".join(missing))

b1, b2, b3 = st.columns([1, 2, 1])
with b1:
    if st.button("← 이전", use_container_width=True, disabled=selected == 0):
        st.session_state.index = max(0, selected - 1)
        st.rerun()
with b2:
    if st.button("저장 후 다음", type="primary", use_container_width=True):
        if missing:
            st.error("필수 항목을 모두 입력해주세요.")
        else:
            target_id = row["dataset_id"]
            for item in rows:
                if item["dataset_id"] == target_id:
                    item.update({
                        **required,
                        "review_evidence": evidence,
                        "review_rationale": rationale,
                        "review_status_v2": status,
                    })
                    break
            write_jsonl(OUTPUT_PATH, rows)
            st.session_state.index = min(selected + 1, len(filtered) - 1)
            st.rerun()
with b3:
    if st.button("다음 →", use_container_width=True, disabled=selected >= len(filtered) - 1):
        st.session_state.index = min(len(filtered) - 1, selected + 1)
        st.rerun()

st.sidebar.divider()
st.sidebar.caption(f"입력: {INPUT_PATH}")
st.sidebar.caption(f"저장: {OUTPUT_PATH}")
