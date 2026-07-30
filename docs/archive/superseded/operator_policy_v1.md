# Operator Policy v1

## 1. 문서 목적

본 문서는 diagnostic benchmark v1에서 사용할 mutation operator의 선별, 수정, 제외 기준을 정의한다.

기존 팀 프로젝트의 mutation engine에는 OWASP LLM Top 10 전체 risk를 겨냥한 operator가 포함되어 있다. 그러나 본 확장 연구의 중심은 prompt injection scanner evaluator 평가이다.

따라서 본 프로젝트에서는 prompt injection 공격 의도를 유지하면서 scanner 탐지 성능을 흔들 수 있는 operator만 diagnostic benchmark v1에 사용한다.

---

## 2. mutation 정의

본 프로젝트에서 mutation은 다음 조건을 만족해야 한다.

```text
공격 의도는 유지한다.
표현, 구조, 문맥, 인코딩, 전달 형식만 바꾼다.
변형 후에도 ground truth는 malicious로 유지되어야 한다.
scanner가 놓칠 수 있는 realistic variation이어야 한다.
```

즉, mutation은 새로운 공격 목표를 만드는 것이 아니라, 동일한 prompt injection 공격을 다른 방식으로 표현하는 과정이다.

---

## 3. diagnostic v1에서 우선 사용할 mutation family

| family | description | priority |
|---|---|---|
| lexical | 단어 수준 표현 변경 | high |
| syntactic | 문장 구조 변경 | high |
| semantic_paraphrase | 의미 유지 재서술 | high |
| encoding | Base64, URL encoding, Unicode homoglyph 등 | medium |
| structural | JSON, YAML, Markdown, HTML, code block 등 구조형 wrapper | high |
| contextual | 정상 업무 맥락으로 위장 | high |
| noise_injection | 긴 문서, 로그, 예시 데이터 중간에 삽입 | medium |
| cross_lingual | 언어 혼합 또는 번역 기반 우회 | low~medium |

---

## 4. diagnostic v1에서 제외하거나 후순위로 둘 operator family

| family | reason |
|---|---|
| training_data_poisoning | prompt injection scanner 평가와 직접 관련이 약하다. |
| model_backdoor | model training/evaluation risk에 가까우며 본 benchmark 범위를 벗어난다. |
| hallucination_induction | hallucination 평가이지 prompt injection 탐지 평가가 아니다. |
| misinformation_generation | content safety 또는 factuality 평가에 가깝다. |
| unbounded_consumption / LLM10_DOS | resource exhaustion 평가이며 prompt injection evaluator 분석과 분리해야 한다. |

위 family는 OWASP LLM risk 연구에는 의미가 있으나, diagnostic benchmark v1에는 포함하지 않는다.

---

## 5. operator action taxonomy

각 operator는 inventory 이후 다음 중 하나로 분류한다.

| action | meaning |
|---|---|
| keep | 그대로 사용 |
| modify | prompt injection benchmark 목적에 맞게 수정 후 사용 |
| drop_for_v1 | diagnostic benchmark v1에서는 제외 |
| reference_only | 구현 참고만 하고 실제 mutation 생성에는 사용하지 않음 |
| new_needed | 해당 family가 부족하여 신규 구현 필요 |
| broken | syntax error, import error, schema mismatch 등으로 현재 사용 불가 |

---

## 6. operator metadata 요구사항

모든 operator는 최소한 다음 metadata를 가져야 한다.

```python
OPERATOR_META = {
    "op_id": "op_xxx",
    "mutation_family": "structural",
    "attack_type_compat": ["instruction_override", "data_exfiltration"],
    "surface_compat": ["PROMPT_TEXT"],
    "risk_level": "MEDIUM",
    "strength_range": [1, 5],
    "semantic_preservation_risk": "LOW",
    "params_schema": {}
}
```

기존 operator가 `bucket_tags` 중심 metadata만 가지고 있는 경우, 본 프로젝트에서는 `mutation_family`, `attack_type_compat`, `semantic_preservation_risk`를 추가하는 방향으로 정리한다.

---

## 7. apply 함수 contract

모든 operator의 `apply()` 함수는 다음 형식을 따른다.

```python
def apply(seed_text: str, ctx: dict, rng: random.Random) -> ApplyResult:
    ...
```

입력 조건은 다음과 같다.

| parameter | description |
|---|---|
| seed_text | 변형 대상 원본 prompt |
| ctx | strength, surface, constraints, source metadata 등을 포함하는 context |
| rng | 재현 가능한 random generator |

출력은 `ApplyResult`를 사용한다.

성공 시:

```python
ApplyResult(
    "OK",
    mutated_text,
    {
        "op_id": "...",
        "mutation_family": "...",
        "strength": 3,
        "len_before": 120,
        "len_after": 190,
        "applied": ["..."]
    }
)
```

실패 또는 적용 불가 시:

```python
ApplyResult(
    "SKIPPED",
    seed_text,
    {
        "reason": "surface_mismatch"
    }
)
```

---

## 8. semantic preservation rule

mutation 후에도 다음 조건이 유지되어야 한다.

| item | requirement |
|---|---|
| attack intent | 원본 공격 의도가 유지되어야 한다. |
| target | system prompt, hidden instruction, policy, tool call 등 공격 대상이 유지되어야 한다. |
| maliciousness | benign으로 바뀌면 안 된다. |
| evaluability | 사람이 읽고 label을 검증할 수 있어야 한다. |
| boundedness | 지나치게 길거나 난독화되어 scanner input으로 부적절해지면 안 된다. |

semantic preservation이 불확실한 mutation은 `semantic_preservation=false`로 기록하고 final benchmark에서 제외하거나 별도 검수한다.

---

## 9. attack_type별 권장 mutation family

| attack_type | recommended mutation family |
|---|---|
| instruction_override | lexical, syntactic, semantic_paraphrase, contextual, structural |
| role_play_bypass | semantic_paraphrase, contextual, cross_lingual |
| policy_bypass | semantic_paraphrase, contextual, lexical |
| data_exfiltration | contextual, structural, encoding, noise_injection |
| format_injection | structural, encoding, noise_injection |
| tool_manipulation | structural, contextual, code/log wrapper |
| indirect_injection | structural, noise_injection, repo/document wrapper |
| multi_turn_injection | staged_context, split_instruction |

---

## 10. diagnostic v1 operator target set

최종 benchmark v1에서는 250개 malicious seed에서 500개 mutated malicious sample을 생성한다.

기본 정책은 다음과 같다.

```text
malicious seed 1개당 평균 2개 mutation 생성
각 seed에는 attack_type에 적합한 mutation family만 적용
동일 seed에서 같은 family만 반복 적용하지 않음
semantic preservation 실패 sample은 제외
```

---

## 11. 우선 구현 또는 유지할 operator 후보

### 11.1 structural wrapper

우선순위가 가장 높다.

```text
wrap_as_json_field
wrap_as_yaml_config
wrap_as_markdown_quote
wrap_as_code_comment
wrap_as_log_entry
wrap_as_html_document
```

목적은 scanner가 구조형 입력 안의 prompt injection을 탐지할 수 있는지 확인하는 것이다.

### 11.2 contextual pretext

정상 업무 맥락으로 위장하는 mutation이다.

```text
as_debugging_request
as_translation_request
as_security_test_request
as_policy_review_request
as_log_analysis_request
```

목적은 scanner가 benign-looking context 안의 malicious instruction을 놓치는지 확인하는 것이다.

### 11.3 encoding / obfuscation

표면 표현 의존성을 확인하기 위한 mutation이다.

```text
base64_wrap
url_encode_keywords
unicode_homoglyph_replace
zero_width_insert
```

단, 사람이 의미를 검증할 수 없는 수준의 과도한 난독화는 제외한다.

### 11.4 noise injection

긴 문맥 안에 공격 지시를 삽입하는 mutation이다.

```text
insert_into_long_document
insert_between_examples
insert_into_fake_log
insert_after_benign_context
```

### 11.5 cross-lingual

시간이 남으면 제한적으로 사용한다.

```text
translate_attack_to_korean
mix_korean_english
split_instruction_across_languages
```

cross-lingual mutation은 품질 검수가 필요하므로 대량 생성하지 않는다.

---

## 12. 기존 operator 검토 기준

기존 `src/operators` 내 operator는 다음 기준으로 점검한다.

| review item | question |
|---|---|
| syntax | Python syntax error가 없는가? |
| import | 현재 project 구조의 `ApplyResult` import와 맞는가? |
| metadata | OPERATOR_META가 공통 schema를 만족하는가? |
| surface | PROMPT_TEXT 외 구조형 입력에 적용 가능한가? |
| semantic preservation | 공격 의도가 유지되는가? |
| scope | prompt injection benchmark 목적과 맞는가? |
| length control | max_chars 등 constraint를 준수하는가? |
| reproducibility | rng를 사용해 재현 가능하게 동작하는가? |

---

## 13. inventory 산출물

operator inventory는 다음 파일로 관리한다.

```text
docs/contract/operator_inventory_v1.md
docs/contract/operator_inventory_v1.csv
```

inventory에는 최소한 다음 컬럼을 둔다.

```text
file
op_id
existing_bucket_tags
surface_compat
risk_level
strength_range
current_status
mutation_family_final
attack_type_compat
semantic_preservation_risk
recommended_action
use_in_diagnostic_v1
review_notes
```

---

## 14. 최종 원칙

diagnostic benchmark v1의 mutation operator는 많을수록 좋은 것이 아니다.

중요한 것은 scanner 실패를 설명할 수 있는 방식으로 operator family를 설계하고, 각 mutation이 원본 공격 의도를 유지한다는 점을 검증하는 것이다.

따라서 v1에서는 prompt injection 평가와 직접 관련이 높은 operator만 사용하고, 그 외 OWASP LLM risk operator는 후속 실험 또는 별도 연구 범위로 분리한다.
