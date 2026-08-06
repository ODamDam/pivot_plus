# Operator Policy v2 Draft

## 1. 목적

본 문서는 `operator_inventory_v1` 결과를 바탕으로 diagnostic benchmark v1에서 사용할 mutation operator의 유지, 수정, 제외, 신규 구현 방침을 정의한다.

## 2. v1 우선 family

| family | current_count | decision |
|---|---:|---|
| lexical | 0 | new_needed |
| syntactic | 0 | new_needed |
| semantic_paraphrase | 0 | new_needed |
| encoding | 1 | sufficient_or_review |
| structural | 15 | sufficient_or_review |
| contextual | 0 | new_needed |
| noise_injection | 0 | new_needed |
| cross_lingual | 0 | new_needed |

## 3. v1 제외 family

| family or keyword | decision | reason |
|---|---|---|
| unbounded_consumption / DOS | drop_for_v1 | prompt injection scanner 평가와 직접 관련이 약함 |
| hallucination_induction | drop_for_v1 | hallucination 평가는 별도 범위 |
| misinformation_generation | drop_for_v1 | content integrity/factuality 평가에 가까움 |
| data_poisoning / training_data | drop_for_v1 | training-time risk이므로 diagnostic prompt injection benchmark 범위를 벗어남 |
| model_backdoor | drop_for_v1 | model-level risk로 분리 필요 |

## 4. 신규 구현 우선순위

### 4.1 structural wrapper

- `wrap_as_json_field`
- `wrap_as_yaml_config`
- `wrap_as_markdown_quote`
- `wrap_as_code_comment`
- `wrap_as_log_entry`

### 4.2 contextual pretext

- `as_debugging_request`
- `as_translation_request`
- `as_security_test_request`
- `as_policy_review_request`
- `as_log_analysis_request`

### 4.3 encoding / obfuscation

- `base64_wrap`
- `url_encode_keywords`
- `unicode_homoglyph_replace`
- `zero_width_insert`

### 4.4 noise injection

- `insert_into_long_document`
- `insert_between_examples`
- `insert_into_fake_log`
- `insert_after_benign_context`

### 4.5 cross-lingual

- `translate_attack_to_korean`
- `mix_korean_english`
- `split_instruction_across_languages`

## 5. attack_type별 적용 정책

| attack_type | allowed mutation families |
|---|---|
| instruction_override | lexical, syntactic, contextual, structural |
| role_play_bypass | semantic_paraphrase, contextual, cross_lingual |
| policy_bypass | lexical, semantic_paraphrase, contextual |
| data_exfiltration | contextual, structural, encoding, noise_injection |
| format_injection | structural, encoding, noise_injection |
| tool_manipulation | structural, contextual, code/log wrapper |
| indirect_injection | structural, noise_injection, repo/document wrapper |
| multi_turn_injection | split_instruction, staged_context |

## 6. 다음 작업

1. `operator_inventory_v1.csv`에서 `recommended_action`을 수동 검토한다.
2. `keep_or_modify` operator 중 prompt injection 의미 보존이 불명확한 항목은 sample test를 수행한다.
3. `drop_for_v1` operator는 diagnostic benchmark 생성 pipeline에서 제외한다.
4. 부족한 family는 신규 operator로 구현한다.
