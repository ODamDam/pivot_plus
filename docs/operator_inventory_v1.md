# Operator Inventory v1

## 1. Scope

본 문서는 현재 `src/operators`에 구현되어 있는 mutation operator를 자동 점검한 inventory이다.

- project_root: `C:\Users\2271086\바탕 화면\PIVOT\llm-prompt-injection-diagnostic-benchmark`
- operators_dir: `C:\Users\2271086\바탕 화면\PIVOT\llm-prompt-injection-diagnostic-benchmark\src\operators`
- total_operator_files: 17

## 2. Summary by inventory status

| status | count |
|---|---:|
| OK | 16 |
| PARSE_ERROR | 1 |

## 3. Summary by mutation family guess

| family | count |
|---|---:|
| contextual | 3 |
| encoding | 1 |
| lexical | 1 |
| noise_injection | 2 |
| structural | 8 |
| syntactic | 1 |
| unknown | 1 |

## 4. Summary by recommended action

| action | count |
|---|---:|
| fix_or_review | 1 |
| keep_or_modify | 16 |

## 5. Missing or weak priority family

- `cross_lingual`
- `semantic_paraphrase`

## 6. Inventory table

| file | op_id | family_guess | input_requirement | output_format | strength | semantic_preservation | label_change_risk | status | action | use_v1 |
|---|---|---|---|---|---|---|---|---|---|---|
| src/operators/op_comp_expand_context.py | op_comp_expand_context | noise_injection | PROMPT_TEXT | plain_text_or_unknown | 1~5 | medium_risk_manual_review_needed | medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_ctx_bypass_review_wrapper.py |  | unknown | unknown | unknown |  | unknown | unknown | PARSE_ERROR | fix_or_review | no_until_fixed |
| src/operators/op_direct_override_prefix.py | op_direct_override_prefix | contextual | PROMPT_TEXT; SYSTEM_MESSAGE | plain_text | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_markdown_wrapper.py | op_fmt_markdown_wrapper | structural | PROMPT_TEXT | markdown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_punctuation_resegmentation.py | op_fmt_punctuation_resegmentation | syntactic | PROMPT_TEXT | plain_text | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_structured_wrapper_json_yaml.py | op_fmt_structured_wrapper_json_yaml | structural | PROMPT_TEXT | json_or_yaml | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_whitespace_noise.py | op_fmt_whitespace_noise | noise_injection | PROMPT_TEXT; SYSTEM_MESSAGE | plain_text_or_unknown | 1~5 | medium_risk_manual_review_needed | medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_json_schema_preserving_field_wrap.py | op_json_schema_preserving_field_wrap | structural | PROMPT_TEXT; TOOL_ARGUMENTS | json | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_homoglyph_injection.py | op_lex_homoglyph_injection | encoding | PROMPT_TEXT | plain_text_or_unknown | 1~5 | medium_risk_decode_or_readability_check_needed | medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_polite_prefix.py | op_lex_polite_prefix | contextual | PROMPT_TEXT | plain_text | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_refusal_suppression.py | op_lex_refusal_suppression | contextual | PROMPT_TEXT | plain_text | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_salience_preserving_line_compression.py | op_salience_preserving_line_compression | lexical | PROMPT_TEXT | plain_text | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_syn_boundary_delimiter_injection.py | op_syn_boundary_delimiter_injection | structural | PROMPT_TEXT; SYSTEM_MESSAGE | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_syn_fake_tool_instruction_injection.py | op_syn_fake_tool_instruction_injection | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_syn_tool_call_argument_perturbation.py | op_syn_tool_call_argument_perturbation | structural | TOOL_CALL; TOOL_ARGUMENTS | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_syn_trust_violation_trigger.py | op_syn_trust_violation_trigger | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_syn_unverified_data_injection.py | op_syn_unverified_data_injection | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |

## 7. Manual review checklist

| item | question |
|---|---|
| operator name | 어떤 이름으로 등록되어 있는가? |
| operator family | lexical, syntactic, encoding, structural 등 어디에 속하는가? |
| input requirement | 어떤 seed에 적용 가능한가? |
| output format | plain text, JSON, markdown 등 어떤 형태를 만드는가? |
| strength | 변형 강도 1~5 중 어디에 해당하는가? |
| semantic preservation | 공격 의도가 유지되는가? |
| risk | label이 바뀔 위험이 있는가? |
| keep/modify/drop | 유지, 수정, 제거, 신규 구현 중 무엇인가? |
