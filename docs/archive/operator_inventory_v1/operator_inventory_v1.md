# Operator Inventory v1

## 1. Scope

본 문서는 현재 `src/operators`에 구현되어 있는 mutation operator를 자동 점검한 inventory이다.

- project_root: `C:\Users\2271086\Desktop\PIVOT\llm-prompt-injection-diagnostic-benchmark`
- operators_dir: `C:\Users\2271086\Desktop\PIVOT\llm-prompt-injection-diagnostic-benchmark\src\operators`
- total_operator_files: 16

## 2. Summary by inventory status

| status | count |
|---|---:|
| OK | 16 |

## 3. Summary by mutation family guess

| family | count |
|---|---:|
| encoding | 1 |
| structural | 15 |

## 4. Summary by recommended action

| action | count |
|---|---:|
| keep_or_modify | 16 |

## 5. Missing or weak priority family

- `contextual`
- `noise_injection`
- `cross_lingual`
- `semantic_paraphrase`

## 6. Inventory table

| file | op_id | family_guess | input_requirement | output_format | strength | semantic_preservation | label_change_risk | status | action | use_v1 |
|---|---|---|---|---|---|---|---|---|---|---|
| src/operators/op_comp_expand_context.py | op_comp_expand_context | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_constraint_schema_preserving_mutation.py | op_constraint_schema_preserving_mutation | structural | PROMPT_TEXT; TOOL_ARGUMENTS | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_markdown_wrapper.py | op_fmt_markdown_wrapper | structural | PROMPT_TEXT | markdown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_punctuation_resegmentation.py | op_fmt_punctuation_resegmentation | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_structured_wrapper_json_yaml.py | op_fmt_structured_wrapper_json_yaml | structural | PROMPT_TEXT | json_or_yaml | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_fmt_whitespace_noise.py | op_fmt_whitespace_noise | structural | PROMPT_TEXT; SYSTEM_MESSAGE | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_homoglyph_injection.py | op_lex_homoglyph_injection | encoding | PROMPT_TEXT | plain_text_or_unknown | 1~5 | medium_risk_decode_or_readability_check_needed | medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_override_instructions.py | op_lex_override_instructions | structural | PROMPT_TEXT; SYSTEM_MESSAGE | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_polite_prefix.py | op_lex_polite_prefix | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_refusal_suppression.py | op_lex_refusal_suppression | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
| src/operators/op_lex_shorten.py | op_lex_shorten | structural | PROMPT_TEXT | plain_text_or_unknown | 1~5 | likely_preserved_but_review_needed | low_to_medium | OK | keep_or_modify | yes_reviewed |
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
