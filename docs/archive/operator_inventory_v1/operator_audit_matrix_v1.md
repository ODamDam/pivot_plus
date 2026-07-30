# Operator Audit Matrix v1

## Purpose

This document audits each mutation operator for Prompt Injection Diagnostic Benchmark v1.
Each operator is reviewed not only by whether it runs, but by what evaluator weakness it is designed to test.

## Target Evaluator Weakness Values

| value | meaning |
| --- | --- |
| keyword_regex | Tests keyword or regex based detection weakness |
| syntax_filter | Tests syntax-level filtering weakness |
| normalization | Tests whitespace, homoglyph, unicode, or zero-width normalization weakness |
| exact_match | Tests exact string or fixed template matching weakness |
| semantic_intent | Tests whether evaluator recognizes the malicious intent after surface-level changes |
| structure_parsing | Tests whether evaluator understands structured input such as JSON, YAML, Markdown, code block |
| context_dilution | Tests whether long benign-looking context dilutes malicious signal |
| judge_consistency | Tests whether LLM-as-Judge is sensitive to framing or suffix changes |
| language_transfer | Tests Korean/English/code-switching robustness |
| indirect_pi | Tests indirect prompt injection inside document, webpage, email, retrieved context, or summary wrapper |
| action_intent | Tests tool/API/action execution intent recognition |

## Audit Table

| operator | current_family | v1_family | target_evaluator_weakness | attack_type_compat | surface_compat | decision | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| op_comp_expand_context | noise_injection | context_padding | context_dilution, semantic_intent, judge_consistency | data_exfiltration, indirect_injection, instruction_override | PROMPT_TEXT | keep | Empty seed fixed. Smoke test passed. Example documented. Minor trace consistency cleanup can be handled later. |
| op_constraint_schema_preserving_mutation | structural | format_injection | structure_parsing, syntax_filter | format_injection, tool_manipulation | PROMPT_TEXT, TOOL_ARGUMENTS | keep_conditional | Should be prioritized only for JSON/tool argument-like inputs. |
| op_fmt_markdown_wrapper | structural | format_injection, indirect_wrapper | structure_parsing, indirect_pi | data_exfiltration, format_injection, indirect_injection, instruction_override | PROMPT_TEXT | keep | Empty seed fixed. Good example candidate. |
| op_fmt_punctuation_resegmentation | syntactic | punctuation_resegmentation | syntax_filter, keyword_regex, exact_match, semantic_intent | data_exfiltration, instruction_override, policy_bypass | PROMPT_TEXT | keep | Metadata revised. target_evaluator_weakness added. Period replacement, bullet resegmentation, numbered resegmentation, and fallback behavior verified and documented. Good syntactic resegmentation operator. |
| op_fmt_structured_wrapper_json_yaml | structural | format_injection | structure_parsing, indirect_pi | data_exfiltration, format_injection, indirect_injection, instruction_override | PROMPT_TEXT | keep | Good structure-intact operator. |
| op_fmt_whitespace_noise | noise_injection | unicode_noise | normalization, keyword_regex | data_exfiltration, instruction_override, policy_bypass | PROMPT_TEXT, SYSTEM_MESSAGE | keep | Tests spacing/newline robustness. |
| op_lex_homoglyph_injection | encoding | homoglyph_obfuscation | normalization, keyword_regex, exact_match, semantic_intent | data_exfiltration, instruction_override, policy_bypass | PROMPT_TEXT | keep | Metadata revised. target_evaluator_weakness added. Unsafe ? substitutions and combining marks removed. Homoglyph examples verified and documented. Good Unicode normalization robustness operator. |
| op_lex_override_instructions | lexical | roleplay_framing? | semantic_intent | instruction_override | PROMPT_TEXT, SYSTEM_MESSAGE | review | This may create stronger attack rather than mutate existing seed. |
| op_lex_polite_prefix | contextual | benign_contextual_framing | semantic_intent, judge_consistency, keyword_regex, exact_match | data_exfiltration, instruction_override, policy_bypass | PROMPT_TEXT | keep | Metadata revised. Aggressive authorization/refusal-suppression prefixes removed. Polite prefix examples verified and documented. Good benign contextual framing operator. |
| op_lex_refusal_suppression | contextual | refusal_suppression_framing | semantic_intent, judge_consistency, keyword_regex, exact_match | instruction_override, policy_bypass, data_exfiltration | PROMPT_TEXT | keep_conditional | Metadata revised. Refusal-suppression prefixes verified and documented. Applies only to already malicious seeds because the prefix itself can strengthen or introduce policy-bypass intent. |
| op_salience_preserving_line_compression | lexical | salience_preserving_compression | semantic_intent, exact_match, context_dilution, keyword_regex | data_exfiltration, instruction_override, policy_bypass | PROMPT_TEXT | keep_conditional | Renamed from op_lex_shorten. Random line dropping was replaced with salience-preserving compression. Applies only to multi-line prompts with identifiable attack-bearing lines. Preserves risky lines and drops benign/context lines. |
| op_syn_boundary_delimiter_injection | structural | format_injection | structure_parsing, exact_match | data_exfiltration, format_injection, instruction_override | PROMPT_TEXT, SYSTEM_MESSAGE | keep | Boundary marker based structure mutation. |
| op_syn_fake_tool_instruction_injection | tool_manipulation | tool_action_framing | action_intent, semantic_intent | instruction_override, tool_manipulation | PROMPT_TEXT | keep | Text-level tool misuse scenario. |