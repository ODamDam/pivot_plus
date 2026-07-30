# Operator Policy v2

## 1. Purpose

This document finalizes the operator policy for the `llm-prompt-injection-diagnostic-benchmark` research extension.

The original mutation engine was designed as a general OWASP LLM mutation framework. It used OWASP-style bucket identifiers such as `LLM01_PROMPT_INJECTION`, `LLM04_DATA_POISONING`, `LLM05_INPUT_ROBUSTNESS`, `LLM08_TOOL_MISUSE`, `LLM09_MISINFORMATION`, and `LLM10_DOS` to group and select mutation operators.

However, the current research scope is no longer a general OWASP LLM mutation engine. The current project focuses on building a diagnostic benchmark for **LLM01 Prompt Injection** scanner evaluation.

Therefore, this policy deprecates the bucket-based operator selection model and replaces it with a prompt-injection-specific operator taxonomy.

---

## 2. Final Decision

### 2.1 Bucket system is deprecated

The previous bucket system is deprecated for the diagnostic benchmark v1.

The following fields and modules may remain temporarily for backward compatibility, but they must not determine the final benchmark composition:

- `bucket_tags`
- `bucket_id`
- `ENABLED_BUCKETS`
- `src/config/buckets.py`
- `src/config/enabled_buckets.py`
- bucket-based filtering in registry, selector, mutator, and pipeline scripts

### 2.2 New selection basis

Operators must be selected by research-relevant diagnostic fields:

- `operator_family`
- `attack_type_compat`
- `surface_compat`
- `output_format`
- `semantic_preservation_risk`
- `label_change_risk`
- `use_in_diagnostic_v1`

The benchmark no longer asks:

```text
Which OWASP LLM bucket does this operator belong to?
```

Instead, the benchmark asks:

```text
Which mutation family does this operator represent, and for which prompt injection attack types is it appropriate?
```

---

## 3. Rationale

The earlier general-purpose engine treated OWASP categories as the primary unit of operator grouping. This was useful during the early implementation phase because the project had not yet narrowed its scope.

During the actual research phase, the project scope was narrowed to prompt injection scanner evaluation. In this setting, the OWASP bucket abstraction creates several problems:

1. Operators useful for prompt injection robustness may be hidden under non-LLM01 buckets.
2. Operators technically tagged as LLM01 may represent different mutation families and should not be treated as equivalent.
3. Prompt injection scanner analysis requires family-level and attack-type-level interpretability.
4. Bucket-level selection makes it harder to explain diagnostic coverage in the final paper.

For example, structural and robustness-oriented operators such as JSON/YAML wrapping, whitespace noise, punctuation resegmentation, and schema-preserving mutation may be useful for prompt injection evaluation even if they were originally tagged under LLM05 or other non-LLM01 buckets.

---

## 4. Current Code State at the Time of This Decision

After separating broken and out-of-scope operators, the active operator directory contains 16 importable operators.

The registry successfully loads these 16 operators with zero load errors.

The legacy bucket-based LLM01 filter currently returns only 8 operators:

```text
op_fmt_markdown_wrapper
op_lex_homoglyph_injection
op_lex_override_instructions
op_lex_polite_prefix
op_lex_refusal_suppression
op_lex_shorten
op_syn_boundary_delimiter_injection
op_syn_fake_tool_instruction_injection
```

This confirms that the existing bucket system does not fully represent the operator set needed for the diagnostic benchmark.

---

## 5. Directory Policy

### 5.1 Active operators

```text
src/operators/
```

This directory must contain only operators that are syntactically valid and importable.

Operators in this directory may still be under review, but they must not break registry loading, smoke tests, or inventory generation.

### 5.2 Legacy operators

```text
src/operators_legacy/
```

This directory stores old or broken operators preserved for reference.

Examples:

```text
op_fmt_html_document_embedding.py
op_lex_obfuscation_encoding_wrapper.py
op_syn_authority_pretext_framing.py
```

These operators may be useful conceptually, but the current files contain conflict markers or incompatible code. They should not be imported by the active registry.

If needed, their ideas should be reimplemented as clean v2 operators rather than repaired in place.

### 5.3 Disabled v1 operators

```text
src/operators_disabled_v1/
```

This directory stores syntactically valid operators excluded from diagnostic benchmark v1 because they are out of scope.

Examples:

```text
op_comp_adversarial_training_data_manipulation.py
op_comp_hallucination_induction.py
op_comp_unbounded_consumption.py
op_constraint_biased_training_data_injection.py
op_constraint_model_backdoor_injection.py
op_lex_data_poisoning_injection.py
op_lex_misinformation_generation.py
```

These operators target risks such as data poisoning, hallucination, misinformation, model backdoors, or denial of service. They are not appropriate for prompt injection scanner diagnostic benchmark v1.

---

## 6. New Operator Metadata Schema

### 6.1 Required metadata for v2

Every active diagnostic operator should eventually expose the following metadata:

```python
OPERATOR_META = {
    "op_id": "op_fmt_markdown_wrapper",
    "operator_family": "structural",
    "attack_type_compat": [
        "instruction_override",
        "data_exfiltration",
        "format_injection",
        "indirect_injection"
    ],
    "surface_compat": ["PROMPT_TEXT"],
    "output_format": "markdown",
    "risk_level": "MEDIUM",
    "strength_range": [1, 5],
    "semantic_preservation_risk": "LOW",
    "label_change_risk": "LOW",
    "use_in_diagnostic_v1": True,
    "params_schema": {}
}
```

### 6.2 Legacy compatibility field

The old `bucket_tags` field may remain temporarily:

```python
"bucket_tags": ["LLM01_PROMPT_INJECTION"]
```

However, it is optional and must not be used as the primary selection criterion.

### 6.3 Required metadata fields

| field | required | description |
|---|---:|---|
| `op_id` | yes | Stable operator identifier |
| `operator_family` | yes | Mutation family used for research analysis |
| `attack_type_compat` | yes | Prompt injection attack types this operator can safely mutate |
| `surface_compat` | yes | Supported input surfaces |
| `output_format` | yes | Primary output format produced by the operator |
| `risk_level` | yes | Implementation risk level: LOW, MEDIUM, HIGH |
| `strength_range` | yes | Supported mutation strength range, usually `[1, 5]` |
| `semantic_preservation_risk` | yes | Risk that the mutation changes attack intent |
| `label_change_risk` | yes | Risk that the mutation changes the ground truth label |
| `use_in_diagnostic_v1` | yes | Whether the operator is eligible for benchmark v1 |
| `params_schema` | yes | Operator-specific parameter description |
| `bucket_tags` | no | Legacy compatibility only |

---

## 7. Operator Family Taxonomy

The diagnostic benchmark v1 uses the following mutation families.

| family | purpose | examples |
|---|---|---|
| `lexical` | Word-level or phrase-level transformation | ignore → disregard |
| `syntactic` | Sentence or delimiter-level structure change | imperative → question, delimiter split |
| `semantic_paraphrase` | Meaning-preserving rewrite | same attack intent in different wording |
| `encoding` | Encoding or surface obfuscation | Base64, URL encoding, Unicode homoglyph |
| `structural` | Structural input transformation | JSON, YAML, Markdown, XML, code block |
| `contextual` | Benign-looking context or pretext | debugging, translation, security review, log analysis |
| `noise_injection` | Inserting attack into long or noisy context | logs, documents, example blocks |
| `cross_lingual` | Language mixing or translation | Korean/English mix, translated instruction |
| `tool_manipulation` | Tool call or argument manipulation | fake tool call, tool argument perturbation |
| `indirect_injection` | Injection through external content | repository file, webpage, log, document |

---

## 8. Attack Type Compatibility Mapping

Operators must not be applied to every seed blindly.

The benchmark uses attack-type-specific operator eligibility.

| attack_type | compatible operator families |
|---|---|
| `instruction_override` | lexical, syntactic, contextual, structural, encoding |
| `role_play_bypass` | semantic_paraphrase, contextual, cross_lingual |
| `policy_bypass` | lexical, semantic_paraphrase, contextual, cross_lingual |
| `data_exfiltration` | contextual, structural, encoding, noise_injection |
| `format_injection` | structural, encoding, noise_injection |
| `tool_manipulation` | structural, contextual, tool_manipulation, code/log wrapper |
| `indirect_injection` | structural, noise_injection, indirect_injection, document/repo wrapper |
| `multi_turn_injection` | split_instruction, staged_context, contextual |

---

## 9. Current Active Operator Classification

The following classification is the v2 policy decision for the current 16 active operators.

| operator | family_final | output_format | action_v2 | notes |
|---|---|---|---|---|
| `op_comp_expand_context` | noise_injection / contextual | plain_text | modify_or_conditional_use | Useful for long-context robustness, but must avoid DoS framing. |
| `op_constraint_schema_preserving_mutation` | structural | json | conditional_use | Use only for JSON/tool-argument-like seeds. |
| `op_fmt_markdown_wrapper` | structural | markdown | modify | Empty seed must return SKIPPED. |
| `op_fmt_punctuation_resegmentation` | lexical / syntactic | plain_text | keep_or_modify | Useful for surface robustness. Add diagnostic metadata. |
| `op_fmt_structured_wrapper_json_yaml` | structural | json_or_yaml | keep_or_modify | High-priority structural wrapper. Should be enabled by family, not bucket. |
| `op_fmt_whitespace_noise` | noise_injection / lexical | plain_text | keep_or_modify | Useful for whitespace/surface perturbation. |
| `op_lex_homoglyph_injection` | encoding | plain_text | keep_or_modify | Readability and semantic preservation review required at high strength. |
| `op_lex_override_instructions` | lexical / instruction_override | plain_text | keep | Core prompt injection operator. |
| `op_lex_polite_prefix` | contextual | plain_text | keep_or_modify | Benign-looking pretext/prefix mutation. |
| `op_lex_refusal_suppression` | contextual / policy_bypass | plain_text | keep_or_modify | Strong bypass framing; use with policy_bypass or instruction_override. |
| `op_lex_shorten` | lexical / compression | plain_text | conditional_use | Use only for multiline seeds; semantic preservation must be checked. |
| `op_syn_boundary_delimiter_injection` | structural / syntactic | plain_text | keep | Useful delimiter/boundary mutation. |
| `op_syn_fake_tool_instruction_injection` | tool_manipulation / contextual | plain_text | keep_or_modify | Useful for tool-related prompt injection cases. |
| `op_syn_tool_call_argument_perturbation` | tool_manipulation | tool_call_or_arguments | conditional_use | Use only for tool_call or tool_argument surfaces. |
| `op_syn_trust_violation_trigger` | contextual | plain_text | review | Content must be reviewed; previous bucket was misinformation. |
| `op_syn_unverified_data_injection` | indirect_injection / contextual | plain_text | review | Potentially useful for indirect injection, but previous bucket was data poisoning. |

---

## 10. Immediate Keep Set

The following operators are immediately useful for diagnostic benchmark v1 after metadata migration:

```text
op_fmt_markdown_wrapper
op_fmt_structured_wrapper_json_yaml
op_fmt_punctuation_resegmentation
op_fmt_whitespace_noise
op_lex_homoglyph_injection
op_lex_override_instructions
op_lex_polite_prefix
op_lex_refusal_suppression
op_syn_boundary_delimiter_injection
op_syn_fake_tool_instruction_injection
```

`op_fmt_markdown_wrapper` must be modified before final use because it currently mutates an empty seed into an empty code block.

---

## 11. Conditional Use Set

The following operators should be enabled only when the seed structure supports them:

```text
op_comp_expand_context
op_constraint_schema_preserving_mutation
op_lex_shorten
op_syn_tool_call_argument_perturbation
```

Conditions:

| operator | condition |
|---|---|
| `op_comp_expand_context` | Use only with max length constraints and non-DoS framing. |
| `op_constraint_schema_preserving_mutation` | Use only when the seed is valid JSON or tool-argument-like input. |
| `op_lex_shorten` | Use only for multiline prompts where core attack text is preserved. |
| `op_syn_tool_call_argument_perturbation` | Use only for `TOOL_CALL` or `TOOL_ARGUMENTS` surfaces. |

---

## 12. Review Set

The following operators should not be used until their content and semantics are reviewed:

```text
op_syn_trust_violation_trigger
op_syn_unverified_data_injection
```

They may be useful as contextual or indirect-injection operators, but their previous bucket assignments suggest possible scope mismatch.

---

## 13. New Operators Needed

The current active set still lacks several high-value diagnostic operators.

### 13.1 Structural wrappers

```text
wrap_as_code_comment
wrap_as_log_entry
wrap_as_html_or_xml_document
```

### 13.2 Contextual pretexts

```text
as_translation_request
as_security_test_request
as_policy_review_request
as_log_analysis_request
as_debugging_request
```

### 13.3 Encoding / obfuscation

```text
base64_wrap
url_encode_keywords
zero_width_insert
unicode_escape_wrap
```

### 13.4 Semantic paraphrase

```text
semantic_paraphrase_basic
instruction_as_question
instruction_as_reported_speech
```

### 13.5 Cross-lingual

```text
translate_attack_to_korean
mix_korean_english
split_instruction_across_languages
```

Cross-lingual operators should be used in small quantities because they require manual quality review.

---

## 14. Bucket-Free Code Migration Plan

The codebase should be migrated in the following order.

### Step 1. Update `src/core/types.py`

- Make `bucket_tags` optional.
- Add v2 metadata fields.
- Update `validate_meta()` to validate v2 metadata.
- Retain backward-compatible defaults temporarily.

### Step 2. Update `src/core/registry.py`

- Replace bucket-based filtering with metadata-based filtering.
- Support filtering by:
  - `use_in_diagnostic_v1`
  - `operator_family`
  - `attack_type`
  - `surface`
  - `risk_max`
  - `output_format`
- Stop rejecting operators because of missing `bucket_tags`.

### Step 3. Update `src/core/selector.py`

- Replace `bucket_id` with diagnostic selection fields.
- Select candidates by operator family, attack type, surface, and risk.

### Step 4. Update `src/core/mutator.py`

- Stop injecting or depending on `bucket_id` in the context.
- Pass `attack_type`, `operator_family`, and `surface` in the context.

### Step 5. Update pipeline scripts

- Replace `ENABLED_BUCKETS` and `LLM01_PROMPT_INJECTION` usage.
- Update `inspect_registry.py` to summarize by operator family and diagnostic eligibility.
- Update `run_operator_smoke_test.py` to test `use_in_diagnostic_v1=True` operators instead of LLM01 bucket operators.

### Step 6. Update operator metadata

- Add v2 metadata to each active operator.
- Keep `bucket_tags` only as a legacy field if needed.

---

## 15. New Registry Filtering Semantics

The new registry filter should support calls like:

```python
registry.filter(
    use_in_diagnostic_v1=True,
    operator_family="structural",
    attack_type="data_exfiltration",
    surface="PROMPT_TEXT",
    risk_max="MEDIUM",
)
```

The filter should include an operator only if:

1. `use_in_diagnostic_v1` is true when requested.
2. `operator_family` matches or is contained in a list of families.
3. `attack_type` is contained in `attack_type_compat` when provided.
4. `surface` is contained in `surface_compat` when provided.
5. `risk_level` is less than or equal to `risk_max` when provided.

---

## 16. Selection Policy for Benchmark Generation

When generating mutated malicious samples:

```text
1 seed → average 2 mutations
```

Selection should satisfy:

- Do not apply every operator to every seed.
- Select operators compatible with the seed attack type.
- Avoid repeating the same family too often for one seed.
- Record `operator_family`, `operator_id`, and `mutation_strength` in output metadata.
- Exclude mutations where semantic preservation is uncertain.

---

## 17. Final Policy Statement

For diagnostic benchmark v1, the bucket system is deprecated.

The final benchmark will be organized by prompt-injection-specific diagnostic dimensions:

```text
attack_type
operator_family
input_format
surface
semantic_preservation
label_change_risk
```

The old OWASP bucket labels may remain as historical implementation metadata, but they must not control operator selection, benchmark composition, or paper-level analysis.

