# Diagnostic Benchmark Dataset Schema v1

## Dataset Scale

| subset | target_count | description |
| --- | ---: | --- |
| seed_malicious | 250 | Original malicious prompt injection seeds |
| mutated_malicious | 500 | Mutated malicious prompts preserving original attack intent |
| structure_intact_malicious | 150 | Structure-preserving or indirect-like prompt injection samples |
| benign | 100 | Normal and hard-negative prompts for false-positive evaluation |
| total | 1000 | Diagnostic benchmark v1 |

## Final Benchmark Fields

| field | type | required | description |
| --- | --- | --- | --- |
| sample_id | string | yes | Final benchmark sample ID |
| subset | enum | yes | seed_malicious, mutated_malicious, structure_intact_malicious, benign |
| parent_seed_id | string/null | conditional | Parent seed ID for mutated samples |
| source_id | string | yes | Source dataset ID |
| source_record_id | string | yes | Original source row ID |
| source_split | string | no | Original split such as train/test/validation |
| scanner_input | string | yes | Final input passed to scanners |
| scanner_input_prompt_only | string/null | no | Prompt-only input for context-eval samples |
| scanner_input_with_context | string/null | no | Context-included input for context-eval samples |
| is_malicious | boolean | yes | Whether the sample is malicious |
| ground_truth_decision | enum | yes | malicious or benign |
| attack_category | enum | yes | High-level risk category |
| attack_type | enum | yes | Fine-grained attack type |
| attack_goal | enum | yes | Intended attacker goal |
| attack_surface | enum | yes | Where the attack is injected |
| input_format | enum | yes | Input format |
| language | enum | yes | Language or encoding state |
| is_mutated | boolean | yes | Whether mutation was applied |
| mutation_family | string/null | conditional | Mutation family |
| mutation_operator | string/null | conditional | Mutation operator name |
| mutation_strength | string/int/null | conditional | Mutation strength |
| target_evaluator_weakness | enum/null | no | Evaluator weakness targeted by the sample |
| semantic_preservation | enum | yes | Whether original attack intent is preserved |
| expected_behavior | enum | yes | Expected safe evaluator behavior |
| review_status | enum | yes | auto, manual_reviewed, disputed |
| notes | string/null | no | Labeling rationale or review notes |
| normalized_record_id | string | yes | Internal normalized pool record ID |
| text_sha256 | string | yes | Hash for duplicate tracking |
| metadata_json | object/string | no | Source-specific metadata |

## Enum Definitions

### subset

- seed_malicious
- mutated_malicious
- structure_intact_malicious
- benign

### ground_truth_decision

- malicious
- benign

### attack_category

- direct_prompt_injection
- indirect_prompt_injection
- data_risk
- action_risk
- robustness_risk
- benign

### attack_type

- instruction_override
- role_play_bypass
- policy_bypass
- system_prompt_extraction
- data_exfiltration
- format_injection
- indirect_injection
- tool_manipulation
- context_poisoning
- benign_general
- benign_hard_negative
- unspecified

### attack_goal

- override_instruction
- leak_system_prompt
- exfiltrate_secret
- bypass_policy
- manipulate_output_format
- manipulate_tool
- poison_context
- evade_detection
- none

### attack_surface

- user_prompt
- system_user_context
- external_document
- repository_file
- structured_input
- tool_context
- none

### input_format

- plain_text
- markdown
- json
- yaml
- xml
- html
- code_block
- command
- log
- repository_file
- mixed
- encoded
- unknown

### language

- english
- korean
- mixed
- encoded
- unknown

### target_evaluator_weakness

- keyword_matching
- regex_boundary
- normalization
- structure_handling
- semantic_understanding
- context_awareness
- judge_consistency
- none
- unknown

### semantic_preservation

- preserved
- partially_preserved
- not_preserved
- not_applicable

### expected_behavior

- detect_as_malicious
- detect_as_benign
- flag_for_review

### review_status

- auto
- manual_reviewed
- disputed

## ID Convention

| ID | format | example |
| --- | --- | --- |
| seed malicious | SEED-000001 | SEED-000042 |
| mutated malicious | MUT-000001 | MUT-000042 |
| structure-intact malicious | STRUCT-000001 | STRUCT-000042 |
| benign | BENIGN-000001 | BENIGN-000042 |
| final sample | SAMPLE-000001 | SAMPLE-000999 |

## Design Principle

Each sample is not only a text input but a diagnostic test case. The schema must preserve the original source, attack intent, attack surface, mutation trace, expected evaluator behavior, and review rationale.
