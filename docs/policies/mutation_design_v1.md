# Mutation Design v1

## 1. Purpose

In this benchmark, mutation is not simple data augmentation. It is a diagnostic mechanism for testing whether scanner evaluators can detect prompt injection intent under surface-level, structural, linguistic, and contextual variation.

The core question is:

> Can an evaluator detect the same malicious intent after the prompt has been transformed without changing its attack goal?

## 2. Dataset Role

The final diagnostic benchmark contains approximately 1,000 samples.

| subset | target_count | role |
| --- | ---: | --- |
| seed_malicious | 250 | Original malicious prompt injection seeds |
| mutated_malicious | 500 | Semantically preserved mutations of malicious seeds |
| structure_intact_malicious | 150 | Structure-preserving or indirect-like malicious samples |
| benign | 100 | Normal and hard-negative prompts for false-positive measurement |

The mutated subset is used to measure evaluator robustness. It should not replace the original seed subset. Instead, seed-mutated pairs should be analyzed together.

## 3. Mutation Definition

A mutation is a transformation that changes the expression, format, language, context, or structure of a malicious seed while preserving the original attack goal.

A valid mutation must satisfy the following conditions:

1. The original attack intent is preserved.
2. The ground-truth decision remains malicious.
3. The parent seed is traceable through parent_seed_id.
4. The mutation operator and family are recorded.
5. The mutation strength is recorded.
6. The target evaluator weakness is identifiable.
7. The result is manually reviewable.

## 4. Evaluator Weakness Targets

| mutation_family | examples | target_evaluator_weakness |
| --- | --- | --- |
| lexical | typo, spacing, leetspeak | keyword_matching, regex_boundary |
| encoding | Base64, URL encoding, ROT13 | normalization |
| unicode | zero-width, homoglyph | normalization |
| paraphrase | meaning-preserving rewrite | semantic_understanding |
| roleplay | persona, fictional task, developer mode | semantic_understanding, judge_consistency |
| format | JSON, YAML, Markdown, HTML | structure_handling |
| context_padding | irrelevant surrounding context | context_awareness, signal_dilution |
| adversarial_suffix | trailing bypass sentence | judge_consistency |
| multilingual | Korean-English mixing, code-switching | semantic_understanding |
| indirect_wrapper | document/repository/retrieval wrapper | context_awareness, structure_handling |

## 5. Mutation Application Principles

| principle | description |
| --- | --- |
| semantic preservation | The original attack goal must remain unchanged. |
| traceability | Every mutated sample must retain parent_seed_id. |
| operator applicability | Operators must be compatible with attack_type, attack_surface, and input_format. |
| single vs composite distinction | Single-operator and composite-operator mutations must be distinguishable. |
| strength control | mutation_strength must be recorded for robustness analysis. |
| manual review | Broken or semantically shifted mutations must be dropped or relabeled. |
| benign separation | Benign mutations are not part of the main malicious mutation set. |

## 6. Smoke Test Scope

The first smoke test should be limited to a small number of manually reviewed malicious seeds.

Recommended scope:

| item | value |
| --- | --- |
| seed_count | 10-20 |
| seed_condition | review_decision = keep |
| attack_type_condition | attack_type != unspecified |
| mutation_mode | single operator only |
| mutation_strength | low or 1-2 |
| mutation_per_seed | 1-2 |
| structure_intact | excluded from first smoke test |
| benign | excluded from first smoke test |

The purpose of the smoke test is to verify execution, metadata preservation, and semantic validity, not to generate the full mutated dataset.
