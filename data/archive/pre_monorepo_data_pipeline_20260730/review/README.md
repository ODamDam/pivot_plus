# Review Data Directory

This directory stores manual-review and curation artifacts used to build the benchmark dataset.

## Purpose

`data/review/` is an intermediate review layer between normalized raw-source candidates and final benchmark-ready datasets.

It is used to:

- inspect normalized source candidates,
- mark rows as keep/drop/pending,
- separate malicious, benign, hard-negative, bypass, context-eval, and structure-intact candidates,
- prepare seed curation batches,
- preserve review and selection audit trails.

## Main review files

| File | Role |
| --- | --- |
| `manual_review_seed_malicious_schema_v1.csv` | Main malicious seed candidate review file. Used for seed curation and mutation input generation. |
| `manual_review_bypass_candidate_schema_v1.csv` | Bypass-oriented malicious candidate review file. Used together with malicious seed candidates for mutation smoke input generation. |
| `manual_review_structure_intact_malicious_schema_v1.csv` | Structure-intact malicious candidate review file. Used to preserve prompts where format, wrapping, encoding, or structured input is part of the attack surface. |
| `manual_review_benign_schema_v1.csv` | Benign candidate review file for safe/negative examples. |
| `manual_review_hard_negative_schema_v1.csv` | Hard-negative candidate review file. These rows may look suspicious but should not necessarily be labeled malicious. |
| `manual_review_context_eval_schema_v1.csv` | Context-evaluation candidate file. Used for cases where system/user context interaction is important. |

## Batch files

`data/review/batches/` contains derived review batches and curated subsets.

| File | Role |
| --- | --- |
| `structure_sensitive_seed_6_v1.csv` | Six structure-sensitive seeds separated for explicit tracking. These emphasize structure handling, format injection, JSON/YAML/HTML/Markdown surfaces, or structure-dependent evaluator behavior. |
| `seed_curation_100_v1.csv` | Curated 100-seed list. It preserves the original 50 kept seeds and adds 50 additional candidates while maintaining source, attack type, and input format diversity. |
| `mutation_input_smoke_excluded_v1.csv` | Audit file for rows excluded while building the smoke-test mutation input. Typical exclusion reasons include `not_kept_by_review` and `zero_mutation_budget`. |

## Review decision fields

Common review-related fields include:

| Field | Meaning |
| --- | --- |
| `review_decision` | Manual or assisted decision such as `keep`, `drop`, or blank/pending. |
| `review_note` | Human-readable rationale for the decision. |
| `needs_relabel` | Whether the row may require label correction. |
| `review_status` | Review state or provenance, such as assistant-suggested pending confirmation. |
| `candidate_use` | Intended use of the candidate, when available. |
| `curation_status` | Curation-stage status added by batch selection scripts, such as `existing_keep` or `added_for_seed100`. |
| `curation_note` | Explanation for why a row was included in a curated batch. |

## Current curated outputs

As of `v1`, the active curated review artifacts are:

- `data/review/batches/structure_sensitive_seed_6_v1.csv`
- `data/review/batches/seed_curation_100_v1.csv`

The 100-seed curation file contains:

- 100 total rows,
- 100 unique `sample_id` values,
- 50 existing keep rows,
- 50 newly added curation rows.

## Relationship to final data

Review files are not necessarily final benchmark files.

The expected flow is:

```text
data/raw/
  -> normalized candidates
  -> data/review/*.csv
  -> data/review/batches/*.csv
  -> data/final/*.jsonl or *.csv
For mutation smoke validation, reviewed malicious seed files are converted into mutation-engine input, mutated, filtered, manually validated if needed, and then exported back into dataset_schema_v1.

Relevant mutation smoke outputs include:

data/final/mutation_input_smoke_v1.jsonl
data/final/mutation_smoke_output_v1.jsonl
data/final/mutation_smoke_valid_v1.jsonl
data/final/mutation_smoke_review_v1.jsonl
data/final/mutation_smoke_dropped_v1.jsonl
data/final/mutation_smoke_valid_manual_v1.jsonl
data/final/mutation_smoke_valid_dataset_schema_v1.csv
Notes
Keep original manual review files stable when possible.
Prefer writing derived subsets to data/review/batches/.
Use batch files to preserve auditability before changing source review decisions directly.
Do not treat blank review_decision rows as final keep rows unless a curation script explicitly selects them.
