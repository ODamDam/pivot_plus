# LLM Prompt Injection Diagnostic Benchmark

A benchmark-building and mutation workflow for evaluating LLM security scanners against **LLM01: Prompt Injection**.

This repository contains the code and curated review artifacts used to prepare prompt-injection evaluation data, run mutation smoke tests, validate mutation outputs, and export benchmark-ready records.

---

## Overview

This project supports a reproducible workflow for building prompt-injection benchmark data.

The current repository focuses on:

* collecting and normalizing prompt-injection candidates,
* manually reviewing malicious, benign, hard-negative, bypass, context-eval, and structure-intact candidates,
* curating seed sets for mutation and evaluation,
* running mutation smoke tests through the mutation engine,
* filtering valid, review-needed, and dropped mutation outputs,
* exporting validated mutation outputs into `dataset_schema_v1`,
* documenting review and curation artifacts for downstream scanner evaluation.

The current pilot scope is centered on **OWASP LLM01: Prompt Injection**.

---

## Project Goal

The goal of this repository is to support a benchmark workflow like the following:

```text
raw prompt-injection source data
-> normalized candidate records
-> manual review and curation
-> curated seed set
-> mutation-engine input
-> mutation smoke run
-> valid/review/drop filtering
-> manual validation when needed
-> dataset_schema_v1 export
-> downstream scanner evaluation
```

This enables evaluation of how LLM security scanners respond to:

* direct prompt injection,
* instruction override,
* role-play bypass,
* policy bypass,
* data exfiltration prompts,
* format or structure-sensitive injection,
* mutated variants of known malicious seeds.

---

## Repository Structure

```text
.
├── data/
│   ├── raw/                    # local raw source datasets
│   ├── review/                 # manual review files and curation artifacts
│   │   ├── README.md           # review-layer documentation
│   │   └── batches/            # derived curation and audit batches
│   └── final/                  # generated final/intermediate artifacts
├── docs/                       # project notes, policy docs, and design documentation
├── reports/                    # generated local summaries and validation reports
├── scripts/                    # review, validation, mutation, export, and inspection scripts
├── src/
│   ├── config/                 # configuration and operator/bucket settings
│   ├── core/                   # mutation engine core logic
│   ├── operators/              # mutation operators
│   └── pipelines/              # pipeline-oriented execution scripts
├── tests/                      # unit tests
└── README.md
```

Large raw datasets and heavy generated outputs may be managed outside the main code repository when needed.

---

## Data Workflow

The active data workflow is organized into four layers.

```text
data/raw/
  -> normalized candidates
  -> data/review/*.csv
  -> data/review/batches/*.csv
  -> data/final/*.jsonl or *.csv
```

### 1. Raw data

`data/raw/` stores local source datasets or downloaded source files.

Raw files are not always intended to be committed. Depending on size and licensing constraints, they may be kept local or managed separately.

### 2. Review data

`data/review/` stores manual-review and curation files.

Main review files include:

```text
data/review/manual_review_seed_malicious_schema_v1.csv
data/review/manual_review_bypass_candidate_schema_v1.csv
data/review/manual_review_structure_intact_malicious_schema_v1.csv
data/review/manual_review_benign_schema_v1.csv
data/review/manual_review_hard_negative_schema_v1.csv
data/review/manual_review_context_eval_schema_v1.csv
```

See:

```text
data/review/README.md
```

for detailed documentation of review files and review fields.

### 3. Review batches

`data/review/batches/` stores derived review batches and audit artifacts.

Current active batch artifacts include:

```text
data/review/batches/structure_sensitive_seed_6_v1.csv
data/review/batches/seed_curation_100_v1.csv
data/review/batches/mutation_input_smoke_excluded_v1.csv
```

Current curation status:

```text
seed_curation_100_v1.csv
- total rows: 100
- unique sample_id values: 100
- existing keep rows: 50
- newly added curation rows: 50
```

The structure-sensitive seed batch contains six explicitly separated seeds for structure-handling, format-injection, and structured-input evaluation.

### 4. Final artifacts

`data/final/` stores generated JSONL/CSV artifacts used by mutation smoke tests and downstream exports.

Typical local mutation smoke artifacts include:

```text
data/final/mutation_input_smoke_v1.jsonl
data/final/mutation_smoke_output_v1.jsonl
data/final/mutation_smoke_valid_v1.jsonl
data/final/mutation_smoke_review_v1.jsonl
data/final/mutation_smoke_dropped_v1.jsonl
data/final/mutation_smoke_valid_manual_v1.jsonl
data/final/mutation_smoke_valid_dataset_schema_v1.csv
```

Some `data/final/` outputs may be generated locally and not committed.

---

## Current Mutation Smoke Status

The current mutation smoke workflow produced the following validation result:

```text
mutation input rows: 44
mutation output rows: 44
failure rows: 0

auto-valid rows: 39
manual-review rows: 1
dropped rows: 4
final manually validated rows: 40
dataset_schema_v1 exported rows: 40
```

The single manual-review row was an encoding-obfuscation / homoglyph mutation. It was manually kept because the malicious instruction intent was preserved and the row is useful for normalization robustness evaluation.

Dropped rows were excluded because the mutation output was unchanged.

---

## Key Scripts

### Build mutation smoke input

Build mutation-engine-compatible smoke input from reviewed seed files.

```powershell
python scripts/build_mutation_input_from_reviewed_seeds_v1.py `
  --input data/review/manual_review_seed_malicious_schema_v1.csv data/review/manual_review_bypass_candidate_schema_v1.csv `
  --output data/final/mutation_input_smoke_v1.jsonl `
  --excluded-output data/review/batches/mutation_input_smoke_excluded_v1.csv `
  --summary-output reports/mutation_input_smoke_summary_v1.md `
  --limit 0
```

On Windows, if relative path handling fails in a local environment, pass absolute paths using `$root = (Get-Location).Path`.

### Run mutation smoke test

Run the mutation engine over the smoke input.

```powershell
python scripts/run_mutation_smoke_from_engine_input_v1.py `
  --input data/final/mutation_input_smoke_v1.jsonl `
  --output data/final/mutation_smoke_output_v1.jsonl `
  --summary-output reports/mutation_smoke_summary_v1.md `
  --seed-base 20260707 `
  --selector weighted
```

### Filter valid mutation outputs

Split mutation smoke outputs into valid, review-needed, and dropped outputs.

```powershell
python scripts/filter_valid_mutation_outputs_v1.py `
  --input data/final/mutation_smoke_output_v1.jsonl `
  --valid-output data/final/mutation_smoke_valid_v1.jsonl `
  --review-output data/final/mutation_smoke_review_v1.jsonl `
  --dropped-output data/final/mutation_smoke_dropped_v1.jsonl `
  --summary-output reports/mutation_smoke_validation_summary_v1.md
```

### Export validated mutation outputs to dataset schema

Convert manually validated mutation smoke JSONL into `dataset_schema_v1` CSV.

```powershell
python scripts/export_mutation_smoke_valid_to_dataset_schema_v1.py `
  --input data/final/mutation_smoke_valid_manual_v1.jsonl `
  --output data/final/mutation_smoke_valid_dataset_schema_v1.csv `
  --summary-output reports/mutation_smoke_valid_dataset_schema_export_summary_v1.md
```

Expected current export result:

```text
rows: 40
columns: 40
subset: mutated_malicious
is_mutated: true
```

---

## Review and Curation Artifacts

### `structure_sensitive_seed_6_v1.csv`

Purpose:

```text
Separate six structure-sensitive seeds for explicit tracking.
```

Selection emphasizes:

* `target_evaluator_weakness = structure_handling`,
* format or structure-sensitive prompts,
* JSON/YAML/HTML/Markdown-like surfaces,
* structure-dependent evaluator behavior.

Current selected rows:

```text
SEED-CAND-000292 | format_injection  | markdown | structure_handling
SEED-CAND-000373 | format_injection  | markdown | structure_handling
SEED-CAND-000212 | data_exfiltration | json     | structure_handling
SEED-CAND-000051 | policy_bypass     | yaml     | structure_handling
SEED-CAND-000272 | format_injection  | html     | structure_handling
SEED-CAND-000127 | data_exfiltration | markdown | structure_handling
```

### `seed_curation_100_v1.csv`

Purpose:

```text
Expand reviewed malicious seed curation from 50 to 100 rows.
```

Current validation:

```text
rows: 100
unique sample_id values: 100
existing keep rows: 50
newly added rows: 50
```

The selection balances:

* source diversity,
* attack type diversity,
* input format diversity,
* structure-sensitive coverage,
* mutation suitability.

### `mutation_input_smoke_excluded_v1.csv`

Purpose:

```text
Audit rows excluded while building mutation smoke input.
```

Typical exclusion reasons include:

* `not_kept_by_review`,
* `zero_mutation_budget`,
* duplicate or unsuitable rows depending on the adapter policy.

---

## Schema Notes

The active review and final-export format is aligned with `dataset_schema_v1`.

Common fields include:

```text
sample_id
subset
source_id
source_record_id
scanner_input
scanner_input_prompt_only
scanner_input_with_context
is_malicious
ground_truth_decision
attack_category
attack_type
attack_goal
attack_surface
input_format
language
is_mutated
mutation_family
mutation_operator
mutation_strength
target_evaluator_weakness
semantic_preservation
expected_behavior
review_status
normalized_record_id
text_sha256
metadata_json
candidate_use
is_structure_intact
is_context_eval
is_augmented
group_id
text_length
scanner_input_preview
```

Mutation-exported rows use:

```text
subset = mutated_malicious
is_mutated = true
ground_truth_decision = malicious
candidate_use = mutation_smoke_valid
```

---

## Mutation Engine Components

### Core

`src/core/` contains the mutation engine core logic, including registry, selection, mutator orchestration, randomization, and validity-related utilities.

### Operators

`src/operators/` contains mutation operators.

Operator families include examples such as:

* contextual wrappers,
* structural wrappers,
* syntactic delimiter injection,
* lexical perturbation,
* whitespace or punctuation noise,
* encoding and homoglyph obfuscation,
* schema-preserving field wrapping,
* salience-preserving compression.

### Scripts

`scripts/` contains practical project scripts for:

* source inspection,
* review status inspection,
* mutation input construction,
* mutation smoke execution,
* mutation-output filtering,
* export to `dataset_schema_v1`,
* operator inventory inspection.

---

## Recommended Working Order

For the current review/mutation workflow:

```text
1. Inspect or update manual review CSV files.
2. Curate seed batches under data/review/batches/.
3. Build mutation smoke input from reviewed seeds.
4. Run mutation smoke.
5. Filter valid/review/dropped outputs.
6. Manually inspect review-needed mutation rows.
7. Create manually validated mutation JSONL.
8. Export validated mutation rows to dataset_schema_v1.
9. Review generated summaries under reports/.
10. Commit only code, documentation, and intentionally selected review artifacts.
```

---

## Git Hygiene

Recommended practice:

```text
- Keep large raw datasets out of normal commits unless intentionally tracked.
- Keep generated reports local unless they are needed for auditability.
- Commit review batch artifacts when they explain a curation decision.
- Prefer data/review/batches/ for derived review subsets.
- Prefer data/final/ for generated mutation or export outputs.
- Keep reports/ ignored unless a summary is explicitly needed in the PR.
```

Before committing:

```powershell
git status --short
git diff --stat
```

Before opening a PR:

```powershell
git show --stat --oneline HEAD
git status --short
```

---

## Current Scope

This repository currently emphasizes:

* OWASP LLM01 Prompt Injection,
* seed curation for scanner evaluation,
* mutation-based robustness testing,
* structure-sensitive prompt tracking,
* evaluator weakness-oriented mutation analysis,
* dataset schema export for downstream scanner execution.

Future work may expand to:

* larger curated seed pools,
* additional mutation operators,
* broader attack-type coverage,
* scanner-specific execution adapters,
* final benchmark dataset generation at larger scale.

---

## Status

The repository is under active development for a cybersecurity graduation project focused on prompt-injection scanner evaluation.

Current active work includes:

```text
- review curation expansion,
- mutation engine validation,
- mutation smoke testing,
- dataset_schema_v1 export,
- final benchmark dataset preparation.
```
