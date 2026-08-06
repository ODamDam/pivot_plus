# Pre-Monorepo Data Pipeline Freeze

- Freeze date: 2026-07-30
- Repository: llm-prompt-injection-diagnostic-benchmark
- Repository role: data collection, normalization, sampling, curation, and mutation
- Status: pilot data-pipeline checkpoint
- Ground Truth status: provisional and not independently validated
- Existing dataset size: 1,000 candidate records

## Important interpretation

The existing 1,000 records are not a validated benchmark or final Ground Truth.
They are a candidate pool produced with substantial reliance on labels supplied
by upstream open-source datasets.

Manual inspection later identified records that:

- were not clearly malicious prompt injections,
- lacked a well-defined attack goal,
- required context that was missing or insufficiently preserved,
- or could not support objective attack-success evaluation.

Therefore, upstream labels and existing provisional labels must be preserved
for provenance, but must not be treated as final human Ground Truth.

## Research purpose

The final dataset must support reliable comparison between scanner-native
evaluators and human Ground Truth for:

- prompt-injection detection,
- attack-goal achievement,
- evaluator disagreement and instability,
- mutation robustness,
- and error analysis by attack type and evaluator weakness.

## Next step

Integrate this repository with pivot_plus, then rebuild the input Ground Truth
before rerunning target-LLM generation, scanner execution, or evaluator analysis.

## Excluded local artifacts

Files intentionally excluded from Git are recorded with their SHA-256 hashes in:

- local_artifacts_manifest_20260730.csv
