# Data Pipeline Repository Integration Plan

- Approved date: 2026-07-30
- Integration branch: `integrate-data-pipeline-v1`
- Destination repository: `pivot_plus`
- Destination freeze tag: `pre-monorepo-execution-pipeline-20260730`
- Destination freeze commit: `2819efe40b237d63aced885d73ef083e57f9c3cb`
- Source repository: `llm-prompt-injection-diagnostic-benchmark`
- Source freeze tag: `pre-monorepo-data-pipeline-20260730`
- Source freeze commit: `adef409ccba5c192b037b41a96e12c7fcca61c52`

## Integration purpose

The two repositories are being integrated into one research workspace so that
dataset construction, mutation, target-LLM generation, scanner execution,
native evaluator comparison, human adjudication, and robustness analysis can be
managed through one reproducible pipeline.

## Approved migration summary

- `import_data_pipeline`: 164 files
- `relocate_data_pipeline`: 92 files
- `keep_execution`: 1 file
- `merge_manually`: 2 files
- unresolved paths: 0
- duplicate destination paths: 0
- unexpected existing-path collisions: 0

## Path policy

### Directly imported

The following source areas are imported into the corresponding destination
paths because no meaningful path or Python module conflict was detected:

- `src/`
- `scripts/`
- `tests/`
- `docs/`
- `examples/`
- `pytest.ini`

The destination repository copy of `src/__init__.py` is retained.

### Relocated

The former data-pipeline repository README is preserved as:

- `docs/legacy/data_pipeline_repository_README.md`

The source repository freeze records are preserved with explicit
data-pipeline-specific filenames under:

- `reports/pre_monorepo_freeze/`

### Archived research artifacts

All tracked files formerly under the source repository's `data/` directory are
relocated under:

- `data/archive/pre_monorepo_data_pipeline_20260730/`

These files are retained as historical curation, mutation, review, and dataset
construction evidence.

They must not be interpreted as:

- active Ground Truth,
- validated final benchmark data,
- current annotation outputs,
- or final experiment results.

Individual records may later be reconsidered as candidates only after source
license review, provenance verification, duplicate checking, and independent
human adjudication.

### Manual merge

The following files are not overwritten automatically:

- `.gitignore`
- `.gitattributes`

Their relevant policies will be merged manually after importing the source
files.

## Source-data policy after integration

Externally hosted original datasets should generally be reacquired from their
official sources through versioned download scripts rather than copied from
local legacy folders.

Before use, each source must be reviewed for:

- data license,
- academic research permission,
- modification and derivative-work permission,
- redistribution restrictions,
- attribution and citation requirements,
- and privacy or third-party content concerns.

Upstream labels remain provenance metadata and do not become final Ground
Truth without independent adjudication.

## Approved migration map

The file-level source, destination, decision, blob hash, and review note are
recorded in:

- `migration_map_approved_v1_20260730.csv`
