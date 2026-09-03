# Target LLM Production Generation Closure v1

## Identity

- Status: `TARGET_LLM_PRODUCTION_GENERATION_v1 CLOSED`
- Run ID: `target-llm-production-v1`
- Branch: `feature/dataset-a-construction-v1`
- Run creation commit: `840ee874d651086d3b0809af5d04e4cecd702697`
- Closure checkpoint: the Git commit containing this report
- Provider: `ollama`
- Model: `qwen2.5:7b`

## Population

- Total generations: 2,661
- Attack generations: 1,746
- Supplemental direct generations: 915
- Total runtime-generated production cases: 887
- Dataset A runtime-bound cases: 582
- Supplemental cases: 305
- Dataset A standalone/no-runtime-boundary cases excluded from production generation: 320

| Population | r1 | r2 | r3 |
|---|---:|---:|---:|
| Attack | 582 | 582 | 582 |
| Supplemental direct | 305 | 305 | 305 |

## Integrity

Canonical results artifact:

`experiments/target_llm_production_v1/runs/target-llm-production-v1/results.jsonl`

- JSONL rows: 2,661
- Valid JSON rows: 2,661
- Bad lines: 0
- Unique `generation_id`: 2,661
- Duplicate `generation_id`: 0
- Empty responses: 0
- `execution_status=completed`: 2,661
- Technical retries: 0
- Results SHA-256: `350345bc370265943f36291558686888682bcbcbff6549a2c8db4babad88fe75`

Authoritative execution plan:

`experiments/target_llm_production_v1/inputs/production_main_execution_plan_2661_v1_1.jsonl`

- Plan SHA-256: `ff933826597e5d4107c011fc2507754e7cf675ef16617c15f3226737eaf79101`
- Plan/result generation ID set equality: `PASS`
- Missing generations: 0
- Extra generations: 0
- Mode mismatches: 0
- Replicate mismatches: 0
- Production case mismatches: 0
- Source artifact SHA mismatches: 0
- Seed mismatches: 0
- Generation option mismatches: 0
- Provider mismatches: 0
- Model mismatches: 0

## Raw Artifact Provenance

The canonical raw run directory is:

`experiments/target_llm_production_v1/runs/target-llm-production-v1/`

The directory is a local runtime artifact and is intentionally not tracked in Git. The GPU notebook working copy is retained, and a full directory backup is retained separately in OneDrive. The backup `results.jsonl` SHA-256 was independently recalculated and exactly matched the canonical results SHA-256 recorded above. No user-specific OneDrive path is recorded here.

The canonical run files have the following verification hashes:

| File | SHA-256 |
|---|---|
| `manifest.json` | `101bf5e1590a16f552904c60c3f061f7610c68fa605280f4991e6e815e14c6ee` |
| `run_summary.json` | `fb88cec54c0a3cfbcadad5d34fea7b1d5bf023427dc4db255c78875adaabd91b` |
| `attempts.jsonl` | `67c9c8c7546fb37601a844280791ffc45d0082a7d12ccd29eb34a34ee73d9982` |
| `checkpoint.json` | `ebea504c491e0f639537795299ddfeaf16364cc355a02866e796232ae10ca4cb` |
| `execution_plan.jsonl` | `5073b6e884e90ffa753547d7db08e071025f988f3283ede8e13f8da94bb8d72c` |

Raw runtime artifacts are not committed to Git. The hashes in this report provide stable verification references without copying response or request content into the report.

## Canonical and Duplicate Runtime Directories

A non-canonical duplicate runtime directory currently exists locally at:

`experiments/target-llm-production-v1/`

At closure audit time, its six runtime files were byte-identical to the corresponding files in the canonical run directory. The canonical artifact location remains `experiments/target_llm_production_v1/runs/target-llm-production-v1/`. The duplicate is not modified or deleted as part of closure and is recorded only as future housekeeping.

## Provenance Note

The run manifest records `git_dirty_at_run_creation=true`, indicating that uncommitted or untracked working-tree state existed when the run directory was created. This provenance value is preserved unchanged. The authoritative plan hash, results hash, exact generation-ID join, and run metadata were independently verified to fix the execution input/output identity.

## Closure Decision

- Target LLM production generation v1 is closed.
- Semantic retry or regeneration of these generations is prohibited.
- Existing responses are immutable source artifacts.
- Any future execution must use a distinct run ID and version.
- The next research stages are Outcome GT followed by Dataset B.
- Scanner Results are not part of this production-generation closure.
