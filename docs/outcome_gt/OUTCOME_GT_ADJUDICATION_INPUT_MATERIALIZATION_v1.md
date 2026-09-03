# Outcome GT Adjudication Input Materialization v1

## Status

- Workflow status: `IMPLEMENTED`
- Outcome GT contract: `outcome-gt-contract-v1`
- Frozen Rule Catalog: `outcome-rule-catalog-v1`
- Rule Catalog closure commit: `09a57a03a1b61740f45be34e0720b74be75573ff`
- Adjudication population: **582 production cases × r1/r2/r3 = 1,746 attack generations**

This workflow begins only after response-blind rule authoring and Rule Catalog v1 closure. It does not modify Dataset A, Target LLM production results, or frozen rules.

## Join identity

The primary Outcome GT unit is one immutable Target LLM generation keyed by `generation_id`.

Materialization performs two joins:

1. attack execution-plan row ↔ production-result row by exact `generation_id`;
2. joined generation ↔ frozen flat rule by exact `production_case_id`.

The following must all hold before any adjudication input is written:

- production plan SHA-256 = `ff933826597e5d4107c011fc2507754e7cf675ef16617c15f3226737eaf79101`;
- canonical production results SHA-256 = `350345bc370265943f36291558686888682bcbcbff6549a2c8db4babad88fe75`;
- frozen flat-rule SHA-256 = `c85f277f897d29b53445f7e292ae32babac277b564f37945a3dc99c5c90248a8`;
- production results contain 2,661 unique completed generations;
- attack plan/results each contain exactly 1,746 matching generation IDs;
- attack population contains exactly 582 production cases;
- every production case has exactly `r1`, `r2`, and `r3`;
- frozen rule case set exactly equals the 582 attack-case set;
- every response hash is recomputed from `response_text` and must match `response_sha256`.

## Annotation view

Each `outcome_gt_adjudication_input.v1` row contains only:

- generation identity and replicate identity;
- the current generation's immutable response and verified response hash;
- trusted instruction, normal task, trust boundary, trusted context, untrusted input, and injection location from the authoritative attack execution plan;
- the already-frozen flat Outcome Rule for the production case;
- immutable artifact hashes and closure provenance.

The row intentionally excludes:

- Case GT PI/maliciousness labels;
- scanner/evaluator results;
- existing Outcome GT;
- final adjudication or other annotator decisions;
- sibling replicate responses/outcomes.

The canonical materialized file contains 1,746 independent rows, but no row embeds or references another replicate's response. Review tooling must present one row at a time or otherwise prevent sibling-response exposure during an independent pass.

## Local-only response-bearing artifact

Target LLM production responses are intentionally not committed to Git. The adjudication input copies `response_text`, so the generated 1,746-row adjudication input is also a **local response-bearing artifact** and must not be committed.

Canonical local output:

`data/outcome_gt/adjudication_v1/input/outcome_gt_adjudication_input_1746_v1.jsonl`

Manifest:

`data/outcome_gt/adjudication_v1/input/outcome_gt_adjudication_input_1746_v1_manifest.json`

The JSONL path is git-ignored. A response-free manifest may be checkpointed later after local materialization and independent hash verification.

## Commands

Static preflight, which requires no response artifact:

```powershell
python scripts/outcome_gt/materialize_outcome_gt_adjudication_input_v1.py --static-preflight
```

Full materialization must be run in the retained working copy containing the canonical production result:

```powershell
python scripts/outcome_gt/materialize_outcome_gt_adjudication_input_v1.py `
  --results experiments/target_llm_production_v1/runs/target-llm-production-v1/results.jsonl
```

The materializer uses exclusive creation. If an output already exists, it refuses to overwrite it. Re-materialization must use a clean destination after explicit provenance review rather than silently replacing prior evidence.

## Next boundary

Successful materialization creates the evidence population for Outcome GT annotation only. It does **not** assign `boundary_violated`, `attacker_goal_achieved`, `normal_task_completed`, `refusal`, `execution_failure`, or `outcome_label`.

Independent annotation-pass construction, annotation, disagreement resolution, and final Outcome GT freeze are subsequent stages. Scanner Results remain excluded throughout Outcome GT construction.
