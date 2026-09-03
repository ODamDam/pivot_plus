# Outcome GT Judge Execution Protocol v1

- Status: implementation protocol for AI-assisted independent Outcome GT annotation.
- Population: 1,746 frozen Target LLM attack generations per independent pass.
- Total planned judge calls: 3,492 (`1,746 × pass_a` + `1,746 × pass_b`).
- Frozen system prompt: `docs/outcome_gt/OUTCOME_GT_JUDGE_SYSTEM_PROMPT_v1.txt`
- Frozen prompt SHA-256: `a6cb893ef69ad4b688505da6a4511182f88d42956119db9af78a4b940837d64c`.
- Rule source: frozen Outcome Rule Catalog v1.
- Scanner Result and Case GT are prohibited from the judge payload.

## 1. Model/runtime freeze

Each independent pass must use one exact judge runtime recorded by `outcome_gt_annotator_provenance.v1`.

Before a full pass starts, freeze:
- `pass_id`
- `annotator_id`
- provider and provider version
- exact model ID and model digest
- repository HEAD / runner version
- frozen prompt SHA-256
- assignment/request SHA-256
- temperature `0.0`, top-p `1.0`, fixed seed, max output tokens
- transport retry policy

Pass A and Pass B must not read each other's outputs. Prefer different judge models when feasible. Model choice is a runtime provenance decision and must not modify the frozen Outcome Rule Catalog or judge prompt.

## 2. Request materialization

After `assignment_1746_v1.jsonl` and each pass manifest exist locally:

```powershell
python scripts/outcome_gt/materialize_outcome_gt_judge_requests_v1.py
```

This creates exactly 3,492 local response-bearing judge requests:
- `judge_requests/pass_a/judge_requests_1746_v1.jsonl`
- `judge_requests/pass_b/judge_requests_1746_v1.jsonl`

The two request manifests are non-response-bearing provenance checkpoints.

## 3. Canary before full execution

Run a small canary with the exact model/settings intended for the pass:

```powershell
python scripts/outcome_gt/run_outcome_gt_judge_v1.py `
  --pass-id pass_a `
  --model <EXACT_OLLAMA_MODEL> `
  --annotator-id <PASS_A_ANNOTATOR_ID> `
  --seed 4101 `
  --limit 10
```

A canary uses its own deterministic run ID and never counts as the production pass.

Inspect only operational validity:
- request/result counts
- JSON/schema validity
- literal evidence validity
- no automatic semantic/parse retry

Do not tune the frozen rule or prompt to improve label distribution.

## 4. Full pass

Run each pass with exact frozen settings and no `--limit`.

```powershell
python scripts/outcome_gt/run_outcome_gt_judge_v1.py `
  --pass-id pass_a `
  --model <EXACT_OLLAMA_MODEL_A> `
  --annotator-id <PASS_A_ANNOTATOR_ID> `
  --seed 4101

python scripts/outcome_gt/run_outcome_gt_judge_v1.py `
  --pass-id pass_b `
  --model <EXACT_OLLAMA_MODEL_B> `
  --annotator-id <PASS_B_ANNOTATOR_ID> `
  --seed 9207
```

The runner:
- verifies Ollama version and installed-model digest;
- freezes prompt/request/assignment hashes in provenance;
- uses deterministic sampling settings;
- permits transport retry only;
- forbids automatic semantic and parse retries;
- appends raw results and updates a resumable checkpoint;
- wraps successful semantic outputs into `outcome_gt_independent_decision.v1`.

If execution is interrupted, re-run the exact same command. The deterministic run ID restores the same run directory and skips all previously terminal requests. Semantic/parse/evidence failures are not silently re-judged.

## 5. Pass validation

A full judge run is accepted only when all 1,746 requests succeed and provenance status is `COMPLETE`.

```powershell
python scripts/outcome_gt/validate_outcome_gt_judge_run_v1.py `
  --pass-id pass_a `
  --run-id <OGTJRUN-V1-A-...>

python scripts/outcome_gt/validate_outcome_gt_judge_run_v1.py `
  --pass-id pass_b `
  --run-id <OGTJRUN-V1-B-...>
```

The wrapper verifies judge provenance and then invokes the existing canonical pass validator, which restores private lineage, verifies response/rule/request equality and literal evidence, derives `outcome_label`, and emits canonical `outcome_gt_annotation.v1`.

## 6. Disagreement construction

Only after both full passes validate:

```powershell
python scripts/outcome_gt/build_outcome_gt_disagreement_queue_v1.py `
  --pass-a <PASS_A_ANNOTATIONS_JSONL> `
  --pass-b <PASS_B_ANNOTATIONS_JSONL>
```

Human adjudication is restricted to disagreement rows, with a separate stratified audit of agreement rows.

## 7. Local-only policy

The following remain local-only because they contain response-bearing material:
- judge request JSONL
- raw judge output JSONL
- independent decision JSONL
- canonical annotation JSONL
- disagreement JSONL

Non-response-bearing request manifests, annotator provenance, checkpoints, and annotation manifests may be committed after validation.
