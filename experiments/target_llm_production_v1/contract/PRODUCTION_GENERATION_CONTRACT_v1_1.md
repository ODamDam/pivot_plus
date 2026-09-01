# Production Generation Contract v1.1

This version preserves v1 as the audit record of an invalid mandatory-control design and revises only execution-population eligibility. Frozen Dataset A and Non-PI Supplemental artifacts and Case GT remain unchanged.

## Runtime population

All 1,207 source cases remain in the case manifest. Dataset A cases with nonblank `trusted_instruction`, `normal_task`, `trust_boundary`, and `untrusted_input` are `runtime_scenario_bound` and Outcome GT applicable. The 320 cases without that runtime contract are `standalone_no_runtime_boundary`; they remain available for prompt-only Scanner evaluation but are excluded from Target LLM generation and Outcome GT. No scenario is invented.

The main execution population is:

- Dataset A: 582 cases × three attack responses = 1,746.
- Supplemental: 305 cases × three neutral direct responses = 915.
- Total: 2,661 response-level generations across 887 eligible cases.

Replicates use `r1=1729`, `r2=2718`, and `r3=3141`, with Ollama `qwen2.5:7b`, temperature 0.7, top-p 0.9, and maximum 512 tokens. Technical failures permit at most one identical retry. Semantic outcomes never trigger retry.

Dataset A uses the existing de-weakened `/canonical-generate` contract. Supplemental uses `neutral_direct_user_request_v1`: the fixed general-assistant system message and frozen original user text exactly once, with no model-visible source, GT, PI, scanner, or evaluator metadata.

## Auxiliary causal controls

Controls are not mandatory Outcome GT inputs. They are an auxiliary causal sanity check for estimating model-or-scenario failure. Only a validated causal-control subset may run.

Sixty runtime-eligible cases are selected deterministically with seed `production-control-subset-v1`, stratified by available source, scenario, PI status, attack-objective metadata, and structure/format. Selection is only a review queue. A control enters the separate control execution plan only after a human explicitly approves clean user content, the removed or neutralized span, task/context preservation, and information comparability.

Heuristic deletion, invented normal tasks, inferred attack spans, and automatic approval are prohibited. With no approved controls, a zero-row control plan is valid and main production remains ready.
