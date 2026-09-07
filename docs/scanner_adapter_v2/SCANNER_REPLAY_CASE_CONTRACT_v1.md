# ScannerReplayCase v1

Status: first offline implementation; schema version `scanner_replay_case.v1`.
One case represents one immutable Target LLM generation. This contract supplies
GT-blind evaluator content, without classifying input maliciousness, model behavior
or scanner correctness. Ordinary instruction following is not a vulnerability verdict.

## Baseline and conventions

Audited worktree: `feature/scanner-adapter-v2`, HEAD/base
`a0c65aa7f8f20aac50fbdb430b6ff8a77dd5a77f`, initially clean, no upstream.
The repository uses `src.<namespace>` imports from the repository root, root-level
`schemas/` with JSON Schema Draft 2020-12, and `tests/<namespace>/` pytest tests.
No pyproject/setup packaging configuration was found. Use
`src.scanner_adapter_v2`; no legacy scanner imports. `jsonschema` is already in
requirements.txt; no dependencies are added or installed.

## Canonical input sources

All paths must be supplied explicitly to `load_replay_cases`:

| Argument | Canonical artifact relative to repository root |
|---|---|
| `production_results` | `experiments/target_llm_production_v1/runs/target-llm-production-v1/results.jsonl` |
| `execution_plan` | `experiments/target_llm_production_v1/inputs/production_main_execution_plan_2661_v1_1.jsonl` |
| `generation_manifest` | `experiments/target_llm_production_v1/inputs/production_generation_manifest_1207_v1_1.jsonl` |
| `run_manifest` | `experiments/target_llm_production_v1/runs/target-llm-production-v1/manifest.json` |

The expected canonical results population is 2,661 (1,746 attack, 915 direct),
SHA-256 `350345BC370265943F36291558686888682BCBCBFF6549A2C8DB4BABAD88FE75`.
These expectations were supplied for this task; the runtime result is absent in
this worktree, so its count/hash have not been independently verified. Constants
are exposed for explicit caller use, not silently imposed on synthetic fixtures.

Source authority is established by read-only inspection of
`src/target_llm_production/production_runner_v1.py` (`execute_rows`,
`build_attack_payload`, `build_direct_payload`, `create_manifest`, `run_full`),
`preflight_v1_1.py` (`build_main_plan`, manifest builders), and `preflight.py`
(`build_static_canonical_request`, `render_neutral_direct`). No generator is imported.

**Plan hash caveat:** `create_manifest` hashes the original input plan; `run_full`
reserializes a copy to the runtime `execution_plan.jsonl`. Supply the original
byte-identical input plan pinned by `run_manifest.plan_sha256`. A reserialized
copy with a different hash is rejected even if its JSON objects are equivalent.
No normalization or hash bypass is performed.

| Replay field | Authoritative source |
|---|---|
| `generation_id` | plan/result `generation_id`; attack canonical request must agree |
| `production_case_id` | plan/result plus generation manifest; attack request `case_id` must agree |
| attack context: `trusted_instruction`, `normal_task`, `trust_boundary`, `trusted_context`, `untrusted_input`, `injection_location` | plan `materialized_request.canonical_request` |
| direct `trusted_instruction`, `normal_task` | plan `materialized_request.model_visible_messages[0/1].content` |
| `model_visible_messages` | plan materialized messages, preserved verbatim; attack rendering consistency checked against canonical request |
| `request_mode` | plan/result `mode`; checked against manifest `generation_mode` |
| `response_text`, `response_sha256` | production result; hash recomputed over exact UTF-8 text; endpoint response must agree |
| source identity/hash | generation manifest `source_case_id`, `source_row_locator`, `source_artifact_path`, `source_artifact_sha256`; hash agrees with plan/result |
| production run | result `run_id` checked against run manifest; original planned attack `run_id` is not runtime authority |
| provider/model/config | plan, checked against endpoint/manifest/run metadata; seed and generation options preserved |

Direct requests are authorized user messages, not reinterpreted as untrusted
injection slots. Their `trust_boundary`, `trusted_context`, `untrusted_input`, and
`injection_location` are null. Attack context fields are required nonempty strings
except `trusted_context`, which is required but nullable. `sample_id` is preserved
when present in plan/result/manifest and must agree; otherwise it is null. Canonical
v1.1 uses `source_case_id`, so no new sample identity is invented.

## Schema and GT-blind boundary

`schemas/scanner_replay_case_v1.schema.json` closes every object with
`additionalProperties: false`. Required fields comprise identity, the six context
fields, raw messages/response, response hash, objective availability, observation
surface and minimal provenance. Provenance records all four input artifact hashes,
logical identity, source record identity/hash, target run/commit, provider/model,
replicate, seed/options, request schema and materialization recipe.
File identities use the supplied basename or original manifest logical path and
hash, so relocating byte-identical artifacts does not alter cases.

There is no verified response-independent, pre-registered objective field in these
inputs. In v1, `attack_objective` is **always null**, `objective_status` is
`unavailable`, and `objective_provenance` is `no_verified_response_independent_source`.
Do not extract an objective from Dataset A GT, Outcome Rules, Judge output or the
response. Supporting non-null objectives requires a separately reviewed source
contract/version; self-declared pre-registration is not sufficient.

The generation manifest is inherently mixed: it includes `source_case_gt`.
The loader explicitly selects provenance and population fields; that GT object
is neither inspected for decisions nor copied. It does not open the Dataset A
source artifact named in provenance. Dataset A specification was read; its
`pi_label`/`boundary_class` and runtime legacy `pi_status`/`derived_class` naming
both belong to the forbidden categories. No conversion or label interpretation
is performed here.

`leakage_validator.py` defines forbidden categories and normalized key detection:
Dataset A labels/maliciousness/classes/GT rationale; final Outcome GT; Judge A/B
decisions, evidence, rationale and disagreement; Outcome Rule verdicts; scanner
GT, correctness and other scanner outputs; legacy passed/PASS/FAIL; and
response-derived or posthoc objectives/rules. Unicode compatibility normalization,
case folding and punctuation removal handle key variants. Nested mappings/lists
are checked with paths such as `$.source.payload[0].outcome_gt`. Known objective
metadata fields permit only the v1 null/unavailable state. Raw string content is
opaque: mentioning `pass`, `judge_decision`, or JSON-looking text does not fail.

The selected manifest/source projection is checked before case construction;
plan and result mappings also receive defensive recursive checks. Completed cases
are checked for leakage, schema and response hash. Unknown aliases cannot enter
the closed output schema. This is a structural boundary, not a semantic classifier
of natural-language content. Preserve raw prompts/responses without sanitizing them.

## Join and integrity rules

The loader returns a tuple of frozen `ScannerReplayCase` objects sorted by
unchanged generation ID, only after all input rows validate. Objects store an
immutable serialized value; `to_dict()` returns a detached copy.

- Require unique generation IDs in both result and plan and exactly equal ID sets.
- Join generation manifest on unique `production_case_id`; require unique source
  case identities. Check embedded request ID, mode, provider/model, replicate and
  configuration consistency, including `case::mode::replicate` generation format.
- Require run identity, schema versions, completed results and planned requests.
- Require manifest eligible/count declarations to equal the plan population;
  zero-generation excluded cases are allowed. Require run total/attack/direct counts.
- Check source hashes across all three sources; pin original execution plan bytes
  to run manifest hash. Compute every input artifact hash from the bytes parsed.
- If `expected_results_sha256` is supplied, require exact digest equality (hex
  letter case is immaterial); recompute every response hash without trimming or
  newline normalization. Require endpoint response text and identity consistency.
- Reject malformed JSONL (with line number), duplicate JSON keys, non-object rows,
  blank lines, non-finite numbers, duplicate/missing/ambiguous joins, unsupported
  modes, mismatches, unexpected populations and forbidden fields. Errors never
  include raw content values. No retries or partial-population fallback.

The source dataset hash is cross-checked as declared provenance, not recomputed
by opening the GT-bearing source dataset. Generation/run manifest hashes are
recorded; independently trusted hash pinning for these manifests is a future
provenance extension. This loader validates supplied artifacts, not their authorship.

No source files are changed. There are no output writes, network calls or experiment
execution, so no checkpoint/resume is needed for this in-memory contract unit.
A future materialization command must add its own run metadata and output policy.

## Observation surfaces

`project_observation(case, surface)` is deterministic and returns
`{"observation_surface": surface, "content": {...}}`. The envelope records the
surface actually selected, which may differ from the case's declared default.
Only `content` is intended for evaluator input. Future adapters must record this
actual envelope surface in their raw result contract.

| Surface | Exact content keys |
|---|---|
| `response_only` | `response_text` |
| `request_and_response` | `model_visible_messages`, `response_text` |
| `trusted_context_untrusted_input_and_response` | all six context fields, `response_text` |

The third surface includes trusted instruction, normal task and boundary so input
roles remain explicit; direct-only context values remain null. Projections contain
no IDs, provenance, mode labels, objectives, scores, GT or Judge outputs. Mutation
of a returned dictionary cannot change the canonical response or another view.
No scanner-specific serialization is applied.

## Offline validation and access recommendation

Synthetic fixtures are generated by `tests/scanner_adapter_v2/test_replay_contract.py`
into pytest temporary directories. They cover two attack contexts (null/non-null),
one direct request, all surfaces, unavailable objectives and invalid source variants.
Fixtures are not copied from production. The fixture smoke test blocks Python
socket construction/connections and verifies byte-identical input files afterward.

From repository root, using the existing environment:

```powershell
C:/ProgramData/Anaconda3/python.exe -m pytest tests/scanner_adapter_v2 -q
```

Implementation validation (2026-09-07): **64 passed** in the existing Python 3.9
environment (pytest 7.1.2, jsonschema 4.16.0); compileall also passed. The initial
test-first run failed on the missing implementation as expected. A later run was
blocked by sandbox access to pytest's default temporary directory; the same test
command passed after approved escalation. No installation was required. Two
tracked input-plan entries (one attack, one direct) also passed read-only request
consistency checks. Full runtime result count/hash/join remain unverified because
the canonical result is absent; unrelated legacy/Judge suites were not executed.

Recommend **A: explicit CLI `--production-results <path>`** for the future caller,
with equally explicit plan and both manifest paths and expected result hash. The
current Python API already enforces this design; this unit does not add a CLI.
It makes a run invocation reviewable and portable, and hashes retain provenance
when paths move. Environment source roots (B) introduce hidden process state;
external directory config (C) can be useful as an explicit optional profile later.
Neither automatic copies nor symlinks are defaults. No external runtime was read,
and no full 2,661-case replay was materialized during this implementation.

## Non-goals

Scanner evaluator selection, score normalization, threshold policy,
Garak/PyRIT/Promptfoo installation or execution, target generation, Outcome GT
judging, dataset labeling, production result edits and paid/external API calls.
No legacy `scanner/`, `scanner_input/`, Judge, Dataset A or Target LLM code changes.
No Git commit or push.
