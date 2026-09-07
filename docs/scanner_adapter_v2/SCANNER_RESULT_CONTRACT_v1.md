# Scanner result contracts v1

This offline unit adds `scanner_raw_evaluator_result.v1`,
`scanner_normalized_result.v1`, and the explicit `scanner_mapping_policy.v1`
interface in `src.scanner_adapter_v2`. It neither imports nor runs scanners.
The existing ScannerReplayCase contract and its stricter GT-blind input boundary
are unchanged. The four normalized verdicts describe evaluator observations,
not input maliciousness, actual boundary violations, or correctness against GT.

> A scanner execution failure is not evidence that the input is safe.

## Raw versus normalized

One raw result represents one evaluator, one frozen generation, and one execution
attempt. `build_raw_result` records an already-obtained native JSON value before
interpretation. `normalize_raw_result(raw_result, mapping_policy)` derives a separate
immutable result. Both expose detached dictionaries through `to_dict()`.
Neither operation mutates input artifacts, native payloads, policies or replay cases.

| Contract | Required content |
|---|---|
| Raw | schema/run/evaluation/generation/production/sample identities; scanner and evaluator names/versions; evaluator kind; actual observation surface; replay/observation/input hashes; operational status/error; entire native JSON output and hash; execution provenance |
| Normalized | same identities, surface, operational status/error and execution provenance; raw result identity/hash; common verdict; normalization error; original selected native value/score/type/threshold/direction; threshold source; mapping policy identity/version/hash/basis |

Schemas are self-contained Draft 2020-12 documents and close all contract objects
with `additionalProperties: false`. Only native JSON payloads and explicit LLM
options permit arbitrary JSON keys, subject to the recursive leakage validator.
Schema validation alone is insufficient: use the public validators to enforce
finite numbers, strict JSON types, leakage rules and hashes.

## Identity and provenance

`scanner_run_id` identifies a scanner run; `evaluation_id` must be unique within
that run for each scanner/evaluator/generation/attempt. Retries need distinct
evaluation IDs. A future run writer must reject duplicate evaluation IDs, store
the run manifest and support checkpoint/resume; this unit performs no writes.
There is no positional batch join and no hidden aggregate result.

`generation_id`, `production_case_id`, and nullable `sample_id` are preserved from
ScannerReplayCase. The replay reference identity is its generation ID; its hash
covers the full replay document, transitively including target source artifact
hashes and target run provenance. No GT source is opened.

Hash encoding v1 is Python JSON with sorted keys, compact separators, UTF-8,
`ensure_ascii=False`, `allow_nan=False`, and no final newline. It is a project
encoding, **not RFC 8785**. It preserves JSON value types and string contents;
object key ordering and source JSON whitespace are not byte-level provenance.
`canonical_hash` documents and implements this encoding.

- `replay_case.sha256`: complete replay case under this encoding.
- `observation_sha256`: actual `project_observation(case, surface)` envelope.
- `evaluator_input.sha256`: caller-supplied actual formatted JSON evaluator input,
  including per-evaluation rubric/options when model-visible. No guessed input.
- `native_output_sha256`: complete native JSON value, including null on no output.
- `raw_result.sha256`: complete raw result; reference identity is evaluation ID,
  scoped by the accompanying scanner run ID.
- `mapping_policy.sha256`: complete explicit policy, not just its display name.

`verify_raw_lineage(raw, replay, actual_input)` recomputes replay/surface/input
hashes and verifies lineage. `validate_normalized_result(value, raw_result=raw)`
also checks raw hash and all carried envelope fields. To audit a normalized
decision against a policy, rerun the deterministic normalizer and compare the
complete result. A hash establishes identity, not trust in the artifact's author.

Execution provenance requires adapter version, Git commit, deterministic
`execution_id`, nullable run seed, configuration identity/hash, runtime identifier,
Python version (nullable) and dependency name/version entries. Configuration and
rubric hashes are caller attestations: persist their exact artifacts in the run
directory for independent verification. Never store credentials, authorization
headers or environment dumps in provenance. No implicit timestamp, random ID,
environment lookup, API call or retry is performed by these helpers.

## Operational status, errors and verdicts

| Operational status | Error type | Normalized verdict |
|---|---|---|
| `success` | null | explicit mapping, `indeterminate`, or `no_result` |
| `error` | required taxonomy entry | `no_result` |
| `timeout` | `timeout` | `no_result` |
| `dependency_error` | `dependency_error` | `no_result` |
| `configuration_error` | `configuration_error` | `no_result` |
| `unsupported` | `unsupported_result` | `no_result` |
| `skipped` | null | `no_result` |

Taxonomy: `adapter_error`, `scanner_runtime_error`, `evaluator_error`,
`parser_error`, `dependency_error`, `timeout`, `invalid_native_result`,
`unsupported_result`, `configuration_error`. Status and verdict are independent.
Authentication/configuration failures are not retry authorization.

Verdicts are `flagged`, `not_flagged`, `indeterminate`, `no_result`.
`not_flagged` means only that this evaluator's explicit policy did not flag the
observation. It is not a safety judgment, Outcome GT, or scanner correctness label.
No mappings infer safe from an operational failure or absent result.

If an execution succeeds but normalization cannot read the result, preserve
`execution_status=success`, `error_type=null`, set `normalization_error` to
`parser_error` or `invalid_native_result`, and return `no_result`. Unknown typed
native categories produce `indeterminate` with `unsupported_result`; they never
fall through to `not_flagged`. A recognized native uncertainty category can map
explicitly to `indeterminate` with no normalization error. Invalid policy or
contract data raises ValueError/LeakageError with a field path, not a verdict.
Schema constraints independently forbid non-success statuses from being safe
and require evidence fields for determinate verdicts.

## Mapping, score and threshold policy

Mapping policies require identity/version/basis, exact scanner and evaluator
names/versions, typed JSON field path, value kind, score direction and either
explicit value mappings or an explicit threshold contract. Changes to mapping
semantics require a new version; the hash exposes any change. Boolean `false`
and numeric `0` are distinct. Duplicate mappings and unknown policy fields fail.

Generic modes (no Garak/PyRIT/Promptfoo mappings are supplied):

- `boolean`: explicit true/false mappings; `native_score` remains boolean and
  `native_direction=boolean_only`. An omitted boolean mapping is indeterminate.
- `categorical`: explicit string mappings; preserve `native_value`, use
  `native_score=null`, `native_direction=categorical`.
- `numeric_threshold`: preserve the original finite number and units; require
  `higher_is_more_suspicious` with `gt/gte`, or `lower_is_more_suspicious` with
  `lt/lte`. Equality behavior is explicit, never implied.

`scanner_native` thresholds must be read from a specified native payload path.
`evaluator_contract` thresholds are literal finite numbers from an identified
versioned evaluator contract. The applied value is stored in `native_threshold`
in native score units, with `threshold_source` distinguishing the two origins.
`adapter_imposed` thresholds are rejected. There is no default `0.5` threshold.
There is no `normalized_score` field in v1 because no meaning-preserving common
scale has been established. A future transform needs a separately reviewed
contract. Entire arrays/components remain in raw output; selecting one path
does not authorize OR aggregation or batch score reduction.

## LLM-as-judge

When `evaluator.kind=llm_judge`, `provenance.llm_judge` is required and non-null:
provider, model, nullable model version, rubric/prompt identity and hash, nullable
seed, JSON options and API/runtime identifier. For deterministic evaluators it
must be null. The actual formatted input hash binds the per-evaluation rubric
as sent; do not assign the first record's rubric to an entire mixed batch.
This provenance is about the scanner's own evaluator, not the Outcome GT Judges.

## GT-blind result boundary and raw preservation

The replay validator intentionally rejects scanner verdicts and Judge output in
evaluator inputs. It cannot validate output envelopes containing legitimate
scanner identity, native `pass`, `decision`, `rationale` or this evaluator's
`judge_response`. Results therefore have a **separate** recursive key policy;
the replay policy is not weakened.

Result policy rejects correctness/incorrectness, TP/FP/TN/FN, expected verdict,
accuracy, Dataset A GT labels/classes/rationale, Outcome GT/Rule comparisons,
Judge A/B decisions/evidence/rationale/disagreement, scanner GT, and nested other
scanner results. Unicode/case/punctuation key variants are normalized. Named
multi-scanner containers are rejected; evaluate each scanner separately.
General strings (even JSON-looking response text) remain opaque and unchanged.
This is a structural check, not natural-language provenance inference.

Accepted payload types are exactly JSON null, boolean, integer, finite float,
string, list and string-keyed dict. Tuples, sets, bytes, arbitrary class instances,
NaN/Infinity, cycles and duplicate keys in serialized result documents fail.
No pickle, repr, default=str, score coercion, trimming or silent field deletion.
Native rationale, component results and response strings remain intact. If native
output includes forbidden comparison metadata, reject it rather than publish a
sanitized raw result. Any future restricted diagnostic retention must be separate
from the accepted GT-blind result stream.

V1 supports **inline JSON only**. Actual large payloads belong in runtime files;
an external payload-reference mode is deferred until its read-only resolver can
verify hashes and apply leakage checks to referenced content. An unchecked path
or hash must not become a validator bypass. If exact transport bytes matter,
future adapters must retain the native response text/bytes artifact separately;
JSON semantic preservation alone does not preserve wire formatting.

## Runtime storage and interface

Contracts, documentation and synthetic tests may be tracked. Runtime native
outputs, actual inputs, configs, policies, dependency manifests and normalized
results belong under `experiments/scanner_adapter_v2/runs/<run_id>/`, with unique
run directories and no overwrites. Only a scanner-local `.gitignore` containing
`/runs/` is added. Root `.gitignore` and Judge paths are unchanged, avoiding the
shared ignore-file conflict surface. This unit creates no runtime results.

`adapter_contract.ScannerAdapter` is a typing-only Protocol:

```python
prepare_input(replay_case, *, observation_surface) -> dict
execute(prepared_input, *, replay_case, run_context) -> ScannerRawEvaluatorResult
normalize(raw_result, mapping_policy) -> ScannerNormalizedResult
```

The implementation must preserve native output, exact input hashes and evaluator
provenance despite scanner API differences. It must use per-evaluation identities,
not list position, and persist the explicit mapping policy. No concrete adapter,
scanner SDK import, subprocess execution or API client is supplied here.

## Read-only legacy audit

| Source | Observed behavior | V1 prevention |
|---|---|---|
| `scanner/garak/runner.py:run_detectors` | fixed `all(s < 0.5)`; empty scores pass; detector exceptions become None | no default threshold; missing output/path is no_result; raw errors retained |
| `scanner/garak/main.py:summarize/execute`, `result_writer.py` | None results skipped; any detector failure makes overall FAIL, zero failures makes PASS; error details omitted | one record per evaluator; no OR aggregate; operational status independent |
| `scanner/pyrit/runner.py:run_scorer`, `result_writer.py` | missing task, scorer exceptions and empty scores return passed=True; only first score retained; writer defaults to passed=True | unsupported/error/no_result explicit; full native output preserved; no safe defaults |
| `scanner/promptfoo/runner.py:run_promptfoo/parse_result` | first record chooses rubric for batch; index-based seed join; missing success defaults false; missing assertion pass defaults true; native structure reduced | explicit generation/evaluation lineage; input/rubric hashes per result; no default native mapping |
| `scanner/promptfoo/config_writer.py` | one defaultTest rubric shared across batch | evaluator/rubric identity per evaluation; no batch execution in this unit |

These are observations about repository legacy code, not claims about current
upstream scanner APIs. No legacy code was imported or executed, and no GT protocol
or Judge decision was used to derive scanner mappings. The existing replay
protocol provides the boundary; no existing cross-scanner verdict contract was
found in the reviewed scanner documentation.

## Validation and remaining scope

On 2026-09-07, baseline 64 tests passed; after adding 75 tests, **139 passed**.
Synthetic fixtures cover booleans, numeric thresholds, categories, own LLM judge
output, uncertainty, all operational failure statuses, invalid schemas/policies,
nested leakage, finite JSON, immutable payloads, all observation surfaces and
replay/input/raw/policy hash lineage. The fixture blocks socket construction and
connections. Test-first missing-module and regression failures were observed
before implementation/fixes; no tests were weakened or skipped.

Command: `C:/ProgramData/Anaconda3/python.exe -m pytest tests/scanner_adapter_v2 -q`.
The existing pytest temporary directory required approved sandbox escalation;
no dependencies were installed. No external API/network, scanner execution,
production replay, Dataset A processing, Judge worktree change, commit or push.
Actual scanner payload compatibility, runtime writer/checkpoint behavior and
scanner-specific policies remain unverified and are subsequent implementation work.
