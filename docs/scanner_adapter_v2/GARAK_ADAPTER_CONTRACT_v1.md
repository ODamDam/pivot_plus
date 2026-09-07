# Garak detector-only frozen-response adapter contract v1

Status: fixture-verified skeleton, **not approved for real scanner execution**.
Audited API: Garak **0.16.0**. Adapter version example: garak_adapter.v1.
See [API audit](SCANNER_API_COMPATIBILITY_AUDIT_v1.md).
The audit checkpoint is aa79849907bea58fcb0be2d7f4c0eec6bd6e1f01.

## Boundary and supported surface

GarakDetectorAdapter implements the common prepare_input / execute / normalize interface.
Only **response_only** is supported. Both request_and_response and
trusted_context_untrusted_input_and_response raise an explicit configuration ValueError
before a backend can run. No request/context concatenation, generator, probe, harness,
multiple-detector aggregation or Target LLM generation is implemented.

prepare_input returns a detached strict-JSON descriptor, not a live Garak object.
Its prompt is {"text": ""}: an explicitly empty structural Message, not a reconstructed
trusted request. Its outputs list has exactly the unchanged response_text from ReplayCase.
Replay schema/leakage and response SHA are revalidated at entry. The backend constructs
Attempt(prompt=Message(text="")) and sets attempt.outputs to the one response string.
The full descriptor, including placeholder, configuration and backend marker, is hashed.
A detector is eligible only after its response-only consumption has been reviewed:
populating a prompt does not make a context-aware detector response-only.

Official pinned references:
[Attempt and Message](https://github.com/NVIDIA/garak/blob/v0.16.0/garak/attempt.py),
[Detector.detect](https://github.com/NVIDIA/garak/blob/v0.16.0/garak/detectors/base.py),
[configuration resolution](https://github.com/NVIDIA/garak/blob/v0.16.0/garak/configurable.py).
The synthetic tests model only these constructor/attribute/detect boundaries.
They do not claim full emulation of Garak conversation histories or detector behavior.

## Configuration and threshold ownership

GarakAdapterConfig is immutable serialized JSON, with closed keys:

- scanner_version (only 0.16.0); detector_id (garak.detectors.module.Class);
  detector_version; adapter_version.
- observation_surface (response_only); response_only_basis describing reviewed input
  consumption; explicit native_direction (higher or lower is more suspicious).
- detector_config: identity and finite JSON options. Options pass the strict replay leakage
  validator; they cannot contain GT, Judge, scanner-result or post-response-objective keys.
- mapping_policy: a pinned common numeric mapping policy, or null.

The scanner name is fixed to garak. Configuration snapshots are detached dictionaries.
Detector config options receive their own hash; the whole config, including the policy,
has another hash. A supplied mapping must match the scanner/detector/version/direction and
the exact native value path ["values", 0].

No threshold is a default. The initial backend returns a score iterable, not a threshold
record. Therefore an explicit registered evaluator_contract threshold is supported; a
scanner_native threshold source is rejected until a backend contract actually supplies one.
The sole test threshold, 0.75, belongs to a **synthetic fixture contract**, not to a selected
Garak detector or a production policy. No universal production mapping artifact is generated.
An approved future policy may cite an official evaluator threshold, but its selection is a
separate research decision. Garak's official ThresholdEvaluator default 0.5 is not silently
adopted. [Official evaluators](https://github.com/NVIDIA/garak/blob/v0.16.0/garak/evaluators/base.py)

Known policies use the existing normalize_raw_result function unchanged.
The common v1 numeric mapper requires a threshold. With no registered threshold, a small
adapter-local abstention path builds a schema-valid normalized result: native numeric score
and explicit direction retained, threshold/source null, verdict indeterminate and
normalization_error unsupported_result. Its named policy is garak-no-threshold-abstention v1.
This is an absence-of-policy marker, not a threshold or a scanner-specific verdict mapping.
No common schema/code change is required.

## Backend and real execution hook

GarakDetectorBackend is a small injected protocol: identifier, synthetic, and
detect(prepared, configuration) returning the native iterable.
Tests use synthetic backends and a minimal native-object double.
Inputs/configs passed to the backend are private copies.

Garak016Backend is a lazy real smoke hook. Importing either adapter module never imports
garak. detect first checks distribution metadata, requires exactly 0.16.0 and requires an
explicit approved_detector_ids allowlist. The default allowlist is empty. No detector is
selected or enabled by this implementation.

When separately approved, the hook resolves the exact detector class, checks Detector
inheritance, provides an explicit per-detector config_root, constructs the Message/Attempt,
sets outputs and calls detector.detect. It never invokes a generator, probe or harness.
Allowlisting must review the detector's constructor, configuration, dependencies and actual
input consumption: an arbitrary detector can itself load models or invoke a judge.
The hook is an in-process boundary, **not** a sandbox or completed subprocess worker.
Separate environment/process isolation remains required before real use.

No automatic pip install, .env loading, config-file writing, model download, retry or
persistence is implemented. Existing Garak global run defaults may still affect a real
detector; effective configuration/seed and global state need the smoke review below.

## Raw result and cardinality

One ReplayCase corresponds to one expected output and one detector evaluation.
native_output is an adapter envelope containing:

- values: native finite JSON values, with floats unconverted.
- output_indices: each retained value's original detector-result index.
- expected_output_count (1), iteration_complete, rejected_indices.
- detector identity/version, detector config identity/hash, mapping identity/version/hash/basis.
- backend identifier and explicit synthetic marker.

This envelope separates native values from adapter bookkeeping. No score is converted to
bool, rounded, rescaled or combined. A single-use iterable is consumed once.
Zero or two values fail cardinality validation; they never become a successful negative.
None is retained as null, with unsupported / unsupported_result and normalized no_result:
the generic native API permits None, but it does not establish a reliable abstention vs
execution-failure distinction. Zero-filling or safe mapping would invent evidence.

Malformed JSON-compatible values (for example a string) remain in the raw values array,
but execution is error / invalid_native_result. Non-finite values, arbitrary objects,
cycles or forbidden nested fields cannot cross the strict raw JSON/leakage boundary.
They are excluded with their exact original rejected_indices; never serialized using repr,
coerced to null/zero or silently renamed. Thus malformed payload preservation has an explicit
limit: prohibited original objects/content are not stored. This is not claimed to be lossless
serialization of invalid Python objects. Ordinary valid native scores remain lossless.

A defensive 1,024-value iteration cap prevents an unbounded result iterator from exhausting
memory. Beyond that cap, iteration_complete=false and invalid_native_result; only the retained
prefix is available. This bound is not a detector aggregation policy.
An iterator exception also retains its collected prefix and marks incomplete execution.
If a detector yields no value because it failed, there is no synthetic safe score.

## Errors and input rejection

| Condition | execution_status / error_type | normalized verdict |
| --- | --- | --- |
| Package unavailable / missing dependency | dependency_error / dependency_error | no_result |
| Version mismatch, unresolved detector class, incompatible construction | configuration_error / configuration_error | no_result |
| Detector not allowlisted | unsupported / unsupported_result | no_result |
| Detector detect or iterable exception | error / evaluator_error | no_result |
| Timeout from detect/iteration | timeout / timeout | no_result |
| Empty iterable, cardinality mismatch, unexpected type, NaN/Infinity | error / invalid_native_result | no_result |
| One None value | unsupported / unsupported_result | no_result |
| Valid numeric value without registered threshold | success / null | indeterminate |

A scanner execution failure is not evidence that the input is safe.

Invalid replay/hash, unsupported surface, modified prepared input, invalid run metadata or
policy substitution raises before execution/normalization rather than fabricating an
evaluation result. Raw result normalization also validates adapter ownership, deterministic
evaluation identity and successful-result shape. Malformed success must not bypass
cardinality checks by constructing a raw wrapper manually.

Exception messages are not copied into raw output: they may contain credentials or input
content. Typed operational cause, iteration state and rejection indices are retained.
The current hook does not provide native tracebacks or transport-level error artifacts.

## Identity and provenance

evaluation_id = garak-eval-v1- plus the canonical hash of scanner name, full replay hash
and prepared-input hash. The prepared input binds generation_id, production_case_id,
response hash, Garak version, detector identity, surface, adapter version/configuration,
mapping policy and backend identity/synthetic marker. No detector output, GT or correctness
value enters the derivation.

Identical replay/config/backend produces the same evaluation_id even if execution returns
another score. scanner_run_id and execution_id distinguish repetitions; random_seed is
explicit run metadata, not a promise of deterministic native execution. Changing a semantic
detector seed must also change detector configuration. The complete replay hash binds
lineage, so replay provenance changes also produce a different identity.

Raw result preserves generation_id, production_case_id and sample_id from ReplayCase;
replay identity/hash; observation/input hashes; adapter version; run Git commit/seed;
config hash; scanner/detector versions; runtime/backend identifier.
Synthetic backends record synthetic=true and no installed Garak dependency in runtime.
A successful real hook records the checked Garak version. On failure, an empty dependency
list means no successful runtime provenance assertion, not that every dependency is absent.

The caller supplies closed run_context keys:
scanner_run_id, git_commit, execution_id, random_seed.
The raw schema is validated before a backend is invoked so invalid metadata cannot cause an
unrecordable evaluation. The caller/next worker must persist exact prepared input, config,
raw and normalized results under experiments/scanner_adapter_v2/runs/<run_id>/.
This skeleton returns immutable results and writes no runtime files.

## Synthetic validation matrix

Tests include 0.0, 1.0, intermediate scores and threshold equality; known fixture threshold
and unknown-threshold abstention; None; dependency missing; version/detector unavailable;
exception and timeout; empty/two-value cardinality; wrong type, bool, NaN and both infinities;
partial iterators; index preservation after rejection; unsupported surfaces; response-hash
tampering; nested GT/Judge/Dataset A/other-scanner keys; prepared-input mutation; policy
substitution; forged raw success; run-context validation before execution; deterministic IDs;
provenance and raw/normalized schema validation; no Garak import at module load; and input
immutability even when a backend mutates its private copy.

Network connections are denied in the new in-process synthetic tests. A separate import test
guards against Garak imports in a fresh interpreter. Native-hook tests substitute metadata,
module resolution and minimal native objects; they do not import or execute real Garak.

## Real Garak 0.16 smoke blockers

The lines marked SMOKE in adapters/garak_backend.py are the first future verification points:

1. metadata.version("garak"): verify isolated distribution and transitive dependency versions.
2. importlib detector resolution: select and approve one deterministic response-only detector;
   verify imports/constructor cause no generator/API/model-download activity.
3. detector_class(config_root=...): verify options, effective defaults and random seed; ensure
   no shared user/.env/config/cache/working-directory or Judge state is consumed.
4. Attempt(prompt=Message(text=...)) and attempt.outputs assignment: verify one output, exact
   text/SHA and actual detector-visible surface with real Garak Message/Conversation behavior.
5. detector.detect(attempt) and deferred iteration: verify return scalar types, cardinality,
   native None/exception behavior and absence of probe/harness/Target generation.

Also verify worker timeouts/cancellation, effective config capture and append-only runtime
persistence before any real run. No actual Garak installation/import/platform smoke has
validated these hooks. Fake success is not evidence of native runtime compatibility.

## Gate and Git scope

**GARAK_SKELETON_GO** means the dependency-free, response-only boundary and synthetic tests
pass. It does not authorize installing Garak, executing the real hook, selecting a detector or
threshold, or replaying the 2,661 production generations. PyRIT/Promptfoo are not implemented.

Audit document: checkpointed and pushed separately.
Skeleton checkpoint covers only the five reviewed adapter/backend/test/documentation files.
Checkpointing does not authorize real scanner installation or execution.
Legacy scanner/scanner_input, Judge, Dataset A, Target LLM and common runtime files unchanged.
