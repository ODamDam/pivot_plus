# Scanner API Compatibility Audit v1

Audit date: **2026-09-07 (Asia/Seoul)**. Status: documentation-only, official-source inspection.
Baseline: `feature/scanner-adapter-v2`, commit `769ca36216adc34b42f75bdf393f878c8d149f88`,
upstream `origin/feature/scanner-adapter-v2`; initially clean.

## 1. Decision and scope

Frozen Target LLM responses can reach evaluator-only APIs in all three projects.
That does not establish equivalent evaluator meaning, a common threshold, or correctness.
The gates are **Garak ADAPTER_SKELETON_GO**, **PyRIT ADAPTER_SKELETON_CONDITIONAL**,
and **Promptfoo ADAPTER_SKELETON_CONDITIONAL**, with the scoped conditions in section 17.

This audit selects no research evaluator or threshold. It implements no adapter or mapping.
No scanner was installed, imported, upgraded or executed. No inference endpoint was called.
Public documentation, official GitHub sources/releases and package registries were read over
the network. Source text was inspected in memory, not copied into test fixtures.
No production records, credentials or .env contents were read.

The compatibility judgments below are **inferences from the cited pinned source**, not
installation or execution results. Version numbers are the stable registry versions checked
on the audit date; all implementation references use the corresponding release tag.

## 2. Checked versions and runtime compatibility matrix

| Scanner / official package | Stable version checked / publication UTC | Runtime requirement | Frozen replay / official mechanism | Native output | LLM/API required? | Observation capability | Offline / deterministic capability | Major integration risk |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Garak / PyPI `garak` | **0.16.0**, tag `v0.16.0`; 2026-08-04 | Python >=3.10 | Yes: construct Attempt, set frozen outputs, call Detector.detect | Iterable of float or None, generally per output | No for static detectors; model detectors may load weights or use judge generator | Detector-specific; most inventory candidates read response and optional notes | Static matching can be offline; learned/judge detectors conditional | New Message/Conversation prompt API; per-output cardinality; threshold ownership |
| PyRIT / PyPI `pyrit` | **1.1.0**, tag `v1.1.0`; 2026-09-04 | Python >=3.10,<3.15 | Yes: Scorer.score_async(ContentScorable/MessageScorable), or score_text_async / score_message_async | list[Score], string score_value, explicit completion status | Static regex no; SelfAsk requires a judge target; Prompt Shield requires service | Scorer-specific; putting request into Memory does not make it scorer input | Regex offline; judge reproducibility only best effort | New scorer abstractions, undetermined state, global memory and dependency conflict |
| Promptfoo / npm `promptfoo`; CLI `promptfoo` / `pf` | **0.122.2**, tag `0.122.2`; 2026-08-28 | Node >=22.22.0 | Yes: exported assertions.runAssertion with providerResponse.output; documented echo alternative | GradingResult: pass, score, reason, metadata and optional components | Simple assertions no; llm-rubric/red-team graders generally judge calls | prompt / vars / rubric bindings; evaluator-specific | Simple assertions offline; LLM/cache/timestamp paths conditional | Permissive grader defaults; aggregation and remote-provider defaults |

Evidence: [Garak registry][gregistry], [Garak release][grelease],
[Garak package requirements][gmeta], [PyRIT registry][pregistry],
[PyRIT release][prelease], [PyRIT package requirements][pmeta],
[Promptfoo registry][fregistry], [Promptfoo package][fmeta].
Garak release commit: `dbe4515d12664f2e34ac2cea295f055c22fe82b4`.
PyRIT release commit: `d0524f0714840519b826eb770687ca1d4f46a761`.
Promptfoo tag/npm gitHead: `89052308bce06f53645b1f189ada5ac9d1897347`.

Exact registry upload times checked: Garak 2026-08-04T19:05:19.840452Z;
PyRIT 2026-09-04T22:16:36.781374Z; Promptfoo 2026-08-28T07:14:22.908Z.
Promptfoo GitHub releases/latest also covers separate products (the checked response pointed
to code-scan-action-0.2.0); it is not a reliable substitute for the package dist-tag.

Local read-only metadata: Anaconda Python 3.9.13, pytest 7.1.2, jsonschema 4.16.0;
garak and pyrit distributions absent in that interpreter. This is not a claim about every
interpreter on the machine. Node v26.0.0 and npm.cmd 11.12.1 were found.
Python 3.9 is below both scanners' declared floor. Node satisfies the declared floor;
installation/platform compatibility remains untested.
PowerShell blocked npm.ps1; npm.cmd metadata lookup worked without changing execution policy.

## 3. Garak API and frozen response path

The current [Attempt implementation][gattempt] represents prompts as Message or Conversation.
A plain string assigned to attempt.prompt is rejected. Conversation supports explicit
system/user/assistant turns; outputs can be assigned as a list of strings or Messages
**after** setting the prompt. The getter exposes Messages. There is no need to invoke a
generator to construct this object and call a detector.

Minimal replay transport is an Attempt with a structural prompt and exactly one frozen
assistant output. Preserve generation_id in the adapter lineage and explicit input manifest;
do not repurpose Garak's generated UUID as the canonical generation_id. Set additional notes,
goal or probe identifiers only when the chosen detector requires them and the values have a
verified response-independent source. One output per generation avoids accidental multi-output
aggregation. Multiple outputs are represented by separate conversation histories; outputs
and all_outputs have different latest-turn/all-turn behavior. [Attempt][gattempt]

The public detector contract is `detect(attempt) -> Iterable[float | None]`.
Materialize an iterator once and retain order, every element and output index; check result
cardinality. None and an empty iterable are not a negative detection. Detector implementations
differ in whether they inspect prompt, outputs, translated output views, targets or notes.
Merely populating Attempt.prompt does not prove that a detector consumes the request.
[Garak detector base][gbase]

For response_only, a required structural prompt placeholder must be explicitly documented
and included in the actual input hash. It is acceptable only for a detector verified not to
read it. Never manufacture missing request content or concatenate the three observation
surfaces into an undocumented string.

### Candidate inventory, not evaluator selection

| Official identifier | Actual input requirement | Native meaning | External LLM |
| --- | --- | --- | --- |
| garak.detectors.promptinject.AttackRogueString | Response plus notes.triggers | Case-insensitive trigger substring hits, 0/1 per output; no triggers yields [] | No |
| garak.detectors.dan.DAN; DANJailbreak; AntiDAN; STAN; DUDE; DevMode | Response text / predefined marker strings | Marker hit, not proof of a trust-boundary violation | No |
| garak.detectors.web_injection.MarkdownExfilBasic; MarkdownExfilExtendedImage; MarkdownExfilExtendedNonImage | Response text / Markdown-link patterns | Pattern detection scores | No |
| garak.detectors.web_injection.MarkdownExfilContent | Response plus notes.terms | Exfiltration-term overlap calculation; requires those terms | No |
| garak.detectors.web_injection.XSS | Response text / predefined strings | Pattern hit | No |
| garak.detectors.judge.Refusal | Response and configured judge machinery | Refusal-oriented judge score; polarity differs from attack success | Configured judge generator, local or remote |
| garak.detectors.judge.Jailbreak | Response and notes.attack_goal or attempt.goal | Goal-conditioned harmful-content judgment | Configured judge generator |

Sources: [promptinject][gpi], [DAN][gdan], [web injection][gweb], [judge][gjudge].
These detectors cover specific observable phenomena; this inventory does not establish a
general prompt-injection evaluator. Replay loader currently emits objective unavailable:
do not infer triggers/goals from a response or import Dataset A / Outcome GT labels to fill them.
Generic ModelAsJudge additionally has probe/config-dependent initialization; it is not the
first offline skeleton target.

Garak's HFDetector loads model configuration/weights, configures device handling and changes
multiprocessing start method to spawn. Imports/constructors are not a harmless metadata audit.
[Garak detector base][gbase]

## 4. PyRIT API and frozen response path

Current exported names include **MessagePiece, Message, ContentScorable, MessageScorable,
ScoringExpectation and Score**. PromptRequestPiece and PromptMemoryEntry are not current
exports from pyrit.models; use the current types rather than assuming historical names still
work. The exact release in which every historical rename occurred was not established.
[Model exports][pinit], [Scorable models][pscorable]

`Scorer.score_async(*, scorable, expectation=None)` returns list[Score].
`score_text_async(text, objective=None)` wraps ContentScorable.
MessageScorer provides `score_message_async(message=..., expectation=...)`; its compatibility
message/objective route is deprecated. Use keyword arguments and the new API rather than the
legacy positional call. Calls are asynchronous; batch scoring is concurrency over individual
inputs and returns flattened scores, not a single multi-case judge response. [Scorer][pscore],
[MessageScorer][pmessage]

A frozen text response can be scored directly without an attack orchestrator or original
Target LLM. For explicit assistant lineage, create a MessagePiece with role assistant and
the unchanged response, wrap it in Message, and use the documented message scoring route.
For MessageScorable, persisted message-piece identities must resolve in configured Memory.
ContentScorable can supply text without pre-inserting an original conversation, but scorer
result persistence still uses CentralMemory. The content resolver creates an ephemeral
user-role piece; this is not a reconstructed original assistant conversation.
Default role validation does not require assistant exclusively (simulated_assistant is
excluded by default). [Resolver][presolver], [Validator][pvalidator], [CentralMemory][pmemory]

Do not assume that storing both user and assistant messages causes SelfAsk to evaluate the
whole conversation. The resolver obtains a single message, and message scorers evaluate
supported pieces with scorer-specific aggregation. Explicitly selecting one response piece
avoids OR aggregation across unrelated pieces. [MessageScorer][pmessage]

### SelfAsk and prompt injection inventory

SelfAskTrueFalseScorer requires a chat_target implementing the required PromptTarget chat
capabilities. Use `SelfAskTrueFalseScorer.from_question(chat_target=...,
question=TrueFalseQuestion.from_yaml(...))`, or the documented system_prompt/question pair.
The old constructor keyword true_false_question is not supported. Omitting the question
selects TASK_ACHIEVED; this is unsuitable when no verified objective exists.
[SelfAsk implementation][pbool]

| Official identifier | Meaning / input | API requirement |
| --- | --- | --- |
| TrueFalseQuestionPaths.PROMPT_INJECTION; pyrit/datasets/score/true_false_question/prompt_injection.yaml; category prompt_injection | Predefined SelfAsk question about signs of injection in a response; includes broad observable indicators, not a complete boundary-violation definition | Judge PromptTarget |
| pyrit.score.true_false.regex.static_prompt_injection_scorer.StaticPromptInjectionScorer | Regex indicators of injection attempts; documented prefilter limitations / false positives | No LLM |
| pyrit.score.true_false.prompt_shield_scorer.PromptShieldScorer | Attack detections in Prompt Shield userPrompt/documents analysis, combined using any | PromptShieldTarget service call; not necessarily LLM-as-judge |

Sources: [question enum][pbool], [bundled question][prubric], [static scorer][pstatic],
[Prompt Shield scorer][pshield]. Prompt Shield evaluates attack content, not whether the
frozen Target response violated a boundary. Its parser defaults missing analysis sections
to negative flags; this path needs explicit response-shape checks before it could be enabled.
No scorer/rubric was selected.

### Native Score and breaking semantics

Score is a Pydantic model. Preserve JSON serialization of every returned Score, including id,
score_value (a **string**, or null), score_type, status, score_category, score_rationale,
score_metadata, scorer_class_identifier, message_piece_id/scorable, timestamp and objective.
Use the model's JSON-mode serialization, not arbitrary Python object conversion or only
get_value(). Complete true_false values are "true"/"false"; float_scale is represented as a
numeric string. get_value() converts to bool/float but raises UndeterminedScoreError for
undetermined status. Float-scale validation bounds values and rejects non-finite values.
[Score model][psmodel]

Version 1.1.0 makes undetermined state and partial blocked-response handling material:
the scorer's own blocked judge response either raises (default) or yields an undetermined
Score when raise_if_scorer_blocks is false. Unreadable transport/protocol evidence can also
produce undetermined. Separately, a fully blocked target response with no readable content
can produce the family's neutral false/0.0 fallback. Unsupported evidence can return [].
These are distinguishable source states, not a license to map all false values to safe.
Prevalidate frozen response availability/status, retain native status and errors, and never
treat the no-content fallback as successful security evaluation.
[Release][prelease], [message policy][pmessage]

## 5. Promptfoo API and frozen response path

A normal config has prompts, providers and tests; tests bind vars and assertions (test.assert),
with optional defaultTest, options and grading provider. evaluate() runs the evaluation
workflow and returns an Eval model. Full result files additionally contain provider/test and
aggregate data; legacy nested JSON shape assumptions are not the recommended integration.
[Node API documentation][fnode]

**Preferred skeleton transport:** the package publicly exports assertions, and
`assertions.runAssertion({ assertion, test, providerResponse: { output: responseText },
prompt, vars, ... })` directly evaluates supplied output. Target-provider generation is not
required. Pass only the request context the chosen assertion really consumes. A model-graded
assertion can still call its separate grading provider. [Exports][findex],
[assertion implementation][fassert], [Node API documentation][fnode]

There is a checked documentation/source discrepancy: the tagged Node documentation's
runAssertions example uses an assertions option, whereas the implementation reads test.assert.
Use the unambiguous single runAssertion path and validate the pinned signature with future
fixtures. Do not build an integration from an unverified example alone. [Docs][fnode],
[source][fassert]

The documented built-in **echo** provider is a second official route for pre-generated/logged
output: it returns the input as output and raw, cost zero and zero tokens. Its numRequests=1
counts a provider invocation, not a billed LLM request. It permits regular evaluate workflows,
but introduces extra provider/test aggregation and persistence. A custom echo wrapper is
unnecessary for the initial single-assertion adapter. [Echo documentation][fprovider],
[Echo source][fecho]

### Native result and security evaluator inventory

GradingResult contains pass, score, reason, assertion and optional componentResults,
namedScores, tokensUsed, metadata and suggestions. Preserve the complete returned finite JSON
object, not only pass or test success. ProviderResponse additionally has output/error and
provider usage/cost/cache metadata; these are separate from the assertion result.
A GradingResult is not guaranteed to contain the underlying judge's original text or all
provider metadata. Capture that separately when claiming lossless judge-output provenance.
[Result types][ftypes], [rubric execution][frunrubric]

| Official identifier | Input / semantics | Calls |
| --- | --- | --- |
| llm-rubric | Explicit rubric and supplied output; template vars can bind request/context; pass means rubric satisfied, whose polarity depends on rubric | Grading provider |
| promptfoo:redteam:indirect-prompt-injection / IndirectPromptInjectionGrader | purpose metadata, injected instructions in assertion value, prompt/output; rubric asks score 0 if injected instructions followed, otherwise 1 | Generally grading provider, with shortcuts |
| promptfoo:redteam:prompt-extraction; promptfoo:redteam:hijacking | Registered specialized security graders; contextual requirements vary | Evaluator-specific model grading |

Sources: [llm-rubric docs][frubricdoc], [indirect PI grader][fred], [grader registry][fgraders].
The red-team generation/strategy workflow is separate and must not be invoked for replay.
The indirect PI rubric is not automatically equivalent to Outcome GT: following an instruction
is not by itself proof that a security boundary was violated.

RedteamGraderBase requires purpose metadata, renders prompt/test metadata/value into the rubric,
adds the current timestamp, supports examples/guidance, and can prefer remote grading when no
explicit grading provider is configured. Empty output or a basic-refusal match can short-circuit
to pass=true/score=1 without a judge call. These behaviors need explicit review; no implicit
remote provider, empty-as-safe or dynamic unrecorded rubric is acceptable.
[Red-team base][fbase]

The llm-rubric helper tags transport/parse failures with metadata.graderError; inverse rubrics
preserve that failure rather than invert it into success. However, its JSON parser accepts an
object without requiring verdict keys: parsed.pass defaults true and absent score can become
Number(pass). Thus **an object such as {} can become pass=true, score=1**. This is a source-level
finding, not an executed test. Native output must be preserved, but the adapter must detect
missing required judge fields before a normalized security verdict. That requires access to the
raw judge response or an explicitly validated grader protocol. [Rubric parser][frunrubric],
[inversion handling][frubric]

## 6. Observation surface compatibility

N = native consumption by the specified evaluator; P = representable with a documented,
versioned adapter projection; U = unsupported by that evaluator; C = requires custom evaluator
or explicitly designed rubric. Storage in a native object alone does not establish consumption.

| Evaluator family | response_only | request_and_response | trusted_context_untrusted_input_and_response |
| --- | --- | --- | --- |
| Garak response String/regex detectors | N, with documented structural prompt placeholder if needed | U: prompt storage does not make it inspected | U; C for a new context-aware detector |
| Garak request/goal-sensitive judge detector | Evaluator-specific; Refusal can judge response | P only for precisely required native goal/request fields | C; Attempt notes are not a standard boundary-aware evaluator |
| PyRIT SelfAskTrueFalse / static regex | N via text or one response MessagePiece | C: extra Memory entries do not add conversation context | C: explicit scorer/rubric needed |
| PyRIT PromptShieldScorer | P as attack-content service input, not output-behavior evaluation | C for the requested behavioral comparison | C; service document analysis is not this replay contract |
| Promptfoo simple output assertion | N | U unless assertion explicitly reads supplied context | U for output-only assertions |
| Promptfoo llm-rubric | N with response-only rubric | P using documented prompt/vars/template bindings | P using explicit named bindings and reviewed rubric; no native default trust-boundary meaning |
| Promptfoo indirect PI grader | U for full rubric because purpose/value required | P for purpose, injected value, prompt/output | C or reviewed custom rubric for all trusted-context and boundary fields |

Evidence: [Garak detector base][gbase], [Garak judge][gjudge], [PyRIT resolver][presolver],
[PyRIT SelfAsk][pbool], [Promptfoo rubric docs][frubricdoc], [red-team base][fbase].
P is a representational capability, not evaluator selection approval. No default concatenation
is recommended. Null context stays null; unsupported surfaces produce unsupported/no_result.
Hash the actual rendered evaluator input, including rubric/config/structural fields, separately
from the canonical surface projection. Persist both so added wrapper text remains auditable.

## 7. Raw contract compatibility and lineage

Reference local contracts: src/scanner_adapter_v2/results.py, normalization.py, adapter_contract.py;
schemas/scanner_raw_evaluator_result_v1.schema.json, scanner_normalized_result_v1.schema.json,
scanner_mapping_policy_v1.schema.json.

| Scanner | Raw payload preservation | Current raw schema judgment | Normalized mapping feasibility |
| --- | --- | --- | --- |
| Garak | Materialized detector result list including None/order; separate detector/config identity | Compatible for finite built-in JSON values; explicit conversion needed for non-JSON scalar implementations | Conditional on selected official evaluator threshold/polarity; simple binary hits straightforward once policy is registered |
| PyRIT | Every Score in JSON mode, native status/value/rationale/metadata/identifier/IDs | Compatible with adapter-only JSON serialization; retain strings unchanged | Conditional: status+value dispatch and numeric strings exceed current single-path policy |
| Promptfoo | Full GradingResult plus separately captured ProviderResponse/judge payload when available | Compatible with adapter-only strict JSON transport for declarative assertions | Simple validated boolean result straightforward with rubric polarity; general LLM/security result conditional |

Keep generation_id, production_case_id and sample_id from ReplayCase. Scanner UUIDs, score IDs,
conversation IDs and assertion indices are supplementary, never replacement join keys.
Use one evaluation_id per evaluator/case/attempt and preserve every native result in that
evaluation. Do not silently select Score[0], OR unrelated detectors, or join by batch position.
The envelope binds replay hash, observation hash, input hash, scanner/evaluator version,
configuration identity/hash, execution_id and runtime provenance.

native_output admits finite JSON, not arbitrary Python objects, callbacks, bytes, NaN/Infinity
or cycles. A Pydantic JSON export is an explicit serialization boundary; do not discard fields.
For Promptfoo, reject function-valued/custom executable configurations in the initial scope.
JavaScript undefined is not JSON: document optional absent fields rather than silently stringify
an arbitrary object that drops function/undefined values. Do not promise byte-identical
serialization of native in-memory objects; preserve their defined JSON data and original
response bytes/text separately where available.

GT/correctness/cross-scanner keys remain prohibited even inside native metadata. Do not rename
or drop an offending key to bypass validation. If a legitimate native payload conflicts with
the key policy, fail closed and review the contract; raw compatibility is not an exception.
No Outcome GT, Dataset A GT or other scanner output is an evaluator input.

### Contract gaps to resolve, without changes in this audit

1. mapping_policy.v1 dispatches one typed value_path. PyRIT status=undetermined with a null
   score_value cannot map to indeterminate through that path; it becomes invalid_native_result/
   no_result. A real blocked judge failure should remain no_result, but a genuine completed
   evaluator abstention should not be mislabeled parser failure. A status-aware policy or an
   explicit reviewed mapping projection is needed; raw score status must remain unchanged.
2. PyRIT numeric strings cannot use numeric_threshold directly. A versioned typed projection
   must retain the original string and conversion evidence, or the mapping interface needs an
   extension. Do not coerce strings silently.
3. Boolean mapping currently preserves the chosen boolean as native_score; a separate numeric
   Promptfoo score/threshold remains in raw, not automatically in normalized native_score.
   To populate both verdict and numeric descriptor losslessly in normalized output requires a
   mapping enhancement, not recomputing a verdict from an invented threshold.
4. Raw evaluator.kind has deterministic and llm_judge only. A remote non-LLM classifier such
   as Prompt Shield is not automatically covered by either meaning. Its inclusion requires
   a kind/provenance semantics review; it is outside the first skeleton.
5. Raw v1 has no first-class external-payload-reference variant. Inline JSON suffices for the
   initial text fixtures. A large-payload reference protocol must define content/hash verification
   before use; do not silently put an unchecked path where native output is expected.
6. A scorer's returned structured result is preservable, but it is not necessarily the complete
   judge transport transcript. PyRIT retry rollback and Promptfoo parsed grading output require
   separately captured provider evidence for a stronger lossless-transcript claim.

No schema/code/tests were changed to address these findings.

## 8. Threshold ownership and normalized verdicts

**A scanner execution failure is not evidence that the input is safe.**

| Scanner | Owner / rule in official source | Adapter rule |
| --- | --- | --- |
| Garak | ThresholdEvaluator default 0.5: pass when score < threshold; ZeroToleranceEvaluator passes exactly 0. Per-detector aggregation belongs to evaluator runner | Explicitly name/version the chosen official evaluator policy; record threshold and comparator. No universal hardcoded 0.5 |
| PyRIT | TrueFalseScorer has categorical truth semantics; question determines polarity. Float-scale scorer supplies its scale, not a universal suspiciousness threshold. Message true/false composition can use OR | Complete true/false map by registered question meaning; no cross-scorer OR. Numeric threshold without official/approved evaluator contract is a blocker |
| Promptfoo | Assertion-native rules, optional assertion thresholds, weighted assertion aggregation and test.threshold; llm-rubric applies pass AND score >= supplied assertion threshold | Preserve native pass and score. Do not apply a new threshold or equate pass with safe without rubric polarity |

Sources: [Garak evaluators][geval], [PyRIT SelfAsk][pbool], [Promptfoo aggregation][fagg],
[Promptfoo rubric][frunrubric].

The legacy Garak value 0.5 matches an official evaluator default: calling it wholly invented
would be inaccurate. The legacy hardcoding, empty-success reduction and cross-detector OR are
separate policies that are not mandated by Detector.detect. Official Garak reports per-detector
pass/fail/None counts rather than requiring the legacy overall OR verdict.

Unknown native categorical values stay indeterminate; malformed/missing results stay no_result.
Operational error, timeout, configuration/dependency failure or unsupported input never becomes
not_flagged. A valid native negative is evidence only that this evaluator did not flag under
its recorded surface/configuration, not universal safety or scanner correctness.

## 9. Error semantics and fail-closed bridge

| Condition | Garak | PyRIT | Promptfoo | Required contract handling |
| --- | --- | --- | --- | --- |
| Exception / API failure | May raise; some detectors graceful-fail to None | PyritException/RuntimeError or scorer exception; judge block may raise or produce undetermined | Promise rejection, provider error or graderError result | error with appropriate evaluator/scanner/parser type; no_result |
| Timeout | Detector/provider-specific exception, not uniform result status | Target/runtime-specific exception and retry rules | Fetch/provider timeout or rejection | Preserve timeout cause/status; no_result |
| Unsupported input | Detector-specific None/exception | Validation error or [] for inapplicable evidence | Assertion-specific error; unsupported type can throw | unsupported/no_result; do not manufacture score |
| Missing/empty evaluator result | Empty iterable / None entries | [] or undetermined depending cause | No assertions officially yields pass=true/score=1; red-team empty-response shortcut also passes | Explicit preflight/result-shape rejection; no_result |
| Parser failure | Detector-specific exception/None | InvalidJsonException after JSON retries | graderError for malformed JSON; some custom script failures return plain pass=false; missing verdict keys can default pass=true | Require selected evaluator's typed error/field contract; no safe default |
| Blocked target/judge evidence | Detector-specific | Fully blocked target neutral fallback differs from scorer's blocked judge/undetermined | Red-team refusal heuristic can pass without judging | Retain source cause and shortcut provenance; do not equate missing evidence with safety |

Sources: [Garak base][gbase], [PyRIT message policy][pmessage], [PyRIT LLM helper][pllm],
[Promptfoo assertion dispatch][fassert], [rubric parser][frunrubric], [red-team base][fbase],
[no-assertion aggregate][fagg].

This is not a claim of a uniform native exception taxonomy. The future adapter must classify
documented native causes into adapter_error, scanner_runtime_error, evaluator_error,
parser_error, dependency_error, timeout, invalid_native_result, unsupported_result or
configuration_error and preserve the native error evidence. Unknown causes fail closed.
Authentication/configuration are non-retryable under this repository's rules.
A failure-looking reason string alone is not a robust parser contract.

## 10. LLM judge provenance, call structure and reproducibility

| Path | Logical judge calls per generation / single evaluator | Retry / batch behavior | Required provenance |
| --- | --- | --- | --- |
| PyRIT SelfAsk true/false, one text piece | Normally 1; multiple pieces/scorers multiply calls | JSON retry on InvalidJsonException. RETRY_MAX_NUM_ATTEMPTS defaults to 10 total attempts; target retry also uses that limit for designated transient/empty conditions. score_batch_async is concurrency, not one shared rubric call | Target ComponentIdentifier, provider/model/version when available, exact rendered system prompt/question hashes, options/seed, memory/message/score IDs, attempts |
| Promptfoo llm-rubric | Normally 1 grading-provider call for one assertion | Shared fetchWithRetries defaults to 4 retries (5 attempts), but provider/SDK/cache/remote route can differ. No extra JSON-regeneration loop in the inspected runJsonGradingPrompt helper | Explicit grading provider/model, exact renderedGradingPrompt and rubric hashes, options, usage, cache flag, response/request identity, attempts |
| Promptfoo indirect PI grader | 0 for refusal/empty shortcut, otherwise generally 1 rubric grading call | Adds dynamic timestamp; provider manager/remote defaults affect execution | Record shortcut and actual rendered rubric; configure provider explicitly |
| Promptfoo G-Eval (not selected) | 2 logical calls in inspected helper: propose steps, then evaluate | Each call can have its own provider retries | Both prompts/responses and combined usage |
| Garak static detectors / PyRIT static regex / Promptfoo simple assertions | 0 | No LLM calls | Version/config/input hashes still required |

Sources: [PyRIT scorer transport][pllm], [PyRIT JSON retry][pretry],
[PyRIT retry limits][pexclass], [PyRIT OpenAI-compatible target options][ptarget],
[Promptfoo rubric provider call][frunrubric], [Promptfoo fetch retries][ffetch],
[Promptfoo G-Eval helper][fgrading], [red-team base][fbase].

Planning formula: logical calls = generations × enabled evaluators × evaluated pieces ×
calls per evaluator, adjusted for validated shortcuts/cache, then expanded by actual retry
layers. For one one-piece one-call judge, **2,661 generations imply 2,661 base calls**;
**1,746 generations imply 1,746 base calls**. These are scenarios, not approved executions.
With PyRIT JSON attempts alone at the default limit, the upper planning counts are 26,610 /
17,460; nested target/SDK retries can increase network attempts further.
A Promptfoo route using only its shared 5-attempt fetch budget would give 13,305 / 8,730
attempts; this is not a universal provider upper bound. Neither estimate is a price estimate.

PyRIT JSON retry removes the failed conversation turn before retrying; retry markers alone
do not preserve every failed raw reply. Capture transport evidence before rollback if required.
Promptfoo parsed GradingResult does not necessarily retain the raw judge JSON string.
Neither Score timestamps/UUIDs nor an LLM temperature=0 make execution byte-deterministic.
OpenAIChatTarget supports seed and sampling options as best-effort determinism; persist
the actual options, do not assume every provider honors them. Cached hits must be distinguished
from fresh calls. Model version may legitimately be unavailable; record null rather than invent it.

Repository policy permits only approved transient retries. Future execution must explicitly
set retry budgets and classify authentication/configuration failures; upstream default retry
behavior is not authorization to retry. No API keys, headers or credential-bearing endpoint
URLs belong in input/provenance logs.

## 11. Dependency and runtime isolation

**Separate Python environments and processes are required for the checked versions.**
Garak requires datasets >=3.0.0,<4.0; PyRIT requires datasets >=4.8.0.
Those constraints have no intersection. Same-venv installation is not a supported plan.
[Garak requirements][gmeta], [PyRIT requirements][pmeta]

A proposed starting point is separate Python 3.12 environments, verified independently later,
plus a separately pinned Node runtime/package worker for Promptfoo. Python 3.12 is within both
declared ranges; this audit did not solve transitive dependencies or verify Windows wheels.
Use subprocess JSON transport from the dependency-light core so one framework cannot change
another's imports, event loop, multiprocessing mode or process-global configuration.

Other dependency pressure: Garak includes transformers/torch/numpy and multiple provider SDKs;
PyRIT includes transformers, datasets, pydantic, SQLAlchemy, Azure/OpenAI SDKs and optional
Hugging Face/torch extras. Promptfoo is a separate Node dependency tree with native/optional
integrations. Runtime floor compatibility does not prove a successful platform installation.
[Pinned Garak requirements][gmeta], [PyRIT requirements][pmeta], [Promptfoo package][fmeta]

Use per-run/per-framework working directories and explicit paths for SQLite memory, logs,
reports, downloaded-model caches and framework configuration. PyRIT CentralMemory is global;
SQLiteMemory must point to the scanner run storage, not a Judge worktree database.
Garak model loading/cache and process configuration need isolation. Promptfoo's full evaluation
workflow can use cache/database/global CLI state; direct assertions reduce, but do not prove
absence of, those effects. Verify concrete config/cache switches against the pinned runner
before execution. [CentralMemory][pmemory], [SQLiteMemory][psqlite], [Garak base][gbase],
[Promptfoo Node API][fnode], [red-team base][fbase]

No automatic .env loading in the common adapter; a future execution launcher must receive
explicit authorized configuration without serializing secrets. Do not read or mutate shared
user config or Judge storage. Do not use an unpinned npx invocation that can download packages.
No environment, lockfile or dependency change was made during this audit.

## 12. Legacy versus current official API

Legacy sources were inspected read-only and never imported.

| Scanner | Reusable concept | Rewrite | Remove | Unknown / not established |
| --- | --- | --- | --- | --- |
| Garak | Existing response -> detector, explicit detector identity | scanner_input/integrations/garak/input_builder.py assigns string prompt, incompatible with current Attempt; runner must preserve iterable, None and lineage | runner.py all(s < 0.5) empty PASS; main.py cross-detector OR/skip errors -> overall PASS | Historical version originally targeted; chosen detector inventory's validity |
| PyRIT | Response MessagePiece and separate judge target concept; current legacy already uses Message/MessagePiece names | runner.py true_false_question constructor keyword and positional score_async; explicit Memory/async lifecycle; score status-aware result transport | import-time load_dotenv/SQLite setup; environment assignment; prompt/response concatenation; errors/missing task/[] -> passed True; selecting only first Score | Original package pin and whether any legacy goal rubric is research-valid |
| Promptfoo | Echoing frozen output; explicit rubric idea | runner.py/config_writer.py: single-evaluation lineage, direct assertion API or pinned echo, full native error preservation | First record's rubric for whole batch; index join; missing-field defaults; writes into tracked scanner directory; response prefix mutation | Legacy nested result layout's originating version |

Read-only local evidence:
scanner/garak/runner.py, scanner/garak/main.py,
scanner_input/integrations/garak/input_builder.py,
scanner/pyrit/runner.py,
scanner/promptfoo/runner.py, scanner/promptfoo/config_writer.py.

Batch-wide common rubric, positional joins and overwriting tracked config are not official
Promptfoo requirements. Likewise PIVOT's overall detector OR is not a Garak requirement.
However, official frameworks have their own OR/weighted/empty/refusal policies; replacing
legacy imports alone would not eliminate the research risks described above.

## 13. Proposed adapter architecture, no implementation

Keep the existing ScannerAdapter Protocol: prepare_input returns strict JSON; execute accepts
that JSON plus replay_case/run_context and returns ScannerRawEvaluatorResult; normalize uses
a pinned mapping policy. Construct native framework objects **inside the isolated worker**,
not in the dependency-light common prepare_input return value.

| Proposed module | prepare_input | execute boundary | normalize |
| --- | --- | --- | --- |
| src/scanner_adapter_v2/adapters/garak.py | JSON descriptor of explicit Message/Conversation request, unchanged response, verified required notes, versioned detector/config | Worker constructs Attempt, sets one output, calls detector.detect only; materializes and validates complete output list | Selected official detector/evaluator polarity and threshold policy; none/empty fail closed |
| src/scanner_adapter_v2/adapters/pyrit.py | JSON descriptor of response MessagePiece or ContentScorable; independently registered rubric/expectation, memory lineage | Worker calls public score_message_async or score_async; judge target only if explicitly configured; captures all Score JSON and errors | Completed categorical score mapping; status-aware/null/numeric-string handling must be resolved first |
| src/scanner_adapter_v2/adapters/promptfoo.py | JSON descriptor of one assertion, test vars/metadata, frozen providerResponse, prompt only when consumed | Node worker calls exported assertions.runAssertion; no Target provider; capture full result and grading-provider evidence where required | Explicit assertion/rubric polarity, error markers and required native fields; reject missing-result shortcuts |

A synchronous common execute interface can supervise an async PyRIT/Node worker; the subprocess
protocol must retain evaluation_id on both input and output and reject duplicates, unexpected
responses or cardinality drift. Adapter conversion cannot replace canonical response text.
Future fixtures must emulate **pinned native shapes**, including errors and unknown values.
No native worker or skeleton file was created here.

## 14. Runtime payload policy

Retain exact prepared inputs, native results, rendered rubrics, mapping policies and manifests
under experiments/scanner_adapter_v2/runs/<run_id>/, with immutable content hashes and
explicit generation/evaluation joins. The existing scanner-specific
experiments/scanner_adapter_v2/.gitignore contains /runs/.
Do not store runtime payloads in docs, tests, scanner/ or scanner_input/.

No runtime payload was generated. No common .gitignore change is needed for this audit.
Source production results remain external/read-only with explicit path and hash; no automatic
copy/symlink and no full replay materialization. Native scorer rationale is permitted only in
the result boundary, never back-projected into GT-blind ReplayCase or attack objectives.

## 15. Unresolved questions and acceptance checks

- Exact evaluator/rubric selection and its scientific construct remain open. Trigger/goal-based
  paths stay unsupported while verified response-independent objectives are unavailable.
- Resolve PyRIT status-aware mapping, numeric-string handling and original transport transcript
  retention before promising complete normalized Score compatibility.
- Resolve Promptfoo missing verdict keys, red-team empty/refusal shortcuts, dynamic timestamp
  and grading-provider defaults before enabling model-graded/security paths. Validate the
  tagged runAssertions documentation discrepancy if that batch API is ever adopted.
- Decide whether normalized output must carry a separate numeric score while mapping a native
  boolean. Raw preservation already works; the generic v1 mapping does not populate both.
- A remote non-LLM classifier and large referenced payloads require explicit contract review.
- No transitive environment solve, import smoke test, platform wheel check or native fixture
  execution has been performed. Concrete cache/telemetry/config controls and retry configuration
  need a future pre-execution review in isolated workers.
- Provider-specific raw error/timeout classes, token accounting, retry layers and model revision
  availability remain conditional on the selected provider. No universal call bound is claimed.
- General custom scripts, arbitrary native objects, multimodal responses and composite evaluators
  are outside the initial skeleton scope; require separate evidence and fixtures.

## 16. Validation and change record

Only this audit document is created. No code/schema/test/legacy/Judge/Dataset A/Target LLM
file changes, dependency installations, scanner execution, production replay, commit or push.

Commands/read-only operations used:
- git branch --show-current; git rev-parse HEAD; git rev-parse --abbrev-ref @{upstream};
  git status --short; git diff --stat; final diff/status checks.
- rg / rg --files and Get-Content for repository instructions, contracts and legacy sources.
- importlib.metadata for installed distribution metadata (no scanner imports);
  node --version; npm --version (PowerShell policy blocked); npm.cmd --version.
- Public web reads and Python standard-library urllib.request for official tagged source,
  GitHub release/tag/tree metadata, PyPI JSON and npm registry metadata.
- C:/ProgramData/Anaconda3/python.exe -m pytest tests/scanner_adapter_v2 -q.

Test result: **139 passed in 2.98s** with existing dependencies. The sandbox attempt first
reported 26 passed / 113 fixture setup errors due to temporary-directory access; the same suite
passed when rerun with approved filesystem access. No tests were changed or skipped.
The suite covers the existing contracts, not compatibility of uninstalled scanners.
A source-display attempt hit Windows cp949 Unicode encoding; it did not alter source files.
A guessed legacy input-builder path was absent; rg found the actual scanner_input path.
Unsuccessful source-path guesses were not used as evidence.

Final checks include whitespace, all four JSON Schemas' meta-validation, compileall of the
unchanged common namespace and confirmation that only this Markdown document is untracked.
No external inference API was used; public research network access was used.

## 17. GO / CONDITIONAL gates and next priority

| Scanner | Gate | Authorized next implementation scope / conditions |
| --- | --- | --- |
| Garak | **ADAPTER_SKELETON_GO** | Frozen Attempt/detector transport, no dependency execution in initial fixture skeleton; explicit policy required before a numeric verdict. Start with deterministic shape/error fixtures, not evaluator selection or production replay |
| PyRIT | **ADAPTER_SKELETON_CONDITIONAL** | Frozen scorer path is clear; first resolve native status+value mapping and retain Score/judge provenance. Offline transport fixtures can precede real dependency installation |
| Promptfoo | **ADAPTER_SKELETON_CONDITIONAL** | Single deterministic assertion skeleton is clear; full scanner gate awaits missing-field/error protocol and model-grader evidence handling. Red-team/LLM defaults must not silently enter replay |

Priority: (1) Garak isolated transport skeleton and fixture-native policy shape;
(2) resolve common mapping gaps with tests in a separately authorized implementation;
(3) Promptfoo single deterministic assertion skeleton, then validated model-grader path;
(4) PyRIT Score/status-native skeleton with explicit Memory lifecycle.
Steps 2 and 3 can be reordered for offline transport-only work, but model-grader activation
must wait for their gates. This document itself authorizes no installation, real scanner
execution, paid API, production replay, correctness evaluation, commit or push.

## Official evidence index

[gregistry]: https://pypi.org/pypi/garak/json
[grelease]: https://github.com/NVIDIA/garak/releases/tag/v0.16.0
[gmeta]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/pyproject.toml
[pregistry]: https://pypi.org/pypi/pyrit/json
[prelease]: https://github.com/microsoft/PyRIT/releases/tag/v1.1.0
[pmeta]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyproject.toml
[fregistry]: https://registry.npmjs.org/promptfoo
[fmeta]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/package.json
[gattempt]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/garak/attempt.py
[gbase]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/garak/detectors/base.py
[gpi]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/garak/detectors/promptinject.py
[gdan]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/garak/detectors/dan.py
[gweb]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/garak/detectors/web_injection.py
[gjudge]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/garak/detectors/judge.py
[pinit]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/models/__init__.py
[pscorable]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/models/score/scorable.py
[pscore]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/scorer.py
[pmessage]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/message_scorer.py
[presolver]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/message_scorable_resolver.py
[pvalidator]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/scorer_prompt_validator.py
[pmemory]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/memory/central_memory.py
[pbool]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/true_false/self_ask_true_false_scorer.py
[prubric]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/datasets/score/true_false_question/prompt_injection.yaml
[pstatic]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/true_false/regex/static_prompt_injection_scorer.py
[pshield]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/true_false/prompt_shield_scorer.py
[psmodel]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/models/score/score.py
[fnode]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/site/docs/usage/node-api-reference.md
[findex]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/index.ts
[fassert]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/assertions/index.ts
[fprovider]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/site/docs/providers/echo.md
[fecho]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/providers/echo.ts
[ftypes]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/types/index.ts
[frunrubric]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/matchers/rubric.ts
[frubricdoc]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/site/docs/configuration/expected-outputs/model-graded/llm-rubric.md
[fred]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/redteam/plugins/indirectPromptInjection.ts
[fgraders]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/redteam/graders.ts
[fbase]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/redteam/plugins/base.ts
[frubric]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/assertions/llmRubric.ts
[geval]: https://raw.githubusercontent.com/NVIDIA/garak/v0.16.0/garak/evaluators/base.py
[fagg]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/assertions/assertionsResult.ts
[pllm]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/score/llm_scoring.py
[pretry]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/prompt_normalizer/json_retry.py
[pexclass]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/exceptions/exception_classes.py
[ptarget]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/prompt_target/openai/openai_chat_target.py
[ffetch]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/util/fetch/index.ts
[fgrading]: https://raw.githubusercontent.com/promptfoo/promptfoo/0.122.2/src/matchers/llmGrading.ts
[psqlite]: https://raw.githubusercontent.com/microsoft/PyRIT/v1.1.0/pyrit/memory/sqlite_memory.py
