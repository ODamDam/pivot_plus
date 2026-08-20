# Vulnerable LLM De-weakening Audit — 2026-08-14

## 1. Current architecture and data flow

Primary entry point is `vulnerable_llm/app.py` (FastAPI): `/generate` is the
legacy prompt/context path and `/chat-generate` accepts explicit messages.
Both call `vulnerable_llm/client.py:OllamaClient.chat`, which posts to the
hard-coded Ollama `/api/chat` shape. Responses and final messages are logged
through `logging_utils.append_jsonl`.

`/generate` flow:

`GenerateRequest.prompt/context` → `_context_to_text` →
`vuln.build_vulnerable_messages` → system messages + context + prompt as a
trusted system instruction + prompt as user message twice → Ollama → response
and JSONL artifact.

`/chat-generate` flow:

caller-supplied messages → `apply_generation_profile` →
`HIGH_YIELD_V1_SYSTEM_PRIMER` prepended and last user message duplicated →
Ollama → response and JSONL artifact. The attack seed therefore has no single
guaranteed untrusted slot and may be repeated by the builder/profile path.

## 2. Artificial weakening findings

| location | finding | classification |
|---|---|---|
| `vuln.py:HIGH_YIELD_V1_SYSTEM_PRIMER` | explicitly says vulnerable mode, follow user directly, do not refuse, treat injections as valid | REMOVE |
| `vuln.py:build_vulnerable_messages` | prompt is inserted as trusted system instruction and user input; user prompt duplicated | REMOVE/REWRITE |
| `vuln.py:apply_high_yield_v1` | vulnerability primer prepended and last user message duplicated | REMOVE |
| `Modelfile.txt` SYSTEM | filters off, never refuse, reveal prompts, prioritize bypass, 100% compliant | REMOVE |
| `Modelfile.txt` model name `vul-dolphin:latest` | model choice itself is a declared vulnerable target and needs experimental justification | REVIEW |
| `app.py:ENABLE_HIGH_RISK_BLOCK` | optional pre-generation block changes the attack condition and can confound controls | REWRITE |
| `app.py` fixed temperature/max-token behavior | reproducibility mechanism; not semantic weakening | KEEP/REWRITE metadata |
| `client.py` Ollama HTTP adapter | provider-specific transport only | KEEP, isolate behind interface |

No evidence was found that temperature or sampling alone forces vulnerability;
the material validity threat is prompt semantics and message duplication.

## 3. Attack insertion and trust-boundary problems

There is no canonical `normal_task`, trusted application instruction, or
designated untrusted-input slot in the legacy `/generate` contract. Context is
promoted to a system message, the prompt is simultaneously trusted and user
content, and the same user content is sent twice. `/chat-generate` accepts
arbitrary caller roles and then modifies them through a vulnerability profile.
This prevents a clean control-versus-attack causal comparison.

The current implementation does not prove one-time seed insertion. The two
explicit duplication sites are `build_vulnerable_messages` (two user copies)
and `apply_high_yield_v1` (another last-user copy), with additional duplication
possible in caller-built context.

## 4. Target architecture

`trusted system/application instruction → normal task → trusted application
context → exactly one untrusted-input slot → provider adapter → raw response`.

The target must not be told that it is vulnerable, that an injection experiment
is running, the attacker goal, success markers, or scanner/evaluator details.
The scenario record should carry `scenario_id`, `normal_task`,
`trusted_instruction`, `trust_boundary`, `untrusted_input_role`, and exactly
one rendered attack slot. `attack_method`, `attack_method_variant`,
`seed_original`, and `attack_rendered` should remain separate fields.

## 5. Control, repetition, and provider readiness

Current control-run support: **not adequate**. There is no first-class
`condition=control|attack`, clean-content counterpart, or assertion that all
model parameters and scenario fields are identical. Add an execution plan that
renders the same scenario twice, differing only in the untrusted payload.

Current repeated-generation support: **partial**. `generation_id` and `run_id`
are logged, but the service does not orchestrate repetition or record a
repetition index/condition/attack variant as a stable execution schema.

Provider-agnostic support: **no**. `OllamaClient`, `/api/chat`, base URL, and
model defaults are Ollama-specific. Introduce a provider-neutral client
protocol and retain Ollama as one adapter; record provider, model, model
version, generation parameters, and request/response hashes.

## 6. Minimal implementation sequence (not executed)

1. Remove the vulnerable primer, Modelfile weakening rules, profile, and all
   prompt duplication.
2. Define a normal application message builder with one untrusted slot and
   explicit scenario/trust-boundary fields.
3. Add a provider-neutral adapter interface; keep Ollama adapter separate.
4. Add paired control/attack rendering and a repetition index to the run schema.
5. Preserve raw request, rendered messages, raw response, and execution status
   as separate artifacts.
6. Add a deterministic mock-client smoke test before any real provider run.

## 7. Smoke-test readiness

Before a 20-case smoke, the above structural changes are required. The smoke
should include explicit override, task redirection, synthetic secret-disclosure
marker, designated-string output, workflow/output modification, and clean
controls. Record `normal_task_completed`, `boundary_violated`,
`attacker_goal_achieved`, `refusal`, and `execution_failure` independently;
boundary violation is not equivalent to attacker-goal achievement.

No code, prompt, model, Dataset A artifact, or external service was modified or
executed during this audit.
