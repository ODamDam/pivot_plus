# Outcome GT Judge Canary Remediation v1

## Status

- Recorded after the first 10-item canary for each independent judge pass.
- This document records an **operational judge-interface revision only**.
- Outcome GT Contract v1, Outcome Rule Template Design v1, and Outcome Rule Catalog v1 remain unchanged and frozen.
- No production Outcome GT annotation was accepted from the failed v1 canaries.

## Canary v1 observations

### Pass A — qwen2.5:7b

- run: `OGTJRUN-V1-A-124F31EED53D1190`
- model digest: `845dbda0ea48ed749caafd9e6037047aa19acfcfd82e7047ca97d631a0b697e`
- target: 10
- success: 5
- failed: 5
- failure classes:
  - schema_error: 4
  - evidence_error: 1
- dominant schema failure: model emitted a rule-field name such as `attacker_goal_success_criterion` as `evidence.supports`, outside the frozen evidence enum.
- evidence failure: `attacker_goal_not_achieved` evidence contradicted the semantic boolean decision.

### Pass B — phi3:latest

- run: `OGTJRUN-V1-B-D5A5AB3B9A85E8ED`
- model digest: `4f222292793889a9a40a020799cfd28d53f3e01af25d48e06c5e708610fc47e9`
- target: 10
- success: 1
- failed: 9
- failure classes:
  - evidence_error: 6
  - parse_error: 3
- dominant evidence failures were non-literal quotes and decision/evidence contradictions.

## Root-cause classification

The observed failures are predominantly output-contract and evidence-grounding failures, not evidence that the frozen Outcome Rule Catalog is under-specified.

Therefore the following are explicitly prohibited as remediation:

- changing Outcome Rule semantics to fit model output;
- weakening exact evidence validation;
- silently repairing semantic decisions after generation;
- automatic semantic, parse, schema, or evidence retries;
- counting failed canary annotations as production GT.

## v2 remediation

Judge execution v2 introduces two operational controls while preserving the semantic annotation contract:

1. **Ollama JSON-Schema structured output**
   - the existing `outcome_gt_judge_semantic_response_v1` schema is supplied directly as the Ollama `format` constraint;
   - this targets parse errors, extra keys, invalid enum values, and malformed output structure;
   - the same schema is still validated after generation.

2. **Frozen Judge Prompt v2**
   - keeps the same Outcome GT axes and rule semantics;
   - explicitly requires verbatim evidence copying;
   - forbids rule-field names as `evidence.supports` values;
   - states boolean/null ↔ evidence-support compatibility rules;
   - does not relax literal-evidence validation.

Frozen prompt v2 SHA-256:

`80a7a218bf34ccbf33a9aa936ac9f2926184be55acd0327fa3b93617e9435ad2`

Structured semantic schema SHA-256:

`d821c295054a0a5a1a8c8df6eb631f8cb0a5d5fb5e680f7d6af840dff0a1bf1f`

## Acceptance rule for the next canary

- Each candidate production judge must complete all 10 canary items with zero transport, parse, schema, or evidence failures.
- Canary success only establishes operational admissibility; it does not by itself establish semantic judge quality.
- Pass B `phi3:latest` is not frozen as a production judge based on the v1 canary. It must either pass the v2 canary or be replaced by a stronger independent model.
- Production judge model/runtime provenance is frozen only after the v2 canary is accepted.
