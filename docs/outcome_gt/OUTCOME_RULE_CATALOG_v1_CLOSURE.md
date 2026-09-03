# Outcome Rule Catalog v1 Closure

## Identity

- Status: `OUTCOME_RULE_CATALOG_v1 FROZEN_APPROVED_CLOSED`
- Rule catalog version: `outcome-rule-catalog-v1`
- Policy version: `outcome-gt-contract-v1`
- Template design: `outcome-rule-template-design-v1`
- Materialization source commit: `27f1ed9a2680dfb30c0ec947e47fb6065cb280ed`
- Closure checkpoint: the Git commit containing this report
- Freeze workflow run: `33719063592`

## Frozen Inputs

- Response-blind source: `data/outcome_gt/rule_catalog_v1/outcome_rule_blind_input_582_v1.jsonl`
- Blind source SHA-256: `22389aa06e6c3504556482a98aaab4fa18e4e5a185372e593cbc7fc2737275d9`
- Blind production cases: 582
- Frozen Template Design: `docs/outcome_gt/OUTCOME_RULE_TEMPLATE_DESIGN_v1.md`
- Template Design SHA-256: `6c99eeb39e9c939791720da5100f43772964c643ad1985d6fa1dd2579ce0d8db`
- Template freeze commit: `eb64112d82a519135184ed9614e1f3adcfd23ce1`

No Target LLM response, Outcome GT label, scanner result, evaluator output, or sibling response result was used to author or bind these rules.

## Canonical Binding Artifacts

- Bindings: `data/outcome_gt/rule_catalog_v1/bindings/outcome_rule_bindings_582_v1.jsonl`
- Binding SHA-256: `df1279ad8b27d66ee681bc22e1a22737c8418c803ee6aced5aa777d99af83499`
- Binding count: 582
- Exception queue: `data/outcome_gt/rule_catalog_v1/bindings/outcome_rule_binding_exceptions_v1.jsonl`
- Exception SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Unresolved exceptions: 0
- Binding manifest: `data/outcome_gt/rule_catalog_v1/bindings/outcome_rule_bindings_582_v1_manifest.json`
- Binding manifest SHA-256: `c10e7f91ad24328c8f2e0ce99b458e958915a3b68b59ab072aa0e5875d7b8d57`

## Canonical Flat Rule Catalog

- Rules: `data/outcome_gt/rule_catalog_v1/final/outcome_rules_582_v1.jsonl`
- Rule SHA-256: `c85f277f897d29b53445f7e292ae32babac277b564f37945a3dc99c5c90248a8`
- Rule count: 582
- Unique production cases: 582
- Rule manifest: `data/outcome_gt/rule_catalog_v1/final/outcome_rules_582_v1_manifest.json`
- Rule manifest SHA-256: `df8302d017b8dc705fe85989b73c645e510e37ea826d1fc1a994f0c3b6452c3d`

## Validation

- Status: `PASS`
- Focused regression/schema suite: `PASS`
- Bindings: 582/582
- Flat rules: 582/582
- Exception queue: 0
- Unbound: 0
- Duplicate bindings: 0
- Duplicate rules: 0
- Invalid composition: 0
- Provenance mismatch: 0
- Response-blind: `true`

Structural families:

- T1_document: 211
- T2_plain_text: 106
- T3_code: 8
- T4_structured: 7
- T5_tool_action: 250

Template distribution:

- S1: 10
- S2: 68
- S3: 31
- S4: 6
- S5: 8
- S6: 182
- S7: 25
- S8: 2
- S9: 240
- S10: 3
- S11: 7

Validation report: `data/outcome_gt/rule_catalog_v1/final/outcome_rule_catalog_v1_validation_report.json`
Validation report SHA-256: `d9deeee1d0fde46fccce2188a94dc378bce908556c712cbb5fc259d5e79c91af`

## Closure Decision

- Outcome Rule Catalog v1 is frozen and closed.
- The 582 bindings and 582 flat `outcome_rule.v1` records are immutable v1 research artifacts.
- No v1 semantic rebinding or template modification is permitted in place; any change requires a new catalog version.
- The empty exception queue is part of the frozen provenance record.
- Response-based Outcome GT adjudication may now begin because the response-blind rule-authoring phase is complete and frozen.
- Scanner results remain outside Outcome GT construction and must not be used to revise this catalog.
