# Outcome GT Common Canary Selection Contract v1

## Purpose

This contract freezes one common ten-generation population for comparative Outcome GT Judge v2 canaries. Pass A and pass B must evaluate the same ordered population even though their full independent-assignment files use different pass-specific shuffles.

## Canonical identifier and algorithm

- The only ranking identifier is the pass-independent `generation_id` from the canonical 1,746-row adjudication input.
- The namespace is `OUTCOME_GT_COMMON_CANARY_V1`.
- For every unique canonical generation ID, compute `SHA-256("OUTCOME_GT_COMMON_CANARY_V1|" + generation_id)`.
- Sort ascending by digest, with `generation_id` as a deterministic tie-break, and select the first 10.
- Preserve that order for both passes.

Response text, response hashes, Outcome GT labels, rule outcomes, scanner results, judge outputs, and judge-model properties are prohibited selection factors. Pass-private `assignment_item_id` values are used only after selection to resolve each common generation ID to the corresponding pass request.

## Frozen artifact and validation

The tracked metadata artifact is `data/outcome_gt/adjudication_v1/canary/common_canary_selection_v1.json`. It contains no response, prompt, private-key, GT-label, or judge-result content.

`scripts/outcome_gt/materialize_outcome_gt_common_canary_v1.py` regenerates the artifact idempotently. Its `--validate-only` mode requires byte-for-byte equality with deterministic regeneration and fails closed on stale source population or request hashes, duplicate or missing generation IDs, or pass coverage mismatch.

## Runner interface

Comparative v2 canaries must use:

```text
--selection-file data/outcome_gt/adjudication_v1/canary/common_canary_selection_v1.json
```

The runner resolves selected generation IDs through each pass's private lineage key, preserves the artifact order, and fails if any selected ID is missing or duplicated. The existing `--limit` option remains available for legacy diagnostics but must not be used for common comparative canaries.
