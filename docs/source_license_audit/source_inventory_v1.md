# Source Inventory v1

## 1. Purpose

This inventory structures repository-internal provenance evidence for the Source
License Audit. It deliberately stops before external license verification and
before any allow, conditional, or exclude decision.

## 2. Scope

The review covered source policy and schema documents, normalization and
structure-intact collection code, the 1,000-row build contract, materialized CSV
review/final-selection artifacts, evaluation artifacts, freeze/integration
records, Git history paths, and Git LFS state. Raw datasets were not present in
the current checkout. Nine archived JSONL artifacts are LFS pointers only.

## 3. Node counts

- Primary sources: **12**
- Upstream/reference nodes: **15**
- Derived collections: **2**
- Total inventory nodes: **29**
- Provenance edges: **24**

The 27 primary/upstream/reference nodes are independent external-evidence
collection targets. The two derived collections are parent-dependent and are
not independent official source-page search targets.

The primary nodes retain SRC-02 Mosscap and SRC-08 PINT even though no current
data records were found for them.

## 4. Ground Truth-connected sources

Ten primary sources connect to the 1,000-row Ground Truth: SRC-01, SRC-03,
SRC-04, SRC-05, SRC-06, SRC-07, SRC-09, SRC-10, SRC-11, and SRC-12.

| source_id | observed GT | inherited mutation GT | total |
| --- | ---: | ---: | ---: |
| SRC-01_lakera_gandalf | 30 | 58 | 88 |
| SRC-03_spml_chatbot_prompt_injection | 56 | 72 | 128 |
| SRC-04_deepset_prompt_injections | 66 | 92 | 158 |
| SRC-05_rogue_security_prompt_injections_benchmark | 27 | 12 | 39 |
| SRC-06_jailbreak_llms | 11 | 18 | 29 |
| SRC-07_prodnull_prompt_injection_repo_dataset | 50 | 0 | 50 |
| SRC-09_neuralchemy_prompt_injection_dataset | 176 | 248 | 424 |
| SRC-10_SCOUT_450 | 64 | 0 | 64 |
| SRC-11_microsoft_BIPIA | 18 | 0 | 18 |
| SRC-12_bordair_multimodal | 2 | 0 | 2 |
| **Total** | **500** | **500** | **1,000** |

SRC-02 is candidate-only and SRC-08 is reference/held-out-only in current
internal evidence.

## 5. Ground Truth calculation

The materialized CSV evidence directly accounts for 250 reviewed malicious
seeds, 150 structure-intact rows, and 100 benign/hard-negative rows. These are
the 500 observed GT rows.

The build contract creates 500 mutations from the 250 seeds, exactly two per
parent. The mutation rows are written with blank `source_id` and use
`parent_record_id`; therefore their 500-source distribution is inferred by
doubling the parent seed distribution. It is recorded only under
`inherited_ground_truth_count` and through child-to-parent `derived_from`
provenance edges. The transformation is verified by internal build evidence;
eligibility remains dependent on each parent source's license and derivative-use
conditions.

## 6. Observed candidate counts

`observed_record_count` is the number of distinct `source_record_id` values
observed across materialized CSV artifacts, not a claim about the upstream
dataset's total size. It is 0 when only policy/reference evidence exists.

## 7. Distribution summaries

### Provenance completeness

| status | nodes |
| --- | ---: |
| partial | 27 |
| missing | 2 |
| complete | 0 |

### Artifact availability

| status | nodes |
| --- | ---: |
| mixed | 11 |
| materialized | 1 |
| lfs_pointer_only | 1 |
| missing | 16 |

`mixed` means materialized CSV evidence coexists with missing raw source data or
LFS-pointer-only derived artifacts. It does not mean the upstream raw dataset is
available.

### License verification status

| status | nodes |
| --- | ---: |
| not_checked | 9 |
| internal_claim_only | 1 |
| unresolved | 19 |

SCOUT-450 is the sole `internal_claim_only` node because the collector and
candidate CSVs contain `source_license=MIT`. No official LICENSE or dataset-card
evidence has yet been checked.

## 8. Current limitations

- Canonical URLs, owners, versions, revisions, and acquisition dates are mostly
  absent.
- Raw source directories are not checked in.
- Nine archived JSONL files are LFS pointers only in this checkout.
- Embedded-source labels do not prove ownership, copying, or exact derivation.
- BIPIA includes CodeQA context, and SCOUT/neuralchemy include upstream labels
  requiring record-level license dependency review.
- SRC-07 wraps repository-derived text, so both the dataset and underlying file
  provenance may matter.
- Mutation source inheritance is a build-contract inference rather than a field
  directly recorded on mutation rows.

## 9. Next external verification stage

Identify owner-controlled URLs, pin dataset/repository revisions, collect
official LICENSE/NOTICE/terms/dataset-card evidence, map upstream dependencies at
record level, and only then prepare allow/conditional/exclude/unresolved
decisions. Evidence collection must retain retrieval dates and content hashes.
