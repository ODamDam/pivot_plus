# Unresolved Sources v1

This is an evidence-collection queue, not a license decision. Search queries are
drafts for the later network-enabled verification phase and were not executed in
this inventory phase.

## Priority summary

| priority | meaning | items |
| --- | --- | ---: |
| P0 | used by current GT; license/provenance not externally verified | 10 |
| P1 | upstream dependency or reference affecting a used source | 15 |
| P2 | candidate/reference with no current GT rows | 2 |

All P0 items block a license-cleared GT rebuild until official evidence is
collected or affected records are removed. P1 items block the dependent record
scope when the relationship is confirmed. P2 items do not block reconstruction
of the current GT but block future inclusion.

The 27 P0/P1/P2 nodes are independent external-evidence collection targets. The
two derived collections are parent-dependent nodes and are tracked separately
below; they do not change the P0/P1/P2 counts.

## P0 — current Ground Truth sources

| source_id | unresolved items | official evidence needed | blocks GT rebuild | query draft |
| --- | --- | --- | --- | --- |
| SRC-01_lakera_gandalf | canonical owner URL, dataset export identity, version, license, SPML overlap | official repository/site; LICENSE; terms; dataset revision; upstream provenance | yes | `Lakera Gandalf Ignore Instructions dataset official license` |
| SRC-03_spml_chatbot_prompt_injection | canonical dataset identity, license, Gandalf-derived rows | official repository; dataset card; LICENSE; revision; upstream provenance | yes | `SPML Chatbot Prompt Injection dataset official repository license` |
| SRC-04_deepset_prompt_injections | canonical HF/repository URL, owner, revision, license | official repository; dataset card; LICENSE; revision | yes | `deepset prompt-injections official dataset card license` |
| SRC-05_rogue_security_prompt_injections_benchmark | canonical repository, revision, license, benign/jailbreak redistribution terms | official repository; LICENSE; NOTICE; revision | yes | `rogue-security prompt-injections-benchmark official license` |
| SRC-06_jailbreak_llms | verazuo/TrustAIRLab relationship, repository revision, upstream community-source rights | official repository; dataset card; LICENSE; NOTICE; upstream provenance | yes | `verazuo jailbreak_llms TrustAIRLab official repository license` |
| SRC-07_prodnull_prompt_injection_repo_dataset | canonical repository, dataset license, underlying repository-file licenses, wrapper derivative status | official repository; LICENSE; NOTICE; terms; record-level upstream provenance | yes | `prodnull prompt-injection-repo-dataset official license provenance` |
| SRC-09_neuralchemy_prompt_injection_dataset | canonical repository, revision, license, augmentation method, HackAPrompt/WildGuard/HarmBench dependencies | official repository; dataset card; LICENSE; revision; upstream provenance | yes | `neuralchemy Prompt-injection-dataset official license dataset card` |
| SRC-10_SCOUT_450 | verify internal MIT claim, revision, generated/copied/naturalized subsets, AIME/BIPIA/InjecAgent dependencies | official dataset card; LICENSE; revision; upstream provenance | yes | `sullivanUCSD SCOUT-450 official dataset card MIT license` |
| SRC-11_microsoft_BIPIA | official repository/revision/license and CodeQA context rights | official repository; dataset card; LICENSE; NOTICE; revision; upstream provenance | yes | `microsoft BIPIA official repository license CodeQA` |
| SRC-12_bordair_multimodal | canonical project, license, generator terms, attack-reference role | official repository; dataset card; LICENSE; terms; paper appendix; revision | yes | `Bordair multimodal prompt injection dataset official license` |

## P1 — upstream and reference dependencies

| source_id | unresolved items | official evidence needed | dependent scope | query draft |
| --- | --- | --- | --- | --- |
| UP-SPML-GANDALF | whether SPML rows copy or merely label Gandalf; duplicate relation to SRC-01 | upstream provenance; dataset revision | SPML rows with `metadata.source=Gandalf` | `SPML Gandalf source records provenance` |
| UP-VERAZUO | owner/repository relationship to SRC-06 | official repository; LICENSE; revision | SRC-06 | `verazuo jailbreak_llms official repository` |
| UP-TRUSTAIRLAB | publisher or mirror relationship to SRC-06 | official repository; dataset card; LICENSE | SRC-06 | `TrustAIRLab jailbreak dataset official repository` |
| UP-FLOWGPT | whether source label denotes copied prompts and applicable terms | terms of use; upstream provenance | SRC-06 rows labelled flowgpt | `FlowGPT prompt dataset terms redistribution` |
| UP-HACKAPROMPT | copied/modified record scope inside neuralchemy | official dataset; LICENSE; revision; upstream provenance | SRC-09 source label | `HackAPrompt dataset official license` |
| UP-WILDGUARD-JUDGECOMP | exact dataset/split identity and redistribution terms | official repository; dataset card; LICENSE; revision | SRC-09 source label | `WildGuard JudgeComp dataset official license` |
| UP-HARMBENCH | exact record mapping and license | official repository; dataset card; LICENSE; revision | SRC-09 source label | `HarmBench official dataset license` |
| UP-HARMBENCH-BENIGN | whether this is a split/alias of HarmBench | dataset card; split documentation; LICENSE | SRC-09 benign rows | `HarmBench benign split dataset license` |
| UP-AIME | identity of SCOUT's `aime` source label | official repository/dataset; LICENSE; revision | 11 SCOUT candidates before selection | `SCOUT-450 AIME source_dataset provenance` |
| UP-SCOUT-BIPIA | mapping to Microsoft BIPIA and copied/transformed scope | official SCOUT/BIPIA documentation; LICENSE; revision | 6 SCOUT candidates before selection | `SCOUT-450 BIPIA source_dataset provenance` |
| UP-INJECAGENT | identity and license of SCOUT's one labelled record | official repository; dataset card; LICENSE | 1 SCOUT candidate before selection | `InjecAgent dataset official repository license` |
| UP-CODEQA | source and license of BIPIA code contexts and author URLs | official dataset card; LICENSE; NOTICE; upstream provenance | SRC-11 contexts | `BIPIA CodeQA context dataset license` |
| REF-GRESHAKE-ET-AL | whether cited work supplies text or only design reference | paper appendix; artifact repository; LICENSE | SRC-12 reference scope | `Greshake indirect prompt injection dataset arXiv 2302.12173 artifact` |
| REF-OWASP | exact document/version and whether content was copied | official page; terms; revision | SRC-12 reference scope | `OWASP prompt injection dataset terms license` |
| REF-MICROSOFT-RED-TEAM | exact publication/artifact and use in generator | official repository/page; LICENSE; paper appendix | SRC-12 reference scope | `Microsoft Red Team prompt injection dataset artifact license` |

## P2 — candidate/reference-only primary sources

| source_id | unresolved items | official evidence needed | blocks current GT | query draft |
| --- | --- | --- | --- | --- |
| SRC-02 | canonical Mosscap dataset identity, URL, version, count, license | official repository; dataset card; LICENSE; revision | no | `Lakera Mosscap Prompt Injection dataset official license` |
| SRC-08 | canonical PINT benchmark identity, URL, version, held-out terms, license | official benchmark page; dataset card; LICENSE; terms; revision | no | `Lakera PINT Benchmark official dataset license` |

## Derived collections - Parent-dependent eligibility

| source_id | dependent parent source(s) | derivative-use judgment needed | independent external search |
| --- | --- | --- | --- |
| DERIVED-MUTATION-500 | SRC-01, SRC-03, SRC-04, SRC-05, SRC-06, SRC-09 seed sources | whether each parent license permits the internally evidenced mutation transformation and resulting derivative use | no |
| DERIVED-SRC07-WRAPPED | SRC-07 and its underlying repository-file sources | whether SRC-07 and underlying-file terms permit the internally evidenced repository-review wrapper transformation and derivative use | no |
