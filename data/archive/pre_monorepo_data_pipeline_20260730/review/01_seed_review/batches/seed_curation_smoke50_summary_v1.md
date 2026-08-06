# Seed Curation Smoke50 Candidate Summary v1

These are assistant-suggested candidates for a first manual-reviewed mutation smoke test. Do not treat them as final labels until manually confirmed.

## Counts

- total_candidates: 50
- seed_malicious_file_candidates: 40
- bypass_candidate_file_candidates: 10

## Attack Type Distribution

| key | count |
| --- | ---: |
| `role_play_bypass` | 18 |
| `instruction_override` | 12 |
| `data_exfiltration` | 8 |
| `format_injection` | 6 |
| `policy_bypass` | 6 |

## Source File Distribution

| key | count |
| --- | ---: |
| `manual_review_seed_malicious_schema_v1.csv` | 40 |
| `manual_review_bypass_candidate_schema_v1.csv` | 10 |

## Source ID Distribution

| key | count |
| --- | ---: |
| `SRC-03_spml_chatbot_prompt_injection` | 19 |
| `SRC-09_neuralchemy_prompt_injection_dataset` | 12 |
| `SRC-04_deepset_prompt_injections` | 5 |
| `SRC-06_jailbreak_llms` | 5 |
| `SRC-05_rogue_security_prompt_injections_benchmark` | 5 |
| `SRC-01_lakera_gandalf` | 4 |

## Input Format Distribution

| key | count |
| --- | ---: |
| `plain_text` | 31 |
| `markdown` | 14 |
| `json` | 2 |
| `html` | 1 |
| `encoded` | 1 |
| `yaml` | 1 |

## Selected IDs

| source_file | row | sample_id | attack_type | source_id | score |
| --- | ---: | --- | --- | --- | ---: |
| `manual_review_seed_malicious_schema_v1.csv` | 296 | `SEED-CAND-000295` | `instruction_override` | `SRC-09_neuralchemy_prompt_injection_dataset` | 36 |
| `manual_review_seed_malicious_schema_v1.csv` | 477 | `SEED-CAND-000476` | `instruction_override` | `SRC-03_spml_chatbot_prompt_injection` | 34 |
| `manual_review_seed_malicious_schema_v1.csv` | 55 | `SEED-CAND-000054` | `instruction_override` | `SRC-01_lakera_gandalf` | 32 |
| `manual_review_seed_malicious_schema_v1.csv` | 386 | `SEED-CAND-000385` | `instruction_override` | `SRC-09_neuralchemy_prompt_injection_dataset` | 30 |
| `manual_review_seed_malicious_schema_v1.csv` | 169 | `SEED-CAND-000168` | `instruction_override` | `SRC-03_spml_chatbot_prompt_injection` | 30 |
| `manual_review_seed_malicious_schema_v1.csv` | 324 | `SEED-CAND-000323` | `instruction_override` | `SRC-09_neuralchemy_prompt_injection_dataset` | 30 |
| `manual_review_seed_malicious_schema_v1.csv` | 380 | `SEED-CAND-000379` | `instruction_override` | `SRC-03_spml_chatbot_prompt_injection` | 30 |
| `manual_review_seed_malicious_schema_v1.csv` | 106 | `SEED-CAND-000105` | `instruction_override` | `SRC-03_spml_chatbot_prompt_injection` | 30 |
| `manual_review_seed_malicious_schema_v1.csv` | 280 | `SEED-CAND-000279` | `instruction_override` | `SRC-03_spml_chatbot_prompt_injection` | 30 |
| `manual_review_seed_malicious_schema_v1.csv` | 17 | `SEED-CAND-000016` | `instruction_override` | `SRC-01_lakera_gandalf` | 29 |
| `manual_review_seed_malicious_schema_v1.csv` | 272 | `SEED-CAND-000271` | `instruction_override` | `SRC-01_lakera_gandalf` | 29 |
| `manual_review_seed_malicious_schema_v1.csv` | 86 | `SEED-CAND-000085` | `instruction_override` | `SRC-01_lakera_gandalf` | 29 |
| `manual_review_seed_malicious_schema_v1.csv` | 128 | `SEED-CAND-000127` | `data_exfiltration` | `SRC-03_spml_chatbot_prompt_injection` | 45 |
| `manual_review_seed_malicious_schema_v1.csv` | 185 | `SEED-CAND-000184` | `data_exfiltration` | `SRC-03_spml_chatbot_prompt_injection` | 42 |
| `manual_review_seed_malicious_schema_v1.csv` | 2 | `SEED-CAND-000001` | `data_exfiltration` | `SRC-03_spml_chatbot_prompt_injection` | 41 |
| `manual_review_seed_malicious_schema_v1.csv` | 131 | `SEED-CAND-000130` | `data_exfiltration` | `SRC-03_spml_chatbot_prompt_injection` | 41 |
| `manual_review_seed_malicious_schema_v1.csv` | 68 | `SEED-CAND-000067` | `data_exfiltration` | `SRC-09_neuralchemy_prompt_injection_dataset` | 35 |
| `manual_review_seed_malicious_schema_v1.csv` | 242 | `SEED-CAND-000241` | `data_exfiltration` | `SRC-09_neuralchemy_prompt_injection_dataset` | 35 |
| `manual_review_seed_malicious_schema_v1.csv` | 206 | `SEED-CAND-000205` | `data_exfiltration` | `SRC-09_neuralchemy_prompt_injection_dataset` | 32 |
| `manual_review_seed_malicious_schema_v1.csv` | 213 | `SEED-CAND-000212` | `data_exfiltration` | `SRC-09_neuralchemy_prompt_injection_dataset` | 32 |
| `manual_review_seed_malicious_schema_v1.csv` | 374 | `SEED-CAND-000373` | `format_injection` | `SRC-03_spml_chatbot_prompt_injection` | 42 |
| `manual_review_seed_malicious_schema_v1.csv` | 273 | `SEED-CAND-000272` | `format_injection` | `SRC-09_neuralchemy_prompt_injection_dataset` | 35 |
| `manual_review_seed_malicious_schema_v1.csv` | 293 | `SEED-CAND-000292` | `format_injection` | `SRC-03_spml_chatbot_prompt_injection` | 33 |
| `manual_review_seed_malicious_schema_v1.csv` | 497 | `SEED-CAND-000496` | `format_injection` | `SRC-03_spml_chatbot_prompt_injection` | 32 |
| `manual_review_seed_malicious_schema_v1.csv` | 321 | `SEED-CAND-000320` | `format_injection` | `SRC-04_deepset_prompt_injections` | 29 |
| `manual_review_seed_malicious_schema_v1.csv` | 388 | `SEED-CAND-000387` | `format_injection` | `SRC-04_deepset_prompt_injections` | 26 |
| `manual_review_seed_malicious_schema_v1.csv` | 501 | `SEED-CAND-000500` | `policy_bypass` | `SRC-03_spml_chatbot_prompt_injection` | 44 |
| `manual_review_seed_malicious_schema_v1.csv` | 203 | `SEED-CAND-000202` | `policy_bypass` | `SRC-03_spml_chatbot_prompt_injection` | 36 |
| `manual_review_seed_malicious_schema_v1.csv` | 448 | `SEED-CAND-000447` | `policy_bypass` | `SRC-03_spml_chatbot_prompt_injection` | 35 |
| `manual_review_seed_malicious_schema_v1.csv` | 94 | `SEED-CAND-000093` | `policy_bypass` | `SRC-09_neuralchemy_prompt_injection_dataset` | 32 |
| `manual_review_seed_malicious_schema_v1.csv` | 52 | `SEED-CAND-000051` | `policy_bypass` | `SRC-09_neuralchemy_prompt_injection_dataset` | 26 |
| `manual_review_seed_malicious_schema_v1.csv` | 469 | `SEED-CAND-000468` | `policy_bypass` | `SRC-09_neuralchemy_prompt_injection_dataset` | 26 |
| `manual_review_seed_malicious_schema_v1.csv` | 496 | `SEED-CAND-000495` | `role_play_bypass` | `SRC-03_spml_chatbot_prompt_injection` | 48 |
| `manual_review_seed_malicious_schema_v1.csv` | 366 | `SEED-CAND-000365` | `role_play_bypass` | `SRC-03_spml_chatbot_prompt_injection` | 48 |
| `manual_review_seed_malicious_schema_v1.csv` | 485 | `SEED-CAND-000484` | `role_play_bypass` | `SRC-03_spml_chatbot_prompt_injection` | 39 |
| `manual_review_seed_malicious_schema_v1.csv` | 299 | `SEED-CAND-000298` | `role_play_bypass` | `SRC-03_spml_chatbot_prompt_injection` | 39 |
| `manual_review_seed_malicious_schema_v1.csv` | 397 | `SEED-CAND-000396` | `role_play_bypass` | `SRC-09_neuralchemy_prompt_injection_dataset` | 34 |
| `manual_review_seed_malicious_schema_v1.csv` | 216 | `SEED-CAND-000215` | `role_play_bypass` | `SRC-04_deepset_prompt_injections` | 34 |
| `manual_review_seed_malicious_schema_v1.csv` | 435 | `SEED-CAND-000434` | `role_play_bypass` | `SRC-04_deepset_prompt_injections` | 26 |
| `manual_review_seed_malicious_schema_v1.csv` | 141 | `SEED-CAND-000140` | `role_play_bypass` | `SRC-04_deepset_prompt_injections` | 26 |
| `manual_review_bypass_candidate_schema_v1.csv` | 11 | `SEED-CAND-000010` | `role_play_bypass` | `SRC-06_jailbreak_llms` | 50 |
| `manual_review_bypass_candidate_schema_v1.csv` | 91 | `SEED-CAND-000090` | `role_play_bypass` | `SRC-06_jailbreak_llms` | 45 |
| `manual_review_bypass_candidate_schema_v1.csv` | 151 | `SEED-CAND-000150` | `role_play_bypass` | `SRC-06_jailbreak_llms` | 45 |
| `manual_review_bypass_candidate_schema_v1.csv` | 136 | `SEED-CAND-000135` | `role_play_bypass` | `SRC-06_jailbreak_llms` | 45 |
| `manual_review_bypass_candidate_schema_v1.csv` | 29 | `SEED-CAND-000028` | `role_play_bypass` | `SRC-06_jailbreak_llms` | 45 |
| `manual_review_bypass_candidate_schema_v1.csv` | 39 | `SEED-CAND-000038` | `role_play_bypass` | `SRC-05_rogue_security_prompt_injections_benchmark` | 45 |
| `manual_review_bypass_candidate_schema_v1.csv` | 181 | `SEED-CAND-000180` | `role_play_bypass` | `SRC-05_rogue_security_prompt_injections_benchmark` | 42 |
| `manual_review_bypass_candidate_schema_v1.csv` | 74 | `SEED-CAND-000073` | `role_play_bypass` | `SRC-05_rogue_security_prompt_injections_benchmark` | 41 |
| `manual_review_bypass_candidate_schema_v1.csv` | 130 | `SEED-CAND-000129` | `role_play_bypass` | `SRC-05_rogue_security_prompt_injections_benchmark` | 39 |
| `manual_review_bypass_candidate_schema_v1.csv` | 223 | `SEED-CAND-000222` | `role_play_bypass` | `SRC-05_rogue_security_prompt_injections_benchmark` | 32 |