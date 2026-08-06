# Source Usage Decision v1

## 1. 문서 목적

본 문서는 prompt injection scanner 평가용 diagnostic benchmark를 구성하기 위해 수집한 source dataset들의 최종 사용 방침을 정의한다.

본 프로젝트의 최종 목표는 1,000개 규모의 diagnostic benchmark를 구성하고, 이를 통해 기존 LLM security scanner의 prompt injection 탐지 성능을 공격 유형, mutation family, 입력 형식별로 분석하는 것이다.

따라서 source dataset은 단순히 많이 수집하는 것이 아니라, 다음 기준에 따라 선별적으로 사용한다.

- prompt injection 평가 적합성
- 원본 label 신뢰도
- 공격 유형 분포 기여도
- benign / hard negative 확보 가능성
- structure-intact 및 indirect injection 지원 여부
- held-out test set으로 분리할 가치
- 중복 및 noise 위험

---

## 2. 전체 source 사용 원칙

### 2.1 raw label과 final label은 분리한다

원본 dataset의 label은 `original_label`로만 보존한다.

최종 실험에서 사용하는 label은 다음 필드에 별도로 기록한다.

- `normalized_label`
- `is_malicious`
- `attack_type`
- `ground_truth_decision`
- `keep_or_drop`
- `manual_review_status`

즉, 원본 label이 1이라고 해서 자동으로 prompt injection malicious sample로 확정하지 않는다.

### 2.2 diagnostic set과 held-out set은 parent seed 기준으로 분리한다

잘못된 방식은 다음과 같다.

```text
diagnostic에 들어간 seed를 변형해서 held-out에 포함
```

이 경우 held-out set이 독립 test set으로 기능하지 못한다.

올바른 방식은 다음과 같다.

```text
전체 seed candidate pool 구성
→ parent seed 단위로 diagnostic candidate와 held-out candidate를 먼저 분리
→ diagnostic seed에서만 diagnostic mutation 생성
→ held-out seed에서만 held-out mutation 생성
```

### 2.3 SRC-07은 일반 malicious seed와 분리한다

SRC-07은 repository file, code, config, README, CI/CD workflow, documentation 기반 prompt injection dataset이다.

따라서 일반 chatbot prompt 기반 malicious seed와 섞지 않고, `structure_intact_malicious` subset으로 별도 관리한다.

### 2.4 SRC-08은 diagnostic seed로 직접 사용하는 것을 최소화한다

Lakera PINT Benchmark는 prompt injection detector 평가를 목적으로 만들어진 benchmark 성격이 강하다.

따라서 최종 1,000개 diagnostic benchmark에 직접 섞기보다는, benchmark 설계 참고 또는 held-out/evaluator 검증 후보로 보관한다.

---

## 3. source별 최종 사용 결정

| source_id | dataset | use_decision | primary_role | target_usage | notes |
|---|---|---|---|---:|---|
| SRC-01 | Lakera Gandalf Ignore Instructions | use | malicious_seed | 50~60 | instruction_override, data_exfiltration 계열 seed로 사용한다. |
| SRC-02 | Lakera Mosscap Prompt Injection | limited_use | candidate_pool, heldout_candidate | 10~20 | noise가 많으므로 강한 필터링과 manual review 후 소량만 사용한다. |
| SRC-03 | SPML Chatbot Prompt Injection | use | malicious_seed, benign, context_eval | malicious 100~110 / benign 30~35 | prompt-only와 context-included 입력을 모두 생성한다. |
| SRC-04 | deepset/prompt-injections | limited_use | baseline malicious/benign | malicious 20~25 / benign 20~25 | sanity check 및 baseline source로 사용한다. |
| SRC-05 | rogue-security/prompt-injections-benchmark | limited_use | benign, hard_negative, bypass_candidate | malicious 10~15 / benign 20~30 | jailbreak label은 prompt injection으로 자동 확정하지 않는다. |
| SRC-06 | verazuo/jailbreak_llms / TrustAIRLab | limited_use | role_play_bypass, policy_bypass | 20~30 | 단순 harmful request는 제외하고 우회 구조가 명확한 샘플만 사용한다. |
| SRC-07 | prodnull/prompt-injection-repo-dataset | use | structure_intact, indirect_injection | malicious 120~150 / benign 20~30 | wrapper context를 붙여 scanner input을 구성한다. |
| SRC-08 | Lakera PINT Benchmark | holdout_or_reference | design_reference, heldout_candidate | diagnostic 직접 사용 최소화 | hard negative, multilingual, benchmark 설계 참고용으로 사용한다. |
| SRC-09 | neuralchemy/Prompt-injection-dataset | limited_use | additional_seed, benign, heldout_candidate | malicious 25~40 / benign 20~30 | augmented sample은 별도 표시하거나 제한한다. |

---

## 4. Diagnostic Benchmark v1 목표 구성

| subset | target_count | description |
|---|---:|---|
| malicious_seed | 250 | 원본 prompt injection 및 bypass seed |
| mutated_malicious | 500 | malicious seed 기반 mutation sample |
| structure_intact_malicious | 150 | JSON, YAML, Markdown, code, config, command, repo file 기반 구조형 공격 |
| benign | 100 | 정상 요청 및 hard negative |
| total | 1,000 | 기존 scanner 진단용 benchmark |

---

## 5. source별 역할 요약

### SRC-01 Gandalf

SRC-01은 malicious seed source로 사용한다.

공격 의도가 명확하고 prompt injection scanner 평가의 기본 seed로 적합하다. 다만 Gandalf challenge 기반이므로 instruction override 표현에 편향될 수 있다.

최종 사용량은 50~60개로 제한한다.

### SRC-02 Mosscap

SRC-02는 candidate pool 또는 held-out 후보로 제한 사용한다.

규모는 크지만 실제 prompt injection이 아닌 일반 prompt와 noise가 많이 섞일 수 있다. 자동으로 malicious seed로 사용하지 않고, 필터링과 manual review를 거친 샘플만 반영한다.

최종 diagnostic에는 10~20개 이하만 사용한다.

### SRC-03 SPML

SRC-03은 본 benchmark의 핵심 source 중 하나이다.

System Prompt와 User Prompt가 함께 있으므로, prompt-only 조건과 context-included 조건을 모두 구성할 수 있다. 이는 scanner가 application context를 제공받았을 때 탐지 성능이 달라지는지 분석하는 데 유용하다.

다만 `Prompt injection=1` label은 그대로 신뢰하지 않고 재라벨링한다.

### SRC-04 deepset

SRC-04는 baseline 및 sanity check source로 제한 사용한다.

규모는 작지만 `text`, `label` 구조가 단순하고 malicious/benign이 모두 포함되어 있어 pipeline 검증에 적합하다.

label 1 중 prompt injection으로 보기 어려운 단순 harmful request는 제외한다.

### SRC-05 rogue-security

SRC-05는 benign, hard negative, 일부 bypass 후보로 사용한다.

`jailbreak` label을 그대로 prompt injection malicious로 간주하지 않는다. role-play bypass 또는 policy bypass 구조가 명확한 샘플만 malicious seed 후보로 사용한다.

benign sample은 false positive 분석에 활용한다.

### SRC-06 verazuo / TrustAIRLab

SRC-06은 role-play bypass와 policy bypass 유형 보완용으로 제한 사용한다.

실제 커뮤니티 기반 jailbreak prompt를 포함하므로 자연스러운 우회 표현을 확보할 수 있다. 그러나 단순 harmful jailbreak와 prompt injection성 우회 공격은 구분해야 한다.

### SRC-07 prodnull

SRC-07은 structure-intact 및 indirect injection subset의 핵심 source이다.

일반 chatbot prompt seed에 섞지 않는다. repository file review 상황을 가정한 wrapper context를 붙여 scanner input을 구성한다.

### SRC-08 PINT

SRC-08은 직접 seed source가 아니라 benchmark 설계 참고 및 held-out 검증 후보로 둔다.

hard negative, multilingual 구성, detector evaluation category 설계를 참고한다.

### SRC-09 neuralchemy

SRC-09는 추가 malicious/benign 후보 및 held-out 후보로 제한 사용한다.

category, severity, tags, augmentation flag를 metadata로 보존한다. augmented sample은 원본 seed와 분리하거나 diagnostic seed에서 제한한다.

---

## 6. 최종 결정

본 프로젝트에서는 SRC-01, SRC-03, SRC-07을 핵심 source로 사용한다.

SRC-04, SRC-05, SRC-06, SRC-09는 분포 보완용으로 제한 사용한다.

SRC-02는 소량 사용 또는 held-out 후보로 둔다.

SRC-08은 최종 diagnostic benchmark에 직접 포함하기보다, benchmark 설계 참고 및 evaluator 검증용 held-out 후보로 관리한다.
