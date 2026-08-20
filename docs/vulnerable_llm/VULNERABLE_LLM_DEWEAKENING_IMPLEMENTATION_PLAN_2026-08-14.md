# Vulnerable LLM De-weakening Implementation Plan

작성일: 2026-08-14

## 1. 현재 execution path

### `/generate`

`GenerateRequest` → `app.generate()` → `_context_to_text()` →
`vuln.build_vulnerable_messages()` → prompt/context를 system·user message로
조립 → `OllamaClient.chat()` → `POST {OLLAMA_BASE_URL}/api/chat` →
response 저장(`append_jsonl`) 및 `GenerateResponse` 반환.

현재 builder는 prompt를 trusted system instruction으로 한 번, user message로
두 번 넣으며 context도 system message로 승격한다.

### `/chat-generate`

`ChatGenerateRequest.messages` → `app.chat_generate()` →
`apply_generation_profile()` → vulnerable primer를 system 앞에 삽입하고
마지막 user message를 복제 → `OllamaClient.chat()` → Ollama `/api/chat` →
raw response/final messages/log metadata 저장.

## 2. 파일별 patch plan

| 파일 | 분류 | 변경 대상 | 현재 문제 | 변경 후 책임 |
|---|---|---|---|---|
| `vulnerable_llm/vuln.py` | REMOVE/REWRITE | `HIGH_YIELD_V1_SYSTEM_PRIMER`, `apply_generation_profile`, `build_vulnerable_messages` | vulnerable mode, never-refuse, bypass priority, prompt duplication, prompt의 system 승격 | 중립적인 application message builder와 exactly-one slot 검증 |
| `vulnerable_llm/Modelfile.txt` | REMOVE | SYSTEM weakening block 전체 | filters-off, never-refuse, prompt disclosure, bypass-priority | 정상 모델 설정만 유지; 모델 교체는 별도 결정 |
| `vulnerable_llm/app.py` | REWRITE | `generate`, `chat_generate`, message assembly 및 config 기록 | 두 endpoint가 서로 다른 취약화 경로를 사용하고 condition/control이 없음 | 공통 generation service 호출, 원본/최종 messages 분리 저장 |
| `vulnerable_llm/schemas.py` | REWRITE | `GenerateRequest`, `ChatGenerateRequest`, 새 generation contract | prompt/context 중심이며 scenario/trust boundary/condition이 불명확 | 명시적 trusted/untrusted input contract와 반복 실행 식별자 제공 |
| `vulnerable_llm/client.py` | KEEP/REWRITE | `OllamaClient` | Ollama transport와 application logic 경계가 없음 | provider-neutral protocol 뒤의 Ollama adapter로 한정 |
| `vulnerable_llm/config.py` | REWRITE | settings/provider/model/generation defaults | Ollama/model 값이 application path에 직접 결합 | provider config와 reproducibility config를 명시적으로 반환 |
| `vulnerable_llm/logging_utils.py` | KEEP | append/write helpers | artifact 보존 기능은 필요 | raw request, rendered messages, raw response, status를 lossless 저장 |
| `Dockerfile`, `requirements.txt` | KEEP/REVIEW | runtime/dependency declarations | transport 실행에 필요; 모델/환경 의존성 확인 필요 | 변경 시 provider adapter 테스트와 함께 검토 |
| `__init__.py` | KEEP | package marker | 문제 없음 | 유지 |

`vul-dolphin:latest`는 이번 patch에서 교체하지 않고 `REVIEW`로 남긴다.
application-level de-weakening 효과와 model-level behavior를 분리하기 위함이다.

## 3. New generation input contract

애플리케이션 내부 canonical contract:

```json
{
  "case_id": "...",
  "scenario_id": "...",
  "condition": "control|attack",
  "trusted_instruction": "...",
  "normal_task": "...",
  "trusted_context": "...",
  "untrusted_input": "...",
  "untrusted_input_role": "...",
  "injection_location": "...",
  "attack_method": null,
  "attack_method_variant": null,
  "seed_original": "...",
  "attack_rendered": "...",
  "generation_config": {
    "provider": "ollama",
    "model": "vul-dolphin:latest",
    "temperature": 0.0,
    "max_tokens": 512
  },
  "run_id": "...",
  "repetition_index": 0
}
```

`trusted_instruction`, `normal_task`, `trusted_context`는 application-owned
입력이고 `untrusted_input`은 지정된 하나의 data slot이다. `attack_rendered`는
원 seed와 별도이며, Dataset A 원문을 overwrite하지 않는다.

## 4. Required invariants

- 최종 model input에서 `untrusted_input`은 정확히 한 번만 포함한다.
- untrusted input을 system instruction 또는 trusted authority로 승격하지 않는다.
- system/context/user 어느 위치에도 attack prompt를 중복 삽입하지 않는다.
- never-refuse, filters-off, bypass-priority, prompt-disclosure 등 취약화 지시를 넣지 않는다.
- normal task와 untrusted content의 역할을 구조적으로 분리한다.
- raw model response를 변환 전 그대로 보존한다.
- provider, model, model version, generation parameters, run/condition/repetition metadata를 보존한다.

## 5. Provider adapter boundary

목표 경계:

`Application prompt builder → ProviderAdapter.generate(messages, generation_config) → OllamaAdapter → Ollama /api/chat`

`OllamaClient`의 HTTP payload/response parsing은 adapter 내부에 남긴다.
application builder가 URL, Ollama response shape, backend-specific 옵션을
알지 않도록 한다. 이번 단계에서는 Ollama transport를 제거하지 않는다.

## 6. Implementation sequence

1. **Contract/schema**: 새 request/plan 모델과 `condition`, `repetition_index`,
   scenario/trust fields를 추가한다.
2. **Neutral builder**: normal task와 trusted context를 구성하고
   untrusted slot을 한 번만 렌더링하는 순수 함수를 작성한다.
3. **Remove weakening**: vulnerable primer, high-yield profile, duplicated user
   message, prompt-as-system insertion을 제거한다.
4. **Service unification**: `/generate`와 `/chat-generate`가 동일한 application
   generation service를 사용하도록 한다. 기존 API compatibility는 adapter로
   명시적으로 유지하거나 deprecation한다.
5. **Provider interface**: `ProviderAdapter` protocol과 `OllamaAdapter`를
   분리한다. transport 자체는 변경하지 않는다.
6. **Artifact schema**: rendered messages, hashes, raw response, status,
   reproducibility metadata를 별도 필드로 저장한다.
7. **Control/repetition runner**: 동일 scenario/config에서 control과 attack,
   repetition N을 실행 계획으로 표현한다.
8. **Deterministic mock smoke**: 네트워크 없는 mock provider로 invariant를
   검증한 뒤에만 실제 provider 실행을 별도 승인한다.

## 7. Smoke-test acceptance criteria

공격 성공률은 합격 기준이 아니다. smoke는 다음을 검증한다.

- 정상 task가 clean control에서 수행된다.
- control/attack 모두 untrusted insertion이 정확히 1회다.
- prompt duplication이 없다.
- 최종 messages에 vulnerability primer가 없다.
- raw response와 request/config metadata가 저장된다.
- benign content, explicit PI, natural-language task redirection,
  representation-only code/config/document가 모두 입력 가능하다.
- refusal, partial boundary violation, execution failure를 구분 기록한다.

## 8. Regression risks

- 기존 `/generate` 호출자의 schema/API 호환성 손상
- prompt duplication 제거로 response distribution 변화
- Ollama model의 기존 Modelfile 의존성
- context와 untrusted slot 순서/role 변경
- 로그 schema 변경에 따른 downstream parser 실패
- control과 attack의 generation config drift
- 모델명은 유지해도 model-level refusal/behavior 차이가 결과에 영향

## 9. Minimum tests after implementation

- builder unit test: 각 field의 role/순서와 exactly-one count
- invariant test: system 승격·중복·primer 문자열 부재
- schema test: control/attack/repetition/provider metadata
- mock provider integration test: raw response 및 failure logging
- `/generate`, `/chat-generate` compatibility test
- Ollama adapter payload/response parsing fixture test(네트워크 없음)
- control-vs-attack same-config equality test
- 20-case smoke fixture: benign, explicit PI, task redirection,
  representation-only, output/workflow cases
- artifact hash/order/sample ID integrity test

이번 문서는 계획만 기록하며 코드, Dataset A, Ollama, Target LLM, scanner는
수정·실행하지 않는다.
