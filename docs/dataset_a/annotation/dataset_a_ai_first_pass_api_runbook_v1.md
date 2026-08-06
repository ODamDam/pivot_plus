# Dataset A AI 1차 판정 API 실행 절차 v1

이 절차는 저장소 최상위 경로에서 실행한다. 기본 모드는 dry-run이며 OpenAI API를 호출하지 않는다.

## 1. 요청 파일 생성

```powershell
python scripts/dataset_a/build_ai_first_pass_requests_v1.py
```

생성물:

- `data/dataset_a/adjudication/api_requests/ai_first_pass_smoke_200_requests_v1.jsonl`
- `reports/dataset_a/ai_first_pass_smoke_200_api_request_manifest_v1.json`

각 JSONL 행은 `custom_id`, `method`, `url`, `body`를 가진다. `body`는 Responses API의 `/v1/responses` 요청이며 strict Structured Outputs schema를 포함한다.

## 2. dry-run 응답 회수

```powershell
python scripts/dataset_a/run_ai_first_pass_responses_v1.py
```

이 명령은 모델 판정이 아닌 합성 응답을 생성한다. OpenAI SDK를 불러오거나 API 키를 확인하지 않으며 네트워크 요청을 보내지 않는다.

## 3. 응답 검증

```powershell
python scripts/dataset_a/validate_ai_first_pass_responses_v1.py
```

통과 조건:

- 요청·응답 각 200건
- `custom_id` 누락·중복·예상 외 ID 없음
- API 오류·refusal·불완전 응답 없음
- 출력 JSON 파싱 성공
- JSON Schema 준수
- 요청 `custom_id`와 출력 `candidate_id` 일치
- Dataset A 1차 판정 필드 간 기본 의미 제약 통과

dry-run parsed 결과는 파이프라인 검증용 합성 데이터이며 판정 또는 GT로 사용하지 않는다.

## 4. 실제 200건 호출 전 확인

다음을 먼저 확인한다.

1. dry-run validation report의 `passed`가 `true`이다.
2. request manifest의 모델·reasoning·prompt/schema hash를 검토했다.
3. `OPENAI_API_KEY`가 로컬 환경에 설정되어 있다. 키 값은 출력하거나 커밋하지 않는다.
4. 기존 live raw output 파일이 없다. 기존 실험 결과를 덮어쓰지 않는다.
5. 실제 호출과 비용 사용을 명시적으로 승인했다.

실제 실행 명령은 다음과 같다.

```powershell
python scripts/dataset_a/run_ai_first_pass_responses_v1.py `
  --execute `
  --confirm-record-count 200
```

중단 후 같은 출력에서 미완료 ID만 이어갈 때에만 `--resume`을 추가한다. 실패 응답은 원시 결과에 보존한다. 판정 내용이 마음에 들지 않는다는 이유로 재호출하지 않는다.

실제 응답 검증 시에는 live 파일 경로를 명시한다.

```powershell
python scripts/dataset_a/validate_ai_first_pass_responses_v1.py `
  --responses data/dataset_a/adjudication/api_responses/ai_first_pass_smoke_200_raw_v1.jsonl `
  --output data/dataset_a/adjudication/api_responses/ai_first_pass_smoke_200_parsed_v1.jsonl `
  --report reports/dataset_a/ai_first_pass_smoke_200_api_validation_v1.json
```

실제 raw·parsed 결과와 validation report는 이전 실행을 덮어쓰지 않도록 실행별 경로 또는 `run_id`를 부여해 보존한다.
