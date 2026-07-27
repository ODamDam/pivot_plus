# P0-1 Generation Pipeline Patch

## 목적

이 패치는 mutation 입력의 lineage를 Vulnerable LLM 응답까지 보존하고, scanner가 읽을 canonical staging file인 `vulnerable_llm/data/vuln_results.jsonl`을 `generated_case.v0.2` 형식으로 생성한다.

아직 `scanner_input`은 수정하지 않는다. 대신 다음 legacy alias를 임시로 함께 출력하므로 기존 scanner 실행을 깨뜨리지 않는다.

- `mutated_prompt`
- `model_output`
- `bucket_id`
- `triggers`

## 교체 파일

프로젝트 루트 기준으로 다음 파일을 교체한다.

```text
auto_runner.py
vulnerable_llm/app.py
vulnerable_llm/client.py
vulnerable_llm/schemas.py
```

선택적으로 schema 문서를 다음 위치에 둔다.

```text
schemas/generated_case_v0_2.schema.json
```

## 주요 변경점

1. `case_id`, `generation_id`, `testcase_id`, `mutation_id`, objective metadata를 API 요청과 서버 로그에 보존한다.
2. 서버가 `bucket_id`, `triggers`를 조용히 버리던 문제를 제거한다.
3. `auto_runner.py`가 API 응답 body를 받아 `vuln_results.jsonl`을 직접 생성한다.
4. 서버 오류가 난 line은 progress를 넘기지 않으므로 다음 실행에서 재시도된다.
5. 성공·실패 실행을 각각 원본 서버 로그와 `generation_failures.jsonl`에 기록한다.
6. 요청 temperature와 실제 적용 temperature를 구분하여 기록한다.
7. `app.py`의 누락된 `httpx` import를 수정한다.

## 적용 전 백업

```powershell
Copy-Item .\auto_runner.py .\auto_runner.py.bak
Copy-Item .\vulnerable_llm\app.py .\vulnerable_llm\app.py.bak
Copy-Item .\vulnerable_llm\client.py .\vulnerable_llm\client.py.bak
Copy-Item .\vulnerable_llm\schemas.py .\vulnerable_llm\schemas.py.bak
```

## clean pilot 주의사항

기존 `progress.json`이 같은 입력 파일을 이미 완료한 것으로 기록하고 있으면 다시 처리하지 않는다. 기존 결과를 보존한 후 1~3개 pilot을 새 파일명으로 넣는 방법을 권장한다.

완전히 새로 시험하려면 다음 파일을 먼저 백업한다.

```text
vulnerable_llm/data/progress.json
vulnerable_llm/data/vuln_results.jsonl
vulnerable_llm/data/generation_failures.jsonl
```

## 재시작

Docker Compose를 사용하는 경우:

```powershell
docker compose up -d --build vulnerable_llm
python auto_runner.py
```

컨테이너 내부에서 Ollama에 접근하려면 `.env`의 값이 일반적으로 다음과 같아야 한다.

```env
OLLAMA_BASE_URL=http://ollama:11434
```

## 확인해야 할 출력

`vulnerable_llm/data/vuln_results.jsonl`의 각 행에 다음 값이 있어야 한다.

```text
schema_version = generated_case.v0.2
case_id
generation_id
lineage.seed_id
attack.metadata_status
prompt
response
target_generation
execution_status = completed
```

기존 `execution_input.v0.1`에는 objective metadata가 없으므로 초기 결과의 다음 값은 정상이다.

```text
attack.metadata_status = objective_metadata_missing
```

이 값은 다음 단계에서 mutation/export schema에 objective metadata를 추가해 해결한다.
