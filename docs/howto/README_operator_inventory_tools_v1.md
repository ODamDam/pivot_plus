# Operator Inventory Tools v1

이 패키지는 `llm-prompt-injection-diagnostic-benchmark` repo의 `src/operators`를 자동 점검하기 위한 보조 스크립트이다.

## 설치 위치

아래 파일을 repo 내부에 복사한다.

```text
scripts/inspect_operator_inventory_v1.py
```

## 실행

```powershell
cd C:\Users\2271086\Desktop\PIVOT\llm-prompt-injection-diagnostic-benchmark
python scripts\inspect_operator_inventory_v1.py
```

## 생성 산출물

```text
docs/operator_inventory_v1.csv
docs/operator_inventory_v1.md
docs/operator_policy_v2_draft.md
```

## 점검 내용

- OPERATOR_META 존재 여부
- apply 함수 존재 여부
- syntax error 여부
- operator family 추정
- input requirement 추정
- output format 추정
- strength_range
- semantic preservation 위험
- label change risk
- keep/modify/drop 후보 판단
