# Operator Assignment Policy v1.1

## 1. 변경 목적

v1.0의 `blocked_operator_families`에는 실제 family가 아닌 값이 함께 들어가 있었다.

- `destructive_format`: operator behavior trait
- `full_encoding`: mutation subtype/trait
- `roleplay_if_goal_shifted`: conditional rule
- `mutation_removing_secret_target`: validity rule

이 값들을 family alias로 정규화하면 `structural`, `encoding`처럼 허용된 family가 동시에 차단되는 충돌이 발생한다. v1.1은 선택 정책의 개념을 아래처럼 분리한다.

## 2. Seed-level assignment contract

| field | meaning |
| --- | --- |
| `allowed_operator_families` | 공격 유형에 허용된 broad operator family |
| `blocked_operator_ids` | 정확히 차단할 operator ID |
| `blocked_operator_traits` | `full_encoding`, `destructive_format` 등 operator 행동 특성 |
| `conditional_block_rules` | seed/context에 따라 적용하는 보존 규칙 |
| `input_format` | 정규화된 seed 입력 형식 |
| `requires_structure_preservation` | 구조 보존이 필수인지 여부 |
| `max_semantic_preservation_risk` | 허용 가능한 의미 보존 위험 상한 |
| `max_label_change_risk` | 허용 가능한 label 변경 위험 상한 |
| `target_evaluator_weaknesses` | mutation이 진단하려는 evaluator 취약점 |

## 3. Operator metadata contract extension

Registry v1.1에서 사용할 operator metadata 필드는 다음과 같다.

| field | meaning |
| --- | --- |
| `input_format_compat` | operator가 입력으로 받을 수 있는 seed format |
| `operator_traits` | 선택 차단에 사용할 행동 특성 태그 |
| `applicability` | 명백한 비적용 case를 selection 전에 제거하는 precheck 규칙 |
| `semantic_preservation_risk` | 의미 보존 위험도 |
| `label_change_risk` | 공격 label 변경 위험도 |

`applicability`가 지원하는 초기 필드는 다음과 같다.

- `requires_nonempty`
- `min_chars`
- `max_chars`
- `min_lines`
- `requires_json_object`
- `requires_any_terms`
- `forbids_any_terms`

## 4. Compatibility note

이 패치는 정책 데이터 모델만 변경한다. Registry가 새 필드를 실제 후보 filtering에 적용하기 전까지 구조 민감 smoke seed의 `mutation_budget=0` 보수 정책은 유지한다. 다음 단계에서 Registry v1.1 filtering을 연결한 뒤 이 임시 제한을 제거한다.
