# Current Documentation

검증 기준일: 2026-09-19. 상태: **구현 전 설계 기준선**.

이번 갱신은 ARCHITECTURE / DESIGN / TASKS / README 네 문서만 대상으로 한다. 실제 기능 구현, Docker 실행, 컨테이너 재시작, 시나리오 실행은 수행하지 않았다. TASK는 모두 미착수다.

## 사실과 설계의 기준

| 구분 | 기준 |
|---|---|
| As-Is 사실 판단 | 실제 source/configuration → 2026-09-18~19 Codex 정적 분석 → 현재 문서 → legacy 참고자료 |
| To-Be 구현 계약 | 이 디렉터리의 DESIGN과 TASKS. 현재 구현됐다는 뜻은 아님 |
| legacy_info_files | 역사적 참고자료. 현재 사실이나 설계의 근거로 우선하지 않음 |
| Runtime 검증 | 정적 분석과 별개. 실제 실행 결과를 확인한 뒤 완료 처리 |

문서와 코드가 다르면 현재 동작은 코드로 판정한다. 목표 동작은 DESIGN을 기준으로 구현하되 새로운 코드 근거가 발견되면 문서와 TASK를 함께 재검토한다. legacy 및 루트 문서는 이번 작업에서 보존한다.

## 읽기 순서

1. [ARCHITECTURE.md](./ARCHITECTURE.md): 실제 구성, As-Is 흐름, To-Be 경계, 런타임 미확인 사항.
2. [DESIGN.md](./DESIGN.md): D1~D8 설계 문제, 데이터 계약, 오류 처리, 완료 조건.
3. [TASKS.md](./TASKS.md): TASK-001~009, 의존성, 파일 범위, 검증과 rollback.

## 확정한 방향

- 기존 Grafana provisioning과 dashboard 두 개를 검증·보정한다. 신규 대시보드 시스템을 만들지 않는다.
- TUI는 시나리오 실행·실시간 검증·데모, Grafana는 metrics/log 관측·이력 분석을 담당한다.
- Docker 이름과 Loki 앱 로그 태그를 작은 명시적 mapping으로 분리한다.
- To-Be 분석 결과의 기준 저장소는 Loki다. TUI는 Pipeline의 단일 GET /results 계약을 사용한다. 현재 해당 route는 없다.
- 실행별 run_id, Alert 발생 건 occurrence_id, 분석 시도 result_id를 구분하고 실제 이벤트로 결과를 연결한다.
- detection / analysis / notification / remediation 성공을 각각 판정한다. Slack 전송을 operator acknowledgement라고 부르지 않는다.
- 기존 periodic coroutine에 ENABLE_PERIODIC_SCAN=false 기본 flag를 추가한다. 기본 webhook 경로와 독립적이다.
- Loki rules/fake/ 구조를 유지한다. 단일 tenant ID를 나타내며 임의 rename 대상이 아니다.

## 용어

| 용어 | 문서 전체에서의 의미 |
|---|---|
| log generation | 기대 로그가 생성·조회됨. Alert 발화 증거는 아님 |
| detection | 해당 detector의 Alert FIRING을 관측함 |
| analysis | 수집 데이터에 대한 LLM 분석. 권고는 실행 결과가 아님 |
| notification | Slack webhook 전송 결과. HTTP 200 및 본문 ok 확인 |
| acknowledgement | 운영자가 인지·승인·거부한 행위. notification과 별개이며 시간 지표는 범위 밖 |
| remediation | 실제 Docker 조치 또는 조치 보류 결정 |
| success / succeeded | 해당 단계의 명시적 완료 조건을 만족함. 전체 흐름 성공을 뜻하지 않음 |
| failure / failed | 해당 단계가 명시적으로 실패함 |
| skipped | 의도적으로 수행하지 않음. reason이 필요하며 성공·오류와 구분 |
| unknown | 결과를 확인하지 못함. failed 또는 succeeded로 추측하지 않음 |

상태 필드와 지표의 정확한 계약은 DESIGN의 공통 계약 및 D3~D5를 따른다. 과거 mtta_seconds는 새 지표와 합산하지 않는다.

## 구현 경계

현재 문서 편집만 허용된 상태다. TASK의 Test procedure는 **향후 해당 구현이 승인된 단계에서 수행할 절차**이며 이번 문서 작업에서 실행하지 않는다. 루트 README, source/configuration, legacy, 결과 로그는 변경하지 않는다. 구현 예상시간이나 실험 성공률을 정적 분석으로 추정하지 않는다.
