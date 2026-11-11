# OI-1 — 관측 인프라 보완 및 런타임 입력 인수

## 목적과 현재 상태

2026-11-10부터 관측 인프라 보완을 룰 정적 일반화와 **별도 마일스톤 OI-1**으로 관리하는 기록이다. 상태는 **계획 수립 완료 / 실환경 확인·구현 미착수**이다. 이 문서 작성은 수집기·네트워크·Pipeline 변경이나 배포를 수행한 결과가 아닌 것이다. GitHub milestone/issue 생성은 미수행이며 현재 추적 위치는 이 저장소의 문서이다.

M1은 정적 감사 완료 / 런타임 검증 대기, M2-1·M2-2·M2-3은 각 정적 초안/오프라인 검사와 실환경 인수를 분리한 상태이다. M1의 VERIFIED 데이터는 0개였으며 이번 M2-3에도 실측 증거를 추가하지 않은 상태이다. 합성 테스트 통과는 OI-1의 수집 성공 증거가 아닌 것이다.

범위의 근거는 [M1 관측 감사](M1_OBSERVABILITY_AUDIT.md), [M2-2 인프라 룰 분석](M2_2_INFRA_GENERALIZATION.md), [M2-3 메모리·네트워크 분석](M2_3_RESOURCE_GENERALIZATION.md)이다. 다음 단계의 인프라 작업은 아래 항목 ID와 완료 증거를 기준으로 진행할 계획이다.

## 경계와 판정 기준

M2는 기존 판단 조건의 대상/source 매핑·정적 코드·합성 검증을 담당하는 단계이다. OI-1은 실환경 조사, 필요한 수집 경로/identity/가용성 보완과 실제 데이터 인수를 담당하는 단계이다. M3는 확인된 입력을 사용하는 신규 탐지 설계를 담당하는 단계이다.

실행 PC/서비스 소유자·주소·접근 범위·수집 방식이 필요한 결정이며 임의로 생성 완료한 값은 없는 상태이다. exporter·Agent·PC 2 Docker API·HTTP probe가 이미 배포되었다고 가정하지 않는 마일스톤이다. 실제 구현/배포는 해당 OI 작업에서 다룰 범위이다.

추적 상태는 `TODO`(작업 미착수), `IN_PROGRESS`(근거 있는 진행), `BLOCKED`(필수 경로/접근 부재), `UNVERIFIED`(실환경 확인 전), `DONE`(완료 증거 충족)인 구분이다. 아래 항목의 상태는 현재 입력/경로의 판정이며 모든 항목의 구현은 미착수인 상태이다. 담당자는 모두 미정이며 사람·일정을 임의로 지정하지 않은 계획이다.

## 작업 목록

| ID | 우선순위 | 보완 작업 | 선행 항목 | 현재 상태·근거 | 완료 증거 |
|---|---|---|---|---|---|
| OI-01 | P0 | 실제 PC 1/PC 2 및 통합 환경의 target·이미지·서비스·관측점 인벤토리 확정이다. | 없음이다. | UNVERIFIED이다. 저장소 예시와 실제 배포를 아직 대조하지 못한 상태이다. | PC별 시각·대상·scrape job/instance·image digest·서비스/namespace·상태의 민감값 없는 기록이다. |
| OI-02 | P0 | PC 2 CPU/메모리/네트워크 exporter와 metadata의 수집 경로·scope·접근 범위 확보이다. | OI-01이다. | BLOCKED이다. 원격 [Prometheus](../../monitoring/prometheus/prometheus.aiops.yml)에 node/cAdvisor job이 없는 구성이다. | 실제 PC 2 counter/gauge 및 같은 Docker 범위의 metadata가 PC 1 저장소에 들어온 표본, id 대응·유일성·값 1·연속성 및 필요한 포트/Tailscale/ACL 적용 증거이다. |
| OI-03 | P0 | PC 2 재시작 상태 전달과 producer의 project/service 지원 범위 확정이다. | OI-01이다. | BLOCKED이다. [Pipeline](../../aiops/pipeline/main.py) 107–196행은 PC 1 로컬 Docker와 고정 project/service를 조회하는 구현이다. | 기대 name마다 RestartCount/StartedAt 표본이 실제 PC 2 상태와 일치하며 수집 실패와 대상 부재를 구분한 증거이다. 전달 방식은 별도 설계 결정인 것이다. |
| OI-04 | P0 | memory limit/working_set과 cAdvisor 네트워크 라벨·fallback 범위 인수이다. | OI-02이다. | UNVERIFIED이다. full-label 나눗셈·metadata join과 per-container name/id·root 범위가 미확인인 상태이다. | limit=0/무제한의 실제 표현, 공통 라벨·재생성 이력, 네트워크 name/interface/id 및 누락·staleness 상황별 fallback 결과의 기록이다. |
| OI-05 | P0 | DB 전체 연결·상한·거부 오류와 Hikari 풀 관측 계약 확보이다. | OI-01이다. | UNVERIFIED이다. 원격 exporter/Actuator 실대상과 정확한 계측명·라벨이 미확정인 상태이다. | 읽기 전용 DB 설정/상태와 exporter·Hikari active/idle/pending/max/acquire/timeout 이름·단위·scope를 대조한 증거이다. |
| OI-06 | P0 | 인증 성공/실패·원인·사용자 식별 계약과 원본 IP·Nginx 요청 필드 확보이다. | OI-01이다. | UNVERIFIED이다. NAT/신뢰 프록시·이벤트 schema와 request_length 등 공백이 남은 상태이다. | 민감값을 제외한 실제 키/결과 계약과 같은 출발지 연계의 근거이며 미수집 본문/WAF를 별도 구분한 기록이다. |
| OI-07 | P1 | MinIO 및 실제 HTTP 가용성 관측 방식 확정·구축이다. | OI-01이다. | BLOCKED이다. MinIO 전용 job·Blackbox/probe_success 경로가 없는 구성이다. | 실행 버전·인증/접근·관측점·허용 URL·성공 조건을 정하고, exporter scrape/HTTP 요청/Docker health를 구분하는 실측 증거이다. |
| OI-08 | P1 | 시간 동기화·수집 연속성·전송/파싱/버퍼 오류와 접근 통제 관측 보완이다. | OI-01이다. | UNVERIFIED이다. NTP·5초 표본·Fluent Bit/Fluentd 전달·소급 event time과 실제 ACL 적용이 미검증인 상태이다. | PC별 UTC/NTP/offset, 원본/수집 시각, 실제 표본 간격·공백·parse/truncation/전송 실패, 24224/24225 listener·인증·방화벽/ACL의 민감값 없는 적용 기록이다. |
| OI-09 | P0 | source를 보존하는 Pipeline identity/중복 제거·host 경보 처리 계약 확정이다. | OI-01 및 해당 수집 항목이다. | UNVERIFIED이다. 현재 AlertLabel은 추가 source 라벨을 보존하지 않고 dedup은 alertname/대상 이름 중심인 구현이다. | 여러 PC의 같은 name 구분, alias→올바른 service/scope 조회, root host 신호와 container 신호의 구분·처리 결과이다. 실제 구현이 필요하면 이 항목에서 다룰 범위이다. |

PC 2의 호스트 PostgreSQL 17은 컨테이너 memory/CPU·restart 룰의 대상과 다른 관측 대상이다. OS/VM/컨테이너 범위를 먼저 확정하고 필요한 수집 방식을 선택할 작업이다. PC 1 지표를 PC 2 값으로 대체하여 OI-02/OI-03을 완료 처리할 수 없는 기준이다.

OI-04에서 fallback 변경이 필요하다고 결정되면 기존 의미와 다른 정책으로 기록하고 별도 룰 변경/검증으로 다룰 항목이다. 이름 없는 컨테이너 시계열·loopback·감시 목록 밖의 시계열이 root fallback을 막는 원본 조건을 이번 M2-3에서 자동 수정하지 않은 상태이다.

OI-09의 구체적 근거는 [Pipeline AlertLabel](../../aiops/pipeline/main.py) 68–80행과 `analyze_alerts`의 annotation 선택·dedup(282–304행), [서비스 해석](../../aiops/pipeline/correlation.py)이다. `rulepack_source`를 alert에 붙이는 일만으로 Pipeline의 PC별 조회 범위를 일반화했다고 판정하지 않는 기준이다. root `id="/"`의 name이 있더라도 그것이 감시 앱 컨테이너 이름이라는 보장은 없는 상태이다.

## 진행 순서와 게이트

1. **OI-01 실환경 인벤토리**를 확보하는 단계이다. 주소/버전/관측점이 없는 항목은 추측으로 채우지 않는 기준이다.
2. OI-02/OI-03/OI-05/OI-06/OI-07/OI-08을 필요한 탐지 범위에 따라 각각 진행하는 단계이다. 한 경로의 미완료가 독립적인 다른 경로의 조사까지 막는 계획은 아닌 것이다.
3. OI-04의 metric/label 계약과 OI-09의 소비측 identity를 실데이터로 대조하는 단계이다.
4. 해당 입력을 쓰는 M2 초안의 실제 쿼리·Alertmanager·Pipeline 연동 인수를 수행하는 단계이다. 교체/reload/배포 결과는 실행한 OI 작업에 기록할 사항이다.
5. **공통 scope/time/identity와 해당 위협의 입력 인수**를 충족한 범위에서 M3 런타임 검증으로 넘어가는 단계이다. 모든 부가 가용성 기능의 구현을 기다려야만 다른 위협의 연구가 가능한 것은 아닌 것이다.

완료 게이트는 다음과 같다.

| 게이트 | 통과 조건 | 연결된 단계 |
|---|---|---|
| G1 관측점·입력 | 실제 target과 source/PC, metric/log 이름·키·라벨·단위·최신 표본·연속성의 증거이다. | M1 런타임 인수 및 해당 OI 항목이다. |
| G2 계산·분기 | id/full-label matching, name/alias, limit 처리, host fallback 범위와 정상·누락·오류의 구분이다. | M2의 해당 룰 런타임 인수이다. |
| G3 소비 경로 | Alertmanager/Pipeline에서 같은 source/대상을 유지하고 host 신호를 container로 오귀속하지 않는 증거이다. | 실제 분석 연동 인수이다. |
| G4 신규 탐지 입력 | 해당 위협에 필요한 데이터가 G1–G3 범위에서 실제 확보되었고 남은 공백을 명시한 결과이다. | M3의 해당 탐지 런타임 검증 진입 조건이다. |

## 증거·업데이트 형식

항목별로 다음 형식을 사용하여 이 목록을 갱신할 계획이다. 증거 경로는 필요 시 `docs/rulepack/evidence/OI-1/` 아래로 두는 계획이며 이번에는 실측 파일을 생성하지 않은 상태이다.

| 항목 | 기록 내용 |
|---|---|
| 항목 ID·담당·상태 | OI-xx, 실제 담당, 이전→현재 상태, 변경일인 기록이다. |
| 대상·관측점 | 통합/PC 1/PC 2, 서비스/컨테이너/호스트/VM, job/instance와 scope인 기록이다. |
| 시각·방법 | UTC/KST 조회 시각, 읽기 전용 명령/쿼리, 실제 확인 결과인 기록이다. |
| 증거 | 키/이름·관련 라벨·비민감 집계·실패 원인과 재현 가능한 조회인 기록이다. 인증정보·비밀번호·토큰·개인 식별값은 포함하지 않는 형식이다. |
| 완료 판단 | 조건별 VERIFIED/CONFIGURED/MISSING/UNVERIFIED와 충족한 게이트 및 남은 항목인 기록이다. |

`DONE`은 해당 완료 증거가 충족된 경우의 상태이다. 정적 설정만 있으면 CONFIGURED, 합성 테스트만 있으면 오프라인 PASS이며 실제 데이터 VERIFIED를 대신할 수 없는 기준이다. OI-1 전체 종료는 확정한 감시 범위의 필수 항목과 G1–G3 인수를 완료하고 남은 제외 범위를 명시한 시점이다.
