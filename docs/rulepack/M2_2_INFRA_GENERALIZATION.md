# M2-2 — CPU·컨테이너 재시작 룰 일반화 및 가용성 관측 공백

## 1. Executive Summary

작업일은 **2026-11-10(KST)**이며 기준 커밋은 M1과 같은 `main`의 `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`이다. 시작 시 `main...origin/main`, tracked 변경 0개, `docs/rulepack/`·`tools/rulepack/`의 M1/M2-1 결과가 untracked인 상태를 확인한 것이다. 이 미커밋 파일을 삭제·초기화·덮어쓰지 않은 작업이다.

**M2-2는 적용 가능한 메트릭 계약 안에서 정적 구현·오프라인 검증 완료인 상태이다. 실제 측정 PC의 런타임 검증은 UNVERIFIED이며 원격 PC 2 수집 경로는 BLOCKED인 상태이다.** M1은 정적 감사 완료 / 런타임 검증 대기, M2-1은 정적 일반화 완료 / 런타임 인수 대기인 기존 상태이다.

| 룰 | 원본 데이터 | 일반화 대상 | 변경 전후 의미 | 정적 테스트 | 런타임 검증 |
|---|---|---|---|---|---|
| `HighCpuUsage` | cAdvisor `container_cpu_usage_seconds_total`, Pipeline `container_name_info`이다. | 명시한 source의 job/instance 쌍과 컨테이너 name인 대상이다. | `irate[30s]`, `/docker/` id, `cpu="total"`, `on(id) group_left(name)`, `sum by(name)`, `> 0.5`, `for: 30s` 유지이며 고정 name 목록을 매핑으로 분리한 결과이다. | PASS이다. | UNVERIFIED이며 원격 경로는 BLOCKED이다. |
| `ContainerRestarted` | Pipeline의 `aiops_docker_container_restarts_total`·`aiops_docker_container_started_at_seconds`이다. | 명시한 Pipeline job/instance와 여러 name인 대상이다. | counter 증분/reset 분기와 StartedAt 변경 분기를 유지한 결과이다. 10분 창·5초 offset/step·`>= 2`·`for: 0m`·`keep_firing_for: 2m` 유지인 구조이다. | PASS이다. | UNVERIFIED이며 PC 2 상태 전달은 BLOCKED이다. |
| 서비스 가용성 | 기존 scrape 구성, Nginx 오류 로그, Docker 로컬 상태 관련 지표이다. | 이번에는 지원 범위와 누락만 조사한 대상이다. | 전용 가용성 룰을 발견하지 못한 결과이며 신규 가용성 룰은 생성하지 않은 상태이다. | 정적 조사 PASS이다. | HTTP/MinIO/Blackbox 관측은 BLOCKED 또는 UNVERIFIED이다. |

기본 초안은 **CPU 4개 대상 + 재시작 1개 대상 = 5개 정의**이다. 같은 alert 이름을 대상별 `rulepack_target` 라벨로 구분하는 구조이다. 원본의 기본 감시 대상 집합을 유지한 것이며 재시작 대상을 임의로 4개 전체로 확대하지 않은 기본값이다. 다른 대상의 추가는 매핑과 실제 입력 계약을 함께 확인할 작업이다.

## 2. M2-1과의 관계 및 변경 범위

### 2.1 선행 자료와 보존

[M1 감사](M1_OBSERVABILITY_AUDIT.md), [M2-1 기록](M2_STATIC_GENERALIZATION.md), [M2-1 생성기](../../tools/rulepack/generate_m2.py), [M2-1 테스트](../../tools/rulepack/tests/test_generate_m2.py), [M2-1 매핑](m2/targets.yml)과 생성 결과를 읽고 현재 코드와 대조한 작업이다. 보고된 메트릭 계약·로컬 socket 범위·고정 project/service와 실제 코드 사이에 변경 사항은 발견하지 못한 결과이다.

작업 시작에 M1/M2-1 파일 7개와 운영 룰·Prometheus 설정·Pipeline/correlation·Compose 7개, **총 14개 파일의 SHA256을 기록**한 상태이다. 종료 검사에서 14개 모두 같은 해시임을 확인한 결과이다. 기존 M1/M2-1 결과를 수정하여 이번 작업에 편입하지 않은 것이다.

별도 생성기 도입 이유는 M2-1의 웹/DB selector 계약과 CPU의 두 수집원 조인·재시작의 Pipeline 계약이 다른 데에 있는 것이다. 기존 생성기의 허용 라벨·입력 스키마·생성 파일을 변경하지 않고 독립적으로 검증하려는 작은 별도 도구인 것이다. M2-1 생성기를 import하거나 변경하는 구조는 아닌 것이다.

### 2.2 신규 결과물 5개

| 파일 | 역할 |
|---|---|
| [generate_m2_2.py](../../tools/rulepack/generate_m2_2.py) | 원본 CPU/재시작 정의를 복사하여 selector·대상 annotation을 바꾸는 독립 생성기이다. |
| [test_generate_m2_2.py](../../tools/rulepack/tests/test_generate_m2_2.py) | 스키마·조건 보존·입력 불변·합성 시계열·원본 비교·조인 오류 검증인 테스트이다. |
| [infra_targets.yml](m2/infra_targets.yml) | 실제 통합 설정에 근거한 명시적 source/target 매핑이며 실행 결과는 UNVERIFIED인 파일이다. |
| [prometheus.infra.rules.yml](m2/generated/prometheus.infra.rules.yml) | 배포 경로 밖의 CPU 4개·재시작 1개 초안이다. |
| [이 보고서](M2_2_INFRA_GENERALIZATION.md) | 지원 범위·의미 차이·테스트·원격 관측 공백의 기록이다. |

운영 `monitoring/prometheus/rules/alert.rules.yml`, M2-1 파일, `HighMemoryUsage`, `HighNetworkReceive`, 수집 코드/Compose를 변경하지 않은 작업이다. 컨테이너 실행·재시작·재생성, 룰 reload, 새로운 exporter/Agent 배포, DB/네트워크 설정 변경, commit/push/PR 생성은 미수행인 상태이다. 시나리오·주입 강도·Heldout은 분석하지 않은 작업이다.

## 3. HighCpuUsage 기존 구조와 일반화 결과

### 3.1 원식과 입력 계약

원본 근거는 [alert.rules.yml](../../monitoring/prometheus/rules/alert.rules.yml) 15–29행이다. 원식은 다음과 같다.

```promql
sum by (name) (
  irate(container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total"}[30s])
  * on(id) group_left(name) container_name_info
) > 0.5
and on(name)
container_name_info{name=~"leafy-frontend|leafy-backend|leafy-db|leafy-minio"}
```

`container_name_info`는 [Pipeline main.py](../../aiops/pipeline/main.py) 205–242행에서 로컬 Docker의 **실행 중 컨테이너**를 조회하여 `id="/docker/<full Docker id>"`, `name`, `service`, 값 `1`로 생성하는 메트릭이다. `service`는 이름 prefix/접미사 가공값이며 이번 CPU 조인의 필수 입력은 아닌 것이다. cAdvisor 쪽에 `service`, `role`, `site`가 존재한다고 가정하지 않은 일반화이다.

| 의존성·질문 | 분석 결과 |
|---|---|
| 환경별 cAdvisor id 형식 | `/docker/.+`와 다른 cgroup 경로만 있으면 필터에서 제외되는 구조이다. 이번 초안도 이 조건을 유지하여 임의로 다른 id를 지원한다고 판정하지 않은 것이다. |
| `cpu="total"` | 해당 시계열이 없고 CPU별 라벨만 있으면 현재 식은 비는 구조이다. 임의로 CPU별 합계를 대체하지 않은 상태이다. |
| 두 메트릭의 id 불일치 | 산술 vector matching에서 대응 시계열이 빠져 결과가 없는 구조이다. 정상 CPU 0과 다른 상태이다. |
| 우변 metadata id 중복 | 선택한 source 안에서 id별 우변이 유일하지 않으면 join 평가 오류인 구조이다. 단순히 name을 미리 잘라 중복을 숨기지 않은 초안이다. |
| 호스트 PostgreSQL 17 | Docker 컨테이너가 아니므로 이 CPU 룰의 지원 대상이 아닌 것이다. 통합 매핑의 `leafy-db`는 PG16 컨테이너를 가리키는 값이다. |
| PC 1의 cAdvisor | PC 1 Docker/VM 자원이며 PC 2 Leafy 자원으로 해석할 수 없는 관측점이다. |
| CPU 사용량의 의미 | CPU 누적 사용 초 counter의 최근 두 표본 증가율을 30초 범위에서 계산한 초/초 값이다. `0.5`는 약 0.5 CPU core 상당이며 전체 멀티코어 호스트의 50%로 정규화한 값은 아닌 것이다. |

원본 summary의 “50%” 표현은 그대로 보존한 값이다. 위 단위를 명시하여 해석을 보완하였으며 코어/quota 정규화나 임계값 변경은 수행하지 않은 작업이다. 조인의 필터링·그룹 수정자는 [Prometheus 공식 연산자 문서](https://prometheus.io/docs/prometheus/latest/querying/operators/#vector-matching), `irate` 의미는 [공식 함수 문서](https://prometheus.io/docs/prometheus/latest/querying/functions/#irate)로 대조한 사항이다.

### 3.2 일반화 결과

CPU source와 metadata source에 각각 실제 scrape 구성에 근거한 `job`·`instance`를 붙이고 마지막 membership 조건의 고정 name 정규식을 target의 정확한 name으로 교체한 구조이다. Backend 예시는 다음과 같다.

```promql
sum by (name) (
  irate(container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total", instance="cadvisor:8080", job="cadvisor"}[30s])
  * on(id) group_left(name) container_name_info{instance="pipeline:8000", job="pipeline-metadata"}
) > 0.5 and on(name)
container_name_info{instance="pipeline:8000", job="pipeline-metadata", name="leafy-backend"}
```

`sum by(name)`과 `on(id)`·`and on(name)`을 보존한 것이며 `on(service)` 같은 미확인 조인으로 바꾸지 않은 결과이다. source별 집계를 별도 룰로 생성하므로 서로 다른 source의 동명 컨테이너가 하나의 합계에 들어가지 않는 구조이다. CPU 입력·metadata 모두 없으면 경보 평가 결과가 비는 원래 의미를 유지하는 구조이며 0을 생성하지 않는 것이다.

조인 우변은 **source 전체 metadata**를 유지한 구조이다. 조인 전 target name으로 줄이면 같은 id를 가진 다른 name의 metadata 중복을 숨길 수 있으므로, 최종 name 필터만 대상별로 분리한 것이다. 런타임에서는 metadata id 유일성과 gauge 값 `1`을 확인해야 하는 계약이다.

원격 PC 2 cAdvisor/Pipeline metadata 전달 경로와 다른 cgroup id 형식의 정규화는 해결하지 않은 상태이다. 대상 이름을 바꿔 생성하는 기능과 실제 입력을 생산하는 기능은 구분한 결과이다.

## 4. ContainerRestarted 기존 구조와 일반화 결과

### 4.1 원식

원본 근거는 [alert.rules.yml](../../monitoring/prometheus/rules/alert.rules.yml) 78–106행이다.

```promql
max by (name) (
  sum_over_time(
    (
      (
        last_over_time(aiops_docker_container_restarts_total{name="leafy-backend"}[10m])
        - last_over_time(aiops_docker_container_restarts_total{name="leafy-backend"}[10m] offset 5s)
      ) >= 0
      or
      (
        last_over_time(aiops_docker_container_restarts_total{name="leafy-backend"}[10m])
        < last_over_time(aiops_docker_container_restarts_total{name="leafy-backend"}[10m] offset 5s)
      ) + 0
    )[10m:5s]
  )
) >= 2
or
max by (name) (
  changes(aiops_docker_container_started_at_seconds{name="leafy-backend"}[10m])
) >= 2
```

### 4.2 생성 위치와 수집 한계

생성 위치는 [Pipeline main.py](../../aiops/pipeline/main.py) 107–196행이며 `/metrics`에 포함하는 위치는 205–242행이다. Docker endpoint는 같은 파일 22행의 `/var/run/docker.sock`이다. 통합 [Compose](../../docker-compose.yml) 371–400행과 원격 [Compose](../../docker-compose.aiops.yml) 146–175행 모두 Pipeline에 **각 PC의 로컬 socket**을 mount하는 구성이다.

| 항목 | 실제 코드의 의미 |
|---|---|
| 감시 project | `_RESTART_WATCH_PROJECT="graduation-project"` 고정이며 메트릭 생성 단계의 제약이다. |
| 감시 service | `frontend`, `backend`, `db`, `minio` 고정 목록이며 Compose service 라벨로 필터링하는 구조이다. |
| 조회 범위 | `all=true`로 중지 컨테이너도 포함하여 inspect하는 구조이다. CPU용 `container_name_info`가 실행 중 대상만 조회하는 것과 다른 범위이다. |
| restart counter | `RestartCount`의 정수를 `aiops_docker_container_restarts_total{name,service}`로 노출하는 구조이다. restart policy에 의한 재시작 수이며 수동 재시작 전체를 세는 값은 아닌 것이다. |
| 시작 시각 | Docker `State.StartedAt`을 epoch 초로 파싱하여 `aiops_docker_container_started_at_seconds{name,service}`로 노출하는 구조이다. 매 시작 때 바뀌는 최근 시작 시각이지 이벤트 목록이 아닌 값이다. |
| 미시작/시각 파싱 실패 | StartedAt이 zero time이거나 파싱되지 않으면 해당 시작 시각 표본을 생략하는 구조이다. 이 경우에도 inspect가 성공했다면 success 1일 수 있는 것이다. |
| 재생성 | 같은 name/service이면 id 변경을 새 라벨로 추가하지 않는 구조이며 counter가 reset되고 StartedAt이 바뀔 수 있는 것이다. name 또는 service까지 바뀌면 새 시계열일 수 있는 구조이다. |
| 일부 inspect 실패 | 해당 대상은 생략하고 성공한 대상의 표본을 유지하며 `aiops_docker_status_scrape_success=0`인 결과이다. |
| 조회 전체 실패/timeout | 부분 결과도 버리고 재시작/시작 시각 값 없이 success 0을 반환하는 구조이다. 잘못된 0으로 채우지 않는 구현이다. |
| 대상 0개 | Docker 조회 자체가 성공하면 success 1도 가능한 구조이다. 기대 name의 메트릭 존재를 따로 확인해야 하는 상태이다. |
| PC 2 | PC 1 socket 조회만으로 PC 2의 이름/상태를 얻지 못하는 구조이다. `TARGET_SERVICE_MAP`은 annotation→service 해석이며 원격 inspect 기능이 아닌 것이다. |

원본 counter 분기는 5초 전 `last_over_time`과 비교한 음이 아닌 증가분을 합산하는 구조이다. reset처럼 현재 값이 작아지면 비교 연산의 bool이 아닌 **현재 counter 값**을 사용하여 새 컨테이너의 증가분을 처리하는 원식이다. 최초 표본처럼 이전 값이 없으면 초기 counter 값 전체를 새 이벤트로 세지 않는 구조이다. `increase()`로 단순화하지 않은 결과이다.

StartedAt 분기는 10분 내 값의 변경 횟수를 별도로 비교하는 구조이다. 두 분기를 `or`로 결합하여 한 자동 재시작의 counter/StartedAt을 더해 두 번으로 세지 않는 의미를 유지한 것이다. 비교 연산의 값 보존은 [공식 연산자 문서](https://prometheus.io/docs/prometheus/latest/querying/operators/#comparison-binary-operators)에 근거하는 사항이다.

### 4.3 일반화 결과와 미해결 범위

생성기는 원식의 restart counter selector 4곳과 StartedAt selector 1곳을 같은 source의 job/instance 및 target name으로 교체하는 구현이다. 분기·함수·계산 순서·10분 창·5초 offset/step·두 `>= 2`·`for: 0m`·`keep_firing_for: 2m`는 그대로인 결과이다. severity `critical`, category `infra`도 원본 유지인 값이다.

기본 target은 원래와 같이 Backend 1개이다. 다른 컨테이너를 `rules: [restart]` 또는 `[cpu, restart]`로 명시하면 대상별 같은 판단식을 생성할 수 있는 것이다. **생성 가능과 현재 producer 지원은 다른 조건**이다. 다른 Compose project나 고정 service 목록 밖의 대상은 현재 Pipeline이 재시작 메트릭을 생성하지 않으므로 매핑만 추가하여 지원할 수 없는 상태이다. 이번 작업에서는 producer를 수정하지 않은 것이다.

동일 name 재생성의 counter reset, 수동 시작, 짧은 수집 공백은 원식의 처리 범위이다. name 변경은 새 시계열/새 매핑이며 이전 이름의 이력을 자동으로 이어받지 않는 구조이다. recreate 직후 첫 scrape 전 증가, 5초 안의 다중 시작, 10분 이상 수집 공백, 같은 name의 service 변경 등에서는 정확한 횟수를 보장하지 못하는 한계가 유지된 상태이다. `keep_firing_for`와 과거 `last_over_time` 때문에 현재 표본이 사라져도 이전 경보가 유지될 수 있으므로 이를 최신 상태 수집 성공으로 해석하지 않는 것이다.

## 5. 가용성 탐지의 현재 지원 범위

### 5.1 실제 저장소 조사 결과

운영 [Prometheus 룰](../../monitoring/prometheus/rules/alert.rules.yml)의 6개 alert에는 `up` 비교, `absent(up)`, `probe_success` 또는 일반 ServiceDown 룰이 없는 결과이다. 이번 초안에도 가용성 룰을 추가하지 않은 상태이다.

| 항목 | 통합 환경 | 원격 2대 환경 | 의미·관측 공백 |
|---|---|---|---|
| Frontend/Nginx | `nginx-exporter:9113` scrape와 `frontend:8081/stub_status`인 구성이다. | nginx-exporter file_sd 자리만 있고 실제 대상 파일/배치는 미검증인 상태이다. | exporter scrape 성공은 실제 사용자 요청/API 성공의 증거가 아닌 것이다. exporter 자체의 Nginx 수집 성공 지표 이름도 실측 확인 대상이다. |
| Backend | `backend:9090/actuator/prometheus`, job `leafy-backend`인 구성이다. | 같은 경로의 file_sd 자리인 구성이다. | 관리 포트의 scrape와 앱 포트/인증/DB 의존 요청의 성공은 다른 사실이다. |
| MinIO | 전용 scrape job이 없는 상태이다. Docker `mc ready local` healthcheck는 있는 구성이다. | 전용 job이 없는 구성이다. | healthcheck를 Prometheus 상태로 내보내는 코드도 없는 상태이다. 지속적인 외부 접근/업로드 기능 가용성은 미지원 범위이다. |
| Blackbox | exporter 서비스/job과 `probe_success` 입력 경로가 없는 상태이다. | 동일하게 없는 상태이다. | 실제 HTTP 요청 성공을 외부 관측점에서 지속 측정할 수 없는 구성이다. |
| Docker healthcheck | DB·MinIO·Fluentd에 존재하며 frontend/backend에는 없는 구성이다. | PC 1 Fluentd에는 통합과 같은 healthcheck가 없는 차이이며 PC 2 실제 앱 Compose는 미확보인 상태이다. | Docker의 Health 상태를 export하는 구현이 없으므로 Prometheus 가용성 지표로 사용할 수 없다고 판정한 것이다. |
| Docker 상태 관련 메트릭 | restart/StartedAt/OOMKilled 및 실행 중 service count가 있는 구현이다. | PC 1 로컬 Docker 범위의 구현이다. | 최근 시작/재시작·마지막 OOM 상태·로컬 개수이며 앱 기능 성공이나 PC 2 상태를 보장하지 않는 데이터이다. |

근거는 [통합 Prometheus](../../monitoring/prometheus/prometheus.yml) 13–42행, [원격 Prometheus](../../monitoring/prometheus/prometheus.aiops.yml) 24–47행, [stub_status](../../leafy/frontend/stub_status.conf), [통합 Compose](../../docker-compose.yml)의 healthcheck 블록과 [Pipeline /metrics](../../aiops/pipeline/main.py) 130–242행이다. 통합/원격의 전역 scrape/evaluation은 5초 설정이며 실제 표본 연속성과 timeout은 실측 대상이다.

### 5.2 네 가지 상태의 구분

| 상태 | 현재 확인할 수 있는 사실 | 보장하지 않는 사실 |
|---|---|---|
| `up == 0` | 등록된 target의 해당 scrape 실패인 사실이다. | 앱 HTTP 장애의 원인/전체 기능 실패가 확정된 것은 아닌 것이다. |
| target 미등록 | targets/API 또는 기대 job/instance 목록과 대조할 대상 부재인 상태이다. | `up=0` 시계열이 반드시 생성되는 상태는 아닌 것이다. |
| HTTP 가용성 | 실제 요청 경로·관측점·응답/본문 성공 조건이 필요한 사실이다. | exporter나 Actuator scrape 성공으로 대체할 수 없는 사실이다. |
| 컨테이너 상태 | Docker process/시작·종료/health 관련 상태인 사실이다. | 프로세스가 running이라고 HTTP·DB·스토리지 기능까지 정상이라는 뜻은 아닌 것이다. |

### 5.3 감지 가능한 장애와 미지원 장애

현재 구성의 정적 지원 범위는 Backend 반복 재시작, 컨테이너 CPU/메모리 이상, Nginx 5xx 증가와 DB 연결 증가 등 **각 룰의 입력이 실제로 들어온 경우의 증상**이다. `up`은 scrape 설정으로 생성 가능한 상태 정보이나 이를 자동 경보하는 기존 룰은 없는 상태이다. 수동 targets/`up` 조회와 자동 장애 탐지는 구분한 결과이다.

Nginx/앱이 완전히 멈추어 로그가 안 생기는 상황, 무트래픽 중 장애, exporter는 살아 있으나 앱이 실패하는 상황, MinIO 외부 기능 실패, PC 2 target 미등록/상태 전송 중단은 현재 룰로 지속 판별한다고 보장할 수 없는 범위이다. HighNginxErrorRate는 요청이 있어야 하는 5xx 건수 신호이며 서비스 가용성 전체를 검사하는 룰은 아닌 것이다.

MinIO 수집을 추가하려면 실제 실행 버전의 metrics/health API·인증·접근 범위·PC 위치·metric family를 먼저 확인하고 metrics scrape와 업로드 기능 확인을 구분할 선행 조건이다. Blackbox를 추가하려면 관측점, 허용된 URL, DNS/Tailscale/라우팅, HTTP 성공 조건·인증정보 처리·라벨 귀속과 probe 부하를 확정할 선행 조건이다. `probe_success`는 그때 실제 수집을 확인할 후보이며 현재 존재하는 입력이 아닌 것이다. 수집/권한/배포는 별도 인프라 작업, 실제 입력 기반 가용성 룰 설계는 M3 이관 대상이다.

## 6. 생성 파일 및 대상 매핑 계약

### 6.1 스키마

[infra_targets.yml](m2/infra_targets.yml)의 source는 수집 경로를 생성하는 설정이 아니라 **이미 존재한다고 확인해야 하는 scrape 쌍을 선택하는 매핑**이다. 기본 source는 통합 환경 하나이며 원격 source를 가짜로 추가하지 않은 상태이다.

```yaml
version: 1
sources:
  integrated:
    cadvisor:
      job: cadvisor
      instance: cadvisor:8080
    pipeline:
      job: pipeline-metadata
      instance: pipeline:8000
targets:
  - id: leafy-backend
    source: integrated
    name: leafy-backend
    alert_target: leafy-backend
    rules: [cpu, restart]
```

전체 기본 파일에는 CPU 대상 frontend/backend/db/minio 4개가 있는 구성이다. `sources.*.pipeline`은 필수이고 `cadvisor`는 CPU 대상이 있을 때만 필수인 구조이다. selector는 `job`, `instance` 두 키의 정확한 동등 비교만 허용하며 `service`, `role`, `site`를 임의로 요구하지 않는 구조이다. 기본 job/주소 근거는 통합 scrape 설정이며 실제 endpoint는 UNVERIFIED이다.

`targets[].name`은 메트릭의 실제 컨테이너 name, `alert_target`은 Pipeline이 `annotations.container`로 읽는 분석 대상 이름 또는 명시적 alias이다. alias는 실제 로컬 Docker 또는 기존 `TARGET_SERVICE_MAP`과 맞아야 하는 별도 런타임 계약이다. `id`는 생성한 alert에 붙이는 `rulepack_target` 고정 라벨이며 collector가 수집한 사실로 간주하지 않는 값이다.

### 6.2 거부 조건과 적용 경계

source id·target id/name/alias 형식 오류, 알려지지 않은 source/rule, source의 job/instance 누락·빈 값·제어 문자·미지원 라벨, CPU target의 cAdvisor source 누락을 거부하는 구현이다. source별 같은 collector의 동일 job/instance 중복, target id/alias 중복, 같은 source/name의 중복도 거부하는 구현이다. 다른 source에서 같은 name을 사용하려면 source selector·target id·alias가 각각 명확하게 구분되어야 하는 계약이다.

source의 두 endpoint가 같은 실제 Docker 관측점을 나타내는지는 스키마 검사만으로 확인할 수 없는 사실이다. name만 맞지만 다른 PC인 매핑은 실행 데이터와 대조해야 하는 오류이다. source selector를 정확히 작성해도 실제 metadata id 중복이나 미수집은 런타임 문제로 남는 구조이다.

출력 경로는 고정된 `docs/rulepack/m2/generated/prometheus.infra.rules.yml`이며 운영 mount 경로 밖이다. 다른 운영 경로를 지정하는 CLI 옵션은 없는 도구이다. 기존 운영 룰/M2-1 파일에는 쓰지 않는 구현이다. 향후 적용은 기존 CPU/재시작 정의의 교체 검토 대상이며 원본과 초안을 함께 로드하여 중복 경보를 만드는 방식은 완료된 적용이 아닌 것이다.

## 7. 기존 룰과 신규 초안의 차이

| 항목 | 기존 | 신규 초안 | 의미 보존/차이 |
|---|---|---|---|
| CPU target | 4개 name의 고정 정규식이다. | target별 정확한 name과 고정 식의 4개 정의이다. | 기본 집합 동일이며 추가 name은 매핑으로 확장 가능한 차이이다. |
| CPU 조인 | 모든 job의 `/docker/` CPU와 모든 metadata를 id로 조인하는 식이다. | 명시한 job/instance 쌍의 CPU와 metadata만 같은 id로 조인하는 식이다. | 같은 수집 scope에서는 계산 동일이며 다른 job의 CPU는 제외하는 의도된 차이이다. |
| CPU id/cpu 라벨·계산 | `/docker/.+`, `total`, irate, name 합계인 식이다. | 동일한 조건이다. | 다른 cgroup/CPU 라벨 지원까지 일반화한 것은 아닌 결과이다. |
| 재시작 target | Backend 고정 name이다. | source/name별 생성이며 기본 Backend만 선택한 값이다. | 기본 범위 동일이며 추가 target은 의도된 확장인 것이다. |
| 재시작 계산 | counter 증가/reset + StartedAt changes의 OR이다. | 동일한 계산 순서/시간창/5초 조건이다. | 기존 대상의 합성 정상·고갈·reset·공백 사례에서 같은 결과이다. |
| `for`·keep firing·심각도 | CPU 30초, restart 0분/keep 2분 및 기존 severity/category이다. | 원본 객체에서 복사한 값이다. | 보존한 결과이다. |
| 분석 대상 | `$labels.name` annotation이다. | 명시한 `alert_target` annotation이다. | 기본은 실제 name과 동일하며 alias 변경 시 Pipeline 매핑 확인이 필요한 차이이다. |
| alert identity | name 중심의 시계열이다. | `rulepack_target` 추가인 결과이다. | rule identity가 달라지므로 향후 교체 시 pending/firing 상태 연속성을 보장하지 않는 차이이다. |
| 미관측 입력 | 빈 결과/평가 오류일 수 있는 상태이다. | 같은 의미이며 0 보간을 하지 않는 구조이다. | 관측 공백을 정상으로 바꾸지 않은 결과이다. |

원본과 비교한 합성 사례 중 의도된 결과 차이는 **추가 name에서의 경보**, **지정하지 않은 cAdvisor job 배제**이다. 두 source의 동명/id 중복 합성 사례는 source별 격리를 검증한 것이며 원본의 전역 조인과 같은 입력 범위를 주장하는 검증은 아닌 것이다. 실제 PC 2 scrape 성공으로 해석하지 않는 결과이다.

### 7.1 HighMemoryUsage·HighNetworkReceive 조사만 수행한 결과

| 룰 | 기존 의존성 | 일반화 가능성과 선행 조건 |
|---|---|---|
| `HighMemoryUsage` | working_set/limit의 라벨 매칭, `/docker/` id와 metadata id/name 조인, limit > 0, `> 0.85`, `for: 5m`인 식이다. | source/name 매핑 분리는 가능한 설계이다. actual limit/working_set 제공·id 유일성·컨테이너 recreate 라벨과 duplicate series를 확인해야 하는 상태이다. 이번에는 수정하지 않은 룰이다. |
| `HighNetworkReceive` | receive bytes의 interface/id/name, 4개 name 정규식, `/docker/` 네트워크 시계열 유무에 따른 root `id="/"` fallback인 식이다. | source/name 매핑은 검토 가능하지만 host fallback은 서비스 트래픽과 다른 범위인 제약이다. 원격 source가 없으면 root fallback도 PC 2 지표가 될 수 없는 것이다. 이번에는 수정하지 않은 룰이다. |

근거는 [alert.rules.yml](../../monitoring/prometheus/rules/alert.rules.yml) 42–56, 116–140행이다. 메모리·네트워크 임계값을 수정하거나 새 초안으로 복사하지 않은 결과이다.

## 8. 오프라인 테스트 결과

### 8.1 실행과 도구

실행 위치는 저장소 루트이며 Python/PyYAML과 검증된 로컬 promtool이 필요한 절차이다. 이번 검증은 앞선 M2-1에서 공식 릴리스 digest와 대조한 임시 `promtool 3.7.3`을 재사용한 결과이다. 임시 디렉터리의 YAML과 합성 시계열만 사용하며 서버/컨테이너를 띄우는 절차가 아닌 것이다. 파일 형식은 [공식 rule unit testing 문서](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)를 따른 것이다.

```shell
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/generate_m2_2.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/generate_m2_2.py --check
promtool check rules docs/rulepack/m2/generated/prometheus.infra.rules.yml
M2_PROMTOOL=/path/to/promtool PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -p test_generate_m2_2.py -v
```

PowerShell에서는 다음과 같이 현재 프로세스에 도구 경로를 지정하는 절차이다.

```powershell
$env:M2_PROMTOOL = '<검증된 로컬 promtool.exe 경로>'
$env:PYTHONDONTWRITEBYTECODE = '1'
python tools/rulepack/generate_m2_2.py --check
& $env:M2_PROMTOOL check rules docs/rulepack/m2/generated/prometheus.infra.rules.yml
python -m unittest discover -s tools/rulepack/tests -p test_generate_m2_2.py -v
```

`M2_PROMTOOL`이 없으면 native 테스트 5개는 **SKIP**이며 나머지 계약 검사만 수행하는 구조이다. SKIP을 native 통과로 집계하지 않는 계약이다. 이번 실행은 **M2-2 unittest 13개 PASS, SKIP 0개**인 결과이다. M2-1을 포함한 rulepack 전체 회귀 검사는 **24개 PASS, SKIP 0개**인 결과이다. `promtool check rules`는 **5개 룰 문법/구조 PASS**이며 M2-1/M2-2 생성기의 `--check`도 모두 PASS인 결과이다. 측정 PC 실데이터 판정은 포함하지 않은 결과이다.

### 8.2 합성 시계열 검증 행렬

합성 입력은 실제 코드/룰이 정의한 metric name과 `id/name/cpu/job/instance` 등 필요한 라벨만 사용하는 테스트이다. 추가 target/source의 이름과 주소는 격리 검사용 합성 값이며 collector/PC 2가 실제로 존재한다는 선언이 아닌 것이다. 원본 조건 비교용 정의는 원본 expr를 그대로 복사하고 테스트 안에서 alert 이름에 `Baseline`만 붙인 것이다.

| 요구 조건 | 검증 사례·기대 결과 | 결과 |
|---|---|---|
| 기존 CPU 이상 | Backend 0.8 core 상당, 30초에는 pending, 35초 이후 firing이며 원본/초안 동일인 결과이다. | PASS이다. |
| 추가 CPU 대상 | 합성 `orders-api`의 같은 CPU 입력은 초안만 발화하며 원본 name 목록 밖인 의도된 차이이다. | PASS이다. |
| 정상 CPU·경계 | 0.2 및 정확히 0.5에서는 무경보이며 raw CPU 합계 값이 존재하는 상태를 확인한 결과이다. | PASS이다. |
| CPU/metadata 누락 | 각각 없는 경우 raw join 결과가 empty이며 0 정상값을 생성하지 않는 결과이다. | PASS이다. |
| id·CPU 라벨 불일치 | id mismatch, `cpu0`만 존재, 다른 cgroup 경로에서 empty인 원본 제약을 유지한 결과이다. | PASS이다. |
| 기존/추가 재시작 | counter 2회와 별도 StartedAt 2회로 각각 발화하며 Backend는 원본과 같은 결과이다. 추가 name은 초안에서 발화하는 의도된 확장이다. | PASS이다. |
| 재시작 없는 정상 | counter 0 표본이 실제 존재하며 무경보인 상태이다. | PASS이다. |
| 대상 시계열 누락 | success gauge 1만 있고 대상 표본은 없는 경우, raw 결과 empty/무경보이며 정상 counter 0과 구분한 결과이다. | PASS이다. |
| reset/recreate | 0으로 reset된 1회 시작은 무경보, nonzero reset 후 증가와 reset 전후 2회 증가의 원식 처리 결과가 동일인 사례이다. | PASS이다. |
| 수집 공백 | 10분 이내의 짧은 공백 후 마지막 값 기반 증가분 유지이며 공백을 counter 0으로 채우지 않은 결과이다. | PASS이다. |
| 최초 표본·이름 변경 | 첫 counter가 5여도 과거 재시작 5회로 신규 집계하지 않으며 새 name은 새 시계열인 결과이다. | PASS이다. |
| 자동/수동 신호 중복 | 한 재시작의 counter 1회와 StartedAt 1회는 합산하여 2회로 세지 않는 OR 의미이다. | PASS이다. |
| 복수 대상 동시 경보 | 기존/추가 CPU와 재시작의 각 target 라벨/annotation을 분리한 결과이다. | PASS이다. |
| keep firing | 조건이 사라진 뒤 원본과 초안 모두 2분 keep 동작을 유지하고 이후 해소되는 결과이다. | PASS이다. |
| 다른 scrape job | 원본의 전역 CPU 조회는 발화하나 초안은 지정하지 않은 job을 제외한 의도된 차이이다. | PASS이다. |
| 두 합성 source의 같은 name/id | 한쪽 CPU, 다른 쪽 재시작이 각 source/alias에만 귀속되는 결과이다. | PASS이다. |
| metadata id 중복 | **native evaluator의 many-to-many 오류가 기대 결과**이며 오류를 0/정상으로 숨기지 않는 계약 검사이다. | 기대 오류 확인 PASS이다. |
| 잘못된 매핑 | 누락/중복/잘못된 runtime·role/site/불명 source/중복 rule 등을 스키마에서 거부하는 검사이다. | PASS이다. |

native 행렬은 **정상 평가 25개 합성 fixture와 metadata 중복의 기대 오류 1개 fixture**이다. 이는 unittest의 5개 native 메서드 안에서 실행하는 사례 수이며 실제 공격 시나리오 실행 수가 아닌 것이다. 문법·식 골격·임계값/시간 속성·입력 불변·생성 재현성을 나머지 8개 계약 테스트에서 검사한 결과이다.

## 9. 원격 2대 환경의 관측 공백

| M1 교차 확인 항목 | 현재 근거 | 미해결 판정 |
|---|---|---|
| PC 2 node/cAdvisor 경로 | [prometheus.aiops.yml](../../monitoring/prometheus/prometheus.aiops.yml)의 job 목록에 없고 PC 1 Compose에도 해당 exporter가 없는 구성이다. | **BLOCKED**이다. PC 1 자원으로 대체하지 않은 상태이다. |
| 로컬 Docker inspect | 원격 Compose의 Pipeline socket도 PC 1 로컬이며 코드의 restart watcher project는 `graduation-project`인 구조이다. | PC 2 restart 상태 경로는 **BLOCKED**이다. |
| 원격 target 실파일 | 이 checkout의 `monitoring/prometheus/targets/*.yml`은 여전히 0개이며 `.example`만 있는 상태이다. | 실제 PC 1 별도 파일·target·접근은 **UNVERIFIED**이다. |
| identity/join | CPU는 cAdvisor id와 PC 2에서 유래한 metadata id의 동일 관측점·형식·유일성이 필요한 계약이다. | 실제 라벨/값은 **UNVERIFIED**이다. |
| MinIO/Blackbox | 서비스·job·probe 입력이 없는 기존 구성이다. | 지속적인 기능 가용성 경로는 **BLOCKED**이다. |
| 실데이터 | M1에서 VERIFIED 0개였으며 이번 작업은 추가 실환경 조회를 수행하지 않은 정적 작업이다. | 실제 탐지 성공은 **UNVERIFIED**이다. |

향후 PC 2 자원/상태 경로의 소유 관측점·수집 주기·접근 방식·canonical identity를 정하는 별도 작업이 필요한 상태이다. PC 2 Docker API나 Phase 3 Agent가 이미 활성화되었다고 가정하지 않은 결과이다. Agent가 있더라도 현재 `/metrics`의 PC 2 값과 올바른 scrape 경로까지 자동 제공한다는 근거는 없는 상태이다. 추가 source를 YAML에 쓰는 행위 자체는 이 공백의 해결이 아닌 것이다.

## 10. 측정 PC 런타임 검증 선행 조건

아래는 측정 PC에서 수행해야 하는 읽기 전용 절차이며 이번 작업의 실행 결과가 아닌 것이다. 상세 HTTP/PowerShell helper는 [M1 §8](M1_OBSERVABILITY_AUDIT.md#8-실제-측정-pc-추가-검증-명령어)에 있는 절차를 재사용할 항목이다. metric name을 discovery하고 실제 job/instance가 매핑과 일치한 뒤에만 아래 쿼리를 실행할 순서이다.

| 실행 위치 | 읽기 전용 확인 | 기대 결과 / 실패 의미 |
|---|---|---|
| 통합 PC 또는 PC 1 | `/api/v1/targets`에서 job/instance/health/lastScrape와 `up`을 확인하는 절차이다. | 기대 target 등록과 최신 scrape가 있는 상태여야 하는 것이다. 미등록은 `up=0`과 다른 공백이다. |
| 데이터가 실제 모이는 Prometheus | cAdvisor CPU metric 이름·id/cpu 라벨과 Pipeline metadata id/name·값을 discovery하는 절차이다. | 동일 Docker scope의 `/docker/` id와 `cpu="total"`, metadata 값 1이 필요하며 불일치는 룰 입력 미충족이다. |
| 동일 Prometheus | 아래 metadata cardinality와 unmatched id 쿼리인 절차이다. | 우변 id 유일성과 대상의 연결이 필요하며 duplicate는 평가 오류, unmatched는 누락이다. |
| Pipeline이 있는 실제 대상 PC | 로컬 Docker의 project/service/name·RestartCount·StartedAt을 제한된 `docker inspect --format`으로 읽는 절차이다. | producer의 project/service 범위와 기대 target이 일치해야 하는 것이다. 전체 inspect/환경변수·인증정보 출력은 필요 없는 절차이다. |
| 동일 Prometheus | 각 name의 counter·StartedAt 최신 표본/라벨과 `aiops_docker_status_scrape_success`를 함께 확인하는 절차이다. | gauge 성공과 기대 대상 존재를 각각 확인할 항목이다. counter 0 존재와 empty를 구분해야 하는 것이다. |
| PC 1/PC 2 | 기존 시계열의 5초 간격·staleness·누락, 두 PC 시각/NTP를 읽기 전용으로 대조하는 절차이다. | 5초 offset/subquery 가정과 event time 비교가 가능한 상태여야 하는 것이다. |
| PC 1 Pipeline | `alert_target`이 실제 Docker name 또는 기존 `TARGET_SERVICE_MAP`과 일치하는지 확인하는 절차이다. | alias 해석 가능성이 필요하며 단순 문자열 rename으로 다른 PC의 컨테이너를 조회할 수 없는 것이다. |

다음은 **통합 기본 source가 실제로 확인된 경우에만** 쓰는 PromQL 예시이다. 분리된 PC 2 source가 없으면 PC 1 주소를 대신 넣어 통과시키지 않을 항목이다.

```promql
count by (id) (
  container_name_info{job="pipeline-metadata",instance="pipeline:8000"}
) > 1
```

위 결과는 없어야 하는 중복 검사이며 0건이라고 필요한 target이 모두 있다는 뜻은 아닌 것이다. 다음은 지정 target의 metadata 존재와 CPU id의 연결 여부를 각각 확인하는 예시이다.

```promql
container_name_info{job="pipeline-metadata",instance="pipeline:8000",name="leafy-backend"}
```

```promql
container_name_info{job="pipeline-metadata",instance="pipeline:8000",name="leafy-backend"}
unless on(id)
container_cpu_usage_seconds_total{job="cadvisor",instance="cadvisor:8080",id=~"/docker/.+",cpu="total"}
```

재시작 관측은 다음 두 조회를 함께 보아야 하는 절차이다. 첫 식이 1이어도 두 번째 식이 empty이면 대상 관측은 미검증/누락인 상태이다. StartedAt도 같은 scope/name으로 별도로 확인할 항목이다.

```promql
aiops_docker_status_scrape_success{job="pipeline-metadata",instance="pipeline:8000"}
```

```promql
aiops_docker_container_restarts_total{job="pipeline-metadata",instance="pipeline:8000",name="leafy-backend"}
```

새 재시작이나 CPU 부하를 주입하는 명령은 포함하지 않은 절차이다. 기존 기간 데이터만으로 판정할 수 없다면 조건별 실제 발화 검증은 UNVERIFIED로 남길 항목이다. HTTP/MinIO 기능 가용성은 등록된 health/probe 경로가 먼저 확정되어야 하는 별도 관측 조건이다.

## 11. M2-2 완료 판정 및 M2-3 후속 작업

| 확인 항목 | 상태 | 결론 |
|---|---|---|
| 기존 CPU·restart 생성/조회 계약 분석 | PASS | 실제 원식·socket·project/service·라벨·실패 동작을 확인한 결과이다. |
| 두 룰의 대상 매핑 기반 초안 | PASS | 기존 계산 계약 안의 CPU 4개/restart 1개 기본 정의와 추가 대상 생성 기능을 구현한 결과이다. |
| 원본 조건·임계값·시간 속성·severity/category | PASS | selector 외 계산 골격과 rule 속성, 원본 비교 합성 사례를 보존한 결과이다. |
| YAML/PromQL·스키마·재현성·합성 테스트 | PASS | M2-2 13개 테스트 및 native 검사 통과인 결과이다. |
| M1/M2-1·운영 파일 보존 | PASS | 시작 시 기록한 14개 파일 해시 일치와 tracked 변경 없음을 확인한 결과이다. |
| 가용성 지원 범위 및 memory/network 의존성 조사 | PASS | 신규 룰 생성/기존 룰 수정 없이 공백과 이관 조건을 기록한 결과이다. |
| 다른 cgroup·CPU 라벨·host PG로의 범용화 | PARTIAL | Docker id/total 메트릭 계약 안만 구현한 상태이며 다른 계약은 별도 설계/실측 선행인 것이다. |
| 실제 통합 PC의 데이터·룰 동작 | UNVERIFIED | 이번 작업에서 실환경 검증하지 않은 상태이다. |
| 원격 PC 2 CPU/restart 및 기능 가용성 | BLOCKED | 현재 저장소 구성에 필요한 수집 경로가 없는 상태이다. |
| M2-2 전체 | PARTIAL | **정적 초안·오프라인 검증 완료 / 런타임 인수 대기**인 상태이다. |

M2-3은 memory/network 등 남은 룰의 대상 매핑과 입력 계약을 정적으로 검토하는 방향으로 진행 가능한 상태이다. memory의 working_set/limit 매칭, network의 per-container 부재와 host fallback 범위를 보존할 설계가 선행 조건이다. 이번 작업에서 이 두 룰의 일반화 구현을 시작하거나 완료 처리하지 않은 것이다.

M3의 입력 설계 검토는 가능하나 실제 탐지 성공 인수는 M1의 데이터 확정과 PC 2 경로 확보가 선행 조건이다. CPU/restart 메트릭 관측점·join·alias, MinIO/Blackbox 관측 계약을 해결하기 전에는 신규 룰이 원격에서 동작한다고 판정할 수 없는 상태이다. 최종 상태는 **M2-2 정적 작업 완료, 실환경 인수 대기 및 원격 관측 공백 유지**이다.
