# M2-3 — 메모리·네트워크 룰 정적 일반화

## 1. 상태와 변경 범위

2026-11-10(KST)에 `main` 커밋 `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50` 기준으로 수행한 작업이다. 시작 시 tracked 변경은 0개이고 M1/M2-1/M2-2 결과가 untracked인 상태를 확인한 것이다. 기존 결과와 운영 설정 19개 파일을 SHA256 보존 검사 대상으로 기록한 작업이다.

**M2-3은 정적 초안·오프라인 검증 완료 / 런타임 인수 대기**인 상태이다. 관측 인프라 보완은 다음 단계부터 [별도 마일스톤 OI-1](OBSERVABILITY_INFRA_MILESTONE.md)에서 추적하는 구조이다. 이번 작업은 OI-1의 계획/인수 기준을 작성한 범위이며 수집기·서비스·네트워크 배포를 수행한 결과가 아닌 것이다.

기존 운영 룰과 M2-1/M2-2 파일을 변경하지 않고 신규 결과물 6개를 작성한 작업이다.

| 파일 | 역할 |
|---|---|
| [generate_m2_3.py](../../tools/rulepack/generate_m2_3.py) | 원본 memory/network 조건을 읽어 source별 초안을 생성하는 도구이다. |
| [test_generate_m2_3.py](../../tools/rulepack/tests/test_generate_m2_3.py) | 계약·원본 비교·합성 시계열·잘못된 입력 검증인 테스트이다. |
| [resource_targets.yml](m2/resource_targets.yml) | 명시적 scrape source와 네트워크 이름 목록인 매핑이다. |
| [prometheus.resources.rules.yml](m2/generated/prometheus.resources.rules.yml) | 운영 mount 밖의 기본 2개 룰 초안이다. |
| [이 보고서](M2_3_RESOURCE_GENERALIZATION.md) | 계산 의미·지원 범위·의도된 차이와 인수 조건의 기록이다. |
| [OBSERVABILITY_INFRA_MILESTONE.md](OBSERVABILITY_INFRA_MILESTONE.md) | 다음 단계의 관측 인프라 보완 작업·상태·선행 조건·완료 게이트인 추적 문서이다. |

새 위협 임계값, exporter/Agent, 가용성 룰을 추가하지 않은 작업이다. 시나리오·주입 강도·Heldout을 읽지 않았으며 Docker 실행/재시작/재생성, 룰 reload, DB/네트워크 변경, commit/push/PR 생성은 미수행인 상태이다.

## 2. HighMemoryUsage 일반화

원본 근거는 [alert.rules.yml](../../monitoring/prometheus/rules/alert.rules.yml) 42–56행이다.

```promql
max by (name) (
  (
    container_memory_working_set_bytes{id=~"/docker/.+"}
    / (container_spec_memory_limit_bytes{id=~"/docker/.+"} > 0)
  ) * on(id) group_left(name) container_name_info
) > 0.85
```

원본에는 frontend/backend 같은 **대상 이름 allowlist가 없는 구조**이다. 따라서 CPU 룰의 4개 목록을 메모리 룰에 새로 적용하지 않은 것이다. source 안에서 필요한 지표와 metadata가 일치하는 모든 컨테이너를 유지한 기본 범위이다. AIOps 컨테이너도 원래 범위에 들어올 수 있는 구조이다.

| 원본 계약 | 초안의 처리 |
|---|---|
| working_set / limit | 두 메트릭에 같은 cAdvisor job/instance를 붙이고 기존 나눗셈을 유지한 구조이다. usage_bytes로 대체하지 않은 것이다. |
| 나눗셈의 vector matching | 전체 라벨 매칭을 유지한 구조이다. 재생성 관련 추가 라벨이 다르면 짝이 빠질 수 있으며 `on(id)` 나눗셈으로 단순화하지 않은 것이다. |
| limit > 0 | 양수 limit만 사용하는 원식을 유지한 구조이다. 0/미수집 limit은 정상 비율 0이 아니라 계산 입력 부재인 결과이다. 무제한이 실제 exporter에서 어떻게 표현되는지는 OI-04 확인 대상이다. |
| id/name 조인 | `/docker/.+` 필터와 metadata `on(id) group_left(name)`을 유지한 구조이다. metadata는 source 전체를 사용하며 id 중복은 평가 오류인 계약이다. |
| `max by(name)` | 일치한 복수 시계열 중 최대 비율을 유지한 구조이다. restartcount 등의 라벨을 임의로 제거해 나누거나 평균으로 바꾸지 않은 결과이다. |
| 판단/시간/심각도 | `> 0.85`, `for: 5m`, warning/infra 및 summary를 유지한 값이다. |

초안은 [통합 scrape 설정](../../monitoring/prometheus/prometheus.yml)의 `cadvisor:8080`, `pipeline:8000`을 명시적으로 선택하는 구조이다. `service`, `role`, `site`를 새 입력으로 요구하지 않은 것이다. metadata의 `id/name`과 값 1의 생성 근거는 [Pipeline main.py](../../aiops/pipeline/main.py) 205–242행이다. 실제 두 입력의 형식·관측점·유일성은 UNVERIFIED이다.

분모와 분자의 full-label matching, 조인과 집계의 해석은 [공식 연산자 문서](https://prometheus.io/docs/prometheus/latest/querying/operators/#vector-matching)를 대조한 사항이다. 이 계산 계약이 맞지 않는 환경의 정규화/수집 보완은 OI-02/OI-04의 범위이다.

## 3. HighNetworkReceive 일반화

원본 근거는 [alert.rules.yml](../../monitoring/prometheus/rules/alert.rules.yml) 116–140행이다.

```promql
(
  sum by (name) (
    rate(container_network_receive_bytes_total{interface!="lo", id=~"/docker/.+", name!="", name=~"leafy-frontend|leafy-backend|leafy-db|leafy-minio"}[1m])
  ) > 1e7
)
or
(
  (
    sum without (interface) (
      rate(container_network_receive_bytes_total{interface!="lo", id="/"}[1m])
    ) > 1e7
  )
  unless on ()
  (count(container_network_receive_bytes_total{id=~"/docker/.+"}) > 0)
)
```

첫 분기는 이름 목록에 들어오는 `/docker/` 컨테이너의 비loopback 수신 bytes/sec를 name별 합산하는 식이다. 두 번째는 `/docker/` 수신 메트릭 시계열이 하나도 없을 때만 root `id="/"`의 수신량을 사용하는 host fallback인 식이다. 판단은 **수신량 증가**이며 외부 반출/프로세스 실행 사실을 증명하는 값은 아닌 것이다.

| 원본 계약 | 초안의 처리 |
|---|---|
| 4개 이름 정규식 | `network_names` 목록으로 분리한 구조이다. 이름의 점은 정규식 wildcard가 되지 않게 escaping하며 선택된 문자열과 정확히 일치하는 의미이다. |
| 컨테이너 계산 | `rate[1m]`, `sum by(name)`, `interface!="lo"`, `/docker/.+`, 비어 있지 않은 name을 유지한 식이다. |
| 호스트 계산 | `id="/"`, `sum without(interface)`, 비loopback과 `> 1e7`을 유지한 식이다. root 관측점은 Docker VM/호스트 범위를 실제로 확인할 대상이다. |
| fallback 조건 | `unless on()`과 모든 `/docker/` 시계열의 존재 검사를 유지한 식이다. 대상 목록·name·interface로 존재 검사를 좁히지 않은 것이다. |
| source 구분 | 세 selector 모두 같은 cAdvisor job/instance로 제한하여 fallback 판단도 source별인 구조이다. |
| 시간/심각도 | `for: 30s`, warning/security 및 원래 annotation을 유지한 값이다. |

**source마다 네트워크 룰 1개와 host fallback 1개만 생성**하는 구조이다. 컨테이너 target마다 root 분기를 복사하여 host 경보가 여러 번 생성되는 구현은 아닌 것이다. 기본 이름 집합은 원래 4개와 동일한 값이다. `rate`의 counter reset 처리는 [공식 함수 문서](https://prometheus.io/docs/prometheus/latest/querying/functions/#rate)와 native 평가로 확인한 사항이다.

### 유지한 관측 공백

fallback의 존재 검사는 **유효한 컨테이너 rate의 존재 검사와 다른 조건**이다. 이름 없는 컨테이너, 감시 이름 목록 밖의 컨테이너, loopback 시계열만 있어도 `/docker/` 시계열이 있으면 root fallback을 막는 원식이다. 이때 첫 분기도 비면 무경보이며 이를 정상/트래픽 없음으로 판정할 수 없는 상태이다. 해당 사례를 원본과 같은 결과로 테스트한 것이다.

root 수신량은 특정 Leafy 서비스의 수신량이 아닌 범위이다. name이 없으면 기존 annotation은 `unknown (host-level)`이며, root 시계열에 name이 있으면 기존 템플릿은 그 name을 사용하는 구조이다. **root의 name이 앱 컨테이너라는 보장은 없는 상태**이다. 원래 annotation은 보존하되 OI-09에서 host 신호의 identity/소비 경로를 확정할 선행 조건이다.

현재 source에 매핑한 PC 1/통합 cAdvisor를 PC 2 Leafy 값으로 해석하지 않는 기준이다. root fallback도 PC 2 관측 경로의 대체 수단이 아닌 것이다.

## 4. 매핑과 생성 계약

기본 파일은 다음과 같은 source 하나를 가진 구성이다. 메트릭/라벨의 실제 존재는 UNVERIFIED이며 예시 주소를 실행 성공 증거로 간주하지 않는 것이다.

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
    rules: [memory, network]
    network_names:
      - leafy-frontend
      - leafy-backend
      - leafy-db
      - leafy-minio
```

각 source의 cAdvisor는 필수이고 메모리를 선택하면 Pipeline scope가 필수인 구조이다. 네트워크만 선택하는 source에는 Pipeline metadata를 요구하지 않는 구조이다. selector는 job/instance 동등 비교만 받으며 미지원 라벨·제어 문자·누락·중복 source·중복/잘못된 network name·중복/미지원 rule을 거부하는 스키마이다.

메모리는 name을 동적으로 보존하고 네트워크는 원래의 name/host annotation을 보존하는 source 단위 일반화이다. `rulepack_source`는 생성한 alert의 고정 라벨이며 수집기가 내보낸 입력을 가정하는 라벨은 아닌 것이다. 기본 출력은 메모리 1개·네트워크 1개, 총 2개 정의이다. 임계값·시간창·for·severity/category·summary/annotation은 원본에서 복사하는 값이다.

현재 Pipeline은 추가 source 라벨을 스키마에 보존하지 않고 alertname/대상 이름 중심으로 dedup하는 구현이다([main.py](../../aiops/pipeline/main.py) 68–80, 282–304행). 서로 다른 source에 같은 컨테이너 name이 있으면 Prometheus 결과가 구분되어도 Pipeline의 분석 대상/중복 제거가 충돌할 수 있는 제약이다. 여러 PC로의 실제 인수는 OI-09가 선행 조건이며, source 라벨 추가만으로 소비측 일반화까지 완료했다고 판정하지 않은 상태이다.

생성기는 M2-1/M2-2를 import하거나 수정하지 않는 독립 도구이다. 출력은 고정된 `docs/rulepack/m2/generated/prometheus.resources.rules.yml`이고 운영 룰 mount 밖이다. 기존 룰과 초안을 동시에 로드하는 배포는 수행하지 않은 상태이다. 향후 교체/실제 인수는 OI-1에서 기록할 단계이다.

## 5. 오프라인 검증과 원본 비교

이번 검증은 앞선 단계에서 검증한 임시 `promtool 3.7.3`을 재사용한 결과이다. 서버·컨테이너·앱 트래픽 없이 임시 YAML과 합성 시계열만 평가한 테스트이다. 추가 source/이름/주소는 합성 값이며 PC 2 collector의 실존 증거가 아닌 것이다. 검증 형식은 [공식 rule unit testing 문서](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)에 따른 것이다.

| 영역 | 검증 내용 |
|---|---|
| 정적 계약 | 원본 계산 골격·시간/심각도·annotation 보존, 기본 memory 전체 name 범위, host fallback 1회, 스키마 거부·입력 불변·생성 drift인 검사이다. |
| 메모리 | 0.9 이상 상태, 0.2 정상, 정확한 0.85 경계, limit 0/누락·working_set/metadata 누락·id 불일치, full-label 불일치, matching restartcount 쌍의 max, 원래 목록 밖 name, 복수 대상과 전체 입력 없음인 사례이다. |
| 메모리 시간 | 4분55초에는 pending, 5분에 firing이며 원본과 초안이 같은 결과인 사례이다. |
| 네트워크 | 컨테이너 고/정상 수신량, 정확한 1e7 경계, interface 합산·loopback 제외, host fallback/interface 합산과 중복 억제, 이름 없음/감시 밖/loopback 존재로 fallback 억제, counter reset·복수 대상·입력 없음인 사례이다. |
| 네트워크 시간 | 합성 counter의 전체 1분 rate가 형성되는 구간을 포함하여 30초 for를 원본과 같은 결과로 확인한 사례이다. |
| 이름 변경/escaping | 추가한 `api.v2`가 정확히 선택되고 `apiXv2`가 잘못 매칭되지 않는 사례이다. |
| source 분리 | 다른 job 제외, 다른 job의 컨테이너가 현재 source의 root fallback을 막지 않는 결과와 두 합성 source의 memory/root 격리인 사례이다. |
| 입력 오류 | metadata id 중복을 native many-to-many 평가 오류로 확인한 사례이며 이를 정상 0으로 숨기지 않는 검사이다. |

정상 수치와 empty를 직접 조회하는 검사를 포함한 결과이다. 메모리 정상 비율/네트워크 정상 rate의 값이 존재하는 상태와 입력 누락으로 raw 결과가 empty인 상태를 구분한 것이다.

원본과 달라지는 의도된 경우는 **매핑의 추가 이름**, **지정하지 않은 job/instance 배제**, **다른 source의 컨테이너 존재가 현재 root fallback을 막지 않는 경우**이다. 같은 scope와 기존 이름 집합에서는 원본과 초안의 정상/이상/누락/분기 사례 결과가 동일한 것이다. source 분리에 따른 차이는 인프라 수집 성공을 의미하지 않는 결과이다.

```shell
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/generate_m2_3.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/generate_m2_3.py --check
promtool check rules docs/rulepack/m2/generated/prometheus.resources.rules.yml
M2_PROMTOOL=/path/to/promtool PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -p test_generate_m2_3.py -v
```

PowerShell에서는 `$env:M2_PROMTOOL = '<로컬 promtool.exe 경로>'`, `$env:PYTHONDONTWRITEBYTECODE = '1'`을 지정하고 같은 Python 명령을 수행하는 절차이다. promtool이 없으면 native 5개 테스트는 SKIP인 구조이며 native PASS로 집계하지 않는 것이다. 이번 M2-3 실행은 **12개 unittest PASS, SKIP 0개**, 기본 **2개 룰의 promtool 문법 검사 PASS**인 결과이다. M2-1/M2-2를 포함한 전체 회귀 검사는 **36개 PASS, SKIP 0개**이며 세 생성기의 `--check`도 모두 PASS인 결과이다. 시작 시 기록한 기존 19개 파일의 SHA256 일치와 tracked 변경 없음을 확인한 결과이다.

## 6. OI-1로 분리한 다음 단계

| 공백 | 별도 추적 항목 | 룰 단계와의 경계 |
|---|---|---|
| PC 2 CPU/메모리/네트워크·metadata 경로 | OI-01/OI-02이다. | 기존 원격 구성에는 경로가 없어 BLOCKED이며 매핑만으로 해결하지 않은 상태이다. |
| PC 2 Docker 상태·producer project/service 범위 | OI-03이다. | M2-2의 원격 restart 공백을 유지하는 상태이다. |
| limit/working_set·id와 라벨·네트워크 name·fallback 범위 | OI-04이다. | 정적 조건은 유지하고 실측/정규화·정책 변경은 별도 작업으로 다룰 항목이다. |
| DB/Hikari·인증/IP·Nginx 필드 | OI-05/OI-06이다. | M1/M3 입력 확정 작업으로 분리한 항목이다. |
| 실제 HTTP/MinIO/Blackbox 가용성 | OI-07이다. | 신규 룰 자동 생성 없이 관측 경로를 먼저 확정할 항목이다. |
| 시간/연속성/파싱·전송 오류 | OI-08이다. | 최근 표본·누락·신호 시각을 검증할 공통 인수 조건이다. |
| 여러 source의 동명 target와 host 경보 | OI-09이다. | Prometheus 라벨 격리와 Pipeline 소비측의 target/조회 범위를 함께 확인할 항목이다. |

각 OI 항목의 담당은 미정이며 실제 작업·증거가 생기면 [마일스톤 추적표](OBSERVABILITY_INFRA_MILESTONE.md#작업-목록)를 갱신할 계획이다. 이번 범위에서 추가 수집기를 배포하거나 상태를 DONE으로 승격한 항목은 없는 상태이다.

## 7. 완료 판정

| 항목 | 상태 |
|---|---|
| M2-3 정적 일반화·오프라인 검증 | PASS이다. |
| 기존 threshold/for/집계·분기·annotation 의미 보존 | PASS이며 source 격리/이름 변경은 명시한 차이이다. |
| 기존 M1/M2-1/M2-2·운영 파일 보존 | PASS이며 기존 19개 파일 해시 일치 및 tracked 변경 없음을 확인한 결과이다. |
| OI-1 작업·상태·의존성·완료 게이트 분리 | 계획 수립 PASS이며 구현은 미착수인 상태이다. |
| 실제 통합 환경의 메트릭·룰 동작 | UNVERIFIED이다. |
| 원격 PC 2의 해당 자원/상태 경로 | BLOCKED이다. |
| 전체 실환경 인수 | PARTIAL이며 정적 완료 / 런타임 대기인 상태이다. |

다음 권장 실행 단계는 **OI-01 실제 배포 인벤토리 확보**이다. 이후 해당 위협에 필요한 OI 항목을 수행하고 실제 입력/소비 경로를 인수하는 순서이다. M3의 설계 검토는 진행할 수 있으나 런타임 탐지 성공은 해당 입력의 G1–G3 완료가 선행 조건이다. 정적 룰을 더 일반화하는 작업으로 수집 경로 부재를 해결했다고 판정하지 않는 결론이다.
