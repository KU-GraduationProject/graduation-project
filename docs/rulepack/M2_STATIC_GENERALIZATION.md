# M2-1 — 기존 4개 룰의 정적 일반화

## 상태와 범위

**M1 = 정적 감사 완료 / 런타임 검증 대기**이다. M2 첫 작업은 기존 4개 룰을 명시적인 대상 매핑으로 생성하는 정적 초안이며, 생성 코드와 오프라인 검증을 완료한 상태이다. 측정 PC에서 데이터가 수집되거나 룰이 발화함을 확인한 결과는 아닌 것이다.

기준은 M1과 같은 `main` 커밋 `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`이다. 기존 [Loki 보안 룰](../../monitoring/loki/rules/fake/security-rules.yml)과 [Prometheus 룰](../../monitoring/prometheus/rules/alert.rules.yml)에서 아래 정의만 읽는 구조이다.

| 기존 룰 | 유지하는 판단 조건 | 일반화 내용 |
|---|---|---|
| `HighNginxErrorRate` | JSON `status >= 500`, 1분 집계 `> 10`, `for: 0m`이다. | 웹 로그 selector와 분석 대상 annotation을 매핑으로 지정하는 구조이다. |
| `VulnerabilityScanningDetected` | JSON `400 <= status < 500`, 1분 집계 `> 50`, `for: 0m`이다. | 웹 로그 selector와 분석 대상 annotation을 매핑으로 지정하는 구조이다. |
| `UnauthorizedDBAccess` | `authentication failed` 문자열, 2분 집계 `> 3`, `for: 0m`이다. | DB 서비스와 선택적 runtime/container 범위를 매핑으로 지정하는 구조이다. |
| `HighNginxRequestRate` | `rate(nginx_http_requests_total[1m]) > 30`, `for: 30s`이다. | exporter의 job과 선택적 instance/site를 매핑으로 지정하는 구조이다. |

숫자 임계값·시간창·`for`·severity/category·summary는 원본에서 복사한 값이며 재결정한 값이 아닌 것이다. 새 탐지 룰, 시나리오, 공격 강도, Heldout은 이번 작업 범위 밖인 항목이다.

## 구현 파일과 적용 경계

| 파일 | 역할 |
|---|---|
| [generate_m2.py](../../tools/rulepack/generate_m2.py) | 원본 4개 룰과 대상 매핑을 읽어 정적 초안 2개 파일을 생성하는 도구이다. Loki/Prometheus API·Docker·DB를 호출하지 않는 구현이다. |
| [targets.yml](m2/targets.yml) | 현재 저장소 설정을 기준으로 한 대상 매핑이며 실측 상태는 UNVERIFIED인 파일이다. |
| [generated/loki.rules.yml](m2/generated/loki.rules.yml) | 웹 상태코드 2개와 DB 인증 실패 룰을 담은 초안이다. |
| [generated/prometheus.rules.yml](m2/generated/prometheus.rules.yml) | Nginx 요청량 룰 초안이다. |
| [test_generate_m2.py](../../tools/rulepack/tests/test_generate_m2.py) | 대상 변경·입력 모호성·원본 조건 보존 및 선택적 native validator 검증인 테스트이다. |

`docs/rulepack/m2/generated/`는 두 Compose가 mount하는 `monitoring/loki/rules/`·`monitoring/prometheus/rules/` 밖의 디렉터리이다. **현재 자동 로드되는 룰 파일은 변경하지 않은 상태**이다. 초안 생성/검사는 reload·배포·컨테이너 실행을 수행하지 않는 절차이다.

장래 적용 시에는 기존 4개 정의를 초안으로 **교체**하는 검토가 필요한 상태이다. 기존 정의와 초안을 동시에 로드하면 같은 현상을 중복 탐지할 수 있는 구조이므로 추가 로드만으로 배포를 완료할 수 없는 것이다. 이번 작업은 그 적용을 수행하지 않은 상태이다.

## 대상 매핑 계약

`web_targets`의 한 항목에서 웹 상태코드 2개와 요청량 1개, `postgres_targets`의 한 항목에서 DB 인증 실패 1개를 생성하는 구조이다. 기본 매핑은 다음과 같다.

| 대상 id | 로그 selector | 메트릭 selector | `annotations.container` |
|---|---|---|---|
| `leafy-web` | `service="frontend"`이다. | `job="nginx-exporter"`이다. | `leafy-frontend`이다. |
| `leafy-postgres` | `service="db"`이다. | 해당 없음이다. | `leafy-db`이다. |

- `id`는 생성 결과의 고정 `rulepack_target` 라벨이다. 수집기가 내보낸 라벨이라고 주장하는 값이 아닌 것이다.
- `log_selector`는 기존 수집 설정에서 확인한 `service`와 선택적 `runtime`, `container_name`, `source`의 **동등 비교**만 받는 구조이다. 가정한 `role`·host/site 라벨을 Loki 입력에 추가하지 않는 구조이다.
- `metric_selector`는 `job`을 필수로 하고 `instance`, `site`를 선택적으로 받는 구조이다. `site`는 원격 file_sd 예시에만 있는 값이므로 실측 확인 뒤 선택하는 항목이다.
- `alert_target`은 [Pipeline](../../aiops/pipeline/main.py)의 `annotations.container` 소비 계약을 유지하는 명시적 분석 대상 이름이다. 실제 컨테이너 이름 또는 PC 1의 `TARGET_SERVICE_MAP`에서 해석 가능한 alias여야 하는 값이다. 설정만으로 그 해석 성공을 증명할 수 없는 상태이다.
- 한 target 안의 로그는 기존 `sum(count_over_time(...))` 의미로 집계하는 구조이다. 서로 다른 target의 로그를 하나의 합계에 넣지 않는 구조이다. 요청량은 기존과 같이 선택된 개별 시계열의 `rate`이며 여러 instance의 자동 합산은 수행하지 않는 구조이다.
- 같은 역할의 target끼리 source selector가 겹치거나, id/alert_target이 중복되면 생성을 거부하는 구조이다. 따옴표·역슬래시는 문자열 literal로 escaping하며 제어 문자와 미지원 selector 키는 거부하는 구조이다.

예를 들어 다른 배포의 웹 대상은 다음과 같이 표현할 수 있는 것이다. 아래 이름/주소는 **합성 예시**이며 현재 측정 PC의 존재 증거가 아닌 것이다.

```yaml
id: shop-web-a
alert_target: shop-nginx-a
log_selector:
  service: shop-web
  runtime: container
  container_name: shop-nginx-a
metric_selector:
  job: shop-nginx-exporter
  instance: web-a:9113
```

동일한 service가 여러 컨테이너/호스트에 존재하면 각 입력이 어떤 target에 속하는지 실제 라벨로 좁혀야 하는 상태이다. `service`만으로 서로 다른 호스트를 분리할 수 있다고 가정하지 않는 것이다. 분리에 필요한 라벨이 수집되지 않는 경우는 M1 관측 공백으로 남길 항목이다. 여러 exporter instance가 서로 다른 앱에 대응하면 실제 `instance`로 나누고 각 `alert_target` 매핑도 확인할 항목이다.

기본 DB selector에는 runtime이 없어 이전처럼 `service="db"`의 host/container 로그가 함께 집계되는 의미이다. 두 runtime을 나누려면 서로 다른 target/alias와 각각 `runtime: host`, `runtime: container`를 명시해야 하는 계약이다. host DB에는 `container_name`을 요구하지 않는 구조이다. 현재 기본 매핑으로 그 분리를 완료했다고 판정하지 않은 상태이다.

## 명시적인 식 변경

두 웹 상태코드 룰은 `log_format="json"`을 유지하고 **status 숫자 비교 뒤**에 `| __error__=""`를 추가한 초안이다. JSON 파싱뿐 아니라 숫자 변환 오류도 metric aggregation에서 제외하려는 처리이며, 성공적으로 파싱된 기존 status 조건과 임계값은 동일한 것이다. 이는 오염된 로그에 대한 처리 변경이므로 실제 이미지의 status 타입·형식과 함께 확인해야 하는 항목이다.

요청량 룰은 필수 `job` selector를 추가하여 같은 metric name을 내보내는 다른 scrape job을 범위에서 제외한 초안이다. exporter의 존재와 실제 시계열은 여전히 UNVERIFIED이다. Alert annotation은 템플릿으로 미확인 수집 라벨을 추정하는 대신 대상 매핑의 `alert_target`을 사용하는 구조이다.

## 재생성과 검증

실행 위치는 저장소 루트이며 Python과 PyYAML이 필요한 절차이다.

```shell
# 초안 파일만 재생성하는 명령이다.
python3 tools/rulepack/generate_m2.py
# 이미 생성한 초안과 입력의 drift를 쓰기 없이 검사하는 명령이다.
python3 tools/rulepack/generate_m2.py --check
# 기본 검사이며 native 도구 경로가 없으면 해당 2개 테스트는 skip인 것이다.
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/rulepack/tests -v
# 선택: 로컬의 검증된 도구를 지정하여 native 오프라인 검사까지 수행하는 명령이다.
M2_PROMTOOL=/path/to/promtool M2_LOGCLI=/path/to/logcli PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -v
```

PowerShell의 native 검사 지정 방법은 다음과 같다. 도구 경로는 실제 로컬 경로로 바꿀 항목이며 영구 시스템 환경변수를 변경하는 절차가 아닌 것이다.

```powershell
$env:M2_PROMTOOL = '<검증된 promtool.exe 경로>'
$env:M2_LOGCLI = '<검증된 logcli.exe 경로>'
$env:PYTHONDONTWRITEBYTECODE = '1'
python tools/rulepack/generate_m2.py --check
python -m unittest discover -s tools/rulepack/tests -v
```

`--check` 실패는 초안 drift/입력 오류이며 런타임 수집 장애를 뜻하는 결과는 아닌 것이다. native 도구가 없어 skip된 검사를 통과로 집계하지 않을 항목이다. Prometheus 합성 시계열 검증 형식의 근거는 [공식 rule unit testing 문서](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)이다.

## 이번 오프라인 검증 결과

2026-11-10에 아래 결과를 확보한 상태이다. 공식 릴리스 바이너리는 임시 디렉터리에만 다운로드하고 GitHub release asset의 SHA256 digest와 일치함을 확인한 상태이다. 실제 서비스나 컨테이너를 가동하지 않은 검증이다.

| 검증 | 결과 | 범위 |
|---|---|---|
| Python unittest | **11개 PASS, skip 0개**이다. | target rename, host/container DB 분리, 겹침/중복/미지원 라벨 거부, escaping, 원본 조건 보존, 입력 불변, 생성 drift와 아래 native 검사인 범위이다. |
| LogCLI `fmt` 3.7.1 | PASS이다. | 기본·이름 변경·escaping 대상의 LogQL 8개 식 파싱인 결과이다. Loki 서버 평가/실로그 검증은 수행하지 않은 상태이다. |
| promtool 3.7.3 `test rules` | PASS이다. | 합성 target A/B를 바꾸어 발화 대상/annotation 분리를 확인하고 다른 job/미매핑 instance 제외, `> 30` 경계, `for: 30s`, 입력 없음의 결과를 확인한 상태이다. |
| promtool `check rules` | PASS이다. | 생성된 Prometheus YAML과 1개 룰의 문법/구조 확인인 결과이다. |
| 생성기 `--check` | PASS이다. | 읽기 전용 생성 drift 확인인 결과이다. |

검증 도구의 기준 릴리스는 [LogCLI 3.7.1](https://github.com/grafana/loki/releases/tag/v3.7.1)과 [Prometheus 3.7.3](https://github.com/prometheus/prometheus/releases/tag/v3.7.3)이다. 해당 버전이 측정 PC에서 실행 중이라는 뜻은 아닌 것이다.

## 완료 판정과 다음 조건

| 항목 | 판정 |
|---|---|
| M1 기록 상태 | **정적 감사 완료 / 런타임 검증 대기**이다. |
| M2 첫 작업: 4개 룰 대상 매핑·정적 초안 생성 | PASS이다. |
| 원본 임계값·시간창·alert timing 유지 | PASS이다. |
| 생성 drift·YAML·native 정적/합성 검사 | PASS이다. |
| 실제 metric/label/로그 필드·target alias 일치 | UNVERIFIED이다. |
| 측정 PC 룰 평가·Alertmanager·Pipeline 연동 | UNVERIFIED이다. |
| 운영 룰 교체·reload·배포 | 미수행인 상태이다. |

다음 인수 조건은 [M1 §8](M1_OBSERVABILITY_AUDIT.md#8-실제-측정-pc-추가-검증-명령어)의 읽기 전용 검증으로 실제 selector/annotation 매핑을 확정하는 단계이다. 특히 `frontend` JSON status, `db` 인증 실패 문구/해당 runtime, Nginx exporter job/instance와 Pipeline alias의 일치가 필요한 상태이다. 그 결과 전까지 **M2 정적 초안 완료 / 런타임 인수 대기**인 상태이다.
