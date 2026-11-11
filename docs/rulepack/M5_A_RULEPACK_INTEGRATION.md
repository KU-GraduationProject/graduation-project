# M5-A — 기존 룰·M2·M3 초안 통합 및 오프라인 회귀 검증

## 1. 결과와 범위

작업일은 **2026-11-11(KST)**이며 시작 기준은 `main`의 `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`이다. 작업 시작 상태는 `main...origin/main`, tracked 변경 0개와 기존 `docs/rulepack/`·`tools/rulepack/` 미커밋 산출물이 있는 상태이다. 원격 HEAD를 새로 조회한 결과는 아니다.

**M5-A는 정적 통합·오프라인 회귀 검증 PASS이다.** 통합 후보는 **Loki 12개 + Prometheus 9개 = 21개 정의, alert 이름 18종**이다. CPU 대상별 같은 이름의 정의 4개를 각각 세는 수치이다. 기존 SQLi 1개는 통합 후보의 중복 경보를 피하기 위해 별도 비교용 파일로 보존한 결과이다.

운영 적용은 **미수행**이며 manifest의 `deployment_allowed`는 `false`이다. 이 묶음은 통합 검토용 후보이며 통합 Docker 관측점·host PG17·Pipeline alias가 하나의 실환경 프로파일로 인수되었다는 뜻이 아니다. 실제 룰 발화·Alertmanager·Pipeline/RCA 연동도 UNVERIFIED이다.

기존 [M1](M1_OBSERVABILITY_AUDIT.md), [M2-1](M2_STATIC_GENERALIZATION.md), [M2-2](M2_2_INFRA_GENERALIZATION.md), [M2-3](M2_3_RESOURCE_GENERALIZATION.md), [M3](M3_NEW_DETECTION_RULES.md), [M4](M4_NORMAL_BASELINE.md), [OI-1](OBSERVABILITY_INFRA_MILESTONE.md)과 관련 파일 **53개**의 SHA256을 시작 시 기록하고 종료 시 일치를 확인한 작업이다. 기존 운영 17개 룰·생성기·매핑·보고서·설정을 수정하지 않았다. Docker 조작·배포·reload·Git commit/push/PR 생성도 없는 작업이다. 시나리오 주입 코드·공격 강도·Heldout은 열람/튜닝 자료가 아니다.

M4는 **분석 도구 및 오프라인 검증 완료 / 실측 Baseline 수립 대기**, `NORMAL_UNCONFIRMED`인 상태를 유지한 결과이다. 이번 통합은 새 임계값이나 정상 P95/P99를 만들지 않는 작업이다. GC→JH 전달의 사용자 확인을 재조사하거나 PC 접속 정보를 요청하지 않았다.

## 2. 통합 정책과 파일

정책은 [integration.yml](m5/integration.yml)의 `m3_primary_legacy_reference`이다. 운영 승인과 구분한 오프라인 후보 선택이다.

1. M2로 일반화한 원본 8개 alert 이름은 기존 정의와 생성 정의를 함께 넣지 않고 M2 정의로 대체하는 방식이다.
2. SQLi는 M3 `SQLInjection`을 후보 주 정의로 선택하고 기존 `SQLInjectionAttempt`를 reference 파일에 두는 방식이다.
3. 나머지 원본 8개는 그대로 유지하고 M3 `DBConnectionLimit`을 추가하는 방식이다.
4. 각 룰 객체의 expr·for·keep_firing_for·labels·annotations를 원본 또는 해당 생성 초안에서 그대로 복사하는 방식이다. 새 source 라벨을 붙이거나 alias를 통합하지 않는 방식이다.

| 파일 | 역할 |
|---|---|
| [integrate_m5.py](../../tools/rulepack/integrate_m5.py) | upstream 재생성 일치·매핑·중복을 검사한 뒤 후보를 조립하는 독립 도구이다. |
| [test_integrate_m5.py](../../tools/rulepack/tests/test_integrate_m5.py) | 통합 산출물 자체를 대상으로 한 계약·native 회귀 테스트이다. |
| [integration.yml](m5/integration.yml) | SQLi 주 정의/reference 분리의 명시적 검토 정책이다. |
| [generated/loki.rules.yml](m5/generated/loki.rules.yml) | Loki 후보 12개 정의이다. |
| [generated/prometheus.rules.yml](m5/generated/prometheus.rules.yml) | Prometheus 후보 9개 정의이다. |
| [reference/loki.legacy-sqli.rules.yml](m5/reference/loki.legacy-sqli.rules.yml) | 기존 SQLi의 원식·속성을 그대로 보존한 비교 전용 파일이다. 후보와 함께 로드할 파일이 아니다. |
| [manifest.json](m5/manifest.json) | 후보 파일 목록·원본 17개 처분·룰별 출처/해시·매핑 검사·경고·보류 항목이다. |
| [verification.json](m5/verification.json) | 이번 테스트·도구 버전·해시 보존의 실행 증거이다. |

출력은 고정된 `docs/rulepack/m5/` 내부이며 Compose의 운영 룰 mount 밖이다. 출력 디렉터리를 운영 경로로 지정하는 CLI 옵션은 없는 도구이다. `generated/`의 두 파일만 후보 목록이며 `reference/`를 포함하는 재귀 glob은 이번 정책과 다른 로드 방식이다.

## 3. 기존 17개 룰의 대응표

근거는 운영 [보안 룰](../../monitoring/loki/rules/fake/security-rules.yml), [네트워크 룰](../../monitoring/loki/rules/fake/network-allowlist.yml), [Prometheus 룰](../../monitoring/prometheus/rules/alert.rules.yml)과 M2/M3 생성 결과이다.

| 기존 룰 | 통합 후보 처리 | 후보 정의 수 |
|---|---|---:|
| UnauthorizedDBAccess | M2-1 정의로 대체이다. | 1 |
| SecretDumpAttempt | 원본 유지이다. | 1 |
| SQLInjectionAttempt | 비교 전용으로 보존, 주 후보는 M3 SQLInjection이다. | 기존 이름 0 / 신규 이름 1 |
| HighNginxErrorRate | M2-1 정의로 대체이다. | 1 |
| SuspiciousProcessExecution | 원본 유지이다. | 1 |
| SuspiciousProcessExec | 원본 유지이다. | 1 |
| VulnerabilityScanningDetected | M2-1 정의로 대체이다. | 1 |
| PathTraversalAttempt | 원본 유지이다. | 1 |
| ContainerEscapeAttempt | 원본 유지이다. | 1 |
| UnauthorizedDataTransfer | 기존 정책 생성 결과를 그대로 유지이다. | 1 |
| UnauthorizedTransferEarly | 기존 정책 생성 결과를 그대로 유지이다. | 1 |
| HighCpuUsage | M2-2의 frontend/backend/db/minio별 정의로 대체이다. | 4 |
| HighMemoryUsage | M2-3의 source 전체 해당 name 범위 유지이다. | 1 |
| ContainerRestarted | M2-2의 Backend 1개 대상 정의로 대체이다. | 1 |
| HighNetworkReceive | M2-3의 컨테이너/root 분기 정의로 대체이다. | 1 |
| HighNginxRequestRate | M2-1 정의로 대체이다. | 1 |
| HighPostgresConnections | 원본 개별 시계열 조건 유지이다. | 1 |

계산은 **원본 유지 8개 + M2 생성 11개 + M3 생성 2개 = 후보 21개**이다. 원본 17개 중 M2 대체 8개 이름과 SQLi reference 1개 이름도 manifest에 남아 있어 누락과 의도된 제외를 구분 가능한 결과이다. 실제 운영 파일의 원본 17개는 그대로인 상태이다.

## 4. 중복과 의미 보존

### 4.1 SQLi의 의도된 후보 선택

기존 `SQLInjectionAttempt`는 원문 전체 line의 2분 **6건 이상**, 신규 `SQLInjection`은 JSON URI 한 번 디코딩 후 2분 **1건 이상**인 조건이다. 같은 이름 변경이나 동등한 탐지식으로 취급하지 않는 선택이다. URI 밖 User-Agent 패턴을 제외하고 일부 인코딩/주석 표현을 다루는 차이도 M3 그대로인 결과이다.

두 정의의 의미 중복은 alert 이름이 달라 자동 dedup되지 않는 위험이다. 이번 후보는 신규 정의만 포함하며 기존 정의는 비교용으로 보존한 정책이다. 이는 정상 오탐이나 탐지 재현율을 근거로 신규 정책의 우수성을 승인한 결과가 아니다. 낮은 빈도 기준의 운영 적절성은 M4 실측·정상 입력 판독이 남은 조건이다.

### 4.2 보존한 계산과 속성

| 범위 | 통합에서 보존한 사항 |
|---|---|
| CPU | irate 30초·core 상당량·id/name 조인·대상별 name·>0.5·for 30초이다. |
| 메모리 | working set/양수 limit의 full-label 매칭·metadata 조인·name 최대값·>0.85·for 5분이다. |
| 재시작 | counter 증분/reset 및 StartedAt 변경 OR·10분/5초 계산·>=2·for 0분·keep_firing_for 2분이다. |
| 수신 | per-container 수신 rate·어떤 Docker 시계열이라도 root fallback을 막는 guard·>1e7 bytes/s·for 30초이다. |
| 웹 | 요청량 >30 requests/s·5xx 1분 >10건·4xx 1분 >50건과 M2 오류 필터이다. |
| DB | 인증 실패·개별 연결 시계열 >40·서버 슬롯 거부는 각각 다른 조건인 범위이다. Hikari/서버 전체 사용률 룰을 추가하지 않은 상태이다. |
| 속성 | severity/category·명시적 alias·template annotation·기존 target/source 고정 라벨·원본 group 속성이다. |

각 후보 룰 객체는 출처 객체와 **전체 필드 일치**를 테스트한 결과이다. 원본 유지 룰을 임의로 일반화하거나 M2/M3 조건을 다시 작성하지 않은 작업이다. 같은 alert/static-label identity와 같은 정확한 식/시간 조건의 중복은 거부하는 구현이다. 모든 정규식의 의미적 교집합이나 상관된 증상 경보까지 제거하는 알고리즘은 아니다.

group 이름에는 출처별 prefix를 붙여 충돌을 피하고 다른 group 속성은 보존한 구조이다. M3의 명시적 `interval:5s`는 유지이며 원본/M2의 미명시 interval은 계속 서버 설정 상속이다. Loki 원본 group까지 5초로 통일한 결과가 아니다. 향후 group/file/경보 identity 교체 시 pending/firing 상태의 연속성을 보장하지 않는 조건이다.

## 5. source·alias·소비 계약 검사

통합기는 기존 생성기를 메모리에서만 다시 실행하여 저장된 M2/M3 초안과 비교하는 검사이다. drift가 있으면 이전 파일을 고쳐 쓰지 않고 거부하는 방식이다. 원본 alert 목록이 17개 기준과 달라져도 조용히 누락하지 않고 재검토 오류인 방식이다.

M2-2와 M2-3에서 같은 source id의 cAdvisor/Pipeline selector가 다르면 거부인 검사이다. M2-1/M3의 같은 역할·alias에서 공통 로그 라벨 값이 충돌해도 거부인 검사이다. 현재 기본값은 이 정적 일관성 검사를 통과한 결과이다.

다만 **정적 일관성과 실제 배포/identity 인수는 별개**이다. manifest에 남긴 경고는 다음과 같다.

| 경고 | 실제 의미와 남은 조건 |
|---|---|
| MIXED_CONFIGURED_SCOPES | 통합 Docker CPU/메모리/재시작과 host PG17 로그가 함께 있는 검토용 구성이다. PC 2 자원 수집/metadata·동일 관측점 인수는 OI-02/OI-03/OI-04 범위이다. |
| HOST_CONTAINER_ALIAS_CONFLICT | `leafy-db`가 통합 Docker CPU 대상과 host PG17 로그 분석 alias에 함께 쓰이는 구성이다. 한 TARGET_SERVICE_MAP으로 두 범위를 올바르게 해석한다고 승인할 수 없는 상태이다. |
| PIPELINE_SOURCE_AND_HOST_ROUTING | [AlertLabel 및 dedup](../../aiops/pipeline/main.py)은 source 라벨을 온전히 보존하지 않고 alertname/대상 이름 중심이다. root `unknown (host-level)`의 처리도 별도 확인인 OI-09 조건이다. |
| BASELINE_NOT_USED | 정상 구간/분위수·후보 임계값을 통합 결정 근거로 만들지 않은 상태이다. |
| LEGACY_MARKER_TELEMETRY | 유지한 stdout marker/명령 문자열은 실제 process 실행·탈출·비밀 유출의 증거를 보장하지 않는 조건이다. |

HighPostgresConnections의 job/instance 없는 원식도 그대로인 범위이다. 따라서 이 룰만으로 source 격리가 일반화되었다고 판단하지 않는 결과이다. DB 인증 실패, 연결 증가, 슬롯 거부는 함께 발생할 수 있지만 동일한 판단 조건으로 합치지 않은 신호이다.

`LoginBruteForce`와 DB 전체 max_connections/사용률 분기는 manifest의 **보류** 상태이다. 빈 식·미확인 메트릭·비활성 가상 경보로 채우지 않은 결과이다. 현재 후보를 운영 파일에 복사하는 것만으로 이 관측/소비 공백이 해결되는 구성이 아니다.

## 6. 오프라인 회귀 검증

사용 도구는 앞선 작업에서 release digest와 대조한 임시 **promtool 3.7.3**, **LogCLI 3.7.1**이다. 설치/서비스 실행 없이 실제 통합 후보 파일을 검사한 결과이다.

| 검사 | 결과·범위 |
|---|---|
| M5-A unittest | **16개 PASS, SKIP 0개**이다. |
| M2~M5-A 전체 회귀 | **93개 PASS, SKIP 0개**이다. 기존 77개도 함께 통과이다. |
| promtool check rules | 통합 Prometheus **9개 정의**의 문법/구조 PASS이다. |
| LogCLI fmt | 후보 **12개 + reference 1개 = 13개** 전체 LogQL 파싱 PASS이다. |
| Native Loki pipeline | 통합 파일에서 추출한 SQL 29개·DB 17개·HTTP 4개 합성 로그 세트의 필터 검사 PASS이다. HTTP 세트는 5xx/4xx 각각 검사인 방식이다. |
| Native Prometheus 평가 | 실제 통합 Prometheus 파일을 한 번에 로드한 **성공 fixture 8개 + 기대 join 오류 fixture 1개**의 회귀 PASS이다. |
| 매핑·원형 보존 | 같은 source/alias 충돌 거부, 21개 룰 객체의 출처 전체 필드 일치·group timing·원본17개 대응·중복 검사 PASS이다. |
| 재현성·파일 보존 | upstream 재생성 일치, bundle/reference/manifest --check, 입력/출력 해시·기존 53개 파일 불변 PASS이다. |

Prometheus 합성 검증의 구체 범위는 다음과 같다.

- CPU frontend/backend, 메모리 frontend/backend, 재시작 Backend, 네트워크 frontend, Nginx 요청량, DB 연결 경보를 같은 입력 창에서 평가하는 동시 경보 검사이다.
- CPU 30초 pending/35초 firing과 메모리 4분55초/5분 경계를 구분하는 검사이다.
- 낮은 합성 값, 전체 입력 없음, metadata 없음, 지정하지 않은 cAdvisor job을 구분하는 검사이다. 무경보를 실환경 정상 판정으로 쓰는 검사가 아니다.
- root만 있는 경우의 host 경보와 이름 없는 loopback Docker 시계열이 root를 막는 원래 guard를 확인하는 검사이다.
- DB active 30·idle 16이라는 **테스트 입력**에서 합계 46을 원본 개별 시계열 >40으로 오해하지 않는 검사이다. 실제 정상 연결 분포가 아니다.
- metadata id 중복은 native evaluator의 many-to-many 오류가 기대 결과이다. 통합기가 조인을 축소하거나 0을 넣어 오류를 숨기지 않는 검사이다.

단위 테스트 형식의 근거는 [Prometheus 공식 rule testing 문서](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/)이다. [LogCLI stdin 설명](https://grafana.com/docs/loki/latest/query/logcli/getting-started/#use-stdin-to-query-locally)처럼 stdin은 실제 stream selector·metric query/Ruler를 평가하는 기능이 아니다. 따라서 Loki 검증은 전체 식 파싱과 native log pipeline 범위이며 실제 count/unwrap 집계·Ruler 로딩/실제 group 시각·알림 전송 성공은 UNVERIFIED이다. 기존 M3의 count 경계 합성 검사도 전체 회귀에 포함되지만 서버 평가의 대체 증거가 아니다.

모든 수치 fixture는 테스트 코드/임시 파일에만 있는 합성 입력이다. 정상 Baseline·실제 공격 실행·탐지 재현율/FPR 결과가 아닌 구분이다.

## 7. 재생성과 검사 명령

저장소 루트에서 Python/PyYAML로 실행하는 오프라인 절차이다. 운영 API·Docker·DB 호출이나 출력 운영 경로 선택은 없는 명령이다.

```shell
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/integrate_m5.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/integrate_m5.py --check
M5_PROMTOOL=/path/to/promtool M5_LOGCLI=/path/to/logcli PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -p test_integrate_m5.py -v
# 기존 M2~M4까지 포함한 전체 회귀이다.
M2_PROMTOOL=/path/to/promtool M2_LOGCLI=/path/to/logcli \
M3_PROMTOOL=/path/to/promtool M3_LOGCLI=/path/to/logcli \
M4_PROMTOOL=/path/to/promtool M4_LOGCLI=/path/to/logcli \
M5_PROMTOOL=/path/to/promtool M5_LOGCLI=/path/to/logcli PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -v
```

PowerShell의 M5-A 개별 검사는 다음과 같다. 경로는 기존에 검증된 로컬 도구 값으로 바꿀 부분이다.

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:M5_PROMTOOL = '<검증된 로컬 promtool.exe 경로>'
$env:M5_LOGCLI = '<검증된 로컬 logcli.exe 경로>'
python tools/rulepack/integrate_m5.py --check
python -m unittest discover -s tools/rulepack/tests -p test_integrate_m5.py -v
```

native 경로가 없으면 M5-A native 검사 **7개는 SKIP**이며 통과로 계산하지 않는 계약이다. --check 실패는 upstream/후보 drift 또는 정책/매핑 오류이며 자동 재생성·운영 수정으로 보완하지 않는 처리이다. reference까지 포함한 재귀 로드나 원본 운영 파일과 후보의 병행 로드는 이번 검증된 파일 목록과 다른 적용이다.

## 8. 완료 판정과 후속 경계

| 항목 | 판정 |
|---|---|
| 원본17개의 처리·M2 대체·M3 추가/SQLi reference 정책 | PASS이다. |
| 후보21개·manifest·출처/해시·중복·교차 매핑 검사 | PASS이다. |
| 통합 파일 native 문법/합성 평가·기존 전체 회귀 | PASS이다. |
| 기존 M1~M4/OI·운영 파일 보존 | PASS이다. |
| M5-A 요청 범위 | **정적 통합 및 오프라인 회귀 검증 완료**이다. |
| 정상 임계값/FPR·재현율 | 미산출이며 M4/M6 범위이다. |
| 원격 resource·host/container alias·Pipeline source/host routing | 별도 인수 필요인 OI 범위이다. |
| 실제 Ruler/Alertmanager/Pipeline/RCA 인수·운영 교체/reload | UNVERIFIED / 미수행이다. |

다음 실환경 단계의 선행 조건은 해당 PC/source의 실제 입력·5초 메트릭 계약, host/container alias 분리와 Pipeline 해석, SQLi 교체 정책 검토와 서버 버전별 룰 평가 증거이다. 이번 산출물은 그 단계에서 검토할 구체적인 후보이며 배포 승인이나 자동 적용 결과가 아니다. M4의 미확정 정상 구간을 이유로 이번 오프라인 통합 작업을 중단하지 않은 결과이다.
