# Leafy AIOps M5 통합 및 실환경 E2E 준비

작성일: 2026-11-11 KST. **오프라인 코드 통합 완료 / 실환경 배포 및 M5-B 최종 인수는 BLOCKED**.

GC collector 실행, JH scrape 성공, 실제 경보 전달, 실제 LLM 추론, Loki read-back, Slack 전달의 새 실환경 증거는 없다. 아래 PASS는 합성 입력·mock HTTP·native 식 평가·설정 문법 검사의 결과다. 과거 `m5b/*.json`도 이번 실행 증거로 승격하지 않았다.

## 1. 통합 범위와 원본 보존

기준은 `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`이다. 원격 fetch나 GitHub 변경은 하지 않았다. 확인한 로컬 remote는 `KU-GraduationProject/graduation-project`이다.

| 원본 Worktree / 브랜치 | 시작 tracked 수정 | 시작 untracked | 소유권 |
|---|---:|---:|---|
| `graduation-project` / `main` | 0 | 50 | M1~M5 문서·생성기·테스트·과거 검증 자료 |
| `oi09-source-identity` / `feat/oi09-source-identity` | 9 | 3 | A: Pipeline identity·collector·RCA |
| `oi02-04-telemetry` / `feat/oi02-04-telemetry` | 0 | 23 | B: GC producer·검증기·scrape/Compose 후보 |
| `m5b-runtime-acceptance` / `test/m5b-runtime-acceptance` | 0 | 54 | C: M5-B probe·인수 자료, M2~M5 참고본 |

네 Worktree 모두 HEAD가 기준 SHA이고 결과는 미커밋이었다. 브랜치 merge로 결과를 가져오지 않았다.

- 통합 위치: `/Users/kwonjunhui/Desktop/graduation/m5-integration-release`, detached HEAD. 새 commit 없음.
- 보존 위치: `/Users/kwonjunhui/Desktop/graduation/m5-integration-preservation-20261111`.
- 변경 파일 139건, 고유 경로 84개를 원본별 복사하고 SHA256을 대조했다. 각 원본의 porcelain 상태와 tracked binary patch도 보존했다. 원래 Worktree 파일은 수정·삭제하지 않았다.
- 복사 우선순위: main → A → B → C. 같은 경로/같은 해시는 동일 자료로 취급했다.
- 내용이 다른 중복 5개는 모두 C 소유 영역이다: `M5_B_RUNTIME_ACCEPTANCE.md`, `m5b/runtime.json`, `m5b/verification.json`, `acceptance_m5b.py`, `test_acceptance_m5b.py`. C 버전을 통합 기준으로 선택하고 다른 버전도 보존했다.
- 원본 main만 가진 `m4/current_run/*`, `m5b/local_metadata.json`, `query-plan.json`, `runtime.sandbox.json` 등도 남겼다. 이 자료의 관측값을 현재 운영 상태로 재해석하지 않았다.
- 기존 Heldout 및 주입 파라미터는 열람하지 않았다. 파일 보존·해시 계산은 내용 해석 없이 수행했다. 테스트는 저장소의 합성 단위 fixture만 사용했다.

전체 경로·소유자·원본 해시·충돌 선택은 [source-manifest.json](integration/source-manifest.json), 종료 시 원본 보존 검사는 [preservation-check.json](integration/preservation-check.json)에 기록한다.

종료 검사 중 main의 `.gitignore`, `claude.md`, 신규 `AGENTS.md`와 `docs/agent-context/*`가 시작 이후 바뀐 것을 관측했다. 시작 시 인수한 139개 파일은 모두 원본/보존본 해시가 같고 제거된 시작 상태 항목도 없었다. 새 동시 변경은 통합 범위에 넣거나 되돌리지 않았다. 별도 `concurrent-main-changes` 보존본과 상태 차이/해시를 남겼으며, main의 전체 Git 상태가 시작 때와 같다고 주장하지 않는다.

## 2. 실제 통합 코드와 diff

| 경로 | 통합 결과 |
|---|---|
| `aiops/pipeline/identity.py` 및 A의 Pipeline 변경 | source-aware 해석·충돌 거부·300초 dedup 유지. `metrics_profile=gc-telemetry-v1` 추가 |
| `aiops/pipeline/collector/metrics.py` | GC working set/RX/limit/CPU 및 안정적인 RestartCount/StartedAt selector 지원. 미지원 usage/TX를 0으로 대체하지 않음 |
| `aiops/pipeline/main.py` | RCA Loki label에 target 추가. 원래 startsAt/fingerprint와 후속 전달 보류 상태를 JSON에 보존 |
| `leafy/fluentd/plugins/filter_leafy_docker_log.rb` | Docker driver metadata의 `aiops.site`, `aiops.source`만 observation label 근거로 사용. 앱 JSON의 `_lbl_*` 위조 제거 |
| `leafy/fluentd/plugins/filter_leafy_postgres_log.rb` | 선택적 수신기 설정 site/source/target 지원. jsonlog 본문에서 identity 추측하지 않음 |
| `tools/rulepack/prepare_release.py` | 실측 프로파일을 받아 GC/JH 검토 번들 생성. placeholder·미확인 inventory·중복 ID/name·host alias 충돌 거부 |
| `tools/rulepack/acceptance_m5b.py` | C 구현에 `--bundle` 추가. 원래 M5-A 또는 생성 번들의 정확한 룰로 probe. rule hash drift와 중복 loaded definition을 거부 |
| `deploy/leafy-pc/telemetry/compose.transport.candidate.yml` | collector의 loopback 전용 publish 후보. 공개 listener나 cAdvisor publish 없음 |
| `tools/rulepack/verify_integration.py` | 외부 TCP·실제 daemon 연결 차단 후 회귀 실행. producer의 임시 mock Unix socket만 허용 |
| 신규 Python/Ruby 계약 테스트 | producer 출력→binding→collector→RCA push, 미확인 source 차단, source 분리, root fallback, identity label template·5분 hold 검증 |

B producer와 원래 M2~M5 생성기·generated 룰은 입력 그대로 보존했다. 현재 운영 mount 파일인 `docker-compose*.yml`, `monitoring/prometheus/prometheus*.yml`, 운영 rule 파일, `monitoring/alertmanager/alertmanager.yml`, `leafy/fluentd/fluent.conf`는 기준 HEAD와 동일하다. 변경한 Ruby plugin은 **새 Fluentd 이미지 후보의 소스**이며 실행 중인 컨테이너에 반영하지 않았다.

[change-inventory.json](integration/change-inventory.json)은 전체 Git 변경 경로와 최종 해시, 복사본 대비 변경 여부를 기록한다. [tracked-vs-base.patch](integration/tracked-vs-base.patch)는 tracked 코드 전체 diff, [integration-fixes.patch](integration/integration-fixes.patch)는 선택한 A/B/C 복사본 위에 더한 통합 코드 diff다. 보존한 역사적 관측 JSON은 내용 diff로 재해석하지 않고 원본/최종 해시로 검사했다. 증거·보고서 파일 자신은 재귀 patch 대상에서 제외한다.

## 3. 공통 Identity 계약

| 필드 | 의미 / 근거 |
|---|---|
| `site` | 관측 대상 배포 환경. 저장소·Pipeline이 JH에 있어도 GC 관측값의 site는 유지 |
| `source` | 검증한 observation producer 계약 ID. scrape 주소나 stdout/stderr로 추측하지 않음 |
| `service` | canonical 업무 서비스: frontend/backend/minio/db 또는 명시한 host context |
| `runtime` | `container` 또는 `host` |
| `target` | 실측 Docker 이름 또는 별도로 식별한 host PostgreSQL 인스턴스. host target을 Docker 조치 대상으로 사용하지 않음 |

`job/instance`는 scrape 경로, `/docker/<64hex>`는 컨테이너 인스턴스다. 이 값들은 site/source와 함께 검증해야 한다. 재생성으로 ID가 바뀌면 binding을 다시 인수해야 한다. `rulepack_source`는 룰 프로파일 이름이며 producer source를 대신하지 않는다.

GC Docker 로그와 telemetry의 공통 source는 운영자가 같은 GC daemon 관측 계약으로 확인한 값만 사용한다. 로그 후보는 기존 출력 채널을 `log_stream=stdout|stderr`로 보존하고 `source`에 observation source를 쓴다. 기존 로그는 자동 재라벨하지 않는다. 기존 dashboard/query의 `source=stdout` 의존성도 전환 전 검토 대상이다.

경보에는 다섯 필드를 모두 남긴다. CPU/restart는 target별 static labels, memory/network는 집계 후 남은 identity를 label template로 옮긴다. 모든 telemetry 입력 selector 및 metadata RHS는 실제 job/instance와 site/source로 제한한다. `sum/max by(name)`은 후보에서 `by(site,source,service,runtime,target,name)`으로 바꾼다. 원래 비교값·윈도·offset·reset 처리·for·keep_firing_for는 유지했다.

Alertmanager는 `group_by=[alertname,site,source,service,runtime,target]` 후보를 사용한다. webhook의 개별 `alerts[].labels`를 Pipeline이 extra labels까지 보존한다. grouping은 identity를 만들어 주지 않으므로 source가 이미 사라진 원래 M5-A 경보를 복구하는 수단으로 쓰지 않는다. [Alertmanager 공식 설정](https://prometheus.io/docs/alerting/latest/configuration/)

이름만 있는 경보, 충돌하는 identity, 복수 binding, 미등록 source는 수집 범위를 넓히지 않는다. binding이 없거나 scoped evidence가 전부 없으면 LLM 호출 없이 confidence=0/action=NONE 결과를 기록한다.

## 4. Identity 문제별 처리와 Producer → Rule → Pipeline 호환성

| 문제 | 구현 / 남은 인수 조건 |
|---|---|
| GC 앱 로그의 site 누락 | GC logging override가 `aiops.site/source` Docker labels를 driver에 전달. plugin+생성 Fluentd 후보가 site/source/target을 Loki labels로 출력. 실제 GC 서비스 재생성 및 새 stream 확인 전 UNVERIFIED |
| host PostgreSQL site/target 누락 | `host_postgres` 실측 항목을 주면 dedicated receiver 설정과 host binding·로그 룰 생성. 동일 shared-key 수신기에 다른 PC/PG가 섞이지 않는다는 확인이 필수. 없으면 host 룰 제외 |
| M5-A 집계의 source 손실 | 원래 M5-A는 보존. 신규 source-scoped 후보에서 selector·집계·경보 label까지 유지. 과거 경보의 source를 사후 추측하지 않음 |
| host/container DB alias 충돌 | host PG는 별도 source/target, runtime=host. GC Docker DB target 등록은 거부. 과거 `leafy-db=db:host` alias는 후보에서 `TARGET_SERVICE_MAP=''`로 비활성화 |
| 실제 OBSERVATION_BINDINGS | 실측 profile에서 `bindings.json`과 Compose environment를 함께 생성. 기본 `[]` 상태로 배포하면 source-unmapped RCA만 남는다는 점을 명시 |
| Alertmanager source-aware 전달 | grouping 후보·개별 labels 보존·source별 dedup 검사 완료. 실제 AM 송신·Pipeline 수신은 UNVERIFIED |
| GC producer/Pipeline metric 불일치 | profile을 명시하여 working_set과 RX 사용, usage/TX는 unsupported로 기록. restart/started는 id 없는 안정적 selector와 별도 반환 label 검증 사용 |

| 입력 | 단위·차원 | Rule / RCA 소비 |
|---|---|---|
| `container_cpu_usage_seconds_total` | seconds counter, `cpu=total`, full id | 기존 irate[30s] 및 >0.5 유지. RCA는 rate[1m] 문맥으로 구분 |
| `container_memory_working_set_bytes` / `container_spec_memory_limit_bytes` | bytes / 동일 full labels | limit>0 필터, 비율>0.85, for=5m 유지. Docker HostConfig.Memory=0이면 cAdvisor VM 분모를 실제 container quota라고 주장하지 않음 |
| `container_network_receive_bytes_total` | bytes counter, interface | 기존 >1e7 bytes/s, 1m rate, 30s hold. TX는 본 producer 대상 밖 |
| `container_name_info` | 값 1, id당 유일 | 같은 source/job/instance로 join. raw id layout을 `/docker/`로 몰래 정규화하지 않음 |
| `aiops_docker_container_restarts_total` | Docker RestartCount, id 없음 | 기존 reset-aware 10분/2회 분기 유지. Docker 수동 stop/start 전체 횟수나 과거 event journal과 동일하지 않음 |
| `aiops_docker_container_started_at_seconds` | 최근 StartedAt epoch seconds, id 없음 | 기존 changes[10m]>=2 분기 유지. 중간에 scrape하지 못한 여러 재시작을 복원했다고 주장하지 않음 |
| `leafy_telemetry_*` / `container_last_seen` | 수집 상태·최종 성공 시각·freshness | `up=1`과 내부 collection_success=1은 별개. 결측·0·오류를 분리 |
| GC 앱/host PG JSON 로그 | Loki stream 다섯 identity + log_format | 정확한 series 존재 및 응답 label 재검증 후 사용. host metrics는 현재 profile에서 생략 |

Docker Desktop에서 Linux VM/cgroup path·cpu dimension·mount 지원은 **BLOCKED/미검증**이다. cAdvisor Linux 실행 지침만으로 Windows host 프로세스 가시성을 보장하지 않는다. [cAdvisor 공식 실행 지침](https://github.com/google/cadvisor/blob/master/docs/running.md)

B collector는 원래 memory source 범위와 network fallback guard를 유지하기 위해 같은 daemon의 다른 컨테이너 metadata도 취급한다. `resources` 성공에는 실행 중 컨테이너의 CPU/memory/freshness coverage가 필요하다. 앱 외 컨테이너의 memory 경보는 binding이 없으면 RCA의 LLM 대상이 되지 않는다. 앱 3개만 수집된다고 가정하지 않는다. 어느 `/docker/` network 시계열이든 존재하면 lo/비관심 이름도 root fallback을 막는 기존 동작을 유지한다. root는 `service=target=docker-vm,runtime=host`이며 Windows PG17이 아니다. root binding에는 앱/OS 근거를 자동 연결하지 않아 LLM 근거가 없으면 confidence=0이다.

### 전체 M5 전환 전에 필요한 후속 구현

현재 생성기는 **부분 M5 검토 후보**다. frontend/backend/minio를 모두 입력하고 host PG도 인수한 합성 예제는 Prometheus 6개, Loki 11개 정의를 만든다. 실제 대상 목록에 따라 수가 달라진다. 원래 M5-A 21개 정의와 동등한 전체 배포로 승인할 수 없다. 제외 항목은 생성 manifest에 남는다.

1. `UnauthorizedDataTransfer`, `UnauthorizedTransferEarly`: 실제 observer/observer_instance와 GC topology를 인수한다. 기존 Network Event stream labels는 유지하고 `| json` 직후 observer/observer_instance 및 src runtime/target을 exact filter한다. 집계로 사라지는 다섯 identity는 검증된 target별 static labels로 보존한다. 1048576 bytes/기존 조기 탐지 조건·allowlist는 변경하지 않는다. 같은 observer 이름만으로 PC를 확정하지 않는다.
2. `HighNginxRequestRate`: 실제 GC nginx exporter job/instance, 서비스 대응, counter 단위와 5초 표본을 확인한다. `rate(nginx_http_requests_total{<검증된 scope>}[1m]) > 30`, for=30s에 static identity를 붙이는 별도 프로파일이 필요하다.
3. `HighPostgresConnections`: host PG17 exporter의 정확한 metric/세션 단위·라벨을 확인한다. 기존 `pg_stat_activity_count > 40`, for=30s를 해당 source/job/instance로 제한한다. 다른 이름의 exporter metric을 의미 검증 없이 alias하거나 DB별 합산으로 바꾸지 않는다.
4. 원래 container DB CPU 정의는 GC host PG의 CPU 룰이 아니다. 별도 PostgreSQL16 컨테이너가 실제 존재한다면 별도 site/source/target/id 프로파일과 인수가 필요하다. 없으면 적용 대상 제외를 명시적으로 승인받는다.
5. 누락 룰과 기존 self/exporter scrape coverage를 모두 결정한 뒤 complete candidate를 만든다. 현재 생성 JH Prometheus 설정은 GC 검토용 한 job만 포함하므로 전체 운영 설정 교체 승인이 아니다. 기존 광역 룰과 후보를 동시에 로드하는 방법으로 coverage 문제를 덮지 않는다.

## 5. RCA·Loki·Remediation·Slack

RCA v2 JSON은 identity, 원래 labels/annotations, startsAt/fingerprint, selector/query/반환 series·stream labels와 가용성 상태를 보존한다. Loki stream에도 site/source/service/runtime/target을 붙인다. `push_to_loki`는 HTTP 실패를 저장 성공으로 표시하지 않는다. **이번 검증의 204는 mock 응답이다. 실제 저장 PASS에는 같은 alert identity·startsAt/fingerprint의 Loki read-back이 필요하다.**

Remediation 전달은 name-only `/action` 계약이 원격 site/source/runtime을 안전하게 주소화하지 못해서 보류했다. LLM의 `action_type`은 제안이며 실행 승인으로 쓰지 않는다. RCA에 `handoff_status=deferred_source_aware_consumer_required`, `remediation_dispatched=false`, `notification_dispatched=false`를 남긴다. 기존 helper·sender 서명 테스트가 존재해도 활성 RCA 경로가 helper를 호출하는 것은 아니다. 주기적 legacy Slack/LLM task도 재활성화하지 않았다.

Slack 데모는 현재 복구하지 않았다. 실제 전송 0회다. 알림만 복구할 후속 소비자 계약은 다음과 같다.

- 별도 notification-only endpoint가 RCA schema_version=2.0, 다섯 identity, alert_starts_at/fingerprint, evidence 상태, root_cause/confidence를 검증한다. 기존 `/action`으로 우회하지 않는다.
- HMAC으로 전송한 본문 바이트를 검증하고 replay/시간창을 제한한다. 알림 event id는 identity+alert+startsAt/fingerprint 기준으로 멱등 처리한다.
- Slack 표시는 다섯 identity와 근거 가용성을 포함하고 mrkdwn/멘션을 escape한다. 실행/승인 버튼, Docker client, action dispatch 분기는 두지 않는다. action 제안은 참고 텍스트로만 표시한다.
- Slack 성공 ACK와 notification audit에 동일 identity/event id를 남긴다. 키 미설정·전송 오류·중복은 별도 상태이며 PASS로 세지 않는다. 알림 실패가 RCA 저장을 되돌리지 않는다.
- Remediation v2는 별도 작업이다. source→executor/site allowlist, runtime별 action allowlist, 관측 full id와 실행 직전 id 재검증, 서명·정책·승인·replay·rollback을 구현하기 전 활성화하지 않는다.

## 6. 오프라인 검증 결과

최종 결과는 [verification.json](integration/verification.json), 원시 실행 로그는 그 JSON이 가리키는 디렉터리에 있다. 같은 테스트의 여러 실행을 합산하지 않았다.

| 검사 | 최종 PASS | FAIL/ERROR | SKIP | 범위 |
|---|---:|---:|---:|---|
| Pipeline/OI-09 | 135 | 0 | 0 | 기존 131 + producer/소비 계약 4 |
| OI-02/03/04 producer | 28 | 0 | 0 | mock Unix socket 19 + native PromQL 9 |
| M2~M5-B + release identity | 122 | 0 | 0 | 기존 106 + 신규 16 |
| Remediation 회귀 | 270 | 0 | 0 | Docker/Slack mock, 실제 조치 없음 |
| Network Observer 회귀 | 12 | 0 | 0 | 합성 event/capture 상태 |
| Fluentd filter | 21 | 0 | 0 | 87 assertions, 실제 Fluentd test driver |
| **고유 테스트 합계** | **588** | **0** | **0** | 런타임 인수 수치가 아님 |

[static-checks.json](integration/static-checks.json): GC base+transport Compose, JH base+override Compose, 원래 all-in-one/aiops Compose, 원래 Prometheus 두 설정 및 후보 설정, bundle query-plan, Ruby 문법/Fluentd config parser, tracked diff whitespace 통과. Compose는 `config`만 호출했다. Prometheus 검사는 `/etc/...` mount 경로를 임시 사본의 실제 파일로 바꾸고 file_sd는 합성/빈 파일을 사용했다. native LogQL은 `logcli fmt`와 기존 합성 pipeline 평가까지이며 Loki 서버의 ruler metric query 검증은 아니다. Alertmanager native `amtool check-config` 및 실제 로딩은 이번에 수행하지 않았다.

초기 실패도 보존했다: producer는 sandbox의 임시 Unix socket bind 제한으로 1 ERROR였고 fixture-only 실행으로 28 PASS를 확인했다. 확장 Remediation 회귀 첫 실행은 Python Docker SDK 누락으로 82 ERROR였으며 임시 의존성 설치 후 270 PASS를 확인했다. all-in-one Compose 첫 검사는 필수 환경변수 미설정으로 실패했고 문법 검사용 placeholder를 명시한 후 통과했다. 이 실패들을 PASS에 합산하지 않았다.

검증 환경: 원본 venv의 Python 3.12, httpx 0.28.1, FastAPI 0.128.8, Pydantic 2.12.5, PyYAML 6.0.3, promtool 3.7.3, logcli 3.7.1. 추가 Python Docker SDK 7.1.0 및 Ruby Fluentd 1.16.3/test-unit 3.5.9는 `/private/tmp`에만 설치했다. 시스템 Ruby 2.6용 gem 빌드에는 SDK header 경로 보정과 임시 cool.io 1.7.1 호환 빌드 옵션이 필요했다. 이는 배포 이미지 검증을 대신하지 않는다. 원본 venv·시스템 Ruby·운영 서비스 설정을 수정하지 않았다.

재현 명령(오프라인, 새 증거 디렉터리 지정):

```sh
python -B tools/rulepack/verify_integration.py \
  --promtool "$PROMTOOL" --logcli "$LOGCLI" \
  --output "$NEW_PRIVATE_EVIDENCE_DIR"
# dependencies: aiops/pipeline/requirements.txt, aiops/remediation/requirements.txt,
# deploy/leafy-pc/telemetry/requirements-test.txt. 별도 venv에서 준비한다.

GEM_HOME="$TEST_GEM_HOME" ruby -Ileafy/fluentd/plugins \
  leafy/fluentd/test/test_filter_leafy_log.rb
```

## 7. GC/JH 배포 파일과 실행 순서

**다음은 실행하지 않은 절차다. 운영 적용은 별도 승인 대상이다.** profile·private env·evidence는 저장소 밖 비공개 디렉터리에 둔다. `<...>`와 REPLACE는 실측값으로 바꾸기 전 사용할 수 없다. `.invalid`, `validation-only`, 합성 ID가 있는 `/private/tmp/m5-release-synthetic-*`는 테스트 전용이며 배포하지 않는다.

### 7.1 공통 사전 준비

1. GC/JH 운영자와 변경 시간·실제 서비스명·현재 이미지 digest·mount·effective config를 비공개로 보존한다. 기존 실행 상태와 rule inventory, Tailscale Serve 기존 설정을 기록한다.
2. `integration/profile.template.json`을 비공개 경로로 복사한다. GC site/source/project, 실제 frontend/backend/minio name/full ID, 승인된 private transport job/instance를 기입한다. GC에서 Docker API를 실제로 조회한 운영자만 `inventory_verified=true`로 바꾼다.
3. host PG가 준비됐다면 다음 형태를 **실측값으로** 추가한다. 없으면 null을 유지하여 host 룰을 명시적으로 제외한다.

```json
{"site":"<실제 site>","source":"<host PG 별도 source>","target":"<실제 PG 인스턴스>","dedicated_receiver_verified":true}
```

4. 새 번들을 생성하고 manifest excluded/gates 및 전체 diff를 검토한다. 이 단계는 파일 생성만 수행한다.

```sh
python -B tools/rulepack/prepare_release.py \
  --profile "$PRIVATE_PROFILE" --output "$NEW_REVIEW_BUNDLE"
python -B tools/rulepack/acceptance_m5b.py --plan \
  --bundle "$NEW_REVIEW_BUNDLE" --output "$NEW_PRIVATE_QUERY_PLAN_JSON"
```

생성 파일: `collector.json`, `gc.logging.override.yml`, `prometheus.rules.yml`, `loki/fake/release.rules.yml`, `prometheus.yml`, `targets.json`, `alertmanager.yml`, `fluent.conf`, `bindings.json`, `pipeline.env`, `jh.compose.override.yml`, empty rule mount 및 manifest. Compose environment가 bindings의 실제 주입 경로다. `pipeline.env`를 별도 구성에 쓰려면 JSON이 보존되는지 effective env 해시를 대조한다.

### 7.2 GC PC

배포 대상은 `deploy/leafy-pc/telemetry/` 전체(새 transport override 포함), 실측 `collector.json`, 검토한 cAdvisor/Python immutable image digest, 실제 앱 Compose에 맞춰 검토한 logging override다. GC host PostgreSQL은 이 collector 이미지에 포함하지 않는다. 기존 Windows Fluent Bit 설정·state DB·storage 경로는 유지하며, 중앙 수신기의 host identity 설정과 실제 data/log 경로를 따로 인수한다.

읽기 전용 inventory/연결 확인:

```powershell
[DateTime]::UtcNow.ToString('o')
w32tm /query /status
tailscale status
tailscale ip -4
tailscale ping $JH_TAILSCALE_PEER
tailscale serve status --json
docker context show
docker info --format '{{.OSType}} {{.CgroupVersion}} {{.Driver}}'
docker ps -a --no-trunc --format '{{.ID}} {{.Names}} {{.Label "com.docker.compose.project"}} {{.Label "com.docker.compose.service"}} {{.State}}'
docker inspect $ObservedContainer --format '{{.Id}} {{.Name}} {{.RestartCount}} {{.State.StartedAt}} {{.State.Running}} {{.HostConfig.Memory}}'
Get-Service '*postgres*' | Select-Object Name,Status
```

별도 승인 후의 적용 순서:

1. cAdvisor VM mount/id/cpu=total/namespace 지원과 image digest를 먼저 확인한다. 불일치는 조용히 수정하지 않고 중단한다.
2. 실제 config/env로 아래 Compose 문법을 확인하고, 승인된 새 telemetry 프로젝트만 build/up 한다. 앱·DB를 이 명령에 포함하지 않는다.
3. loopback collector GET이 성공한 후 기존 Serve 설정과 충돌하지 않는 새 private TCP proxy를 구성한다. Tailscale ACL/grants는 **JH→GC pull**과 GC→JH 로그 방향을 각각 확인한다. 이미 로그가 전달된다는 사실은 metric pull 허용 증거가 아니다.
4. GC logging 변경은 실제 앱 Compose와 대조하여 별도 승인된 서비스별 재생성으로 적용한다. 자동 일괄 재시작 명령은 두지 않는다. 그 후 바뀐 full ID로 profile/bindings를 다시 생성·검토한다.

```powershell
# private env: CADVISOR_IMAGE, PYTHON_IMAGE, TELEMETRY_CONFIG,
# GC_TELEMETRY_LOOPBACK_PORT. 이미지는 검토한 digest를 사용한다.
docker compose -f deploy/leafy-pc/telemetry/compose.candidate.yml -f deploy/leafy-pc/telemetry/compose.transport.candidate.yml config --quiet
# 다음 두 줄은 적용 승인 후에만 실행한다.
docker compose -f deploy/leafy-pc/telemetry/compose.candidate.yml -f deploy/leafy-pc/telemetry/compose.transport.candidate.yml up -d --build
tailscale serve --bg --tcp=$ApprovedTailnetPort "tcp://127.0.0.1:$LocalCollectorPort"

# 승인 후 상태와 read-only GET
docker compose -f deploy/leafy-pc/telemetry/compose.candidate.yml -f deploy/leafy-pc/telemetry/compose.transport.candidate.yml ps
curl.exe --fail --silent --show-error --max-time 4 "http://127.0.0.1:$LocalCollectorPort/metrics"
```

Tailscale Serve TCP proxy의 구문과 비공개 tailnet 범위는 [공식 Serve 문서](https://tailscale.com/docs/reference/tailscale-cli/serve)를 기준으로 검토했다. 이 Windows 설치의 버전·권한·지원 여부는 확인하지 않았다. Funnel은 사용하지 않는다. listener는 loopback만 publish하고 JH는 승인된 Tailscale host:port를 사용한다. public NIC에 raw 9108/8080을 열지 않는다.

1분 이상 연속 캡처와 `verify.py --config <실측 collector.json> --captures <timestamp/path manifest>`의 정확한 PowerShell 명령은 [B 절차](OI_02_03_04_TELEMETRY.md)의 §9를 사용한다. 5초마다 채집하되 실제 시작 시각을 기록한다. verifier snapshot/cadence PASS도 runtime_accepted=false다. RestartCount/StartedAt 실제 변화 검증은 자연 관측/별도 승인된 이벤트 없이는 미검증으로 남긴다.

### 7.3 JH PC

배포 대상은 통합 Pipeline 코드, 새 Fluentd plugins, 검토한 GC/JH 번들, 기존 volume/state를 보존하는 JH override다. Pipeline/Fluentd 이미지를 이 소스로 build하고 digest를 기록해야 하며 현재 생성된 배포 이미지는 없다. Prometheus/Loki/AM도 실제 실행 버전과 native 도구 호환성을 확인한다.

1. Tailscale 상태와 GC proxy까지 접근을 확인한다. 같은 daemon의 raw cAdvisor/다른 collector/JH Pipeline metadata를 GC source로 중복 수집하지 않는다.
2. 아래 설정 검사를 먼저 수행한다. complete rule coverage와 BLOCKED 항목이 해결되기 전 현재 부분 override를 운영 전체에 적용하지 않는다.
3. 승인된 완전한 후보에서 수신기·source labels·bindings를 먼저 정렬한다. Pipeline/Fluentd 소스 이미지와 설정을 함께 적용한다. 그다음 승인한 scrape/rule/AM 구성을 적용한다. 기존 광역 룰과 source 후보를 동시에 로드하지 않는다.
4. 실제 effective mounts, bindings의 비공개 해시, loaded rule 개수/식/labels/for/interval, duplicate-source 여부를 확인한다. 민감한 전체 config/env/inspect를 공유 로그로 덤프하지 않는다.

```sh
tailscale status
tailscale ping "$GC_TAILSCALE_PEER"
curl --fail --silent --show-error --max-time 4 "$GC_PRIVATE_COLLECTOR_ORIGIN/metrics" -o "$PRIVATE_SNAPSHOT"
docker compose -f docker-compose.aiops.yml -f "$RELEASE_BUNDLE/jh.compose.override.yml" config --quiet
# RELEASE_BUNDLE은 이 JH PC에서 존재하는 검토 번들의 절대 경로다.
promtool check rules "$RELEASE_BUNDLE/prometheus.rules.yml"
# check config는 컨테이너 mount 경로가 존재하는 검토 환경에서 수행한다.
promtool check config "$MOUNT_RESOLVED_PROMETHEUS_CONFIG"
amtool check-config "$RELEASE_BUNDLE/alertmanager.yml"

# 아래 적용 명령은 complete 후보에 대한 별도 승인 후에만 실행한다.
docker compose -f docker-compose.aiops.yml -f "$RELEASE_BUNDLE/jh.compose.override.yml" up -d --build fluentd pipeline prometheus loki alertmanager remediation
docker compose -f docker-compose.aiops.yml -f "$RELEASE_BUNDLE/jh.compose.override.yml" ps
curl --fail "$PROMETHEUS_ORIGIN/-/ready"
curl --fail "$LOKI_ORIGIN/ready"
curl --fail "$ALERTMANAGER_ORIGIN/-/ready"
curl --fail "$PIPELINE_ORIGIN/health"
```

이 명령은 이번에 실행하지 않았다. `REMEDIATION_MODE=disabled`, Pipeline Slack env 빈 값, legacy periodic tasks 비활성 상태를 실제 적용 후에도 확인한다. 기존 all-in-one과 aiops Compose는 동일 이름/상태를 공유하므로 동시에 올리지 않는다.

## 8. 실환경 메트릭·로그·경보 E2E 검증 명령과 판정

아래는 기존 승인된 endpoint에 대한 GET만 수행하는 절차다. private evidence directory에 저장하고 인증·주소·원문 로그를 저장소에 커밋하지 않는다.

```sh
curl --fail "$PROMETHEUS_ORIGIN/api/v1/targets" -o "$EVIDENCE/targets.json"
curl --fail "$PROMETHEUS_ORIGIN/api/v1/rules?type=alert" -o "$EVIDENCE/prometheus-rules.json"
curl --fail "$LOKI_ORIGIN/prometheus/api/v1/rules" -o "$EVIDENCE/loki-rules.json"
curl --fail "$ALERTMANAGER_ORIGIN/api/v2/alerts" -o "$EVIDENCE/am-alerts.json"
curl --fail "$PROMETHEUS_ORIGIN/api/v1/alerts" -o "$EVIDENCE/prometheus-alerts.json"

python -B tools/rulepack/acceptance_m5b.py --bundle "$RELEASE_BUNDLE" \
  --prometheus "$PROMETHEUS_ORIGIN" --loki "$LOKI_ORIGIN" \
  --alertmanager "$ALERTMANAGER_ORIGIN" --pipeline "$PIPELINE_ORIGIN" \
  --ollama "$OLLAMA_ORIGIN" --expected-model "$VERIFIED_DEPLOYED_MODEL" \
  --output "$EVIDENCE/runtime.json"
```

probe는 GET만 사용하고 입력 존재/식 평가/정확한 loaded definition을 분리한다. `--bundle` 없이 실행하면 역사적 M5-A 21개 룰을 probe하므로 새 후보 검증으로 혼동하지 않는다. `--plan`은 네트워크 접근이 없다. probe 자체는 `actual_alert_e2e_verified=false`를 유지한다.

PromQL은 `<...>`를 profile의 실제 값으로 치환하여 `/api/v1/query`, `/api/v1/query_range`로 실행한다.

```promql
up{job="<job>",instance="<private instance>"}
leafy_telemetry_collection_success{site="<site>",source="<source>"}
leafy_telemetry_target_present{site="<site>",source="<source>"}
leafy_telemetry_target_scrape_success{site="<site>",source="<source>"}
time() - leafy_telemetry_last_success_timestamp_seconds{site="<site>",source="<source>"}
count by(site,source,id) (container_name_info{site="<site>",source="<source>"}) != 1
count by(site,id,cpu) (container_cpu_usage_seconds_total{site="<site>",cpu="total"}) > 1
count_over_time(container_cpu_usage_seconds_total{job="<job>",instance="<private instance>",cpu="total"}[1m])
aiops_docker_container_restarts_total{site="<site>",source="<source>"}
aiops_docker_container_started_at_seconds{site="<site>",source="<source>"}
```

range query의 step=5s 자체는 실제 5초 scrape 증거가 아니다. `/targets`의 interval=5s/timeout=4s, loaded group interval=5s 및 raw sample timestamp 차이·freshness·공백을 함께 확인한다. capture gap·API warning·빈 응답·0은 서로 다른 결과로 기록한다. `honor_labels=true`는 producer label 보존이고 `honor_timestamps=false`는 scrape 시간 사용이며 인수 증거를 만드는 기능이 아니다. [Prometheus 공식 설정](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)

LogQL 예시:

```logql
{site="<site>",source="<docker source>",service="backend",runtime="container",target="<실제 Docker name>"}
{site="<site>",source="<host PG source>",service="db",runtime="host",target="<실제 PG target>"}
{job="aiops-llm",site="<site>",source="<source>",service="<service>",runtime="<runtime>",target="<target>"}
```

자연 발생한 승인 범위의 경보에 대해 다음 증거를 **같은 alertname + 다섯 identity + startsAt/fingerprint**로 연결한다.

1. 원본 producer 단위/ID/name/로그 stream과 시간 동기화 증거.
2. 정확한 식·for·keep_firing_for·5초 interval의 loaded definition 하나. 동일 정의 중복 또는 기존 광역 룰 동시 로딩은 FAIL.
3. 시간창 전체 표본 및 pending→firing 증거. instant expression이 true인 것만으로 for 통과로 보지 않는다.
4. Prometheus/Loki firing→Alertmanager 개별 alert identity. AM retry/송신 로그와 Pipeline 수신을 대조한다.
5. source-aware RCA의 `identity_status=resolved`, 실제 사용 query/stream/series, 모델 호출 성공 여부. Ollama tags 목록 존재는 추론 성공 증거가 아니다.
6. Loki read-back의 원래 startsAt/fingerprint·다섯 identity·schema_version=2.0·근거·결과 확인. Pipeline 메모리 history나 push HTTP 성공만으로 저장/전체 E2E를 인수하지 않는다.
7. unknown source는 evidence/LLM 호출 0, confidence=0이며 자동 조치 0이어야 한다. 이 부정 경로는 이번에는 오프라인 fixture로만 확인했다.

실제 경보가 없으면 FIRING/ALERT_DELIVERED/RCA는 UNVERIFIED이다. 이를 채우기 위해 시나리오·재시작·SQL/부하 주입·alert POST를 실행하지 않았다. 추후 통제된 trigger가 필요하면 운영자의 별도 승인과 시나리오 담당자 절차가 선행되어야 한다. 기존 Heldout/주입 파라미터를 이 runbook에서 사용하지 않는다.

## 9. 배포 전 BLOCKED 게이트

| 게이트 | 해제 증거 / 담당 |
|---|---|
| GC inventory와 이미지 | 실제 daemon/project/name/full ID/VM/cgroup/메모리 한도, 검토한 immutable digest / GC 운영자 |
| cAdvisor Desktop 호환성 | raw id/cpu=total/full-label memory/network namespace/freshness/전체 coverage / GC 운영자 |
| Private metric pull | 승인된 Serve 또는 기존 private proxy, JH→GC ACL·연속 GET / 양 PC 운영자 |
| 로그 identity 이행 | 실제 driver label 전달, site/source/target stream, 출력 채널 query 호환성 / GC+JH |
| host PG 별도 계약 | 실제 PG target/서비스/data path, dedicated authenticated receiver, host 로그 labels. node/DB exporter 입력은 별도 / GC+JH |
| 실제 bindings | 재생성 후 ID를 반영한 profile/bindings/env 해시와 exact scope 검증 / 통합 담당 |
| 전체 M5 coverage | 미포함 network/nginx/PG/container DB 및 기존 scrape coverage 처리, complete candidate 승인 / 룰 담당 |
| loaded cadence/중복 | 실제 5초 scrape/evaluation, 한 daemon 한 endpoint, metadata join 유일성 / JH |
| AM→Pipeline→Loki | 동일 identity/startsAt/fingerprint의 firing·전달·실제 추론·read-back / JH |
| Slack(데모에 필요할 때) | notification-only v2 소비자 구현·서명·멱등성·실제 송신 증거 / 후속 담당 |
| 배포 승인·원복 준비 | effective config/image/state 백업, 변경 시간, 위험 수용·원복 실행자 지정 / 양 PC 운영자 |

위 항목을 실환경 PASS로 계산한 것은 없다. 특히 현재 부분 JH 후보를 기존 운영 전체에 그대로 적용하면 누락 룰 및 기존 scrape coverage가 사라지므로 **전체 교체 금지/BLOCKED**이다.

## 10. 원복 절차와 운영 위험

현재는 아무것도 배포하지 않아 운영 원복이 필요하지 않다. 향후 승인된 적용의 원복 단위는 변경 전 보존한 effective Compose/config/image/bindings/Serve 설정이다.

1. JH는 후보 alert evaluation/scrape부터 변경 전 승인 구성을 복원해 잘못된 신규 경보 확산을 멈춘다. 기존 광역 룰에 새 GC scrape만 남지 않도록 rule/scrape를 함께 원복한다.
2. Pipeline/Fluentd/AM은 이전 image digest와 config/env를 함께 복원한다. 이전 Pipeline이 name-only 경로라면 자동 조치·Slack은 disabled 상태를 유지하고 운영자 인수를 받는다. 새/옛 로그 schema의 query 차이를 기록한다.
3. GC는 이번에 추가한 Serve listener만 `tailscale serve --bg --tcp=$ApprovedTailnetPort off`로 제거한다. 전체 `serve reset`을 사용하지 않는다. 이번 telemetry 프로젝트만 승인된 stop 명령으로 중지하며 다른 앱/DB는 건드리지 않는다.
4. logging override를 되돌리는 앱 재생성은 원래 설정과 대상 서비스별로 별도 승인받는다. 재생성 시 ID가 또 바뀌므로 대응 binding도 원복/재인수한다.
5. Fluentd buffer/Fluent Bit state DB·storage, Prometheus/Loki data, remediation ledger 및 증거는 삭제하지 않는다. `down -v`, volume prune, 기존 Worktree 삭제, `git reset --hard`, `git clean`을 원복 수단으로 쓰지 않는다.
6. 정상 readiness·기존 rule/target inventory·새 scrape 미잔존·원래 로그 전송·자동 조치 0을 read-only로 확인한다. 이미 발송된 경보/Slack/분석 결과는 원복으로 사라지지 않으므로 감사 기록을 남긴다.

운영 위험은 cAdvisor privileged/host mounts와 Docker socket 접근, Windows Docker Desktop 미지원, collector 수집 시간 초과, label 전환으로 인한 로그 query 단절/이중 적재, 앱 재생성 중 로그 손실, source/binding 오기입, 광역 룰과 새 scrape 혼합, Tailscale 기존 listener 충돌 및 coverage 축소다. socket의 `:ro` mount는 Docker API 권한 경계가 아니며 collector 코드의 고정 GET allowlist만으로 호스트 전체 위험이 없어지는 것은 아니다. 이 위험은 배포 검토 대상이며 이번 작업에서 운영 권한을 확장하지 않았다.

## 11. M5-B 최종 판정

**최종 인수 불가(BLOCKED).** 세 작업과 구현 가능한 identity/telemetry 연결은 별도 Worktree에 보존·통합했고 오프라인 검증은 통과했다. 현재 산출물은 실측 profile을 채워 검토할 코드와 절차이며 운영 배포 승인이나 실환경 E2E PASS가 아니다. 실제 수집·전체 rule coverage·정확한 cadence·AM 전달·Loki read-back 게이트를 충족한 후 M5-B를 다시 판정해야 한다. commit/push/PR, 실제 배포, 실제 Docker/DB 변경, 시나리오 실행, Slack 송신은 수행하지 않았다.
