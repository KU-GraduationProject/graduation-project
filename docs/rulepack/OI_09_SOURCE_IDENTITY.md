# OI-09 — Source-Aware Identity 및 Pipeline RCA 소비 경로

## 상태와 작업 경계

2026-11-11 KST. **소비 경로 구현 및 오프라인 회귀 검증 완료 / 실제 source 매핑·라벨·배포·E2E는 UNVERIFIED**이다. 검증되지 않은 source를 다른 PC의 데이터로 대체하지 않는다. 실제 환경의 관측이 없다는 판정은 아니다.

- 브랜치: `feat/oi09-source-identity`
- 전용 worktree: `/Users/kwonjunhui/Desktop/graduation/oi09-source-identity`
- 기준 HEAD: `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`
- 시작 원본은 `main`, tracked 변경 0개, `docs/rulepack/`·`tools/rulepack/` untracked였다. 기존 별도 detached worktree 2개가 존재했으며 그 파일은 수정하지 않았다.
- 로컬 `origin/main...HEAD`는 `0/0`이었다. shell GitHub DNS 실패 후 GitHub connector의 `fetch_commit(main)`으로 원격 main도 같은 SHA임을 확인했다. fetch/commit/push/PR은 수행하지 않았다.
- 원본은 `/Users/kwonjunhui/Desktop/graduation/graduation-project`에 그대로 두었다. 필요한 문서·코드·설정은 `/private/tmp/oi09-input-snapshot-20261111`에 복사하여 원본/복사본 SHA256을 비교했다. 코드 원본은 기준 Git blob과도 일치했다. 해시는 아래 보존 표에 기록했다. 다른 세션의 후속 변경을 되돌리지 않는다.
- 변경 범위는 `aiops/pipeline/`, 그 단위 테스트, 이 문서뿐이다. GC collector·Compose·Prometheus/Loki/AM 배포 구성·M1~M5 룰·M5-B 도구는 수정하지 않았다. Docker/DB 조작, reload/배포, 시나리오 실행 및 Heldout 열람은 수행하지 않았다.

## AS-IS / TO-BE

| 구간 | AS-IS | TO-BE |
|---|---|---|
| Webhook | labels 4개만 모델에 남음 | site/service/runtime/target/source/job/instance/name/id/observer를 선언하고 extra labels도 보존 |
| 대상 해석 | annotation container → 전역 alias map 또는 PC1 Docker | 검증된 `OBSERVATION_BINDINGS`의 source 조건과 명시된 identity가 모두 일치해야 사용 |
| 불명 대상 | HighCpuUsage를 전역 top CPU 이름으로 대체 | 자동 대체 제거. UNKNOWN과 이유를 결과에 기록 |
| dedup | alertname + container, 300초 | alertname + observation identity + 원래 source/target 식별 필드와 추가 labels, 300초 유지 |
| 앱 로그 | `{service="db"}` | 검증된 site/service/runtime/target 또는 container_name exact selector, 동일 시간창 series 존재 확인 |
| 메트릭 | PC1 로컬 inspect → id, 실패 시 job 미제한 host fallback | site에 연결한 정확한 job/instance 및 원격 cAdvisor full id만 사용. host/container 쿼리 분리 |
| 네트워크 | src/dst service만 조회 | 기존 stream label + JSON observer/observer_instance 필터, 응답 body에서 runtime/target 재검증 |
| RCA | container와 LLM 결과만 저장 | v2 envelope에 실제 identity, 원래 labels/annotations, 사용 selector·쿼리·실제 series/stream labels·가용성 상태 저장 |
| 후속 조치 | 이름만 전달 | 현재 Remediation이 site/source를 소비하지 않으므로 이번 경로의 전달 보류 |

`site`는 관측 대상 배포 환경이고 `source`는 producer/관측 출처이다. JH 저장소에 들어온 GC 데이터를 JH 관측으로 바꾸지 않는다. 예전 Fluentd `source=stdout|stderr`는 출력 채널이다. 원래 alert labels에는 보존하지만 observation source로 승격하지 않는다. `rulepack_source`도 룰 파일 출처이며 PC/producer 증거가 아니다.

## 코드와 해석 계약

- `identity.py`: `ObservationIdentity`, 검증된 `ObservationBinding`, 설정 파싱, 충돌 검사, source별 dedup, list/dict 호환 evidence 결과.
- `main.py`: webhook labels 보존, 먼저 identity 해석 후 collector 호출, 전역 top CPU 추측 제거, v2 RCA 저장. source 미확인 또는 scoped evidence 전체 부재이면 LLM을 호출하지 않고 `confidence=0`, `NONE`을 남긴다.
- `correlation.py`: 시간창 context에 identity/binding 추가. legacy `resolve_service`도 host placeholder에 Docker 요청을 보내지 않는다. RCA는 이 legacy resolver를 호출하지 않는다.
- `collector/logs.py`: 필수 scope의 series가 없으면 `scope_unavailable/no_matching_series`, 조회 범위를 넓히지 않는다. 실제 반환 stream labels도 다시 검사한다.
- `collector/metrics.py`: Docker 의존 제거. container는 cAdvisor 지표만, host는 명시한 node exporter의 OS 지표만 조회한다. 정상 empty, API 오류, 잘못된 응답, source 불일치 및 부분 수집을 구분한다.
- `collector/network.py`: observer 출처와 endpoint runtime/target을 보존·검증한다. host는 `src_target`/`dst_target`이 있어야 하며 null container를 host target으로 추측하지 않는다.
- `prompt/builder.py`: identity와 근거 가용성을 전달한다. host를 Docker container로 설명하지 않으며, OS 지표를 PostgreSQL 프로세스 사용량으로 주장하지 않도록 명시한다.

`TARGET_SERVICE_MAP`은 기존 설정을 계속 파싱하지만 service 이름의 힌트만 제공한다. 이 전역 map으로 site/source/runtime을 확정하거나 원격 데이터를 조회하지 않는다. source가 빠져도 job/instance 또는 검증된 site/target 매핑이 유일하면 binding에서 보완할 수 있다. 아무런 source 근거가 없는 이름 하나는 매핑하지 않는다. 서로 충돌하는 site/runtime/source/name/id, 복수 binding 일치는 수집을 차단한다.

`unknown (host-level)`과 `id="/"`는 host 신호이다. cgroup의 name을 앱 container target으로 쓰지 않는다. 명시 target 없는 root 경보는 `service=host`인 host binding에만 연결할 수 있다. node source라는 이유만으로 PostgreSQL 서비스에 연결하지 않는다. host PG17은 `runtime=host,service=db` 및 별도 target을 가진 binding으로 처리한다. container PG16은 다른 runtime/target/id이다. PG 버전은 alias에서 추정하지 않으며 실제 인벤토리 인수가 필요하다.

## 설정 및 B 세션 전달 계약

새 환경변수 `OBSERVATION_BINDINGS`는 JSON 배열이고 기본값은 `[]`이다. **미설정 상태에서 이 코드를 배포하면 기존 경보는 수신하지만 source 미확인 RCA만 기록한다.** 기존 Compose에 자동 설정하거나 실제 주소를 추정하지 않았다.

각 row의 `identity`에는 site/service/runtime/target/source가 필요하다. `match`는 alert labels/annotations의 exact match이며 source, observer+observer_instance, job+instance 또는 site+target 중 하나로 출처를 입증해야 한다. source=stdout/stderr만으로 매핑할 수 없다. 서로 다른 target에 같은 match를 사용할 경우 alert의 target/service/id로 유일하게 구분되어야 한다. 그렇지 않으면 `ambiguous_source`이다.

다음은 **실제 값이 아닌 구성 템플릿**이다. 꺾쇠 안을 실제 검증값으로 교체하기 전 적용하지 않는다. logs/metrics/network 중 미인수 경로는 `{}` 또는 생략으로 독립적으로 비활성화할 수 있다.

```json
[
  {
    "identity": {
      "site": "<GC 관측 환경>",
      "service": "backend",
      "runtime": "container",
      "target": "<실제 GC container 이름>",
      "source": "<이 관측 대상을 식별하는 producer 계약 ID>"
    },
    "match": {"job": "<경보에 남는 실제 job>", "instance": "<경보에 남는 실제 instance>"},
    "logs": {
      "site": "<GC 관측 환경>", "service": "backend", "runtime": "container",
      "container_name": "<실제 GC container 이름>"
    },
    "metrics": {
      "job": "<GC cAdvisor job>", "instance": "<GC cAdvisor instance>",
      "id": "/docker/<검증한 64자리 lowercase hex full id>"
    },
    "network": {"observer": "<실제 observer>", "observer_instance": "<해당 observer 배포 인스턴스>"}
  }
]
```

host PostgreSQL row는 `service=db,runtime=host,target=<실제 PG17 인스턴스>`로 별도 작성한다. logs에는 기존 `service=db,runtime=host`에 `site,target`이 필요하다. host metrics에는 실제 GC node exporter job/instance를 지정하고 `id`를 넣지 않는다. 이것은 **DB 연결 수·PG 프로세스 CPU가 아닌 호스트 OS 문맥**이다. DB exporter/Hikari 전용 수집은 OI-05의 별도 계약이며 이번 범위를 확장하지 않았다.

| 생산 구간 | 재사용하는 현행 필드 | B/후속 소유자에게 필요한 계약 |
|---|---|---|
| Prometheus → alert | job/instance, name/id가 남는 식 | job/instance가 어느 site/runtime을 관측하는지 명시. source가 서로 다른 동명 target을 합산하지 않고 경보에 출처가 남아야 함 |
| GC cAdvisor | container 자원 지표와 id | 실제 job/instance, `/docker/<full id>`와 target 이름의 대응, 유일성 및 재생성 시 갱신. PC1 pipeline metadata id로 대체 금지 |
| GC metadata | container_name_info, restart/started_at/OOM 계열 | 같은 GC cAdvisor 범위의 id/name/service, site/source의 대응을 인수. 기존 PC1 `/metrics`는 로컬 producer이므로 원격 identity 근거로 사용하지 않음 |
| Docker 앱 로그 → Loki | service/runtime/container_name, source=stdout/stderr | 현행 값에 site 추가 필요. 출력 채널 source와 관측 producer를 구분. 같은 site에서 target이 여러 개이면 실제 container_name으로 분리 |
| host PG17 로그 → Loki | service=db/runtime=host/log_format | site 및 PG 인스턴스 target 추가 필요. 현행 설정에는 둘 다 없으므로 host 로그 수집은 미인수 상태에서 차단됨 |
| Network event | stream의 log_type/src_service/dst_service, body의 observer와 endpoint runtime/container | body observer_instance를 실제 배포 단위로 채우고 site와 명시 연결. host endpoint는 src_target/dst_target 필요. 새로운 Loki label을 전제하지 않음 |
| Alertmanager | 각 alert.labels, annotations | 동일 alertname/target이어도 site/source 보존. webhook에 모든 alert가 전달되는지 확인. group_by 설정 변경은 이번 범위 밖 |

현재 Fluentd 설정에는 앱 로그의 `site`가 없고 PG 로그의 `site,target`이 없다. 따라서 이번 코드는 이 라벨이 있다고 가정하지 않으며 series preflight에서 차단한다. 추가 라벨은 본 세션에서 생산하지 않았다. producer 변경은 해당 소유자에게 위 표로 전달할 작업이다.

**룰 단계의 별도 BLOCKED:** M5 CPU의 `sum by(name)`, restart/memory의 `max by(name)`, Loki의 `sum(count_over_time(...))` 및 network `sum by(dst_ip,dst_port)`는 source 라벨을 제거할 수 있다. producer 라벨 추가만으로 복원할 수 없다. 현재 룰·임계값은 유지했다. 후속 승인된 룰 작업에서 조회 범위와 집계 키에 source를 보존하거나, 실제 단일 source만 평가하는 프로파일을 명시적으로 증명해야 한다. `rulepack_source` 또는 고정 alias만으로 이 게이트를 통과시키지 않는다.

## 가용성·저장·하위 호환성

| 상태/필드 | 의미 |
|---|---|
| identity_status=resolved | 유일한 검증 설정과 입력이 일치. 실제 배포/데이터 존재의 증명은 아님 |
| source_unknown/source_unmapped | source 근거 없음 / 알려진 일부 필드는 있으나 binding 없음 |
| identity_conflict/ambiguous_source | 입력과 binding 충돌 / 여러 해석 가능. 조회 안 함 |
| collector scope_unavailable | 필수 매핑·라벨·동일 시간창 series 미확인. reason으로 source_unknown, collector_unmapped, no_matching_series 구분 |
| collector empty | 정확한 쿼리가 성공했고 결과 0건. 정상 상태·무트래픽 증명 아님 |
| api_error/invalid_response | HTTP/API 실패 / 응답 형식 불일치. 0 값으로 대체하지 않음 |
| source_mismatch | 반환 라벨이 지정 출처와 다름. 해당 응답을 RCA에서 제외 |
| partial/truncated | 일부 쿼리 실패·경고·행 제한·network skip 등. 성공한 출처의 근거만 보존 |
| storage_status | 메모리 history의 stored/api_error. Loki 원문은 push 성공 여부를 사전에 주장하지 않음 |

기존 envelope의 `timestamp,alert_name,container,result`와 nested `LLMAnalysisResult`는 유지했다. 새 필드는 `schema_version=2.0,identity,identity_status,alert_labels,alert_annotations,evidence_sources`이다. 미확인 identity 필드는 문자열 `UNKNOWN`으로 직렬화한다. host의 legacy `container` 및 `target_container`는 `unknown`이며 실제 host target은 `identity.target`에 있다. 따라서 host 결과 소비자는 `container`만 읽지 말고 identity를 읽어야 한다.

Loki 결과 stream은 기존 job/alert/target_container/threat_level을 유지하고 site/service/runtime/source를 추가한다. 실제 target과 입력 job/instance 및 증거 selector/실제 labels는 JSON body에 보존한다. timeline body에도 identity/evidence_sources를 남긴다. 앱 Loki `container` legacy 라벨을 조회 identity로 되살리지 않았다. 저장 HTTP 실패를 확인하고 성공 timeline을 발행하지 않도록 수정했다. 기존 JSONL 파일은 쓰기 경로가 아니며 수정하지 않았다.

Collector 반환은 list/dict 호환이며 메타데이터는 `.report`에 있다. legacy MetricsCollector 인자도 수용하지만 이름/id만 주는 호출은 이제 scope_unavailable이다. 주기적 스캔은 현재 비활성화되어 있으며 binding 없는 기존 periodic context도 조회하지 않는다. 다시 활성화하려면 binding별 순회가 먼저 필요하다.

**소비자 영향:** Remediation은 action_targets의 컨테이너 이름만으로 정책·실행 대상을 정한다. source/runtime을 무시하는 그 소비자에게 v2 경보를 전달하면 동명 타 PC/host 조치를 막을 수 없다. 이에 이번 webhook RCA 경로는 Remediation 전달을 보류한다. Slack도 해당 전달 경로에 의존하므로 함께 영향받는다. 기존 서명 전달 helper의 단위 계약은 유지했지만 실제 webhook에서는 호출하지 않는다. 재활성화는 Remediation의 site/source/host 계약 인수 후 별도 변경이다.

## 테스트 결과와 재현

변경 전 기존 Pipeline 테스트 **100 PASS**. 변경 후 기존 회귀와 OI-09 신규 **31개**를 합해 **131 PASS, SKIP 0**. 모든 source/IP/target은 합성이며 HTTP는 MockTransport/AsyncMock이다. 실제 Docker·DB·LLM 또는 운영 API를 호출하지 않았다.

기존 service-only 조회를 기대하던 테스트 1개는 source 미확인 시 조회하지 않는 변경 계약으로 대체했다. timestamp 정렬은 새 scoped 로그 테스트로 계속 검증한다. network 기존 fixture에는 실제 응답 계약의 status/resultType과 observer_instance를 추가하고 scope를 명시했다. 시간창·양방향·중복 제거·threshold/final 구분·파싱·오류·truncation 검사는 유지했다. 구현 실패를 허용하도록 assertion을 약화하지 않았다.

| 필수 사례 | 오프라인 검증 |
|---|---|
| 동명 서비스가 GC/JH에 존재 | Loki selector의 site 분리, 다른 observer 이벤트 제외 |
| 같은 alertname/target, 다른 site/source | 다른 dedup key와 별도 history. 동일 source는 299초 억제/300초 재수신 |
| host PG17 / container PG16 | 다른 identity/runtime/target selector, host=node 지표, container=cAdvisor 지표만 사용 |
| source/runtime 누락, 기존 webhook | 입력 수용. 검증된 job/instance로만 보완하거나 UNKNOWN 결과 저장. LLM/임의 조회 없음 |
| unknown (host-level), root id/name | Docker 대상 해석·top CPU 대체 없음. root를 PG 서비스로 귀속하지 않음 |
| Loki 라벨 미존재 | series preflight 후 중단, service-only fallback 없음 |
| Prometheus job/instance/id 불일치 | identity conflict 또는 source_mismatch, 다른 source 값 제외 |
| API 실패 / 정상 empty / 부분 성공 | 별도 상태, 실패를 숫자 0으로 채우지 않음, 검증된 성공 시계열은 보존 |
| RCA identity 보존 | webhook → context → 실제 collector selector → prompt → history/Loki payload 및 timeline body 코드 확인 |
| 소비자 영향 | nested LLM 결과 재검증, 기존 HMAC helper 회귀, host/source-aware RCA의 Remediation 호출 금지 |

```shell
# 저장소 루트. 활성화된 테스트용 Python 환경에서 실행한다.
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s aiops/pipeline/tests -v
git diff --check
```

이번 실행 Python은 원본 `venv/bin/python`(Python 3.12)을 읽기 전용으로 사용했고 로그는 `/private/tmp/oi09-baseline-tests.log`, `/private/tmp/oi09-all-tests.log`에 있다. LogQL 새 observer JSON 필터의 실제 Loki 서버 평가와 Prometheus 원격 시계열 평가는 수행하지 않았다. 시스템에 logcli/promtool 실행파일도 없으므로 단위 테스트를 native 엔진 검증으로 간주하지 않는다.

## M5-B 재검증 및 실제 적용 전 절차

아래는 **향후 운영자가 수행할 절차**이고 이번에 실행하지 않았다.

1. 실제 JH/GC 인벤토리에서 site, runtime, PG17 host target과 PG16 container target, cAdvisor full id, exporter job/instance, observer 배포 인스턴스를 확정한다. 수집 성공과 빈 결과를 구분한다.
2. producer 소유자가 위 라벨 계약을 구현·배포한 뒤 기존 읽기 전용 M5-B 경로로 실제 label keys/값 및 같은 시간창 series를 확인한다. 원격의 현재 source를 로컬 Mac에서 추측하지 않는다.
3. 룰 집계 이후 AM alert.labels에 source가 남는지 확인한다. source가 사라진 룰은 후속 source 보존 작업을 완료하거나 인수에서 BLOCKED로 남긴다. 이번에 M1~M5 식/임계값을 바꾸는 절차는 없다.
4. 실제 확인값만으로 `OBSERVATION_BINDINGS`를 작성한다. Pipeline 전용 환경 설정으로 주입하고 파싱 및 유일성을 오프라인에서 검증한다. 본 세션은 Compose/배포 파일을 수정하지 않았다. 현재 binding은 비어 있다.
5. 격리된 테스트 환경에서 이 테스트 묶음을 실행하고, 실제 Loki에서 observer JSON 필터와 series/query_range 계약을 평가한다. 반환 labels/body가 site/runtime/target/source와 일치해야 한다. 권한/API 실패를 empty로 판정하지 않는다.
6. 담당 배포 절차로 Pipeline 이미지를 빌드·교체하고 실제 이미지/환경 매핑/OpenAPI를 대조한다. 운영 reload·시작·재시작·시나리오 주입은 이번 권한 범위에 포함하여 실행하지 않았다. 이전 이미지 및 환경 설정은 보존하고 문제 시 담당 절차로 되돌린다.
7. 우선 기존 자연 발생 사건으로 AM → webhook → collector selectors → Ollama 결과 → Loki 신규 v2 JSON을 대조한다. GC/JH 동명, 같은 site의 다른 producer, host PG17/container PG16, root host, source 누락, API 실패를 각각 확인한다. queued 응답이나 confidence=0 fallback은 성공 RCA가 아니다.
8. host 결과는 `job=aiops-llm,site=<실제 site>,runtime=host,service=db`와 JSON `identity.target/source`로 찾는다. 예전 target_container=leafy-db만으로 인수하지 않는다. 두 PC에 대한 dedup 독립성과 300초 정책도 확인한다.
9. Remediation/Slack 경로가 보류됨을 운영 인수에 반영한다. site/source를 이해하는 후속 소비자 인수 전에는 자동 전달을 켜지 않는다. 결과 저장 실패와 source 미확인을 별도 운영 상태로 처리한다.

## 남은 BLOCKED / UNVERIFIED

- **BLOCKED — 실제 binding 값:** 원격 site/job/instance/id·observer_instance·PG target 인수값이 없다. 가짜 운영값을 등록하지 않았다.
- **BLOCKED — Loki producer 라벨:** 앱 site와 host PG site/target이 현행 저장소 설정에 없다. B/수집 경로 소유자의 변경·인수가 필요하다.
- **BLOCKED — 룰의 source 소실:** 현행 집계가 버린 출처를 소비자가 복원할 수 없다. source 없는 경보는 계속 보류한다.
- **BLOCKED — 후속 자동 대응/통지:** 현재 name-only Remediation 계약. 이번 작업에서 다른 소비자 파일을 수정하지 않았다.
- **UNVERIFIED — 실제 엔진/전송/RCA:** 실제 GC/JH 데이터에 대한 selector/LogQL/PromQL 평가, AM 전달, 실제 Ollama JSON 품질 및 신규 Loki 저장은 검증하지 않았다.
- **UNVERIFIED — 시계열·재생성:** full id 변경 시 binding 갱신, GC metadata 조인 유일성/연속성, host OS와 DB 프로세스의 구분은 실제 인수 대상이다. 현재는 바뀐 id를 다른 컨테이너로 자동 대체하지 않는다.
- legacy `/metrics` producer는 PC1 로컬 Docker를 계속 관측한다. 이번 RCA는 이를 GC metadata로 사용하지 않는다. OI-02/03의 원격 producer 구축과 별개이다.
- dedup의 프로세스 메모리 저장, 분석 전에 기록하는 기존 300초 정책, 최대 20건 history는 유지했다. 수집·LLM·저장 실패 후 300초 안 재통지가 억제될 수 있으며 영속 재시도는 이번 범위 밖이다.

## 원본 보존 SHA256

작업 시작 자료의 복사본과 원본을 비교한 값이다. 원본 tracked 코드는 기준 HEAD와도 비교했다. 종료 검사에서 원본 16개 파일의 SHA256 일치, 비소유 tracked 파일 불변, Python AST 및 `git diff --check` PASS를 확인했다. 원본 worktree의 status도 시작과 같은 untracked 두 경로였다.

| 원본 경로 | SHA256 |
|---|---|
| `docs/rulepack/M5_B_RUNTIME_ACCEPTANCE.md` | `3f17d97f57574af9639f9ae293e2195ea728042bd6a8ffbb73a3fb889647baf8` |
| `docs/rulepack/M5_A_RULEPACK_INTEGRATION.md` | `97bdcde9e97d9722c6b9424d810b70019ebb4811a17aab166acb2fde577a45ce` |
| `docs/rulepack/OBSERVABILITY_INFRA_MILESTONE.md` | `9026c770f80f4dfdf371123eda26de576852947229ee20dc8725fa41d2f6fe96` |
| `docs/rulepack/OI_01_RUNTIME_INVENTORY.md` | `3b333b4708ef90791b5f1a70a8d9cfd16dbd382f7a67fd3e0dfd96c5677227a6` |
| `docs/rulepack/M1_OBSERVABILITY_AUDIT.md` | `6a6bc9dea1fa9c7531f3b9e4740653e9f78709cfce3dfc1e1c8fa304ebc5d7ba` |
| `docs/rulepack/m5/generated/prometheus.rules.yml` | `a44cdf682e38a293595f2492a17f51371f88d88bca80e685ad70dd4a2c8ad96b` |
| `docs/rulepack/m5/generated/loki.rules.yml` | `f96b927313e31492ef0f4daf228562f9bf2851301b022c6cc548e44087527aa6` |
| `aiops/pipeline/main.py` | `965aa8491699236b5e524f19cafd5ac9347d829dfc5fd991b0cf725588e53e25` |
| `aiops/pipeline/correlation.py` | `fdea56fcc9624a8609e8a5036290ac44ac7441f5cd9ecc460664950b7233d1d9` |
| `aiops/pipeline/collector/logs.py` | `1f56ae0eff3b2f5d11895b9bc03ac95feff639c37fb0ee54600d9420921bc8dd` |
| `aiops/pipeline/collector/metrics.py` | `0b4698efc7f87c5101a68c1fbe0d90f190b4b550e85afaaca60d20054e830af9` |
| `aiops/pipeline/collector/network.py` | `5370441108d69f5da79c0468dfebadb8351f4292dfb0bc92b940c99214c73b62` |
| `docker-compose.aiops.yml` | `0cd74be9fc88ea0fcc89efce6ce6fa5688d07a40000546f8f1a83ee8ab6439de` |
| `monitoring/alertmanager/alertmanager.yml` | `82288464773b906b8b7954462d24cb63ab7f6949d18ed1d6c8825c9dd5c0d4bf` |
| `monitoring/loki/loki-config.yml` | `e9488d51cd9145522030358001e8699cf22d3f73002dfd1b06586a7f458d9a4f` |
| `monitoring/prometheus/prometheus.aiops.yml` | `b5f15232156b121b2882ab31fadef2e0bdaf3ea643b25fbeb08e8eb43ba55ecc` |
