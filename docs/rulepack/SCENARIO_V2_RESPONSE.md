# 시나리오 v2 탐지·대응 룰팩 (#85)

## 구현 범위

2차 A군의 새 관측 신호를 `tools/rulepack/scenario_v2.py`에서 생성하고 기존
`prepare_release.py`의 source-aware 배포 후보에 합친다. 실제 서비스에 룰을 로드하거나
조치를 실행하는 명령은 생성기에서 호출하지 않는다. 기존 운영 룰 파일을 직접 덮어쓰지 않는다.
기존 M5 후보와 겹치는 4xx 경보만 V2ReconScan으로 교체해 중복 발화를 피한다.

Remediation의 `response_profiles.py`는 새 신호의 대응 범위를 검증한다. 시나리오 이름,
정답 레이블, injected marker로 실행할 조치를 고르지 않는다. 분석이 추천한 조치가
정확한 사건·identity·대상에 묶여 있는지 검증한 다음 기존 정책·실행기로 넘긴다.
새 신호의 변경 조치는 `propose_rca_action`, `propose_manual_action`, `propose_plan`,
`replan_action`의 기존 엄격 계약을 사용하며, 자동 실행 플래그가 켜져 있어도 승인 대기한다.

| 2차 A군 | 탐지 신호 | 대응 범위 | 정상 대조·한계 |
|---|---|---|---|
| S1-b 취약점 스캔 | V2ReconScan: frontend 4xx 1분 >50 | NONE/NOTIFY | C-l 산발적 404. 요청량 증거이며 침해 성공을 뜻하지 않음 |
| S2-b C2 비컨 | V2RepeatedExternalConnections: 허용 목록 밖 동일 목적지에 5분 내 서로 다른 연결 ≥3, 연결당 송신 0~4096바이트 | NONE/NOTIFY, RCA 근거가 있는 ISOLATE 제안·승인 | C-j는 공유 allowlist의 endpoint/service로 제외. 반복 연결을 탐지하며 주기성·C2 의도는 단정하지 않음 |
| S2-d 내부 정찰 | V2InternalPortScan: 2분 내 내부 IPv4 IP/port 조합 ≥6 | NONE/NOTIFY, ISOLATE 제안·승인 | 정상 DB·MinIO 반복 연결은 endpoint 수가 증가하지 않음. 허용 서비스도 포트 탐색 대상에 포함 |
| S2-e DB 대량 조회 | V2DBReadSurge: 지정 DB pg_stat_database_tup_returned rate[2m] >10000/s, 30초 지속 | NONE/NOTIFY | C-h 백업도 일치 가능. DB 행 방문 수이며 반출 행 수·공격자·세션을 식별하지 못함 |
| F1-a CPU 과부하 | 기존 source-aware HighCpuUsage | 기존 THROTTLE 정책·승인/TTL 복구 | C-b 짧은 부하와 기존 for 경계 회귀 유지 |
| F1-c OOM 반복 재시작 | 기존 ContainerRestarted·HighMemoryUsage | 기존 RESTART 제안·승인 | C-d 재시작 1회와 구분. 재시작 반복이 OOM 원인임을 보장하지 않음 |
| F3-b 잘못된 환경변수 | V2DependencyErrors 및 기존 5xx·재시작 신호 | NONE/NOTIFY, 근거·불변 배포계획이 있는 RESTART/RECREATE/ROLLBACK 제안·승인 | C-d 정상 배포 오류 없음. SDK/연결 오류 없이 실패하는 설정은 이 룰로 보장하지 않음 |

로그인 대입(S1-c)도 V2LoginBruteForce(2분 실패 ≥6)로 보완한다. 집계 경보에는
잠글 계정이 없으므로 LOCK_ACCOUNT로 추정 연결하지 않는다. C-e 정상 오입력은 빈도 경계로 검증한다.
F2-a MinIO 중단은 backend의 MinIO/S3 SDK·연결 오류로 증상을 관측한다.
그 경보의 identity는 backend이므로 이를 MinIO RESTART 대상으로 바꾸지 않는다.
S2-c 반출은 V2UnauthorizedDataTransfer·V2UnauthorizedTransferEarly로 기존 공유 allowlist의 바이트 임계값을 유지한다.
최종 이벤트는 connection_id별 최대 송신량으로 중복 전달을 제거하며, 조기 이벤트는 기록된 bytes_threshold가 정책 임계 이상인 경우만 인정한다.
C-a 인가 전송은 같은 허용 목록으로 제외한다.
기존 ISOLATE·RESTART·THROTTLE·DB·배포 실행기는 재사용하며 새 OS 방화벽 실행기를 만들지 않는다.
BLOCK_EGRESS/BLOCK_PATH/RATE_LIMIT 및 2차 B군(`BATCH2_DEFERRED.md`)은 미지원 범위를 유지한다.

## 관측 범위와 설정

1. `docs/rulepack/integration/profile.template.json`을 저장소 밖에 복사하고 실제 inventory를 확인한다.
   Docker의 전체 ID와 site/source/target, 호스트 PG의 별도 source를 확인한 뒤 attestation을 설정한다.
2. `docs/rulepack/integration/scenario-v2.template.json`도 저장소 밖에 복사한다.
   network의 `observer`, `observer_instance`가 지정 backend 컨테이너를 관측하는지 확인하고
   `mapping_verified=true`로 한다. 없으면 `network=null`로 두며 네트워크 룰과 바인딩은 생성하지 않는다.
   이름만 같은 다른 PC의 연결은 포함하지 않는다. observer 매핑은 운영자의 검증 사항이다.
3. DB 읽기 룰을 쓰려면 `postgres_exporter`를 다음 구조로 설정한다(아래는 합성 예시).
   host_postgres inventory가 있어야 하며, 실제 exporter의 해당 DB·카운터·단위를 확인해야 한다.

```json
{
  "job": "verified-postgres",
  "instance": "verified-pg.invalid:9187",
  "database": "verified_database",
  "metrics_verified": true
}
```

생성된 Prometheus scrape가 정확한 host identity를 붙인다(`honor_labels=false`).
이 source는 Docker source와 분리된다. 기존 LLM host 수집기는 PostgreSQL 전용 지표를
수집하지 않으므로 상세 DB RCA는 경보·PG 로그에 의존한다. LLM 담당자의 전용 PG 지표
collector 확장은 별도 제안 사항이며 이번 변경에 포함하지 않는다.
DB exporter 설정이 null이면 DB 룰은 빠지고 manifest에 제외 사유가 남는다.

```sh
python tools/rulepack/prepare_release.py \
  --profile /absolute/private/inventory.json \
  --scenario-profile /absolute/private/scenario-v2.json \
  --output /absolute/new-review-bundle
```

기존 번들 경로에는 덮어쓰지 않는다. 생성물에는 Prometheus/Loki 룰, source 바인딩,
읽기 전용 compose override, 설정 해시와 남은 인수 조건이 포함된다.
network allowlist는 `aiops/policy/allowlist.yml` 한 곳에서 읽는다. 정책을 바꾸면 재생성한다.
관측 범위가 불명확하면 전체 PC/서비스를 탐지하도록 fallback하지 않는다.

## 신호·평가 해석

임계값은 초기 운영 후보이며 시나리오 강도나 정답에 맞춰 최적화한 값이 아니다.
독립된 정상 데이터로 오탐·지연을 평가하고 동결한 뒤 변형·heldout에 사용한다.
네트워크는 최종 connection 이벤트만 사용한다. connection_threshold와 중복 합산하지 않는다.
관측기·출발 컨테이너·event_type·목적지 타입을 검증하며 connection_id로 중복 전달을 합친다.
내부 스캔은 RFC1918 IPv4만 대상으로 하고 IPv6·비공개 IPv4 외 경로는 범위 밖이다.
닫히지 않는 연결은 최종 conn.log가 생길 때까지 지연될 수 있다.
SDK 오류 룰의 메시지 형식과 PG counter 가용성은 실제 배포 환경에서 확인해야 한다.

`scenarios/v2/registry.py`의 평가 정답은 실행기 존재 여부만으로 변경하지 않는다.
특히 S2-e의 평가 정답 ISOLATE와 이 DB aggregate 경보의 NOTIFY는 동일하지 않다.
DB 경보만으로 backend 컨테이너나 세션을 추정하면 잘못된 조치가 되므로 보류한다.
공격 출발 서비스·정확한 DB 세션을 연결하는 별도 증거가 있을 때만 기존 실행기용
사건/계획을 새로 검증할 수 있다. 이 제한을 평가에서 성공 조치로 부풀리지 않는다.

## 검증과 배포 인수

공식 native LogCLI 3.7.1의 fmt·stdin 필터와 promtool 3.7.3으로 합성 로그,
목적지 allowlist, 다른 observer/컨테이너, JSON 타입·파싱 오류, DB rate 경계·reset·다른 DB,
source 라벨 보존을 확인한다. stdin은 실제 stream label 선택·Loki range 집계를 실행하지 않는다.
네트워크 집계 자체의 실제 Loki Ruler 평가는 배포 인수에서 확인해야 한다.
Remediation 격리 suite는 실제 Docker·DB·Slack·네트워크 변경을 차단한다.

```sh
# native 도구 경로는 신뢰한 로컬 바이너리로 지정한다.
M2_PROMTOOL=/path/to/promtool M2_LOGCLI=/path/to/logcli \
M3_PROMTOOL=/path/to/promtool M3_LOGCLI=/path/to/logcli \
M4_PROMTOOL=/path/to/promtool M4_LOGCLI=/path/to/logcli \
M5_PROMTOOL=/path/to/promtool M5_LOGCLI=/path/to/logcli \
python -m unittest discover -s tools/rulepack/tests -v
python testing/run_isolated.py remediation
PYTHONPATH=scenarios python -m unittest discover -s scenarios/v2/tests -v
```

생성기 옵션을 생략한 기존 사용법도 유지한다. 기본 Remediation disabled와
`deployment_allowed=false`, `runtime_accepted=false`는 실제 인수 전 유지한다.
실제 inventory → 룰 로드·중복 없음 → 공격/장애와 정상 대조군 → Alertmanager → Pipeline RCA
→ signed proposal → Slack 승인 → 대상 바인딩 → 실행 효과·복구를 별도로 확인해야 한다.

### 2026-11-28 로컬 결과 (기준 main c6bd125)

- 룰팩: 133개 모두 PASS, skip 0. native LogCLI 3.7.1·promtool 3.7.3 포함.
- Remediation: 격리 suite 525개 모두 PASS.
- Pipeline: 격리 suite 235개 중 1 skip, 실패 없음(실제 Gemini smoke opt-in 미설정).
- scenarios/v2: 181개 중 1 skip, 실패 없음(비공개 heldout 폴더가 없는 저장소 기본 상태).
- git diff --check PASS. trail check: 충돌 없음; 음성 테스트에 나타나는 차단 대상 조치 문자열을 1건 참고 경고로 표시했으며 해당 테스트는 실행 0회를 검증한다.
- 실제 서비스 배포·룰 발화·LLM 호출·Slack 승인·DB/Docker 조치는 수행하지 않았다.
