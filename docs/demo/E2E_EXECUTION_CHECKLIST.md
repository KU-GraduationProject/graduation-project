# Leafy AIOps — E2E 당일 실행 체크리스트

기준: 2026-11-11 / GC(Windows 11, 관측 대상) + JH(Windows, AIOps 관리)

**현재: 실환경 E2E·본 촬영 BLOCKED.** 체크는 실제 관측 후에만 표시한다.
명령의 전체 설명·예상 출력·원복은 GC_JH_WINDOWS_E2E_RUNBOOK.md의 같은 STEP을 사용한다. 새 PowerShell 창에서는 메인 STEP 0.1 함수와 해당 PC의 STEP 0.2 변수를 먼저 준비한다.

## 오늘 기록할 정보

| 항목 | 실제 기록 |
|---|---|
| 시험 ID / GC 실행자 / JH 실행자 | |
| 시작·종료 UTC / KST | |
| GC/JH Git SHA + 미커밋 코드 hash | |
| 실제 image ID/digest 및 bundle hash | |
| GC site/source / Docker name/full ID | 비공개 원본에 기록 |
| host PG service/source/target | 비공개 원본에 기록 |
| Tailscale 공유·ACL 및 metric transport | 실제 주소/키는 공개 페이지 제외 |
| 선택 범위 | 전체 M5-B / 선택 SQL 경로 부분 데모 / 진단 리허설 |
| 변경 승인자·변경 목록·원복 담당자 | |

## 1. 병렬 준비 [PARALLEL]

**GC — 메인 STEP 0/1.1/3**

- [ ] 실제 앱 Compose와 private env 경로를 확인했다. 무조건 pull/reset/clean하지 않았다.
- [ ] Docker Desktop/Linux daemon, 앱 project/service/name/full ID를 기록했다.
- [ ] Windows PG17과 Docker DB를 구별했다.
- [ ] 실제 PG jsonlog/Windows Fluent Bit 경로·계정을 확인했다.
- [ ] Zeek의 backend namespace/interface와 Enricher의 observer.instance를 확인했다.
- [ ] Telemetry config/image/loopback/private transport를 확인했다. 미구축이면 BLOCKED다.
- [ ] 실제 공개 GET API의 path/parameter 및 읽기 전용 동작을 앱 담당자가 검토했다.

**JH — 메인 STEP 0/1.1/2**

- [ ] 통합 코드·미커밋 hash와 실제 Pipeline/Fluentd 이미지를 대조했다.
- [ ] Fluentd/Loki/Prometheus/AM/Pipeline/Ollama/Grafana readiness를 확인했다.
- [ ] 설정 모델과 실제 Ollama tags를 대조했다. 아직 추론 성공으로 표시하지 않았다.
- [ ] source-aware bindings가 비어 있지 않고 실제 profile과 대응한다.
- [ ] Remediation disabled, Slack/legacy 자동 전달 보류를 확인했다.
- [ ] 원래 17개·M5-A 21개·부분 GC 번들의 범위를 구분했다.
- [ ] 이전 config/image/bindings/Serve 상태·state 보존본과 원복 담당자를 확보했다.

**공통**

- [ ] 양 PC UTC/KST/동기화 상태를 확인했다.
- [ ] Tailscale online과 ping을 각 방향에서 확인했다.
- [ ] 한 PC의 localhost를 상대 PC endpoint로 사용하지 않았다.


### DAY-C1 — 준비 상태 빠른 재확인 [BATCH]

| 항목 | 설명 |
|---|---|
| 담당 PC | GC + JH |
| 운영체제 | Windows |
| 실행 터미널 | PowerShell 5.1 이상 |
| 실행 권한 | 일반 사용자 |
| 실행 위치 | $Repo (STEP 0.1에서 입력한 실제 경로) |
| 실행 구분 | 읽기 전용 |
| 실행 방식 | [BATCH] |
| 선행 조건 | 메인 STEP 0 세션·실제 경로 준비. 본 블록은 환경 초기화 대체가 아님 |
| 성공 조건 | 명령별 실제 상태를 기록. 한 항목 실패 시 다음 합류 단계 중단 |
| 실패 시 조치 | 메인 해당 STEP 또는 Troubleshooting T01~T15에서 재개 |

**① 실행 명령어**

```powershell
git rev-parse HEAD
Assert-Native
git status --short --untracked-files=all
Assert-Native
tailscale status
Assert-Native
docker ps -a --no-trunc --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}'
Assert-Native
[pscustomobject]@{utc=[DateTimeOffset]::UtcNow.ToString('o'); kst=[TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTimeOffset]::UtcNow,'Korea Standard Time').ToString('o')}
```

**② 명령어 설명**

이 블록은 한 번 복사 가능하다. native 실패는 Assert-Native에서 중단한다. 변경 파일 목록을 보여 주되 파일을 변경하지 않는다.

**③ 예상 출력 예시 — 실제 관측값 아님**

```text
실제 HEAD·변경 목록·서비스 상태·UTC/KST
```

**④ 결과의 의미**

SHA만으로 미커밋 통합 또는 배포 이미지 일치를 증명하지 않는다. 이 출력은 readiness/E2E PASS가 아니다.

**⑤ 실패 시 확인 사항**

실제 역할별 상세 점검은 메인 STEP 0~3을 수행한다. 키·주소·전체 .env는 촬영하지 않는다.

- [ ] 실행자 / 실제 UTC·KST 시각 / 결과 / 증거 파일을 기록했다.


## 2. 합류 1 — 통신·로그·메트릭 [SEQUENTIAL]

- [ ] JH 수신기 준비 후 GC→JH 24224/24225 TCP를 각각 확인했다.
- [ ] 승인된 경로에서 JH→GC metric TCP/API를 확인했다.
- [ ] GC의 정상 GET 1건과 로컬 JSON 로그·실제 시각을 확보했다.
- [ ] JH Loki에서 같은 다섯 identity·시간·request_id/URI 타입의 로그를 read-back했다.
- [ ] host PG 로그는 runtime=host/별도 target/source로 분리했다.
- [ ] Network는 observer/instance와 endpoint runtime/target을 확인했다. instance:null이면 BLOCKED다.
- [ ] GC snapshot 13개와 verifier 결과를 확보했다. snapshot PASS를 scrape PASS로 바꾸지 않았다.
- [ ] JH target 하나, up=1, component/target 상태=1, metadata 유일성·중복 0을 확인했다.
- [ ] 실제 raw timestamp와 target interval/timeout, loaded evaluation interval을 확인했다.
- [ ] Memory limit=0/VM 분모·RX-only·root Docker VM·host PG를 혼동하지 않았다.

**중단 위치:** 경로·identity·freshness 중 하나라도 미확인 → 메인 STEP 4 또는 5 / T03·T05~T08. 주입하지 않는다.

## 3. 합류 2 — 소비 계약·룰 [SEQUENTIAL]

- [ ] OpenAPI의 다섯 identity 및 extra labels를 확인했다.
- [ ] bindings canonical hash와 실제 full ID/job/instance를 대조했다.
- [ ] 후보 input → selector → query → 정확한 load를 순서대로 확인했다.
- [ ] loaded 식·static labels·annotations·for·keep_firing_for·interval과 중복을 확인했다.
- [ ] 원본 21개와 실제 부분 번들 결과를 서로 다른 파일에 저장했다.
- [ ] API exit 0·instant predicate true를 전체 E2E PASS로 간주하지 않았다.

**중단 위치:** 미인수 candidate·source 손실·누락 룰 → 메인 STEP 6/7. 전체 교체 금지. 선택 경로의 부분 데모 승인도 따로 기록한다.


### DAY-C2 — 기존 서비스/API 빠른 재확인 [BATCH]

| 항목 | 설명 |
|---|---|
| 담당 PC | JH |
| 운영체제 | Windows |
| 실행 터미널 | PowerShell 5.1 이상 |
| 실행 권한 | 일반 사용자 |
| 실행 위치 | $Repo (STEP 0.1에서 입력한 실제 경로) |
| 실행 구분 | 읽기 전용 |
| 실행 방식 | [BATCH] |
| 선행 조건 | 메인 STEP 0.2에서 실제 JH origin/Compose와 모델을 확인 |
| 성공 조건 | 같은 관리 서비스가 준비돼 있음 |
| 실패 시 조치 | 응답 불일치/오류면 주입·촬영 중단, 메인 STEP 2/6/7에서 재개 |

**① 실행 명령어**

```powershell
curl.exe --fail --silent --show-error --max-time 10 "$Loki/ready"
Assert-Native
curl.exe --fail --silent --show-error --max-time 10 "$Prom/-/ready"
Assert-Native
curl.exe --fail --silent --show-error --max-time 10 "$Am/-/ready"
Assert-Native
Get-ApiJson "$Pipe/health"
(Get-ApiJson "$Ollama/api/tags").models | Select-Object name
```

**② 명령어 설명**

ready와 /health는 기능 인수와 별개다. curl.exe를 명시하고 max-time으로 연결 지연을 제한한다. 모델 목록 조회는 추론 요청을 하지 않는다.

**③ 예상 출력 예시 — 실제 관측값 아님**

```text
ready, Pipeline status=ok, 실제 모델 목록
```

**④ 결과의 의미**

API 준비까지만 확인한다. 실제 LLM 완료·Loki RCA read-back은 뒤의 사건 관찰이 필요하다.

**⑤ 실패 시 확인 사항**

404가 나오면 다른 프로세스의 포트인지 OpenAPI를 대조한다. 임의 서비스 재시작·모델 pull을 하지 않는다.

- [ ] 실행자 / 실제 UTC·KST 시각 / 결과 / 증거 파일을 기록했다.


## 4. 정상 대조 → 승인된 공개 SQL 패턴 [SEQUENTIAL]

- [ ] GC와 JH가 선택 시험의 시작을 합의했다.
- [ ] 이전 동일 경보가 해소됐고 2분 룰 윈도·300초 dedup 영향을 검토했다.
- [ ] 정상 대조 요청의 데이터가 실제 저장됐고, 합의 관찰창 동안 해당 원인 경보가 없었다.
- [ ] 이것을 C-a 또는 M4 정상 Baseline 인수라고 표현하지 않았다.
- [ ] 메인 STEP 8.2의 공개 모듈 2 GET만 승인받았다. 기본 전체 payload/legacy 고부하 실행기/V2는 실행하지 않는다.
- [ ] GC가 STEP 8.2 코드를 개별 실행하고 실제 status와 UTC/KST를 JH에게 전달했다.
- [ ] JH가 STEP 8.3을 실행해 같은 사건을 추적했다.
- [ ] Ruler firing → AM 개별 identity/startsAt/fingerprint → Pipeline 수신 → 실제 [LLM] 완료 → Loki read-back을 연결했다.
- [ ] schema=2.0, identity_status=resolved, 사용한 evidence scope·모델·결과를 확인했다.
- [ ] confidence=0/NONE·UNKNOWN·저장 실패는 정상 추론 성공으로 촬영하지 않았다.
- [ ] 자동 조치·Slack은 보류 상태를 유지했다.

**중단 위치:** 요청 status/사건 유일성/LLM/저장 실패 → 메인 STEP 8.3 및 T09~T12. 주입 반복으로 해결하지 않는다.

## 5. 시나리오 선택 금지선

| 시나리오 | 당일 처리 |
|---|---|
| S2 V2 | Heldout 최종 평가. 실행/열람/freeze 금지 |
| C-a/S2 현 runner | GC host DB·sink·remote endpoint adapter 미완료로 BLOCKED |
| F2-c 현 runner | Docker DB/sh watchdog 전용. Windows Host PG17에 실행 금지 |
| legacy 고부하 SQLi | 기본 데모에서 제외 |
| 공개 S1-a 제한 2 GET | 실제 API 비파괴 검토와 source-safe 경로 승인 후만 수행 |

## 6. 촬영·종료 [PARALLEL 가능 부분만]

- [ ] 실제 성공한 사건만 E2E_DEMO_RECORDING_SCRIPT.md의 장면에 사용했다.
- [ ] 실패하면 BLOCKED/PARTIAL을 표시하고 과거 자료를 현재 성공처럼 편집하지 않았다.
- [ ] 모든 시각·대기시간은 실제 값으로 기록했다. 예상 시간으로 자막을 만들지 않았다.
- [ ] 실제 IP/주소·토큰·cookie·개인정보·비공개 payload가 영상/Notion에 없다.
- [ ] GC/JH가 각각 메인 STEP 10.1 결과를 저장했다.
- [ ] 적용한 항목만 승인된 사전본으로 원복했다. 미변경이면 NOT_CHANGED다.
- [ ] 앱/PG·수신·기존 rule/target·buffer/state/ledger 보존과 자동 조치 0을 확인했다.
- [ ] 다음 시험은 새 RunId와 증거 폴더에서 시작한다.

## 최종 판정 칸

| 항목 | 실제 결과 | 근거 |
|---|---|---|
| 통신 | UNVERIFIED | |
| 로그/메트릭/source | UNVERIFIED | |
| M5-A 21개 전체 | BLOCKED | 누락·미발화 candidate 별도 |
| 선택 SQL 경로 | UNVERIFIED | |
| 실제 Ollama/RCA 저장 | UNVERIFIED | |
| 원복/미변경 | UNVERIFIED | |
| 영상 본 촬영 | BLOCKED | 선택 경로 인수·공개 검토 후 재판정 |

순서: 병렬 준비 → daemon ping → 서버/producer 준비 → TCP → 새 로그 저장 → metrics/cadence → bindings → 정확한 룰 → 정상 대조 → 제한 GET → 실제 사건 연결 → 결과 기록·복구.
