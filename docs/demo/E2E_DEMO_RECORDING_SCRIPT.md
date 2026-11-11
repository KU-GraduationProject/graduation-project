# Leafy AIOps — E2E 데모 영상 촬영 대본

기준: 2026-11-11 / GC(관측 대상) + JH(AIOps 관리), 두 PC 모두 Windows

**현재 본 촬영: BLOCKED.** 아래는 촬영 계획이다. 실제 Windows 수집·firing·Ollama 추론·Loki read-back을 확인한 성공 기록이 아니다.
정확한 실행 코드는 GC_JH_WINDOWS_E2E_RUNBOOK.md, 당일 체크는 E2E_EXECUTION_CHECKLIST.md를 사용한다.

## 1. 데모 범위와 시나리오 선정

권장 후보는 **일반 HTTP 정상 대조 → 공개 S1-a의 제한된 SQL 패턴 2 GET → SQLInjection 탐지 → source-aware RCA → Loki 저장**이다.

- 실제 GC API가 읽기 전용인지 앱 담당자가 검토한 뒤 개별 승인한다.
- SQLInjection은 request_uri 패턴 탐지다. SQL 실행·데이터 탈취·침해 성공 영상이라고 설명하지 않는다.
- 전체 M5-B 21개가 인수되지 않았다면 “선택한 SQLInjection 경로의 부분 데모”라고 제목·나레이션에 표시한다.
- M4 정상 Baseline은 NORMAL_UNCONFIRMED다. 짧은 정상 요청을 전체 정상 구간으로 일반화하지 않는다.
- C-a/S2 현 runner는 host DB/sink/remote endpoint 이식이 미완성이고 S2 V2는 Heldout 최종 평가다. 대본에 실행 명령을 넣지 않는다.
- F2-c는 Docker DB 전용이다. Windows PostgreSQL 17에 해당 스크립트를 실행하지 않는다.
- Slack 및 자동 Remediation은 보류 상태다. 성공 장면·승인 버튼·자동 복구 장면을 구성하지 않는다.

## 2. 촬영 전 합류 게이트

- [ ] GC/JH가 메인 Runbook STEP 0~7의 선택 경로를 실제로 검증했다.
- [ ] 현재 앱/로그/metric/source와 배포 image·bindings가 일치한다.
- [ ] 선택한 SQLInjection rule의 정확한 source·target·식·for·평가 interval을 확인했다.
- [ ] 이전 동일 경보/2분 윈도/300초 dedup 영향을 제거하는 실제 시간 격리를 확인했다.
- [ ] 실제 모델이 준비됐고, 컨테이너 자원·지연 상태를 기록했다.
- [ ] 적용한 변경의 사전본과 원복 책임자를 확보했다.
- [ ] 전용 요청 대상·두 GET의 비파괴 검토·실행 승인과 중단 기준을 기록했다.
- [ ] 관찰 순서·촬영 담당·시각 전달 방식을 합의했다.
- [ ] 화면 알림·브라우저 프로필·터미널 히스토리·비밀 설정 노출을 점검했다.
- [ ] Slack/자동 조치는 비활성·보류 상태이며 그대로 설명한다.

명령 실행 정보는 메인 문서 해당 STEP의 10항목 표와 ①~⑤ 설명을 따른다. 아래 표의 “실행 명령”은 그 검증된 코드 블록의 참조이며, 임의 축약 명령으로 바꾸지 않는다.

## 3. 장면별 촬영 순서

| 장면 | 촬영 담당 | 보여줄 화면 | 실행 명령·방식 | 보여야 할 결과 | 핵심 설명·발표 대본 | 촬영 전 확인 | 실패 시 대체 화면 |
|---|---|---|---|---|---|---|---|
| Scene 1 — 구성·범위 | GC+JH | 두 PC 역할·전체 흐름 Mermaid, 실제 버전 요약 | 메인 STEP 0.1/0.3 [PARALLEL] | 실제 코드·image 증거, 선택 경로 범위 | “GC가 데이터를 만들고 JH가 탐지·분석합니다. 오늘은 승인된 공개 입력으로 선택 경로를 확인합니다.” | 동명 서비스/다른 PC 혼동 없음, 민감정보 가림 | 아키텍처 설명만 가능. 실환경 성공이라고 말하지 않음 |
| Scene 2 — Leafy 정상 동작 | GC | 실제 서비스 화면·정상 공개 GET | STEP 4.1 [SEQUENTIAL] | 실제 정상 응답과 Nginx 로그 | “먼저 서비스와 로그 생산을 확인합니다. 화면이 열린 것만으로 AIOps 전체 성공은 아닙니다.” | 실제 읽기 전용 path/parameter | 상태 오류와 진단 화면. 과거 정상 화면은 날짜·범위 표시 |
| Scene 3 — Grafana 관측 | JH | localhost Grafana Explore, Loki와 Prometheus | STEP 4.2/5.2 [SEQUENTIAL] | 실제 source별 새 로그·메트릭·freshness | “같은 이름의 다른 PC가 섞이지 않도록 site/source/runtime/target을 확인합니다.” | dashboard query가 실제 GC source를 선택함 | 준비된 도식/오프라인 결과는 오프라인임을 표시 |
| Scene 4 — 정상 대조 | GC 실행, JH 촬영 | 일반 GET과 실제 경보 관찰 화면 | STEP 8.1 [SEQUENTIAL] | 데이터가 저장되고 해당 원인 경보가 없다는 실제 관찰 | “정상 요청의 데이터가 관측되는 상태에서 비교합니다. 이것은 M4 정상 Baseline 인수는 아닙니다.” | 이전 경보 clear·관찰창 합의 | 기존 경보가 남으면 중단하고 상태 그대로 설명 |
| Scene 5 — 공개 입력 2 GET | GC | 승인된 공개 모듈 실행 결과와 실제 시작 UTC/KST | STEP 8.2 [SEQUENTIAL] | sent=2와 실제 HTTP statuses | “공개 시나리오의 제한된 GET만 사용합니다. 공격 성공을 만드는 대신 요청 패턴 탐지 경로를 검증합니다.” | 실제 API 비파괴 검토, JH 관찰 준비 | 요청 오류를 그대로 기록. 다른 스크립트/강도 증가로 대체 금지 |
| Scene 6 — 데이터·탐지 | JH | 같은 요청의 Loki URI 타입·source, 정확한 Ruler와 AM alert | STEP 4.2 및 8.3 [SEQUENTIAL] | source-safe SQLInjection firing, AM 개별 labels/startsAt/fingerprint | “서비스 데이터가 룰을 거쳐 경보가 됐는지 같은 사건으로 연결합니다.” | raw URI/계정 노출 제거, 정확한 loaded rule | 경보 미발화는 PARTIAL/FAIL을 표시. 유사 이름의 과거 경보로 대체 금지 |
| Scene 7 — 실제 RCA·저장 | JH | Pipeline [LLM] 완료 metadata, Loki RCA JSON·요약 | STEP 8.3 [SEQUENTIAL] | 실제 모델 완료, schema 2.0, resolved identity, 같은 사건/evidence/read-back | “관측 source를 유지한 근거로 실제 모델 분석을 수행하고 결과를 저장했습니다.” 이 문장은 증거 연결 완료 시에만 사용 | tags/queued/양수 confidence만으로 성공 처리하지 않음 | UNKNOWN/timeout/storage error면 그 결과와 안전 거부 이유를 설명 |
| Scene 8 — 비교·안전 경계·복구 | GC+JH | 실제 결과 표, source·사건 대응, 원복/미변경 확인 | STEP 10.1, 변경했다면 승인된 10.2 [PARALLEL/SEQUENTIAL 구분] | 실제 정상/비정상 비교·상태·남은 BLOCKED | “확인한 범위와 남은 제약을 구분합니다. 자동 조치와 Slack 전달은 보류하며 데이터·기록은 보존합니다.” | 전체 M5-B 또는 자동 복구 성공이라고 표현하지 않음 | 실패 결과와 후속 게이트를 최종 장면으로 사용 |

SQLInjection의 for=0m이면 pending 장면이 없을 수 있다. pending을 보이려고 임계값이나 for를 바꾸지 않는다.
Grafana 저장 dashboard의 기본 query는 현재 GC profile을 선택한다고 보장되지 않는다. 실제 설치된 “Leafy AIOps SOC Dashboard”(저장소 uid leafy-aiops) 또는 Explore에서 메인 문서의 실측 selector를 사용한다. 빈 panel을 정상 0으로 설명하지 않는다.

## 4. 각 담당자가 실행할 순서

### GC — 촬영 중 역할

1. STEP 0/3의 실제 앱·PG·ID·Observer·collector 상태를 확인한다.
2. JH의 “관찰 준비”를 받은 뒤 정상 GET 1건과 시각을 전달한다.
3. JH의 정상 대조 저장/관찰 완료를 기다린다.
4. 별도 승인된 STEP 8.2만 개별 실행한다. 실제 주입 시작·종료 UTC/KST와 status를 전달한다.
5. 예상과 다른 영향/0·4xx·5xx/대상 차이가 있으면 즉시 중단을 알린다.
6. 원래 세션 env 복원, 앱/PG 상태, 적용한 변경만 승인된 절차로 복구한다.

### JH — 촬영 중 역할

1. STEP 2/4~7로 source-safe 관측과 정확한 rule/binding/model을 확인한다.
2. 실제 selector와 시간창을 준비하고 정상 대조를 read-back한다.
3. GC 시작 시각을 받은 뒤 STEP 8.3의 WindowStart를 이번 사건으로 다시 입력한다.
4. Ruler firing과 AM active/suppressed를 구분해 개별 alert를 선택한다.
5. Pipeline/실제 Ollama 완료 로그·모델·시간과 Loki read-back의 startsAt/fingerprint·identity를 대조한다.
6. 근거 가용성·UNKNOWN·저장 오류를 그대로 기록하고 실패를 성공으로 편집하지 않는다.
7. 공개할 화면만 비식별화하고 원본은 private evidence에 보존한다.

## 5. 촬영 시각·증거 기록 — 예상 소요시간 대신 실제 값

| 장면 | 실제 시작 UTC | 실제 시작 KST | 실제 종료 UTC | 증거 파일/영상 구간 | 실제 결과 |
|---|---|---|---|---|---|
| 1 | | | | | UNVERIFIED |
| 2 | | | | | UNVERIFIED |
| 3 | | | | | UNVERIFIED |
| 4 | | | | | UNVERIFIED |
| 5 | | | | | UNVERIFIED |
| 6 | | | | | UNVERIFIED |
| 7 | | | | | UNVERIFIED |
| 8 | | | | | UNVERIFIED |

| 사건 상관 키 | 실제 기록(공유본은 비식별화) |
|---|---|
| 시험 ID / 요청 시작·종료 | |
| site/source/service/runtime/target | |
| 요청 request_id / GC 로그 시각 | |
| Ruler group/expr hash / firing 시각 | |
| AM fingerprint / startsAt / 상태 | |
| Pipeline 수신·실제 [LLM] 모델/완료 시각 | |
| Loki RCA entry timestamp / alert_starts_at | |
| 근거 가용성 / 결과 / 실제 저장 증거 | |
| 실제 경과시간 산정 기준·오차·관찰 공백 | |

호출 시작, 첫 firing 관측, AM 전달, 모델 완료, 저장 시각은 서로 다른 사건이다. polling 간격과 시계 오차를 기록하고 임의로 정확한 MTTD/MTTA라고 이름 붙이지 않는다. 비동기 분석의 대기 시간을 성공 화면으로 건너뛰면 편집 구간과 실제 시각을 표시한다.

## 6. 실패 시 대본과 중단

| 상태 | 설명할 문장 | 다음 행동 |
|---|---|---|
| transport/입력 없음 | “현재 입력 수집 경로가 준비되지 않아 E2E를 시작하지 않습니다.” | STEP 1/4/5 및 관련 진단, 주입 금지 |
| 데이터는 있고 경보 없음 | “입력·룰·시간창을 확인 중이며 탐지 성공으로 판정하지 않습니다.” | STEP 7/T04/T15, threshold 변경 금지 |
| AM까지 있고 RCA 없음 | “전달 또는 비동기 분석 단계가 미확인입니다.” | T09/T11, 같은 사건 로그 확인 |
| source UNKNOWN | “출처를 확정할 수 없어 다른 PC 데이터로 대체하지 않고 분석을 보류했습니다.” | T10, identity 인수 |
| LLM 완료·저장 실패 | “분석은 완료했지만 저장 인수는 실패해 전체 성공으로 표시하지 않습니다.” | T12, 실제 read-back |
| Slack/자동 조치 없음 | “현재 전달 계약은 보류 상태로, 자동 조치가 실행되지 않는 것이 의도된 범위입니다.” | 기능 활성화하지 않음 |
| 기존 자료밖에 없음 | “다음은 표시된 날짜·환경의 과거 증거이며 이번 Windows 시험 결과가 아닙니다.” | 출처·범위·날짜가 검증된 자료만 사용 |

S2 V2·Heldout 입력/정답, F2-c host 이식, high-load legacy SQLi를 실패 대체 시나리오로 즉석 실행하지 않는다.

## 7. 촬영 완료 체크

- [ ] 영상 제목에 전체 인수/부분 경로/리허설 범위를 정확히 적었다.
- [ ] 실제 정상 요청과 실제 source-safe 데이터가 관측된다.
- [ ] 같은 사건의 데이터→정확한 룰→경보→실제 모델→Loki 저장을 연결했다.
- [ ] 현재 성공하지 않은 장면은 성공 자막/음성으로 표현하지 않았다.
- [ ] M4 미확정·M5-B 잔여 게이트·M6/M7 분리 상태를 유지했다.
- [ ] Slack/자동 Remediation 성공 장면을 넣지 않았다.
- [ ] 계정·토큰·cookies·실제 주소·민감한 본문·비공개 params/정답을 제거했다.
- [ ] 비식별 공유본과 private 원본·hash·촬영 시각을 구분해 보존했다.
- [ ] 원복/미변경 상태를 양 PC 운영자가 확인했다.
- [ ] 재촬영은 새 시험 ID·시간 격리와 실제 검증 후 수행한다.

**최종 촬영 판정:** 현재 BLOCKED. 실제 선택 경로를 인수한 뒤에만 부분 데모 본 촬영을 승인할 수 있다. 전체 M5-B 인수·자동 복구 시연을 승인한 것은 아니다.
