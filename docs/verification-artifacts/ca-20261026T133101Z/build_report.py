import json
from pathlib import Path
from datetime import datetime,timedelta,timezone

out=Path(__file__).parent
summary=json.loads((out/'summary.json').read_text(encoding='utf8'))
transfer=json.loads((out/'transfer.json').read_text(encoding='utf8'))
browser=json.loads((out/'browser-verification.json').read_text(encoding='utf8'))
zeek=json.loads((out/'zeek-connections.json').read_text(encoding='utf8'))
assert not browser['page_errors'] and all(summary['checks'].values())
def kst(value):
    return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone(timedelta(hours=9))).isoformat()

text=f'''# C-a 정상 전송 통합 검증

검증일: 2026-10-26, Asia/Seoul. 결과: **PASS — C-a로 인한 신규 비인가 전송 경보 0건**.

| 검증 항목 | 결과 | 근거 |
|---|---|---|
| C-a 정상 전송 | PASS | V1, S2=0/C-a=1, valid=true, TN |
| 송수신 해시 일치 | PASS | 8개 연결 모두 SHA-256 및 바이트 일치 |
| Zeek 연결 관측 | PASS | Backend 출발 연결 8개, UID를 Loki connection_id와 대조 |
| Loki 정상 전송 기록 | PASS | connection 8건, connection_threshold 8건 |
| 신규 비인가 경보 0건 | PASS | API 29회 관측 및 최종 조회, 정상 Ruler 평가 3회 모두 신규 인스턴스 없음 |
| Grafana 전송량 표시 | PASS | 63=10,486,888 bytes, 64=Sink A 시계열, 65=실제 이벤트 |
| MTTD 평균 오염 없음 | PASS | 고정 기간의 평균 {summary['mttd_before']:.9f}초와 표본 수 3 유지 |
| 실제 Alertmanager 상태 표시 | PASS | 73=0, 74=빈 목록, API와 일치 |
| 기존 패널 회귀 없음 | PASS | 기존 전체 34개 객체(행 포함) deep-equal, 쿼리/배치/옵션 불변 |
| 안전 제약 준수 | PASS | pipeline/remediation 중지 유지, S2/Slack/격리 실행 없음 |

**실행 정보**

- 브랜치: `feature/s2_scenario`.
- 시작/종료 HEAD: `8c64545a5399703cf16fd7e137ccf7540732fb17`.
- 기존 CLI: `python scenarios/network/experiment.py run V1 --s2-reps 0 --ca-reps 1`.
  실제로 `experiment.main(...)`에 동일 인자를 전달했다. 별도 계측 래퍼는 기존
  run_transfer를 그대로 1회 호출하고 반환된 송신/수신 메타데이터만 저장했다.
- C-a를 정확히 1회 실행했다. 검증 스크립트의 후처리를 재개할 때 전송은 다시 호출하지 않았다.
- 실험 ID: `{summary['experiment_id']}`.
- orchestration t0: `{kst(summary['record']['started_at'])}`.
- 송신기 데이터 전송 시작: `{kst(summary['sender_started_at'])}`.
- 호스트의 전송 완료 관측: `{kst(summary['transfer_completed_observed_at'])}`.
  마지막 패킷 시각으로 표현하지 않는다. 기존 송신 메타데이터는 연결별 started_at/duration_sec를 제공한다.
- 출발지: backend `10.210.0.7`, 목적지: 인가 Sink A `10.210.0.30:8080`.
- payload 송신/수신: 각각 **10,485,760 bytes** (10 MiB), 8개 연결 각각 1,310,720 bytes.
- Zeek 연결 바이트: **10,486,888 bytes**, HTTP 오버헤드를 포함하여 payload와 구분한다.
- 송신 전체 payload SHA-256: `{transfer['result']['sender_meta']['payload']['sha256']}`.

**연결별 송수신 SHA-256**

수신기는 각 분할 연결을 별도로 해시한다. 전체 payload 해시가 수신기에서 별도로 계산됐다고 주장하지 않는다.

| 연결 번호 | 송신 SHA-256 | 수신 SHA-256 | 바이트/일치 |
|---|---|---|---|
'''
for index,connection in enumerate(transfer['result']['sender_meta']['connections'],1):
    text+=f"| {index} | `{connection['sha256']}` | `{connection['sink_sha256']}` | {connection['bytes_sent']:,} / PASS |\n"

text+=f'''
**경보와 평가 지연**

실행 전 원본 API는 [alertmanager-baseline.json](alertmanager-baseline.json),
실행 후는 [alertmanager-after.json](alertmanager-after.json)에 저장했다.
두 응답 모두 `[]`였다. 이전 S2 경보는 이미 자연 만료되어 baseline에 fingerprint/startsAt/labels가 없었다.
경보 삭제·강제 해결·라우팅 수정은 하지 않았다.

기준선과 매 관측에서 `(fingerprint, startsAt, labels)`를 비교하고 status를 보존했다.
두 네트워크 규칙의 기존 경보가 동일 fingerprint로 C-a 발생을 가린 상태도 아니었다.
Ruler의 인스턴스 목록에도 Sink A 대상 경보가 없었고, 두 규칙 상태와 health는 inactive/ok였다.
실제 규칙 LogQL을 직접 조회한 결과도 두 규칙 모두 빈 vector였다.

런타임 설정: evaluation_interval=60초, for=0, notification_timeout=10초,
resend_delay=60초. API 수신은 Alertmanager group_wait(10초)의 webhook 전달 지연과 구분한다.
전체 이벤트가 Loki에 들어온 시각 `{summary['first_all_events_ingested_at']}` 이후
최소 135초(평가 2주기+알림 timeout+poll 여유)를 기다렸다. 실제로 확인한 평가 시각(UTC):
'''
for evaluation in summary['completed_rule_evaluations']:
    text+=f'- `{evaluation}`\n'
text+=f'''
5초 간격 관측은 [observations.jsonl](observations.jsonl)에 {summary['observation_samples']}회 저장했고,
관측 API 오류는 없었다. 최종 경보 조회는 후처리 시점에도 다시 수행했다.
신규 `UnauthorizedDataTransfer`와 `UnauthorizedTransferEarly` 인스턴스는 모두 0건이다.

**Grafana 검증**

- 61: 비인가 threshold 이벤트 없음, 62: 비인가 바이트 없음. 해당 LogQL은 빈 결과이며 0값을 만들어 넣지 않았다.
- 63: 인가 전송량 10,486,888 bytes, 브라우저 **10.0 MiB**.
- 64: `sink-a / 10.210.0.30` 시계열에 양의 전송량 존재.
- 65: Backend→Sink A connection/threshold 및 원본 시각/바이트 기록 확인.
- 71: 같은 시작 시각의 24시간 범위에서 전후 평균 **25.612초**, 표본 **3개**.
  과거 S2 표본이 최근 1시간 창에서 빠지는 효과와 C-a의 영향을 구분하기 위해 범위를 고정했다.
- C-a만 필터링한 71은 MTTD 시계열이 없고 표본 수 **0**이다. 평균 0초로 표시하지 않는다.
- 72: C-a가 새 결과로 추가되며 `not_detected`, `mttd_seconds=null`, `detected_at=null`.
  브라우저에서 `미측정`으로 표시되는 것을 확인했다.
- 73: 실제 API와 동일한 활성 건수 **0**. 74: 동일하게 상세 목록 없음.
- 모든 기존 패널 JSON과 Grafana에 로드된 패널을 비교했다. 코드/쿼리/레이아웃 변경은 없다.
- headless Edge의 페이지 오류 0건. 스크린샷은 [전송량](grafana-ca-network.png),
  [전체 평가 결과](grafana-ca-overview.png), [C-a 필터](grafana-ca-only.png).

전송량의 5분 창 만료에 영향을 받지 않도록 패널 데이터/화면은 실제 관측 종료 시각
`{summary['panel_snapshot_at']}` (KST `{kst(summary['panel_snapshot_at'])}`)을 기준으로 조회했다.
Alertmanager API 및 Infinity 경보 패널은 현재 상태를 조회하므로 과거 시간 범위와 독립적이다.

**발견 사항 및 후속 작업**

- 애플리케이션 수정이 필요한 오탐이나 MTTD 집계 문제는 발견되지 않았다.
- 최초 Zeek 대조 스크립트는 목적지 기준으로만 세어 호스트의 `/stats` 접근 1개를 포함했다.
  후처리에서 Backend 출발 IP로 제한하고 8개 UID를 대조했다. C-a를 재실행하지 않았다.
- Zeek의 8개 connection 모두 `missed_bytes > 0`을 기록했다. 이는 TCP 재조립에서 보고한 gap이며
  실제 송수신 데이터 손상으로 단정할 수 없다. 수신 바이트/해시는 별도 Sink 증거로 확인했다.
  패킷 캡처/오프로딩 및 재조립 품질은 별도 점검 대상이며 이번 작업에서는 설정을 변경하지 않았다.
- baseline이 비어 있어 기존 활성 S2 경보와 C-a의 동시 존재는 이번 실행에서 재현하지 않았다.
  이를 위해 S2를 새로 실행하지 않았다.

코드·정책·대시보드 수정 없음, 서비스 재시작 없음, 커밋 및 push 없음. 종료 워킹트리는 깨끗하다.
증거는 저장소 밖의 현재 폴더에만 보존했다. Docker/Grafana 자격증명은 출력하거나 증거에 저장하지 않았다.
'''
(out/'REPORT.md').write_text(text,encoding='utf8')
print(out/'REPORT.md')
