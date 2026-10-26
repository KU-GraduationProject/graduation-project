# Grafana Alertmanager 연동 검증

검증일: 2026-10-26 (Asia/Seoul). Grafana 12.4.2, Alertmanager 0.31.1.

## 작업 기준

- 브랜치 `feature/s2_scenario`, 시작 HEAD `c81b00c126f7dbb49722920d5e33edfb33fcb5e5`.
- 시작 시 미커밋 변경 없음. 이전 네트워크 대시보드는 이미 위 커밋에 포함되어 있었다.
- `git ls-remote origin refs/heads/feature/s2_scenario`도 같은 해시였다. 기존 커밋은 재작성하지 않았다.
- 대시보드 초기 파일을 임시 디렉터리에 복사한 후 변경했다.

## 구현 및 제약

`monitoring/grafana/provisioning/datasources/datasources.yml`에 UID
`leafy-alertmanager`를 추가했다. URL은 `http://alertmanager:9093`,
implementation은 `prometheus`, `handleGrafanaManagedAlerts`는 `false`이다.
기존 Prometheus/Loki UID, URL, 기본 설정은 유지했다.

설치된 컨테이너의 다음 소스를 직접 확인했다.

- `/usr/share/grafana/public/app/plugins/datasource/alertmanager/DataSource.ts`:
  `query()`가 `of({ data: [] })`를 반환한다. 기본 Stat에 수신 경보를 조회할 수 없다.
- 같은 디렉터리 `plugin.json`: `metrics: false`, Alertmanager API proxy 용도.
- [동일 버전 Alert list 구현](https://github.com/grafana/grafana/blob/v12.4.2/public/app/plugins/panel/alertlist/UnifiedAlertList.tsx):
  `fetchPromAndRulerRulesAction` 및 Grafana 규칙 API를 조회한다.
  Alertmanager 수신 경보 목록을 표시하는 패널이 아니다.
- [공식 Active notifications 안내](https://grafana.com/docs/grafana/latest/alerting/monitor-status/view-active-notifications/):
  외부 Alertmanager의 실제 알림 조회 화면을 제공한다.

61/62는 삭제하거나 데이터소스를 교체하지 않았다. 설명만 수정하여 각각
Loki 이벤트 수/전송량이며 실제 Alertmanager 수신 건수가 아님을 명시했다.
실제 수신 조회 대안은 Grafana의 Alerting > Active notifications에서
Alertmanager 선택이다. 브라우저에서 해당 화면을 열어 렌더링을 확인하지는 않았다.
실제 수신 경보를 표시하는 대시보드 패널은 미구현이다.

데이터 출처: 61=connection_threshold 이벤트 수, 62=비인가 connection 바이트 합계,
63=인가 목적지 전송량, 64=목적지별 추이, 65=네트워크 이벤트 로그. 모두 기존 Loki 쿼리 유지.

## 런타임 검증

| 검증 | 결과 | 근거 |
|---|---|---|
| Alertmanager 등록 | PASS | 인증된 `/api/datasources`에서 type/URL/UID/jsonData 확인, 기존 두 데이터소스 유지 |
| 연결 | PASS | 내장 `testDatasource()` 성공 분기의 proxy `/api/v2/status` 요청 HTTP 200, versionInfo 0.31.1. UI 버튼 실행은 미수행 |
| Alertmanager 실제 경보 조회 | PASS | 직접 API와 Grafana 경유 API에서 아래 2개 활성 인스턴스 확인 |
| Grafana 수신 API 일치 | PASS | 이름, labels, status.state, startsAt, fingerprint 및 인스턴스 수 일치 |
| Grafana 대시보드 실제 경보 패널 | SKIP | 기본 데이터소스/Alert list 제약. 기존 Loki 패널 보존 |
| 브라우저 렌더링 | SKIP | 브라우저 시각 검증 미수행 |
| S2 1회 | PASS | 송수신 바이트·해시 교차검증 및 이번 실행 이후 Ruler firing/Alertmanager 수신 확인 |
| 회귀 | PASS | 초기 스냅샷과 deep-equal. 변경 대상 외 모든 패널 및 전체 대시보드 필드 동일 |
| 안전 제약 | PASS | pipeline/remediation 중지 유지, Slack/자동 조치 테스트 없음 |

등록 후 다음 관리 API로 provisioning만 다시 읽었다. Grafana 재시작 명령은 사용하지 않았다.

```text
POST /api/admin/provisioning/datasources/reload
POST /api/admin/provisioning/dashboards/reload
```

각각 `Datasources config reloaded`, `Dashboards config reloaded` 응답.
`GET /api/dashboards/uid/aiops-main`의 모든 패널이 최종 파일과 deep-equal이었다.
Grafana/Loki/Alertmanager는 running, aiops-pipeline/aiops-remediation은 exited였다.

## S2 실행과 실제 경보

기존 CLI `scenarios/network/experiment.py run V1 --s2-reps 1 --ca-reps 0`를
`experiment.main(...)`으로 호출했다. Docker DB 컨테이너 환경에서 자격증명을 메모리로만
읽어 `DB_PASSWORD` 환경변수로 전달했으며 출력하지 않았다. 출력 디렉터리는
`%TEMP%/leafy-alertmanager-verification`으로 지정했다. 기존 구현/정책은 수정하지 않았다.

- 실행 기준 시각: `2026-10-26T12:01:54.571422Z` (21:01:54.571 KST).
- 실행 전 Alertmanager 목록은 빈 배열. 기존 firing을 성공 근거로 사용하지 않았다.
- transfer_id 접두사: `S2-V1-0-1793016114`, 연결 8개.
- Sink B `10.210.0.31:8080`: 10,485,760 bytes 수신, 송수신 SHA-256 교차검증 성공.
- Zeek/enricher 로그: 해당 시각 backend `10.210.0.7` → Sink B connection 관측.
- Ruler의 두 규칙 `activeAt`: `2026-10-26T12:02:29.387511846Z`, `state=firing`.
- Alertmanager 두 인스턴스의 `startsAt`: `2026-10-26T12:02:29.387Z` (21:02:29.387 KST).
- API 비교 시각: `2026-10-26T12:04:04.973210Z` (21:04:04.973 KST).

| alertname | detection | dst_ip | dst_port | status.state | fingerprint |
|---|---|---|---|---|---|
| UnauthorizedDataTransfer | cumulative | 10.210.0.31 | 8080 | active | 8aa2943458e4c4a7 |
| UnauthorizedTransferEarly | early | 10.210.0.31 | 8080 | active | c129d63aa2be952e |

공통 labels: `category=security`, `severity=critical`.
비교 API는 `GET http://localhost:9093/api/v2/alerts`와 인증된
`GET http://localhost:3000/api/alertmanager/leafy-alertmanager/api/v2/alerts`.
Grafana API는 Alertmanager 0.31.1의 `status.mutedBy: []`를 생략하므로 전체 JSON 대신
위 식별 필드와 상태를 비교했다. 경보 수는 코드의 상수가 아니라 응답 인스턴스를 기준으로 셌다.

동일 시점 61의 LogQL 결과는 8 이벤트, 62는 10,486,880 bytes였다.
후자는 Zeek의 연결 바이트로 HTTP 오버헤드를 포함하므로 Sink payload와 구분한다.
어느 값도 Alertmanager 활성 인스턴스 수 2로 해석하지 않았다.
실험 결과는 valid=true, detected=true, crosscheck_ok=true,
stages={loki_ruler_firing:true, alertmanager_received:true, delivery:false}였다.
delivery는 안전 제약에 따라 비활성 서비스를 유지했기 때문에 성공으로 주장하지 않는다.
MTTD 표시/계산 로직은 수정하지 않았다. C-a 재실행은 이번 범위에서 수행하지 않았다.

## 회귀 검사와 재검증

초기 29개 항목(기존 23 + row 60 + 패널 61~65)의 ID/순서를 보존했다.
61/62의 description을 제외한 전체 패널 객체를 비교했고, 패널 외 전체 대시보드 객체도 동일했다.
이전 대시보드 추가 커밋의 부모 `c81b00c^`와도 기존 23개 객체가 deep-equal이었다.
따라서 제목, 쿼리, UID, 위치/크기, 시각화 옵션을 포함해 보호 범위를 확인했다.
`git diff --check`도 통과했다.

재검증 시 데이터소스 목록, proxy `/api/v2/status`, 두 경보 API를 읽고,
경보가 실행 전부터 존재하는지 먼저 확인한다. 재실험은 격리된 Sink에 한정하고
pipeline/remediation을 시작하지 않는다. 경보는 정상 만료에 맡기며 임의 삭제하지 않는다.

## 남은 작업

- 기본 기능 제약을 벗어나 실제 수신 경보를 대시보드 안에 표시하려면 별도 방식을 결정해야 한다.
  이번 작업에서는 제3자 플러그인이나 새 서비스를 추가하지 않았다.
- Active notifications 화면의 브라우저 렌더링 및 UI 연결 테스트 버튼 검증은 미수행이다.
