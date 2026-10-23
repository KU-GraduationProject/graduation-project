# JSON 로그 전환에 따른 탐지 규칙 영향 검토 (작업 C)

상태: **방안 1로 확정, 2026-10-24 적용.** 실제 Nginx JSON 스키마를 확인한 뒤 `HighNginxErrorRate`, `VulnerabilityScanningDetected` 두 규칙만 수정했습니다. 대시보드·시나리오는 수정하지 않았습니다.

## 0. 적용 결과

### 0.1 확인한 Nginx JSON 스키마

근거: 팀 이미지 `gicks/ai-ops-leafy-frontend@sha256:86310f08…`(2026-09-27 빌드)의 `/etc/nginx/conf.d/default.conf`입니다. 같은 이미지로 실제 요청을 보내 Loki에 저장된 줄로도 확인했습니다.

```nginx
log_format leafy_json escape=json '{"time_iso8601":"$time_iso8601","msec":$msec,"request_id":"$request_id",
  "remote_addr":"$remote_addr","realip_remote_addr":"$realip_remote_addr","http_x_forwarded_for":"$http_x_forwarded_for",
  "request_method":"$request_method","request_uri":"$request_uri","uri":"$uri","args":"$args","status":"$status",
  "upstream_status":"$upstream_status","request_time":$request_time,"upstream_response_time":"$upstream_response_time",
  "http_user_agent":"$http_user_agent","body_bytes_sent":$body_bytes_sent}';
```

규칙에 필요한 정보:
- `status`(문자열)만 필요합니다. `| json` 뒤 `status >= 500`은 문자열 `"502"`도 숫자로 비교합니다.
- `escape=json`이 켜져 있어 공격자가 넣은 따옴표가 JSON을 깨지 않습니다.
- 액세스 로그만 stdout(JSON)으로, error_log는 stderr(텍스트)로 나갑니다. 그래서 `log_format="json"` 셀렉터로 액세스 로그만 고를 수 있습니다.
- 점(`.`) 경로와 없는 파일은 404를 돌려주고 index.html 폴백이 없습니다. 따라서 스캔이 4xx로 드러납니다.

### 0.2 패치 (`monitoring/loki/rules/fake/security-rules.yml`, 식 2줄 + 주석)

```diff
       - alert: HighNginxErrorRate
         expr: |
           sum(count_over_time(
-            {service="frontend"} |~ "\" [5][0-9][0-9] " [1m]
+            {service="frontend", log_format="json"} | json | status >= 500 [1m]
           )) > 10
       - alert: VulnerabilityScanningDetected
         expr: |
           sum(count_over_time(
-            {service="frontend"} |~ "\" [4][0-9][0-9] " [1m]
+            {service="frontend", log_format="json"} | json | status >= 400 and status < 500 [1m]
           )) > 50
```

다음 항목은 바꾸지 않았습니다. 따라서 Pipeline 분기, Alertmanager 라우팅, Grafana `ALERTS` 패널에는 영향이 없습니다.
- 임계값, `for`, labels(severity/category), annotations(summary, `container: leafy-frontend`)
- 규칙 이름

### 0.3 회귀 테스트 (9개 규칙 전체)

방식:
- JH의 실제 `docker-compose.aiops.yml`을 격리 이름으로 띄웁니다.
- GC 측은 팀 이미지로 재현하고, 실제 트래픽과 공격을 발생시킵니다.
- Loki ruler에는 수정본과 **수정 전 원본(이름에 `_BEFORE`)**을 함께 로드해 같은 데이터로 평가합니다.
- 발화 여부는 Alertmanager를 거쳐 Pipeline에 도착한 webhook으로 확인합니다.

테스트 전용 설정은 ruler `evaluation_interval: 10s` 하나만 저장소와 다릅니다.

| 규칙 | 발생시킨 데이터 | 수정본 | 수정 전 |
|---|---|---|---|
| UnauthorizedDBAccess | PostgreSQL 인증 실패 5회 (jsonlog → 24225) | 발화 | 발화 |
| SecretDumpAttempt | backend PID 1 stdout `[ATTACK] printenv executed` | 발화 | 발화 |
| SQLInjectionAttempt | sqlmap UA, `UNION SELECT`·`OR 1=1`·`information_schema` 7건 | 발화 | 발화 |
| **HighNginxErrorRate** | Nginx 502 12건 (`/files`, MinIO 없음) | **발화** | **미발화** |
| SuspiciousProcessExecution | `wget http://…` | 발화 | 발화 |
| SuspiciousProcessExec | `suspicious_outbound …` | 발화 | 발화 |
| **VulnerabilityScanningDetected** | 404 55건 + 인증·검증 실패 4xx | **발화** | **미발화** |
| PathTraversalAttempt | `/.env`, `/.git/config` | 발화 | 발화 |
| ContainerEscapeAttempt | `container_escape_attempt …` | 발화 | 발화 |

예상 영향:
- 두 규칙이 JSON 전환 후에도 다시 동작합니다.
- 텍스트(combined) 액세스 로그는 이제 집계되지 않습니다. 팀 이미지가 JSON만 쓰므로 영향은 없습니다. 다른 Nginx 이미지로 바꾸면 `log_format`부터 확인해야 합니다.
- 전환 전에 Loki에 저장된 key_value 줄은 `log_format` 라벨이 없어 제외됩니다. 이는 오탐을 막는 효과도 있습니다.

---

아래 §1~§4는 결정 전 검토 기록입니다.
작성: 2026-10-24. 근거는 격리된 테스트 Loki(3.7.1)에 실제 로그를 넣고 운영 규칙식을 그대로 질의한 결과입니다.

## 1. 실측 근거

테스트 데이터:
- 팀원 제공 원본 [부록B] JSON 모드 22줄과 [부록A] TEXT 모드 253줄(backend)
- Nginx 형식 합성 샘플 4줄: JSON 502, JSON 404, 텍스트 503, stderr error_log
- PostgreSQL 17 테스트 컨테이너가 실제로 만든 jsonlog

운영 규칙식은 [security-rules.yml](../../monitoring/loki/rules/fake/security-rules.yml)에서 그대로 읽고, 시간창과 테스트 컨테이너 범위만 바꿔 실행했습니다(스크립트: 세션 스크래치 `rules_probe.py`).

| 질의 | 결과 | 해석 |
|---|---|---|
| `HighNginxErrorRate` 원식 (5xx 2건: JSON 502 + 텍스트 503) | **1** | 텍스트 503만 잡힘. **JSON 502 미탐** |
| `VulnerabilityScanningDetected` 원식 (JSON 404 1건) | **0** | **JSON 4xx 미탐** |
| `SQLInjectionAttempt` 원식 (JSON `UNION%20SELECT`) | 1 | JSON 줄에서도 정규식이 동작 |
| `PathTraversalAttempt` 원식 (JSON `/../../etc/passwd`) | 1 | 동작 |
| `UnauthorizedDBAccess` 원식 (호스트 PG jsonlog 인증 실패) | 7건 생성 → 집계됨 | `message`에 문구가 그대로 있음 |
| 후보 `\| json \| status >= 500` (Nginx 문자열 `"502"`) | 1 | |
| 후보 `\| json \| logger="ACCESS" \| status >= 400` (Backend 숫자 `401`) | 5 | |
| 후보식을 TEXT 모드 로그에 적용 | 0 | JSON 필드가 없으므로 당연한 결과 |
| 기존 key_value 줄에 `\| json` | 1 (오류 줄도 집계) | `__error__=""` 추가 시 0 |

결론 세 가지:

1. **실제로 깨지는 규칙은 2개**입니다. 둘 다 combined log 형식(`" 5xx `)을 가정한 상태코드 정규식입니다.
2. Backend의 숫자 `status`와 Nginx의 문자열 `"status":"502"`의 **타입 차이는 LogQL에서는 문제가 되지 않습니다.** `| json`으로 추출한 값은 문자열이지만 `>=` 비교에서 숫자로 변환됩니다. 문제가 되는 것은 **필드 이름 차이**입니다(`http_method`/`request_method`, `uri`/`request_uri` 등).
3. Loki 3.7은 JSON 파싱 오류 줄을 쿼리 실패로 처리하지 않고 **집계에 포함**합니다. 후보식에는 `log_format="json"`이나 `__error__=""`를 넣어, 전환 전에 저장된 key_value 줄이 섞이지 않게 해야 합니다.

## 2. 영향 목록

### 2.1 Loki 규칙 (9개)

| 규칙 | 대상 | 방식 | JSON 전환 영향 |
|---|---|---|---|
| UnauthorizedDBAccess | `{service="db"}` | `\|= "authentication failed"` | **동작** (호스트 PG jsonlog 실측). 컨테이너 DB와 호스트 DB가 같은 `service="db"`라 함께 집계됨 |
| SecretDumpAttempt | backend | 텍스트 키워드 | 동작 (시나리오가 stdout에 텍스트를 씀 → `log_format="text"`) |
| SQLInjectionAttempt | frontend | 정규식 (줄 전체) | **동작** (실측). JSON 이스케이프(`"`→`\"`, `\`→`\\`)는 기존 key_value와 같아서 패턴 의미가 바뀌지 않음 |
| HighNginxErrorRate | frontend | `" 5xx ` 정규식 | **깨짐** (실측) |
| SuspiciousProcessExecution / SuspiciousProcessExec | backend(+frontend) | 텍스트 키워드 | 동작 |
| VulnerabilityScanningDetected | frontend | `" 4xx ` 정규식 | **깨짐** (실측) |
| PathTraversalAttempt | frontend | 정규식 | **동작** (실측) |
| ContainerEscapeAttempt | backend | 텍스트 키워드 | 동작 |

참고:
- Backend에는 SQLi 규칙이 없습니다. 하지만 실측 결과 Backend ACCESS 로그의 `query_decoded`에 `lat=1' OR 1=1--`가 그대로 남아 있습니다. Nginx보다 정확한 탐지 근거가 될 수 있습니다.
- 반대로 Backend 줄 전체에 정규식을 걸면, `Hibernate: select ...` 줄과 `ddl-auto` DDL도 매칭 대상이 됩니다.

### 2.2 Prometheus 규칙

JSON 전환과는 무관합니다. 다만 원격 배포(D) 때문에 `HighNginxRequestRate`와 `HighPostgresConnections`는 팀원 PC exporter가 붙기 전까지 데이터가 없습니다. `HighCpuUsage`, `HighMemoryUsage`, `ContainerRestarted`, `HighNetworkReceive`도 원격 cAdvisor가 없는 동안 데이터가 없습니다([REMOTE_DEPLOYMENT.md](REMOTE_DEPLOYMENT.md) §1).

### 2.3 Grafana 패널

| 패널 | 영향 |
|---|---|
| aiops-main 31/32/33 (`{service=...}` 원본 로그) | 동작. JSON 원문이 그대로 표시됨 (가독성은 `\| json \| line_format` 추가로 개선 가능) |
| leafy-aiops 4 (`{service="db"} \|= "password authentication failed"`) | 동작 (PG jsonlog `message`) |
| aiops-main 5/13 (`pg_stat_activity_count`) | JSON과 무관. postgres-exporter 원격 배치 전까지 데이터 없음 |
| LLM/timeline/slack 패널 (`job=...`) | 영향 없음 |

### 2.4 AIOps Pipeline 조회 코드

| 코드 | 영향 |
|---|---|
| `collector/logs.py` `{service="X"}` | 동작 (실측: backend/frontend/db 모두 조회) |
| `collector/network.py` | 동작 (원격 shipper 경로 회귀 테스트 통과) |
| `prompt/builder.py` `line[:200]`, `[{labels.container}]` | **→ 2026-10-24 수정** (`prompt/log_line.py`: JSON 핵심 필드 우선, `[db]` 접두어, 비밀값 마스킹). 수정 전: **품질 저하**. PG jsonlog는 앞 200자가 메타데이터(timestamp, pid, session_id…)라 `message`가 잘림. 호스트 PG에는 `container` 라벨이 없어 `[?]` 표시. Backend JSON은 `message`가 약 130~150자에서 시작해 일부만 보임 |
| `main.py` periodic scan (현재 비활성) | `"level":"ERROR"` 문자열로 키워드 집계는 동작. 오탐·누락 경향은 재평가 필요 |

### 2.5 시나리오

| 항목 | 영향 |
|---|---|
| `verifier.verify_loki(keyword=...)` | 동작 (줄 전체 부분 문자열 검색) |
| `run.py fetch_logs` | 동작 (`message` 또는 `log` 추출. Nginx JSON에는 `message`가 없어 원문 표시) |
| 시나리오 docstring의 `{container="backend"}` 표기 | 기존부터 오래된 표기 (JSON과 무관) |
| `docker exec leafy-*`, `psql -h leafy-db` 기반 시나리오 | **원격 배포에서 AIOps PC에서 실행 불가** (D 영향, JSON과 무관) |

## 3. 해결 방안 비교

### 방안 1 — Loki 규칙만 JSON LogQL로 변경

수정 대상: `monitoring/loki/rules/fake/security-rules.yml`의 2개 규칙. 선택 사항으로 대시보드 31/32의 `line_format`도 손볼 수 있습니다.

```logql
# HighNginxErrorRate (예시. 필드 이름은 팀 Nginx log_format 확인 후 확정)
sum(count_over_time({service="frontend", log_format="json"} | json | status >= 500 [1m])) > 10
# VulnerabilityScanningDetected
sum(count_over_time({service="frontend", log_format="json"} | json | status >= 400 and status < 500 [1m])) > 50
```

| 장점 | 단점 |
|---|---|
| 변경이 가장 작음. Fluentd와 본문은 그대로 | 서비스마다 필드 이름이 달라 규칙이 앱 로그 형식에 묶임 |
| 문자열/숫자 status를 LogQL이 함께 처리 | Nginx JSON 실제 필드 이름 미확인 (팀 `log_format` 원문 필요) |
| 정규식 보안 규칙 4개는 그대로 둬도 됨 | 전환 직후에는 `[1m]` 창 안에 TEXT 줄과 JSON 줄이 섞임. 둘 다 잡으려면 한시적으로 두 식을 `or`로 결합해야 함 |

- 호환성: `log_format="json"` 셀렉터로 기존 key_value와 텍스트 줄의 파싱 오류를 배제합니다. 규칙 이름과 annotation은 유지해 Pipeline 분기(alertname 기준)를 바꾸지 않습니다.
- 필요한 테스트:
  - 픽스처(JSON 4xx/5xx, 텍스트, 기존 key_value)를 테스트 Loki에 넣고 ruler `/prometheus/api/v1/alerts`에서 발화와 미발화를 확인
  - `sql_injection.py` E2E
  - 5xx가 없으면 발화하지 않는지 확인하는 음성 테스트

### 방안 2 — Fluentd에서 공통 JSON 스키마로 정규화한 뒤 규칙 변경

수정 대상: `leafy/fluentd/plugins/filter_leafy_docker_log.rb`(서비스별 필드 매핑 추가), `fluent.conf`, 플러그인 테스트, 규칙 2개 이상, 대시보드.

예시: 본문에 `http: {method, status(int), path, client_ip}` 같은 정규화 객체를 추가하고, 원본 필드는 유지합니다.

| 장점 | 단점 |
|---|---|
| 모든 서비스에 같은 규칙식 적용 (`\| json \| http_status >= 500`) | 앱 로그 형식에 대한 결합이 Fluentd로 옮겨갈 뿐 사라지지 않음 (Nginx/Backend 형식이 바뀌면 Fluentd도 수정) |
| 타입·이름 통일 → Pipeline 코드에서도 쓰기 쉬움 | 본문에 파생 필드가 추가되어 "원본 그대로" 원칙이 약해짐 (네임스페이스로 분리 필요) |
| | 변경 범위와 회귀 위험이 가장 큼. 정규화 규칙에 오류가 있으면 탐지가 조용히 빠짐 |

- 호환성: 원본 필드를 남기면 기존 질의는 깨지지 않습니다.
- 필요한 테스트: 서비스별 매핑 단위 테스트, 실데이터(부록B, Nginx 원문) E2E, 규칙 발화 테스트, 매핑 누락 시 표시(예: `http_normalize_error`) 테스트.

### 방안 3 — HTTP 상태코드는 Prometheus, 보안 이벤트는 Loki

근거 (실측, 부록C): Backend Actuator가 이미 `http_server_requests_seconds_count{method, status, outcome, uri}`를 노출합니다. `outcome`은 `CLIENT_ERROR`/`SERVER_ERROR`로 정규화돼 있고, `uri`는 템플릿 경로라 cardinality가 낮습니다. `logback_events_total{level}`, `hikaricp_connections_*`, `spring_security_authorizations_seconds_count{error=...}`도 쓸 수 있습니다.

```promql
sum(rate(http_server_requests_seconds_count{job="leafy-backend", outcome="SERVER_ERROR"}[1m])) * 60 > 10
sum(rate(http_server_requests_seconds_count{job="leafy-backend", outcome="CLIENT_ERROR"}[1m])) * 60 > 50
```

수정 대상: `monitoring/prometheus/rules/alert.rules.yml`(신규 규칙), `monitoring/prometheus/targets/leafy-backend.yml`(원격 scrape 활성화), `security-rules.yml`(규칙 2개 교체 또는 제거), 대시보드, Pipeline alertname 문서.

| 장점 | 단점 |
|---|---|
| 로그 형식과 무관하고, 집계 비용이 낮으며, 지표가 정규화돼 있음 | **Backend가 죽으면 지표도 없음.** Nginx가 내는 502/504(backend 다운)는 이 방식으로 못 잡음 |
| 탐지 규칙 2개를 로그 형식에서 분리 | Actuator 9090을 Tailscale로 열어야 함. **확정 포트표에 없는 포트** |
| | Nginx 단계에서 끝나는 요청(정적 경로 스캔 등)은 보이지 않음. SPA fallback이면 스캔도 200으로 응답할 수 있음 |
| | alert 이름(`HighNginx…`)과 측정 대상(backend)이 어긋남. NIST 명명 원칙 주석과 충돌하므로 이름 변경이 필요 |

- 필요한 테스트: `promtool test rules`(합성 시계열), 실제 Actuator scrape, 장애 주입(MinIO 중단 → 업로드 500은 부록B와 같은 상황), backend 중단 시 Nginx 502를 Loki 경로로 잡는지 확인.

## 4. 추천

**방안 1을 먼저 적용하고, 방안 3을 보강으로 추가하는 순서**를 추천합니다. 방안 2는 지금은 보류합니다.

1. 실제로 깨진 규칙은 2개뿐이고, LogQL이 타입 차이를 이미 흡수합니다. 그래서 방안 2의 정규화 비용에 비해 얻는 것이 작습니다.
2. 방안 1만 쓰면 규칙이 Nginx 필드 이름에 묶입니다. 하지만 Nginx `log_format`은 팀이 관리하는 하나의 설정이라, 바뀔 때 규칙도 함께 바꾸면 됩니다. 구현 전에 **팀 Nginx JSON `log_format` 원문**(부록B 같은 실제 샘플)이 필요합니다.
3. Backend 5xx/4xx 비율은 메트릭이 더 정확하고 저렴하므로, 메트릭 포트 합의 후 방안 3으로 추가합니다. 단, **Nginx 502(backend 다운)는 Loki 규칙(방안 1)으로 남겨야** 탐지 공백이 생기지 않습니다.
4. 선택 시 함께 결정할 것: 전환 기간 동안 TEXT와 JSON 이중식을 유지할 기간, Backend SQLi를 `query_decoded` 필드 기준 규칙으로 추가할지 여부.
