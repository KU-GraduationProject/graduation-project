# M3 — 신규 탐지 룰 구현 및 오프라인 검증

## 1. 결과와 작업 범위

작업일은 **2026-11-10(KST)**이며 기준은 `main`의 `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`이다. 시작 시 `main...origin/main`, tracked 변경 0개와 기존 `docs/rulepack/`·`tools/rulepack/` 미커밋 산출물을 확인하였다. 원격 HEAD를 새로 조회한 결과는 아니다.

**GC PC → JH PC의 실제 관측 데이터 전달은 사용자의 직접 확인 사실로 수용하였다.** OI-01 재조사나 PC 접속 정보 요청 없이 M3 구현을 진행하였다. 이전 [OI-01 기록](OI_01_RUNTIME_INVENTORY.md)은 당시 조사 결과로 보존하였다. 전달 경로의 사용자 확인과 이번 신규 룰의 필드별 검증·실제 발화는 구분한다.

| 대상 | 이번 구현 결과 | 남은 항목 |
|---|---|---|
| `SQLInjection` | **정적 구현·오프라인 검사 완료**이다. JSON 요청 URI를 한 번 URL 디코딩한 뒤 SQLi 의심 구문을 검사한다. | 현재 Nginx 이미지의 필드·타입, 서버 버전 호환성, 정상 트래픽 오탐과 실제 룰 평가는 UNVERIFIED이다. |
| `LoginBruteForce` | **해당 룰만 보류**하였다. 인증 결과를 생성하는 계약이 없어 경보를 생성하지 않는다. | 인증 실패 빈도와 실패→성공 모두 정확한 결과 이벤트 및 동일 행위자 계약이 필요하다. |
| `DBConnectionLimit` | **서버 연결 거부 로그 분기 구현·오프라인 검사 완료**이다. PG17 host jsonlog의 서버 슬롯 부족 오류를 검사한다. | 전체 연결 사용률/상한 기반 조기 경보는 보류이다. Hikari 풀 고갈은 이번 룰의 대상이 아니다. |

기본 결과는 Loki 경보 **2개**이다. 새 Prometheus 운영 룰은 생성하지 않는다. 테스트 통과는 실제 Loki Ruler·Alertmanager·Pipeline 경보 발화 확인이 아니며 M3 전체 상태는 **부분 구현 완료 / 해당 입력의 런타임 인수 대기**이다.

기존 M1/M2/OI 문서·매핑·생성기·테스트와 관련 운영 파일 **39개**의 SHA256을 시작 시 기록하고 종료 시 일치함을 확인하였다. 운영 17개 룰, 수집/Compose/Pipeline 설정은 변경하지 않았다. 컨테이너 조작·배포·reload·DB 변경·Git commit/push/PR 생성은 수행하지 않았다. 시나리오 주입 구현·공격 강도·Heldout은 개발 입력이나 임계값 결정 자료로 사용하지 않았다.

## 2. 구현 파일과 입력 계약

| 파일 | 역할 |
|---|---|
| [generate_m3.py](../../tools/rulepack/generate_m3.py) | 신규 두 룰의 독립 생성기이다. API·Docker·DB를 호출하지 않는다. |
| [targets.yml](m3/targets.yml) | 실제 수집 계약에 있는 service/runtime으로 대상과 Pipeline 분석 alias를 지정한다. |
| [loki.rules.yml](m3/generated/loki.rules.yml) | 신규 `SQLInjection`, `DBConnectionLimit`의 전체 LogQL·라벨·annotation 정의이다. |
| [test_generate_m3.py](../../tools/rulepack/tests/test_generate_m3.py) | 합성 JSON, native 필터, 기존 SQLi 룰 비교, 문법·매핑·경계 검증이다. |

출력은 고정된 `docs/rulepack/m3/generated/loki.rules.yml`이며 Compose의 운영 룰 mount 밖에 있다. 생성기는 운영 경로를 출력 대상으로 받는 옵션이 없다. 기존 M2 생성기나 결과를 import·변경하지 않는다.

| 입력 | 저장소 근거 | 이번 사용·판정 |
|---|---|---|
| Nginx `request_uri` | [기존 JSON 형식 기록](../remote/LOKI_RULES_JSON_REVIEW.md)의 Nginx 형식, [Pipeline 소비 필드](../../aiops/pipeline/prompt/log_line.py)의 `request_uri/uri`, [Docker 필터](../../leafy/fluentd/plugins/filter_leafy_docker_log.rb)의 JSON 보존이다. | `request_uri` 하나만 사용한다. Nginx 생성 소스는 외부 이미지에 있어 현재 이미지 적용은 런타임 확인 항목이다. |
| 앱 Loki `service`, `runtime`, `log_format` | 위 Docker 필터와 [Fluentd 라벨 route](../../leafy/fluentd/fluent.conf)이다. | 기본 `service="frontend",runtime="container",log_format="json"`이다. 새 수집 라벨을 가정하지 않는다. |
| PG17 `error_severity`, `state_code`, `message` | [PG 필터](../../leafy/fluentd/plugins/filter_leafy_postgres_log.rb)의 원본 키 보존, 위 소비 코드의 severity/SQLSTATE/message 지원, [PG Fluent Bit JSON parser](../../deploy/leafy-pc/postgresql/parsers.conf)이다. | PG17 jsonlog의 실제 표준 키를 사용한다. 기본 `service="db",runtime="host",log_format="json"`이다. |
| 인증 event/result/reason·성공/실패 의미 | 소비 코드에 `principal`, `source_ip`, `status` 지원은 있지만 결과 생성 계약은 없다. Java 인증/ACCESS 생성 소스는 저장소에 없다. | 소비 키 존재를 로그인 결과 생성 증거로 삼지 않는다. 미확인 event 이름·성공 문구를 만들지 않는다. |
| DB 전체 연결 상한·현재 연결수 | 기존 룰은 `pg_stat_activity_count`를 사용하지만 exporter 차원·전체 집계와 상한 메트릭의 정확한 이름이 고정되지 않았다. | `max_connections` 계열 이름이나 상한값을 추정하여 PromQL을 생성하지 않는다. |

PostgreSQL의 `state_code`·`error_severity`·`message`는 [PG17 JSON 로그 공식 명세](https://www.postgresql.org/docs/17/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-JSONLOG)에 있는 키이다. 원본 보존 경로와 표준 필드 존재를 근거로 구현했으며 이번 세션의 원격 로그 실측이라고 표시하지 않는다.

매핑은 service/runtime 필수의 동등 비교이며 Docker의 `container_name`, `source`만 선택적으로 허용한다. 현재 DB 분기는 host PG17 JSON 계약만 지원하므로 container DB·host의 container_name/source를 거부한다. 중복 id/alias와 겹치는 selector도 거부한다. 한 종류의 target 목록을 비워 그 종류만 보류할 수 있다.

`rulepack_target`은 생성한 경보의 고정 라벨이며 수집 데이터의 라벨이 아니다. `m3_*`는 쿼리 안에서 만든 임시 파싱/검증 라벨이고 집계 전에 제거한다. `annotations.container`는 기존 Pipeline 소비 계약을 따라 각각 `leafy-frontend`, `leafy-db`이다. 별도 PC의 같은 service를 현재 라벨로 분리할 수 없는 경우에는 OI-09의 scope/identity 작업이 필요하다.

## 3. SQLInjection

### 3.1 탐지 조건

전체 정의는 [생성된 LogQL](m3/generated/loki.rules.yml)에 있다. 다음 순서로 평가한다.

1. frontend/container/json stream을 선택한다.
2. `fromJson(__line__)`으로 문서 전체가 유효한 JSON 객체이고 `request_uri`가 문자열인지 검사한다.
3. `request_uri`만 추출하여 `urldecode`를 **한 번** 적용한다. 파싱·템플릿/디코딩 오류는 `__error__=""` 조건으로 제외한다.
4. 디코딩된 URI에서 대소문자 구분 없이 다음 패턴 중 하나를 검사한다.
5. 임시 라벨을 제거하고 대상별 `sum(count_over_time(...[2m])) > 0`으로 집계한다. `for: 0m`, severity `warning`, category `security`이다.

| 의심 패턴 | 지원 범위 |
|---|---|
| `UNION SELECT`, `UNION ALL SELECT` | 공백·개행 및 단순 `/*...*/` 구분자를 허용한다. |
| `OR/AND 1=1`, 따옴표로 감싼 `'1'='1'`, `"1"="1"` | 제한된 동등 참 비교 패턴이다. 일반 SQL 의미 분석기는 아니다. |
| `sleep(`, `pg_sleep(`, `extractvalue(`, `updatexml(` | 함수 형태의 의심 표현이다. |
| `information_schema` | 메타데이터 접근 의심 표현이다. |
| `; DROP/ALTER/TRUNCATE TABLE` | 세미콜론 뒤의 테이블 변경 구문이다. |

`urldecode`·`fromJson`은 [Loki 공식 template 함수](https://grafana.com/docs/loki/latest/query/template_functions/)를 사용한다. 필드 정규식 필터는 전체 문자열에 매칭하므로 앞뒤 검색 범위와 개행 모드를 식에 명시하였다. 전체 JSON/문자열 검사에는 Go template의 `printf "%T"`, `index`, 조건식을 사용하며 LogCLI 3.7.1에서 실제 실행하였다.

### 3.2 기존 룰과 의미 차이

기존 `SQLInjectionAttempt`는 전체 로그 line의 패턴을 2분 동안 합산하여 **6건 이상**이면 발화한다. 신규 룰은 **URI 필드의 한 번 디코딩한 표현**에 한정하고 2분 내 **1건 이상**을 의심 요청 신호로 알린다. User-Agent나 다른 JSON 필드에만 있는 SQL 문자열은 제외한다. 키워드 자체를 percent 인코딩한 표현과 `UNION/**/SELECT`는 신규 룰이 추가로 다루는 예이다.

이는 빈도 임계값을 보존하는 M2 일반화와 다른 신규 정책이다. 1건 기준은 구문 신호를 조기에 검토하는 연구 기본값이며 공격 주입 횟수/강도를 따라 정한 값이 아니다. 정상 업무 URI에도 SQL 문장이 있을 수 있어 운영 오탐 검토는 남아 있다. 기존 룰과 동시에 운영하면 중복 경보가 가능하므로 향후 통합·교체 정책 검토가 필요하다. 이번에는 둘 다 운영에 추가·교체하지 않았다.

탐지 의미는 **요청의 의심 문자열**이다. 실제 SQL 실행·DB 영향·침해 성공을 의미하지 않는다. 요청 본문·WAF·`request_length`·미생성 `query_decoded`는 사용하지 않는다. 재귀/이중 디코딩, 잘못된 percent escape, 임의 SQL 난독화·대체 인코딩, 요청 본문에만 있는 SQLi는 지원하지 않는다. 상태코드·응답 시간 조건은 공격 성공의 대리값으로 추가하지 않았다. 원본 IP 신뢰가 미확정이므로 client별 빈도로 확장하지 않고 target 전체의 사건 수로 집계한다.

## 4. LoginBruteForce — 해당 룰만 보류

실패 빈도를 셀 **정확한 인증 실패 이벤트**, 성공 결과 이벤트, 실패 원인, 같은 출발지/사용자의 연결 계약이 저장소에서 확정되지 않았다. 단순 401/403, DB의 `authentication failed`, 소비 코드에 있는 `principal`만으로 이를 대체할 수 없다. 외부 Java 이미지의 생성 코드를 확인하지 않고 `login_failed`, `login_success` 같은 새 필드를 가정하지 않았다.

| 분기 | 구현을 재개할 최소 입력 | 현재 처리 |
|---|---|---|
| 실패 빈도 | 인증 실패를 명확히 구분하는 기존 키/값 또는 안정된 message 계약, 시각, 신뢰 가능한 집계 키이다. | 보류이며 일반 401 빈도 룰을 대신 만들지 않는다. |
| 실패→성공 | 위 실패와 같은 행위자의 성공 계약, 사건 시각/지연 및 순서 판정이다. | 보류이며 같은 시간창에 실패와 성공이 있다는 사실을 순서 증거로 쓰지 않는다. |

`request_id`는 한 요청의 여러 로그를 연결하는 값이며 여러 로그인 요청의 행위자 식별자를 대신하지 않는다. 동일 출발지 IP도 NAT나 공유 프록시에서는 동일 사용자 증거가 아니다. 성공/실패를 각각 집계할 때 ACCESS/AuthService 중복 이벤트를 어떻게 피할지도 정해야 한다.

필요한 것은 OI-06의 **기존 인증 로그 결과 계약**이다. 새 공격/로그인 시도나 PC 접속 정보는 이번 구현의 선행 요청으로 두지 않았다. 해당 계약이 확보되면 실패 빈도부터 추가하고, 순서를 보장하는 분리 시간창 또는 명시적 상관분석을 별도로 검증할 수 있다. 현재 생성기는 `LoginBruteForce` 요청을 명시적으로 거부하며 테스트도 이를 확인한다. 미구현 룰을 빈 식이나 미확인 필드의 비활성 경보로 포장하지 않는다.

## 5. DBConnectionLimit — 서버 연결 거부 분기

### 5.1 구현한 조건

host PG17/json stream의 필수 세 키가 **문자열**이고 전체 문서가 유효한 객체인지 먼저 확인한다. 다음 세 조건을 모두 만족한 사건을 2분 동안 집계하여 1건 이상이면 경보한다.

```text
error_severity = FATAL
state_code = 53300
message = "sorry, too many clients already"
       또는 "remaining connection slots are reserved for ..."
```

조건은 `sum(count_over_time(...[2m])) > 0`, `for: 0m`, severity `critical`, category `infra`이다. message는 전체 필드의 시작/끝을 제한하여 statement 안의 인용 문구를 제외한다. 실제 서버가 연결을 거부한 사건이므로 반복 횟수를 기다리지 않는 기본 정책이다. 공격 강도와 무관하게 가용성 증상으로 분류하며 악의적 고갈 원인을 단정하지 않는다.

[PG17 SQLSTATE 명세](https://www.postgresql.org/docs/17/errcodes-appendix.html)는 `53300`을 `too_many_connections`로 정의한다. 그러나 역할·DB별 연결 제한도 같은 코드일 수 있어 코드만으로 서버 전체 상한 도달을 선언하지 않는다. 위 서버 슬롯 문구와 FATAL을 함께 요구하여 역할별/DB별 연결 제한을 제외한다. 예약 슬롯 경고는 일반 접속에 대한 거부이며 모든 권한의 잔여 연결 수가 0임을 뜻하지 않는다. 관련 예약 슬롯 의미는 [PG17 연결 설정](https://www.postgresql.org/docs/17/runtime-config-connection.html)을 따른다.

### 5.2 분리한 미지원 범위

| 항목 | 판정 |
|---|---|
| 실제 서버 슬롯 거부 | 새 로그 룰의 구현 범위이다. |
| 현재 연결수/상한 사용률·사전 경고 | 정확한 exporter 계측명·라벨·DB 전체 집계와 상한이 없어 보류이다. 상한을 100 등으로 가정하지 않는다. |
| 기존 `HighPostgresConnections` | `pg_stat_activity_count > 40`인 개별 시계열 조건이다. 서버 전체 연결 사용률이나 접속 거부 증거를 뜻하지 않는다. |
| HikariCP active/pending/max/timeout | 애플리케이션 풀의 입력이며 PG 서버 상한과 별개이다. 이번 룰에 포함하지 않는다. |
| PG16 Docker stderr 텍스트 | host PG17 JSON 필드를 가진다고 가정하지 않는다. 현재 생성기의 DB 분기 지원 밖이다. |
| 로컬 언어 오류·필수 키 누락 | 현재 영문 메시지 조건에서 빠질 수 있다. 코드만 보고 서버 고갈로 일반화하지 않는다. |

서버 거부가 없어도 Hikari 풀이 먼저 고갈될 수 있고, Hikari timeout이 있어도 PostgreSQL 서버 슬롯이 남아 있을 수 있다. F2-c의 서버 연결 한도 고갈과 풀 고갈은 별도 입력·별도 판단 대상으로 유지하였다.

## 6. 기존 17개 룰과 조건 중복

근거는 운영 [Loki 보안 룰](../../monitoring/loki/rules/fake/security-rules.yml), [네트워크 룰](../../monitoring/loki/rules/fake/network-allowlist.yml), [Prometheus 룰](../../monitoring/prometheus/rules/alert.rules.yml)의 alert/expr이다. 시나리오 구현은 대조 자료로 사용하지 않았다.

| 기존 룰 | M3와의 관계 |
|---|---|
| `SQLInjectionAttempt` | SQLi 요청의 직접 중복이다. 원문 전체/2분 6건과 URI 디코딩/2분 1건의 차이가 있다. |
| `UnauthorizedDBAccess` | DB 인증 실패이며 서버 슬롯 부족과 다르다. 신규 DB 룰은 인증 실패를 제외한다. 앱 로그인 brute force도 아니다. |
| `HighPostgresConnections` | DB 연결 증가 증상은 관련되나 고정 개별 시계열과 서버 거부 사건은 다른 조건이다. |
| `HighNginxErrorRate` | 같은 HTTP 요청이 5xx를 내면 함께 경보할 수 있다. 신규 SQLi에는 status 조건이 없다. |
| `VulnerabilityScanningDetected` | 같은 요청이 4xx이면 빈도 경보와 함께 발생할 수 있다. 일반 4xx를 인증 실패로 바꾸지 않았다. |
| `HighNginxRequestRate` | SQLi나 인증 시도 중 요청량 조건이 함께 충족될 수 있다. 신규 구문/거부 조건과 직접 동일하지 않다. |
| `PathTraversalAttempt` | 같은 URI가 두 패턴을 포함할 수 있으나 traversal과 SQL 구문은 별도 조건이다. |
| `SecretDumpAttempt` | printenv/marker이며 신규 조건과 직접 중복하지 않는다. |
| `SuspiciousProcessExecution` | 명령 문자열이며 신규 조건과 직접 중복하지 않는다. |
| `SuspiciousProcessExec` | outbound marker이며 신규 조건과 직접 중복하지 않는다. |
| `ContainerEscapeAttempt` | escape marker이며 신규 조건과 직접 중복하지 않는다. |
| `UnauthorizedDataTransfer` | L4 bytes/목적지 조건이며 신규 조건과 직접 중복하지 않는다. |
| `UnauthorizedTransferEarly` | L4 threshold/목적지 조건이며 신규 조건과 직접 중복하지 않는다. |
| `HighCpuUsage` | 자원 증상이 동시 발생할 수 있으나 직접 동일한 조건은 아니다. |
| `HighMemoryUsage` | 위와 같은 자원 증상 관계이다. |
| `ContainerRestarted` | 시작/재시작 상태이며 직접 동일한 조건은 아니다. |
| `HighNetworkReceive` | 수신량 증상이며 직접 동일한 조건은 아니다. |

alert 이름이 달라지면 Pipeline의 기존 alertname/대상 중심 dedup으로 SQLi의 의미 중복을 자동 제거하지 못한다. `rulepack_target` 추가도 OI-09의 source/identity 처리를 해결하지 않는다. 이번 결과는 배포되지 않은 초안이며 기존 경보 억제·삭제 정책은 변경하지 않았다.

## 7. 오프라인 검증 결과와 한계

사용 도구는 이전 M2 작업에서 공식 release digest와 대조한 임시 **LogCLI 3.7.1**, **promtool 3.7.3**이다. 이번에는 바이너리를 새로 설치하거나 서비스/컨테이너를 실행하지 않았다.

| 검사 | 결과·범위 |
|---|---|
| M3 unittest | **13개 PASS, SKIP 0개**이다. |
| M2+M3 전체 회귀 | **49개 PASS, SKIP 0개**이다. |
| LogCLI `fmt` | 기본/escaping 대상의 전체 LogQL 4개 문법 검사 PASS이다. |
| LogCLI `--stdin query` | **SQL 29개 + DB 17개 = 46개 합성 로그**의 실제 필터/템플릿 실행 PASS이다. 실제 로그를 복사하지 않았다. |
| 기존 SQLi와 native 비교 | 원문 UNION은 둘 다 일치, 키워드 인코딩·주석 구분자는 신규만 일치, User-Agent에만 있는 패턴은 기존만 일치한다. |
| source/time fixture | 다른 service/runtime, 미래 사건, 2분 창의 왼쪽 경계와 현재 시각을 구분한다. 라벨/시각 선택은 테스트 fixture 코드에서 수행한다. |
| promtool 검사 | **테스트 전용 count gauge로 치환한 PromQL/YAML**의 문법·sum/비교, 0/1/복수 건·해소·입력 없음·annotation/라벨 검증 PASS이다. |
| 재생성·불변성 | 생성기 `--check` 및 시작 시 기존 39개 파일의 해시 보존 PASS이다. |

SQL 합성 로그에는 정상 URI, 단어 경계, 참이 아닌 `1=10`, User-Agent/message만의 패턴, 키 누락/null/숫자/객체/배열, JSON escaping, 잘린 JSON/후행 쓰레기, 잘못된 percent escape, 이중 인코딩을 포함하였다. DB 합성 로그에는 서버 슬롯 문구 3종, 인증 실패, 다른 SQLSTATE/severity, 역할/DB별 제한, Hikari timeout, statement 인용, 로컬 언어·키/타입 오류를 포함하였다.

Native 검사에서 필드 선택형 `json` 파서가 필요한 키를 얻고 일찍 종료하여 잘린 JSON 앞부분을 받아들이는 동작을 확인하였다. 이를 전체 `fromJson` 검증으로 차단하고, 객체/배열 URI가 문자열로 변환되어 패턴에 걸리는 문제도 원본 타입 검사로 차단하였다.

**검증의 경계:** [LogCLI stdin 공식 설명](https://grafana.com/docs/loki/latest/query/logcli/getting-started/#use-stdin-to-query-locally)처럼 stdin은 실제 stream 라벨이나 metric query를 평가하지 않는다. 따라서 전체 LogQL 문법과 로그 pipeline은 native 검사, scope/시간창은 합성 fixture, 경보 경계는 promtool의 테스트 전용 count로 나누어 검증했다. `m3_fixture_matches`는 테스트 임시 파일에만 존재하며 새 수집 메트릭이 아니다. 실제 Loki의 `count_over_time`·Ruler 로딩·평가 스케줄·실제 라벨 선택을 native end-to-end로 검증했다고 주장하지 않는다. 정상 입력 없음과 수집 장애도 이 두 룰만으로 구분하지 못한다.

## 8. 재생성·검증 명령

저장소 루트에서 실행하며 Python/PyYAML이 필요하다. 출력은 초안 파일뿐이다.

```shell
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/generate_m3.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/generate_m3.py --check
M3_LOGCLI=/path/to/logcli M3_PROMTOOL=/path/to/promtool PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -p test_generate_m3.py -v
# M2를 포함한 전체 회귀 검사이다.
M2_LOGCLI=/path/to/logcli M2_PROMTOOL=/path/to/promtool \
M3_LOGCLI=/path/to/logcli M3_PROMTOOL=/path/to/promtool PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -v
```

PowerShell에서는 현재 프로세스에만 도구 경로를 지정한다.

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:M3_LOGCLI = '<검증된 로컬 logcli.exe 경로>'
$env:M3_PROMTOOL = '<검증된 로컬 promtool.exe 경로>'
python tools/rulepack/generate_m3.py --check
python -m unittest discover -s tools/rulepack/tests -p test_generate_m3.py -v
```

도구 경로를 생략하면 M3의 native 검사 6개는 SKIP이며 통과로 계산하지 않는다. LogQL 식을 그대로 `promtool check rules`에 넣는 것은 PromQL 검사가 아니므로 하지 않는다. 테스트가 만드는 임시 PromQL/count fixture만 promtool의 검사 대상이다.

## 9. 실제 환경에서 남은 확인과 완료 판정

기존에 접근 가능한 Grafana/Prometheus/Loki 운영 조회 경로에서 **현재 저장된 데이터**로 아래 항목을 인수할 수 있다. PC 주소 재요청이나 OI 전체 완료 대기는 이번 구현을 막는 게이트로 두지 않았다.

| 항목 | 필요한 확인 |
|---|---|
| SQL 입력 | 실제 frontend/container/json 라벨과 `request_uri` 문자열, 현재 이미지의 원문 URI 의미를 확인한다. 본문·다른 필드로 자동 fallback하지 않는다. |
| SQL 계산 | 설치된 Loki에서 생성식의 파싱·template 함수 지원·평가 오류·기존 정상 트래픽 오탐을 확인한다. 매칭 로그가 없으면 실제 조건 발화는 UNVERIFIED이다. |
| DB 입력 | host DB/json 라벨과 세 키/타입·영문 슬롯 거부 문구를 확인한다. 기존 거부 사건이 없으면 해당 사건의 실제 발화는 UNVERIFIED이다. |
| DB 상한 | OI-05에서 전체 DB 연결 scope와 상한의 정확한 메트릭/차원을 확보한 뒤 조기 경보 분기를 추가한다. Hikari 입력은 따로 취급한다. |
| 로그인 | OI-06에서 기존 성공/실패 로그의 키/값·원인·시각·actor 및 중복 계약을 확정하여 보류 룰을 구현한다. |
| 소비 경로 | 현재 `leafy-frontend`, `leafy-db` alias와 실제 service/runtime 대응을 확인한다. source 보존·중복 제거는 OI-09에 연결한다. |
| 향후 적용 | 기존 SQLInjectionAttempt와 신규 SQLInjection의 교체/공존 정책, 실제 평가·Alertmanager·Pipeline 연결을 별도 인수한다. 이번에 운영 load/reload는 하지 않았다. |

| 완료 항목 | 판정 |
|---|---|
| SQLInjection 정적 코드·초안·합성 검증 | PASS이다. |
| DBConnectionLimit 서버 연결 거부 분기 | PASS이다. |
| LoginBruteForce 빈도·실패→성공 | 입력 생성 계약 미확정으로 해당 룰만 보류이다. |
| DB 전체 상한/사용률 기반 분기 | 상한 계측 계약 미확정으로 해당 분기만 보류이다. |
| 기존 M1/M2·운영 룰/설정 보존 | PASS이다. |
| GC→JH 전달 사실 | 사용자 직접 확인이다. 이번 세션의 재측정 결과로 쓰지 않았다. |
| 신규 룰 실제 경보·운영 적용 | UNVERIFIED / 미수행이다. |
| M3 전체 | **2개 로그 룰 구현·오프라인 검증 완료, 인증 및 상한 계측 분기는 개별 보류**이다. |
