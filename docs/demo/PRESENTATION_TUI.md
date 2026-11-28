# Leafy AIOps 발표용 TUI (#87)

Python 3.11+ / Textual. 실제 상태만 표시한다. LLM 프롬프트·호출·스키마·레거시
`scenarios/run.py`는 변경하지 않는다. TUI는 Slack 승인 버튼을 대신 누르지 않는다.

## 빠른 실행 (Mac, 저장소 루트)

```sh
python3 -m venv .venv-tui
.venv-tui/bin/python -m pip install -r scenarios/presentation/requirements.txt
mkdir -p .local
cp scenarios/presentation/config.example.json .local/presentation.json
.venv-tui/bin/python -m scenarios.presentation --config .local/presentation.json --profile mac-dev --check
.venv-tui/bin/python -m scenarios.presentation --config .local/presentation.json --profile mac-dev
```

홈과 선택 화면은 연결 없이 열 수 있다. 실제 실행 전 프로필과 AIOps 설정을 맞춰야 한다.
설정 예제의 identity/selector/주소는 **예시**다. 테스트 PC에서 확인한 값으로 교체한다.
`.local`과 `.venv-tui`는 로컬 전용으로 관리하고 비밀값을 Git에 추가하지 않는다.

현재 세션에서 사용한 격리 개발 인터프리터는 `/private/tmp/leafy-tui-venv/bin/python`이다.
이 환경으로 화면을 열 때는 프로필의 `runner.python`도 이 경로로 바꾼다.

## 환경별 역할 설정

| 프로필 | 용도 | 실제 장비 역할 |
| --- | --- | --- |
| `mac-dev` | Mac 화면/단위 테스트, 로컬 Gemini 연동 | 루프백 주소 예시, 로컬 주입기 |
| `mac-jh` | Mac + JH 연동 테스트 | AIOps/시나리오 호스트는 테스트 직전 확정 |
| `gc-jh` | GC + JH 정식 시연 | AIOps/시나리오 호스트는 시연 환경에서 확정 |

`pipeline_url`, `remediation_url`, `prometheus_url`, `loki_url`, `airflow_url`은
서로 독립이다. TUI를 어느 PC에서 열어도 각 서비스의 직접 주소 또는 SSH 포워드 주소를 쓴다.
샘플의 GC/JH SSH 이름과 경로는 미검증이며 **장비 역할을 지정하는 결정이 아니다**.

`identity`는 기존 `OBSERVATION_BINDINGS`로 확정한 다섯 필드
`site/service/source/runtime/target` 전체다. `metric_selector`와 `log_selector`는
동일 관측 원천의 정확한 라벨이다. CPU·메모리·RX 기본 PromQL을 실제 exporter에 맞게
`metric_names`로 바꿀 수 있다. 값이 없거나 여러 시계열이면 0으로 채우지 않는다.

시나리오별 관측 대상이 다르면 `scenario_profiles`로 덮어쓴다. 예를 들어 MinIO 중단은
backend 프로필을 그대로 쓰지 말고 실제 탐지·조치 대상의 identity와 selector를 지정한다.

```json
{
  "scenario_profiles": {
    "f2_a_minio_outage": {
      "identity": {"site":"실측값","service":"minio","source":"실측값","runtime":"container","target":"leafy-minio"},
      "metric_selector": {"job":"실측값","instance":"실측값","name":"leafy-minio"},
      "log_selector": {"site":"실측값","service":"minio","source":"실측값","runtime":"container"}
    }
  }
}
```

시나리오 실행은 **대상 Docker 호스트에서** 수행한다. Mac은 제어 화면만 맡을 수 있다.

```json
{"runner":{"mode":"ssh","host":"SCENARIO_PC","shell":"powershell","repo":"C:\\work\\graduation-project","python":".venv-tui\\Scripts\\python.exe"}}
```

POSIX 호스트는 `shell: "posix"`, 절대 repo/python 경로를 쓴다. SSH는 `BatchMode=yes`이므로
키 인증을 사전에 설정한다. Windows는 OpenSSH에서 PowerShell 명령 실행이 가능해야 한다.
원격 레포에도 같은 TUI/worker 변경과 requirements가 있어야 한다. PC 시계는 NTP로 맞춘다.

## 기존 AIOps에 필요한 설정

기존 배포 Compose 조합 **마지막에** `-f deploy/presentation.compose.yml`을 추가한다.
기존 remote/extended 실행기·정책·대상 매핑 설정을 유지해 사용한다. 기본 AIOps Compose의
`REMEDIATION_MODE=disabled`만으로는 실제 데모가 실행되지 않는다.

```sh
# 기존 환경의 Compose 인자를 그대로 사용하고 마지막에 presentation override를 추가
docker compose -f docker-compose.aiops.yml \
  -f deploy/aiops-pc/remediation-remote.example.yml \
  -f deploy/presentation.compose.yml up -d --build pipeline remediation
```

위 remote 파일은 참조 예제다. 이미 실측된 배포 override가 있으면 그것을 사용한다.
원격 Agent 주소·키 파일·대상 바인딩은 기존 [원격 조치 절차](../remote/PHASE3_REMOTE_AGENT.md)를 따른다.
이 명령은 이 작업에서 GC/JH에 실행하지 않았다.

| 설정 | 적용 위치 / 역할 |
| --- | --- |
| `GEMINI_API_KEY`, `LLM_PROVIDER=gemini` | Pipeline의 기존 Gemini 설정 |
| `OBSERVATION_BINDINGS` | Pipeline의 실제 관측 원천 매핑. 기본 `[]`로는 RCA 불가 |
| `CONTEXT_CAPTURE_DIR=/app/results/context` | 기존 경보 입력 캡처. override가 활성화 |
| `PRESENTATION_CONTEXT_DIR=/app/presentation-context` | Remediation이 캡처를 읽는 읽기 전용 공유 경로 |
| `REMEDIATION_API_KEY` | Pipeline·Remediation·TUI 프로세스의 동일한 서비스 HMAC 키 |
| `REMEDIATION_APPROVAL_ENABLED=true` | 기존 RCA→승인 제안 경로. override가 활성화 |
| `REMEDIATION_AUTO_EXECUTE_ENABLED=false` | 발표에서는 기존 승인 게이트를 기다림 |
| `SLACK_TRANSPORT`, `SLACK_APP_TOKEN`, `SLACK_TEAM_ID`, `SLACK_CHANNEL_ID` | 기존 Socket Mode HITL 설정 |
| `SLACK_BOT_TOKEN` | 추가 Web API 전송. `chat:write`, 채널 멤버십, 메시지 permalink 조회 권한 필요 |
| `REMEDIATION_SERVICE_VERIFICATION_LOCAL_PATH` | 실제 대상별 Health + Prometheus 복구 프로필 |

토큰·키 값은 기존 환경 파일/비밀 저장소에서 주입한다. 설정 JSON에는 넣지 않는다.
기존 Incoming Webhook과 Socket Mode 흐름도 계속 지원하지만, Incoming Webhook 응답만으로는
메시지 ts를 얻을 수 없어 TUI의 실제 메시지 링크에는 bot 전송이 필요하다. 승인 버튼의
`remediation_id`, 서명/채널 검증, 멱등성, TTL 및 기존 실행기는 그대로 사용한다.

복구 프로필의 기본값은 `profiles: []`다. 실제 시연 전
[기존 서비스 검증 예제](../../deploy/aiops-pc/remediation-service-verification.example.yml)를
실측 identity·health URL·토큰 환경변수 이름·정확한 PromQL·SLO 임계로 작성한다.
CPU/메모리/가용성 등 **선택 시나리오가 정상으로 돌아왔음을 증명하는** 지표를 포함한다.
명령 성공·컨테이너 running만으로는 COMPLETED가 되지 않는다.

## 화면과 시연 순서

1. 홈 → **시나리오 실행** → S/F/C → 레지스트리의 실제 항목 선택 → 실행.
2. 대상 지표·로그, 서비스 HMAC 읽기 경로와 캡처 설정을 확인한 뒤 주입기를 시작한다.
3. 경보 수신 → RCA → Slack 승인 대기로 갱신된다. `[O]`/버튼으로 해당 메시지를 연다.
4. Slack의 기존 **Approve**를 누르면 승인된 실제 조치 단계와 로그를 표시한다.
5. 조치 효과 검증 후 기존 `/service/verify`의 연속 Health/새 scrape 검증을 진행한다.
   `service_recovered_at`이 확인될 때만 **COMPLETED**다.
6. 거절은 **REJECTED**, 승인 만료는 **EXPIRED**, 조치/검증 실패는 단계·원인과 **FAILED**다.
7. Esc/중지/Ctrl+Q는 주입기에 정리를 요청한다. 정리 실패·미확인은 별도로 표시한다.

현재 주입 확인 이벤트를 제공하는 발표용 생명주기 어댑터:

| ID | 레포 이름 | 재사용 |
| --- | --- | --- |
| `f1_b_memory_leak` | 메모리 압박·누수 (서서히) | 기존 inject/cleanup/watchdog, 승인 동안 즉시 cleanup하지 않음 |
| `s2_a_resource_theft` | 자원 탈취 (채굴형 CPU) | 기존 inject/cleanup/watchdog, 유한 시간 부하 |
| `f2_a_minio_outage` | MinIO 중단 | 기존 inject(down_seconds=0)/cleanup/watchdog |

다른 구현 항목도 기존 v2 러너로 실행하지만, 일부는 자체 정리/주입 시각 훅이 없으므로
TTD/TTR 평균 표본에 넣지 않는다. 외부 도구/독립 네트워크 러너 항목은 목록에서 설명을
보여주고 실행 버튼을 끈다. C 대조군에서 경보가 없으면 **NO_ALERT**, NONE/NOTIFY이면
**NO_ACTION**으로 끝나며 승인이나 복구 시각을 만들어내지 않는다.

F1-b의 allocator는 기존 안전 가드/420초 hold를 유지한다. S2-a는 timeout까지 유한 부하다.
안전 종료나 자가 치유를 승인 조치의 성과로 해석하지 말고 시연 로그를 함께 확인한다.
worker가 종료되더라도 기존 watchdog은 대상 장비에 남아 안전 복구를 수행한다.

RCA 패널은 현재 지표와 별도로 경보 시점 캡처를 표시한다. v2 formatter를 읽기 전용
별도 프로세스에서 재사용해 M/L 증거 ID·정렬·예산을 재현하고 LLM이 인용한 줄에 `▶`를 붙인다.
호스트의 레포 버전은 배포 Pipeline 버전과 맞춘다. 다른 builder/버전은 원문 요약만 보여준다.

## 시간 지표의 의미

| 표시 | 근거 |
| --- | --- |
| TTD | 기존 inject()가 실행을 확인한 이벤트 → Pipeline의 실제 `received_at` |
| TTR | 같은 주입 확인 이벤트 → 기존 검증기의 `service_recovered_at` |
| 승인 대기 | `approval_requested_at` → 승인/거절/만료 시각, 대기 중에는 현재까지 경과 |
| 조치 소요 | `action_started_at` → `action_verified_at` |
| MTTD / MTTR | 현재 환경의 기록 중 각각 탐지/복구 종료 이벤트가 있는 실행 전체의 평균, 각각 n 표시 |

주입 확인은 프로세스 생성 시각이 아니다. 물리적 장애가 시작한 나노초를 추정하지 않고
주입기 acknowledgement 이벤트를 기준으로 한다. 탐지도 경보 startsAt(룰의 pending 시작)을
발화/수신 시각으로 오인하지 않는다. 시각은 UTC, 평균 이력은 `~/.leafy-presentation/<profile>.sqlite3`.
한 실행은 한 행으로 갱신하므로 폴링 횟수가 표본 수가 되지 않는다.

사건은 5필드 대상 + fingerprint + startsAt + 이번 주입 이후 시간창으로 연결한다.
같은 대상에 새 사건이 둘 이상이면 임의로 고르지 않고 실패시킨다. 다른 발표/실험을
같은 대상에서 동시에 실행하지 않는다.

## Airflow 분기

홈 → **Airflow 배치 실행** → 배포된 기존 `dp_*` DAG 선택 → `dag_run.conf` JSON → **Trigger**.
Airflow 3의 `/api/v2`를 사용한다. run ID를 POST 전에 확보하고 queued/running/success/failed와
개별 task 상태를 조회한다. 접수 응답이 유실되면 같은 ID로 조회하고 POST를 자동 재시도하지 않는다.

`AIRFLOW_API_TOKEN` 또는 `AIRFLOW_USERNAME`/`AIRFLOW_PASSWORD`를 TUI 프로세스 환경에 설정한다.
현재 로컬 개발 Compose의 SimpleAuth all-admin 구성은 토큰 없이 접근 가능하다.
기본 예제의 `dp_bronze_acquire`에 `{}`를 Trigger하면 **기존 fixture mock 원천을 읽는 실제 DAG 실행**이며,
실제 AIOps 사건을 적재했다는 뜻은 아니다. 실데이터는 기존 IncidentRequest conf와 원천 설정이 필요하다.
기본 DAG의 provenance 검증을 위해 실제 `DP_GIT_SHA`, clean source 상태를 전달해야 한다.

Mac의 18080을 다른 프로젝트가 사용하면 Airflow Compose override에서 `ports: !override`
`["127.0.0.1:18090:8080"]`을 사용하고 프로필 airflow_url도 맞춘다. 기존 서비스를 끄지 않는다.

## 검증 및 남은 현장 확인

```sh
.venv-tui/bin/python -m unittest discover -s scenarios/presentation/tests -t . -v
cd aiops/remediation
../../.venv-tui/bin/python -m unittest discover -s tests -v
```

개발 검증 결과와 실제 연동 결과는 아래에 별도로 기록한다. 실제 GC/JH 장비의 SSH·경로·역할,
관측 라벨, Slack bot 설정 및 서비스 복구 프로필은 실측 전 미확정이다.

### 2026-11-28 Mac 개발 검증

- TUI/어댑터/시간·상관관계/키보드·반응형·정리 응답 테스트 18개 통과.
- Remediation 기존/추가 회귀 테스트 517개 통과. 실제 Docker 조치·Slack 전송은 mock으로 격리.
- 기존 Gemini 실제 스모크 1개 통과: `gemini-3.5-flash-lite`, 약 1.5초,
  `analysis_status=valid`. 스모크 증거에 대한 결과이며 실제 장애의 RCA 검증은 아니다.
- Textual 실제 화면의 **Trigger** 버튼 → Airflow 3.3.2 기존 `dp_bronze_acquire`
  실행 `leafy_tui__0e332670ea4c43339503e67bc66e06d1` → **SUCCESS** 및 task 상태 표시 확인.
  깨끗한 저장소 HEAD 스냅샷과 별도 `leafy-tui-check` 프로젝트/18090 포트를 사용했다.
  원천은 기존 fixture mock, 실제 DAG와 scheduler/task 실행이다.
- 첫 Airflow 검증은 짧은 SHA를 전달해 기존 provenance 검증에서 FAILED로 표시됨.
  **40자리 전체 Git SHA**를 전달한 다음 실행에서 성공했다. TUI는 실패 상태도 그대로 표시했다.
- Compose override 병합 구문 검사, Python compile, `git diff --check`, trail 검증 통과.
- 실제 Slack 버튼 승인→GC/JH 실행기→실측 서비스 복구 검증은 **미실행**.
  사용자와 합의한 대로 장비 역할·SSH·경로를 받은 뒤 확인한다. 로컬 `SLACK_BOT_TOKEN`도 미설정이다.
- 임시 Airflow 검증 스택은 검증 후 정리한다. 사용자 기존 18080 서비스는 변경하지 않는다.
- main 직접 커밋 전 최신 `origin/main` 통합 검증: TUI 18개 및 Remediation 528개 통과.
  새 formatter의 `targets` 출력 인자를 읽기 전용 어댑터에 반영했다.

참고: [Modern TUI/CLI](https://velog.io/@dkvlg/Modern-TUI-CLI-현대-개발자의-필수-도구),
[TUI Studio](https://news.hada.io/topic?id=27484),
[프레임워크 설계 철학](https://wikidocs.net/blog/@jaehong/8465/),
[Textual workers](https://textual.textualize.io/guide/workers/),
[Airflow REST API](https://airflow.apache.org/docs/apache-airflow/stable/stable-rest-api-ref.html).
