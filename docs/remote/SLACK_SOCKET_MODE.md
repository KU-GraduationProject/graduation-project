# Remediation Slack Socket Mode

Remediation이 Slack으로 WebSocket 연결을 유지해 승인·거부·복구 버튼을 수신한다.
Slack 앱 화면과 ngrok, 공개 Request URL은 필요 없다. Remediation 컨테이너와
인터넷 연결은 유지해야 한다. 기존 정책·실행 모드와 Pipeline의 M5 handoff 보류는
그대로 적용된다. 이 변경만으로 RCA→알림→실제 조치 전체가 활성화되지는 않는다.

## Slack 앱 설정

1. 기존 Incoming Webhook을 소유한 **같은 Slack 앱**을 선택한다.
   다른 앱이 보낸 버튼은 이 앱의 Socket Mode 연결로 오지 않는다.
2. **Basic Information → App-Level Tokens**에서 `connections:write` 권한의
   App-Level Token(`xapp-`로 시작)을 생성한다.
3. **Socket Mode → Enable Socket Mode**를 켠다. **Interactivity & Shortcuts**도
   켠다. Socket Mode에서는 공개 Request URL을 등록할 필요가 없다.
   이 수신기는 `block_actions`만 처리하므로 메시지 읽기 이벤트 구독은 필요 없다.
4. Slack workspace ID(`T...`)와 실제 승인 담당자의 member ID(`U...`/`W...`)를 확인한다.
   표시 이름을 권한 식별자로 사용하지 않는다.
5. 해당 배포 PC의 비공개 `.env`에 아래 값을 입력한다. 토큰을 채팅·Git에 남기지 않는다.

```dotenv
SLACK_TRANSPORT=socket_mode
SLACK_APP_TOKEN=<app-level-token>
SLACK_TEAM_ID=<workspace-id>
SLACK_ALLOWED_USER_IDS=<member-id>,<another-member-id>
SLACK_APPROVAL_TTL_SEC=900
SLACK_WEBHOOK_URL=<same-app-incoming-webhook>
REMEDIATION_MODE=disabled
```

Socket 연결에는 App-Level Token만 사용한다. 메시지 전송은 기존 Incoming Webhook,
버튼 결과 갱신은 Slack의 `response_url`을 사용하므로 이 구현에는 Bot Token이 필요 없다.
App-Level Token은 Incoming Webhook URL이나 Signing Secret과 다른 자격증명이다.

## 적용과 확인

아래 명령은 설정 준비 후 운영자가 배포할 때 사용한다. 실제 Slack 메시지나 Docker
조치를 이번 코드 검증에서 보내거나 실행했다는 뜻은 아니다.

```sh
# 일반 all-in-one 배포
docker compose up -d --build --no-deps remediation

# AIOps 전용 배포에서는 위 명령 대신 사용
docker compose -f docker-compose.aiops.yml up -d --build --no-deps remediation

curl http://127.0.0.1:8001/health
```

`/health`의 최상위 `status=ok`는 API 생존 상태다. Slack 준비 상태는 별도
`slack.connected=true`, `slack.status=connected`로 확인한다.

| Slack 상태 | 의미 / 조치 |
|---|---|
| `not_configured` | App-Level Token 미입력. Slack 수신 없음. HTTP 우회 경로도 닫힘 |
| `starting`, `retrying` | 최초 연결/재시도 중. 앱 Socket Mode·토큰 권한·outbound HTTPS/WebSocket 확인 |
| `reconnecting` | 기존 연결이 끊어져 SDK가 재연결 중 |
| `connected` | WebSocket 연결됨. 버튼 수신·조치 성공을 별도로 확인해야 함 |

토큰이 있는데 workspace/user 설정이 없거나 TTL이 잘못되면 시작을 거부한다.
토큰/응답 URL/전체 interaction payload는 로그로 출력하지 않는다.
다른 프로세스와 JSON 상태 파일을 공유하지 않도록 **Remediation은 단일 worker/replica**로 운영한다.
Compose의 `restart: unless-stopped`와 SDK 재연결을 사용한다.

## 승인 동작과 실패 처리

- Socket envelope는 실행 전에 ACK한다. ACK는 전송 수신 확인이며 조치 성공 응답이 아니다.
  동일 envelope 중복은 제한된 메모리 캐시로 제거하고, 실제 실행 중복은 기존 영속
  `remediation_id` 선점으로 막는다. 느린 작업은 SDK 수신 루프 밖에서 처리한다.
- ACK 이후 강제 종료되면 메모리의 대기 작업은 유실될 수 있다. 실행 여부는 저장된
  레코드로 확인한다. 아직 승인 대기이며 유효기간 내라면 같은 버튼을 다시 클릭한다.
  실행 중 종료된 건은 기존 UNKNOWN/NEEDS_REVIEW 복구 절차를 따른다.
- 허용 workspace/user, 저장된 remediation ID, 경보명·조치·대상 일치와 요청 만료를 검사한다.
  ID가 없는 예전 버튼은 새 실행 레코드를 만들지 않는다. 새 승인 요청이 필요하다.
- 거부 시 레코드를 `REJECTED`로 저장한다. 이미 승인/실행된 건을 뒤늦은 거부로
  되돌리지 않으며, 거부한 건은 이후 승인해도 실행하지 않는다.
- 승인 요청은 기본 15분 후 만료된다. 복구 승인은 TTL 스캐너가 복구 요청을 발행한
  시점부터 계산한다. 만료/과거 형식 요청은 운영자가 상태를 확인하고 새 승인 요청을
  준비해야 한다. 자동 재발행 API는 이번 변경에 포함하지 않는다.
- `REMEDIATION_MODE=disabled`에서는 버튼을 받아도 Docker 조치를 하지 않는다.
  원격 조치는 기존 Agent 승인·대상 allowlist·증거/복구 검사를 계속 거친다.

## HTTP 호환 모드와 범위

기본 `SLACK_TRANSPORT=socket_mode` 또는 `disabled`이면 `/slack/action`은 410을 반환한다.
기존 HTTP 콜백을 의도적으로 복구할 때만 `SLACK_TRANSPORT=http`와
`SLACK_SIGNING_SECRET`을 설정하고 Slack 앱의 Socket Mode를 끈다. HTTP 호환 모드는
기존 인증·버튼 형식을 유지하며 Socket Mode 전용 사용자/만료 검사를 대신하지 않는다.

Pipeline→Remediation `/action` HMAC, 원격 Agent HMAC, Incoming Webhook 알림 전송은
Socket Mode와 별도다. 사건 단위 `/action` 중복 제거와 source→Agent 라우팅은 후속 작업이다.

공식 근거: [Socket Mode 설정](https://docs.slack.dev/apis/events-api/using-socket-mode/),
[Python SDK 비동기 Socket Mode](https://docs.slack.dev/tools/python-slack-sdk/socket-mode/).

## 구현 검증 기록

2026-11-11, `feat/31-slack-socket-mode`에서 Python 3.11 / slack-sdk 3.46.0 /
aiohttp 3.14.5로 `python testing/run_isolated.py remediation`을 실행했다.
기존 270개와 신규 30개, **총 300개 PASS**다. 실제 Docker·외부 네트워크 연결은
격리 실행기가 차단했다. SDK 객체 생성/종료도 실제 연결 없이 검증했다.
두 Compose 파일의 `config --quiet`는 문법 검사용 placeholder 환경에서 PASS다.
App-Level Token이 로컬에 없어 실제 Slack 연결·버튼 수신·메시지 송신·배포는 미검증이다.
