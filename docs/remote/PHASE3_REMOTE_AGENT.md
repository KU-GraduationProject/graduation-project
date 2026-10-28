# Phase 3 원격 Remediation Agent — 구현 및 Phase 4 인계

이 문서의 배포 명령은 **다음 Phase에서 실행할 절차**다. Phase 3에서는 PC 2 배포,
실제 Docker 조치, Slack 발송, S2 실행을 수행하지 않았다. 기본 모드는 양쪽 모두 disabled다.

## 1. 사전 점검과 기반

시작 브랜치 `feature/s2_scenario`, HEAD `0ed75b907121f58612f80fcaa25a2f1a6caa34de`.
미커밋 변경 없음. `git ls-remote`로 확인한 원격 HEAD는
`831dfd58be23e599602f9bbd3da19f6b9b749e9d`, 로컬 ahead 3 / behind 0이었다.
전달된 Phase 2.1 완료 상태는 존재하지 않았다. 기본 docker 모드, 복구 선점 부재,
테스트 IO 격리 부재, 시작 시만 NIC 탐지 등을 발견했다.

이를 선행 커밋 **`b640060`**으로 보완했다. 상세 내용과 검증은
[Phase 2.1 안전 기반](PHASE21_SAFETY_BASELINE.md)에 기록했다. 기존 Phase 0~2 커밋은
재작성하지 않았다. 이 기반은 PC 2 운영 안전성 실측을 대신하지 않는다.

## 2. 실행 구조와 파일

```text
PC 1: Pipeline → LLM → Policy → Controller → Slack 승인
                                         ↓ RemoteExecutor
                           HTTPS + Agent 전용 HMAC / Tailscale
                                         ↓
PC 2 Windows 호스트: Tailscale Serve → 127.0.0.1:8002
                                         ↓ Docker Desktop 포트 전달
PC 2 Linux 컨테이너: FastAPI Agent → SQLite 선점/증거 → PinnedDockerExecutor
                                         ↓ LocalDockerExecutor 재사용
                              로컬 Unix Docker socket → inspect/조치/검증
                                         ↓
PC 1: 원격 상태 동기화 → 원래 검증 시각/TTL/MTTR 기록
```

| 파일 | 역할 |
| --- | --- |
| `aiops/remediation/agent/contract.py` | 엄격한 요청·Allowlist 스키마 |
| `agent/api.py` | HMAC 선검증, 실행/복구/조회, 단일 프로세스 잠금, TTL 루프 |
| `agent/service.py` | 독립 인가, 런타임 식별, 증거·검증, Agent TTL |
| `agent/ledger.py` | SQLite nonce·멱등성·대상 잠금·증거 영속화 |
| `security/agent_auth.py` | method/path/controller/nonce/raw body 결합 서명 |
| `executor/remote.py`, `executor/remote_sync.py` | 원격 전송·UNKNOWN·조회·동기화 |
| `main.py`, `recovery.py`, `store.py`, `evidence.py` | 승인된 레코드 전달, 모드별 복구, 원격 상태·MTTR |
| `executor/local_docker.py` | 기존 검증 재사용, network ID 및 CPU period 복구 검증 보강 |
| `Dockerfile.agent`, `deploy/leafy-pc/remediation-agent/*` | PC 2 배포 예시 |
| `deploy/aiops-pc/remediation-remote.example.yml` | 소켓 없는 PC 1 원격 모드 예시 |
| `tests/test_remote_agent.py`, `tests/test_remote_controller.py` | FakeDocker 및 메모리 HTTP 통합 검증 |

Agent 이미지에는 LLM·Slack notifier·정책 설정/엔진을 넣지 않는다. 정책을 재판단하지 않고
승인 증명 정보와 로컬 실행 권한을 검증한다. 로컬 실행기는 기존 `RecordStore` JSON 저장소를
유지하고, Agent는 프로세스 간 선점과 nonce 원자성이 필요해 별도 SQLite 저장소를 사용한다.

## 3. API 계약

| API | 인증 | 동작 |
| --- | --- | --- |
| `GET /healthz` | 없음 | liveness·mode·키 설정 유무만 반환, Docker 접근 없음 |
| `POST /v1/executions` | HMAC 필수 | 승인 요청 검증 → 선점 → 증거 저장 → 실행·검증 |
| `GET /v1/executions/{remediation_id}/{target}` | HMAC 필수 | 원 실행과 복구 상태·증거·시각 반환; Docker 호출 없음 |
| `POST /v1/recoveries` | HMAC 필수 | 기존 레코드/증거로만 UNPAUSE·RECONNECT·UNTHROTTLE |

요청 예시(설명용이며 실행하지 않음):

```json
{
  "remediation_id": "r_example",
  "action_type": "ISOLATE",
  "target": "leafy-backend",
  "authorization": {
    "decision_id": "r_example",
    "approval_id": "controller-durable-approval-reference",
    "kind": "manual",
    "approved_by": "slack-user"
  },
  "expires_at": 1793280000,
  "ttl_seconds": 3600,
  "recovery_mode": "require_approval"
}
```

예시 expires_at은 런타임에 현재 시각+120초로 생성한다. 최대 유효기간 300초.
허용 필드 외 값, Docker 옵션, 복구용 임의 evidence 입력은 거부한다. 본문 최대 64 KiB.
복구 요청은 같은 remediation_id/target, 짝이 맞는 recovery action, 새 수동 승인 참조를
사용하고 ttl_seconds=null, recovery_mode=none으로 보낸다.

응답은 `state`, `execution`, `verified_at`, `evidence`, `deadline`, `recovery_state`,
`recovery`, `recovery_verified_at`, `observation`을 포함한다. 실행 결과에는
`action/target/status/verified/detail/before/after`가 있다. `SUCCESS`는 Docker 재조회
검증을 통과했을 때만 기록한다. 200 HTTP 자체는 조치 성공을 뜻하지 않는다.

오류: 401 인증·nonce 거부, 403 권한/만료/복구 조건 거부, 409 ID 충돌·대상 잠금·복구 불가,
413 크기 초과, 422 스키마 오류, 503 인증 저장소 장애. 인증 거부 전에 Docker를 생성하지 않는다.

PC 1의 `POST /remote/reconcile`은 기존 Pipeline→Controller HMAC을 요구한다.
서명 본문 `{"operation":"reconcile_remote","remediation_id":"...","retry":false}`로
조회 동기화하며, `retry:true`는 **이미 승인되어 저장된 UNKNOWN 레코드만** 현재 정책과
저장된 승인자를 재확인한 후 동일 ID로 재전송한다. 새 조치를 생성하거나 승인을 생략하지 않는다.
GET 404 또한 뒤늦게 도착할 요청의 부재를 증명하지 않으므로 실패로 단정하지 않는다.

## 4. 인증과 인가

- Agent 전용 공유키: `AGENT_HMAC_KEY_FILE` 우선, 또는 `AGENT_HMAC_KEY`. 최소 32자,
  운영은 무작위 32바이트 이상의 키를 사용한다. Pipeline 키/Slack secret과 공유 금지.
- `security.signing`의 Phase 0 SHA256 HMAC·constant-time 비교를 재사용한다.
  Agent의 도메인 문자열에는 HTTP method, path, controller ID, nonce, **raw body**가 들어간다.
  timestamp도 Phase 0 canonical string에 포함된다. 서명 창은 과거/미래 ±60초다.
- 헤더: `x-agent-timestamp`, `x-agent-nonce`(32 hex), `x-agent-controller`,
  `x-agent-signature`. nonce는 SQLite UNIQUE insert로 소비하며 재시작해도 유지된다.
  같은 업무 요청을 재시도할 때는 같은 ID/내용, 새 timestamp/nonce/서명을 사용한다.
- 인증은 승인 자체가 아니다. Agent가 action allowlist, 수동 승인 kind/참조/사용자,
  만료, TTL/복구 모드, 자기 설정의 대상 권한을 별도로 검증한다.
- 승인 정보는 HMAC으로 인증된 Controller의 **승인 사실 진술**이다. Agent가 Slack 서명을
  재검증하거나 사람의 판단을 독자적으로 증명하지는 않는다. Controller/키가 침해되면
  허용된 범위 내 악성 명령은 가능하므로 키·PC 1 보호와 Agent allowlist 축소가 중요하다.
- backend/frontend/minio Compose service만 허용 가능하며 workload 라벨과 실제 project
  라벨이 필요하다. 관리 컨테이너, Agent 자신, 미등록 대상, 호스트 서비스는 금지한다.
  Windows PostgreSQL을 조작하는 API/명령 실행 기능은 없다.
- 전체 64자리 container ID, sha256 image ID, 정확한 이름과 라벨을 inspect로 검증하고
  모든 Docker 변경은 ID로 수행한다. privileged/host network/host PID/Docker socket
  보유 컨테이너도 거부한다. 컨테이너 재생성 시 자동으로 새 ID를 신뢰하지 않는다.

## 5. 멱등성과 장애 처리

SQLite transaction + synchronous=FULL로 `(remediation_id,target)`와 payload digest,
대상별 lease를 원자적으로 선점한다. 만료 시각만 제외한 의미 있는 요청 필드가 달라지면
409다. 같은 ID의 POST를 반복해도 재실행하지 않는다. 미복구 대상에는 새 ID도 차단한다.
역조치 권한이 allowlist에 없으면 최초 가역 조치도 차단한다.

증거는 container ID/네트워크 ID·IP·alias/CPU/상태를 변경 전에 저장한다. 재시작 시
EXECUTING을 UNKNOWN으로 전환하며 자동 재실행하지 않는다. Docker와 DB 사이에 분산
트랜잭션이 없으므로 crash 직전 조치 여부를 완벽히 확정할 수 없다. **최대 한 번 시도**와
불확실 상태 보존을 보장하고, 모호한 작업을 자동으로 다시 수행하는 가용성은 포기한다.

프로세스 수명 파일 잠금으로 단일 Agent만 허용한다(`--workers 1`). DB는 Linux named
volume에 저장하며 복사본을 두 Agent에 각각 주면 멱등성이 깨지므로 금지한다. 상태 파일
삭제/과거 백업 복원/새 state volume으로 우회하지 않는다. 용량 부족·손상 시 실행을 멈춘다.

PC 1은 응답 유실 시 상태를 재조회한다. 확인 불가 시 `UNKNOWN`/`RECOVERY_UNKNOWN`을
저장하고 성공·실패·MTTR을 만들어내지 않는다. 재조회는 TTL scanner와 수동 reconcile
API로 수행한다. 원격 기록은 모드 변경 후 PC 1 LocalDockerExecutor로 복구하지 않는다.

## 6. TTL·복구·Zeek

- RESTART: 승인 필수, 비가역. 기동 시각 변경과 running 검증.
- PAUSE/ISOLATE: 승인 필수. TTL은 **복구 승인 요청 시한**이며 자동 UNPAUSE/RECONNECT 금지.
- THROTTLE: 원격 **자동 실행은 항상 금지**. PC 1 정책상 자동 후보도 수동 승인 대기로
  전환한다. 승인된 THROTTLE은 원래 quota/period와 최대 1800초 deadline을 Agent가 보존한다.
  PC 1이 없어도 Agent가 5초 간격으로 UNTHROTTLE을 수행한다. 기존 NanoCPUs 모드는
  quota 모드로 안전하게 변환할 수 없어 차단한다(원래 설정을 임의로 덮지 않음).
- Agent가 꺼지거나 PC 2가 중단되면 복구는 지연된다. 다시 기동하면 검증된 overdue
  THROTTLE을 처리한다. UNKNOWN/실패 작업은 자동 복구하지 않고 사람이 판단한다.
  시간 동기화가 필요하고 엄격한 wall-clock TTL SLA는 제공하지 않는다.
- ISOLATE는 inspect의 업무 네트워크만 끊고 실제 관리 네트워크 존재를 요구한다.
  RECONNECT는 **같은 network ID**에 기존 IPv4·alias를 넣고 재조회한다. IP 충돌,
  네트워크/컨테이너 교체, alias 불일치면 성공으로 기록하지 않는다.
- RECONNECT 성공 후 `observation=awaiting_zeek_subnet_rediscovery`를 반환한다.
  Phase 2.1 supervisor가 subnet route/ifindex를 재탐지하고 capture-interface를 갱신한다.
  Docker 연결 복구와 실제 Zeek 패킷 수신은 다른 검증이다. 실제 conn.log/Enricher 확인은
  Phase 4에서 수행한다. backend 자체 교체 시 observer netns도 재생성해야 한다.
- Agent의 UNKNOWN 실행에 보존된 증거가 있으면 Controller에 동기화한 뒤 **명시적 수동
  복구 승인**으로 복구할 수 있다. 실행 중인 Agent claim은 복구 요청도 거부한다.
  RECOVERY_UNKNOWN/RECOVERY_FAILED는 맹목적으로 재실행하지 않는다. Phase 4 운영자가
  inspect와 증거를 대조해야 하며 DB 레코드를 지우는 방식으로 우회하면 안 된다.
- MTTR은 Agent의 실제 recovery_verified_at과 원 경보 시각으로 계산한다. PC 1이 늦게
  돌아와 조회한 시각을 복구 시각으로 쓰지 않는다. action_verified_at은 containment 지표다.

## 7. PC 2 준비 — 다음 Phase에서만 실행

Windows 11 Docker Desktop **Linux containers** + 호스트 Tailscale을 사용한다.
Docker Engine의 `Expose daemon on tcp://localhost:2375 without TLS`는 꺼 둔다.
Agent만 Linux VM 내부 `/var/run/docker.sock`을 마운트하며 엔진 TCP 포트를 게시하지 않는다.

저장소의 `deploy/leafy-pc/remediation-agent`로 이동한 뒤:

```powershell
Copy-Item allowlist.example.yml allowlist.yml
New-Item -ItemType Directory -Force secrets
# 현재 사용자만 접근 가능한 경로에 키를 생성하고, 키 값을 콘솔/로그에 출력하지 않는다.
$agentKeyBytes = New-Object byte[] 32
$agentRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$agentRng.GetBytes($agentKeyBytes)
$agentKeyHex = [BitConverter]::ToString($agentKeyBytes).Replace('-', '').ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $PWD 'secrets/agent_hmac_key.txt'), $agentKeyHex)
$agentRng.Dispose()
icacls secrets /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F"
docker compose -f compose.yml config --quiet
docker compose -f compose.yml up -d --build
Invoke-RestMethod http://127.0.0.1:8002/healthz
```

이 단계는 disabled이며 Docker socket도 없다. 키는 별도 안전한 경로로 PC 1에 전달하고
PC 1 secret 파일도 사용자 제한 ACL을 적용한다. 키 값·.env·실제 allowlist는 Git에 넣지 않는다.
키 교체는 양쪽을 disabled로 하고 교체·재기동하며 Agent 상태 volume은 보존한다.

## 8. Tailscale·Windows 노출 검증

Windows 관리자 터미널에서 양쪽 Tailscale 연결 상태와 PC 2 이름을 확인한다.
HTTPS/MagicDNS 설정 및 장치 소유권을 확인한 뒤 PC 2에서:

```powershell
tailscale status
tailscale serve --bg --https=443 http://127.0.0.1:8002
tailscale serve status
Get-NetTCPConnection -State Listen -LocalPort 8002
```

Windows에서는 관리자 터미널을 사용하며 로컬 서비스에 Serve를 연결한다.
([Tailscale Windows Serve 예제](https://tailscale.com/docs/reference/examples/serve),
[Serve 명령](https://tailscale.com/docs/reference/tailscale-cli/serve))
Funnel은 사용하지 않는다. 기존 Serve/Funnel 설정을 먼저 검토하고 다른 서비스를 덮어쓰지 않는다.
tailnet ACL/grants는 PC 1 전용 identity/tag → PC 2 전용 identity/tag의 TCP 443만 허용한다.
기존 전체 허용 규칙이 있으면 새 제한 규칙을 추가하는 것만으로 차단되지 않으므로 기존 정책도
검토한다. 팀원의 다른 장치에서 접근이 거부되는지 실제 측정한다.

기본 포트 게시는 외부 인터페이스로 열릴 수 있다. 본 설정은 `127.0.0.1:8002:8002`만
게시한다. Docker Desktop은 호스트 backend 프로세스로 포트를 전달하므로 호스트 Tailscale
Serve가 이 localhost에 접속하도록 구성한다.
([Docker Desktop 네트워킹](https://docs.docker.com/desktop/features/networking/),
[Docker 포트 게시](https://docs.docker.com/engine/network/port-publishing/))

아래 결과는 **이번 Phase에서 실측하지 않았다**. Phase 4에서 disabled 상태로 검증하고
하나라도 다르면 live로 전환하지 않는다.

| 접속 위치/대상 | 기대 결과 |
| --- | --- |
| PC 2 → 127.0.0.1:8002/healthz | 성공, mode=disabled |
| 다른 LAN 장치 → PC 2 LAN IP:8002 | 실패 |
| PC 1 → PC 2 Tailscale IP:8002 | 실패 (직접 게시 없음) |
| 허용된 PC 1 → PC 2 FQDN.ts.net:443/healthz | 성공 |
| 다른 tailnet identity → 같은 443 | ACL 거부 |
| PC 1/다른 장치 → PC 2:2375,2376 | 실패 |
| PC 1에서 HMAC 없는 status/execute | 401, Docker 호출 없음 |

`Test-NetConnection <상대 IP> -Port <포트>` 및 `Get-NetTCPConnection`으로 확인한다.
Windows Defender 방화벽에서 Docker Desktop 관련 넓은 허용 규칙과 포트 전달 규칙을 검토한다.
방화벽을 끄거나 8002/2375를 모든 네트워크에 허용해서 문제를 해결하지 않는다. PC 1 컨테이너
내부에서 Windows Tailscale DNS/라우팅과 HTTPS 인증서 검증이 되는지도 별도로 확인한다.

## 9. Allowlist·Disabled → Live (Phase 4 전용)

1. 위 네트워크 행렬과 무인증/재전송 차단을 disabled에서 확인한다.
2. 실제 변경 허용 시간·승인자·PC 2 로컬 복구 담당자를 정한다. `leafy-backend` 등의
   workload 라벨은 팀원과 계획한 재생성 시 추가해야 하며, 이 Phase에서는 기존 서비스에
   라벨을 추가하거나 컨테이너를 재생성하지 않는다.
3. **그 이후** 로컬 `docker inspect`로 전체 ID, 이미지 ID, project/service/workload 라벨,
   업무·관리 네트워크 ID/IP/alias, 원래 quota/period를 확인해 allowlist.yml에 넣는다.
   NanoCPUs 설정이면 THROTTLE을 허용하지 않는다. 예시는 allowlist.example.yml을 따른다.
4. Agent named volume과 PC 1 state를 보존/백업하고, 단일 인스턴스인지 확인한다.
5. 명시적 운영 승인 후에만 아래 PC 2 live override를 적용한다.

```powershell
docker compose -f compose.yml -f compose.live.yml config --quiet
docker compose -f compose.yml -f compose.live.yml up -d --build
```

6. PC 1은 **저장소 루트에서** `REMEDIATION_AGENT_URL=https://<pc2>.<tailnet>.ts.net`,
   `AGENT_HMAC_KEY_LOCAL_PATH=<PC1의 절대 키 파일 경로>`를 설정하고 다음 override를 적용한다.
   PC 1에는 Docker socket을 추가하지 않는다.

```powershell
docker compose -f docker-compose.aiops.yml -f deploy/aiops-pc/remediation-remote.example.yml config --quiet
docker compose -f docker-compose.aiops.yml -f deploy/aiops-pc/remediation-remote.example.yml up -d --build remediation
```

7. 먼저 별도 희생용 테스트 대상에서 승인/상태 조회/중복/재시작/장애/복구를 검증한다.
   실제 S2 → 승인 → 원격 격리 → 복구는 별도 Phase 4 승인 아래 진행한다.

소켓에 접근 가능한 Agent는 Docker daemon을 통해 매우 강한 권한을 갖는다.
read-only filesystem, cap_drop, no-new-privileges는 소켓 권한을 제거하지 않는다.
allowlist·키·네트워크 제한을 함께 유지하고 다른 업무 컨테이너와 agent-control network를 공유하지 않는다.

## 10. 긴급 중단·종료

- 즉시 새 원격 요청 차단: PC 1 disabled로 재기동, 해당 Agent Serve 포워딩 중지 또는
  해당 tailnet ACL만 차단. 전역 Serve reset은 다른 서비스를 끊을 수 있으므로 피한다.
- PC 2에서 Agent만 `docker compose -f compose.yml -f compose.live.yml stop remediation-agent`로 중지.
  이는 **Agent 서비스만** 대상으로 하며 업무 컨테이너·PostgreSQL은 조작하지 않는다.
- 소켓 제거 후 disabled 재기동: base compose.yml만 사용한다. `down -v` 금지.
- 실행 중 SDK 호출은 이미 적용됐을 수 있다. 중단은 원복 명령이 아니다. ISOLATE/PAUSE를
  종료 훅에서 자동 해제하지 않는다. Agent 정지 동안 THROTTLE TTL도 정지한다.
- 정상 재시작 시 SQLite의 불확실 실행은 UNKNOWN으로 보존된다. 검증된 overdue THROTTLE은
  live Agent가 복구하지만, 실행/복구 자체가 UNKNOWN이면 운영자가 inspect와 증거로 판단한다.
  새 ID 또는 DB 삭제를 이용한 재시도는 금지한다. state volume과 원 IP/alias/CPU 증거를 보존한다.

## 11. 테스트와 검증 범위

저장소 루트에서 준비된 가상환경 Python으로만 실행한다. 일반 unittest를 직접 실행하지 않는다.

```powershell
.\.venv-readme\Scripts\python.exe testing/run_isolated.py remediation
.\.venv-readme\Scripts\python.exe testing/run_isolated.py pipeline
.\.venv-readme\Scripts\python.exe testing/run_isolated.py network
.\.venv-readme\Scripts\python.exe testing/run_isolated.py observer
& 'C:/Program Files/Git/bin/bash.exe' testing/test_zeek_supervisor.sh
```

필요 의존성은 각 requirements.txt 및 기존 scenario 테스트의 rich다. 테스트 실행 중 외부
라이브러리 설치나 Docker 컨테이너 실행은 하지 않는다. HTTP는 TestClient/MockTransport,
Docker는 기존 FakeDocker를 쓴다. 인증 실패 테스트는 factory 0회·mutation 0회를 확인한다.
테스트 수집 전에 Docker 생성자·socket 연결·DNS·subprocess·Docker pipe를 차단하고
차단 자체도 self-check한다. 네트워크 회귀 테스트만 자신이 만든 임시 loopback 서버에 접속한다.
Zeek는 임시 route/ifindex/가짜 zeek 프로세스로 재탐지를 검증한다.

구체적 최종 숫자와 파일 정적 검증은 [Phase 3 검증 기록](PHASE3_VERIFICATION.md)을 참조한다.
실제 컨테이너의 전후 inspect 비교는 하지 않았다. 실제 Docker 접근 없이 수행한 코드·격리
검증이 근거이며 PC 2 Windows/방화벽/Tailscale/실제 daemon 결과까지 검증했다고 주장하지 않는다.

## 12. 남은 위험·Phase 4 인계

- PC 2 Windows Docker Desktop 포트 전달, Tailscale ACL/HTTPS, PC 1 컨테이너의 DNS/라우팅 실측.
- 실제 label/ID/image pin, 업무/관리 네트워크 분리, IP·alias 복원, Zeek conn.log 관측 확인.
- Docker Desktop/PC 2 종료·재부팅 시 복구 지연, SQLite volume 보존, disk-full/crash 및 수동
  UNKNOWN 복구 절차 실연. 자동 THROTTLE은 코드에서도 계속 차단된다.
- 멱등성은 저장소가 보존될 때 최대 한 번 시도다. 백업 rollback/복제 ledger, Docker 외부
  관리자의 동시 조작까지 exactly-once로 묶지 못한다. lease는 Agent 내부 작업만 직렬화한다.
- 복구 중 crash/검증 실패 후 재복구는 자동화하지 않았다. 확인되지 않은 결과를 성공 처리하지 않고
  운영자에게 남긴다. 무조건 반복 복구하는 기능보다 안전한 중단을 우선했다.
- IPv6 네트워크 복원, NanoCPUs 모드 변경, 호스트 서비스, SCALE/EXEC 등은 지원하지 않는다.
- 테스트 런타임과 컨테이너 이미지 빌드 환경은 다를 수 있다. 이번에는 Docker image build도
  실행하지 않았으므로 Phase 4에서 의존성 고정과 이미지 빌드를 검증해야 한다.

## 13. 커밋과 롤백

선행 기반 `b640060` → 독립 Phase 3 `feat(remediation): add authenticated remote remediation agent`.
Phase 3 커밋만 `git revert <Phase3 해시>` 하면 코드 기준으로 선행 Phase 2.1 상태로 돌아간다.
코드 롤백은 실제 조치 복구/SQLite 삭제가 아니다. 향후 실제 운영 이후에는 pending 복구를
먼저 점검하고 Agent ledger를 보존해야 한다. 이 작업에서는 push·main 병합·force push 없음.
