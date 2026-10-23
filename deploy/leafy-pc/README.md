# GC PC 작업: Leafy 로그를 JH PC(AIOps)로 보내기

| 이름 | PC | 실행하는 것 |
|---|---|---|
| **GC** | Windows 11, Docker Desktop | Leafy frontend/backend/MinIO (`back/deploy/`), 호스트 PostgreSQL 17, Zeek/enricher, Fluent Bit 2개 |
| **JH** | AIOps PC | `docker-compose.aiops.yml` (Fluentd, Loki, Prometheus, Grafana, Alertmanager, Pipeline, Ollama) |

이 저장소에서는 GC의 Leafy 저장소(`back/deploy/`)를 볼 수 없습니다. 그래서 그 파일을 직접 고치지 않고 **병합할 설정 예시와 명령만** 제공합니다.

- 각 단계에는 **정상 결과**를 적었습니다. 결과가 다르면 그 단계에서 멈추고 출력 전체를 JH에게 보내 주세요.
- `(미검증)`은 JH PC에서 재현할 수 없었던 항목입니다. GC PC에서 처음 확인하게 됩니다.

JH PC에서 같은 구성을 격리 컨테이너로 재현해 확인한 내용입니다(2026-10-24). 팀 이미지 `gicks/ai-ops-leafy-frontend`·`gicks/ai-ops-leafy-backend`(2026-09-27 빌드), PostgreSQL jsonlog, Fluent Bit 5.1.3, Zeek/enricher를 사용했습니다.
- 탐지 규칙 9개 발화
- Nginx↔Backend `request_id` 연결
- 33KB 예외 로그 복원
- 300KB 로그 크기 정책 적용
- 잘못된 공유 키 거부

## 0. 흐름

```text
GC                                                                          JH (Tailscale)
 frontend/backend/minio ─ Docker fluentd driver ──────────────────────────▶ Fluentd :24224 ─┐
 Zeek ─▶ enricher ─▶ network-events.jsonl ─▶ Fluent Bit(컨테이너) ──────────▶ Fluentd :24224 ─┼─▶ Loki ─▶ 탐지·RCA
 PostgreSQL 17 (*.json) ─▶ Fluent Bit(Windows 서비스, shared_key) ─────────▶ Fluentd :24225 ─┘
```

- 로그는 GC에서 **나가는 방향**으로만 흐릅니다. 로그 수집을 위해 GC에 열어야 하는 수신 포트는 없습니다.
- 5432는 로그 수집에 쓰지 않습니다. JH에게 열지 마세요.
- **순서**: JH가 AIOps를 먼저 띄웁니다([JH 절차](../../docs/remote/REMOTE_DEPLOYMENT.md#3-jh-pc-실행-절차)). 그다음 GC가 1→6 순서로 진행합니다.

## 1. 전달받을 값과 연결 확인

| 값 | 설명 |
|---|---|
| `AIOPS_TAILSCALE_IP` | JH의 Tailscale IPv4 (JH에서 `tailscale ip -4`) |
| `FLUENTD_PG_SHARED_KEY` | 24225 인증 키. JH `.env`의 값과 같아야 합니다. **채팅방·커밋에 남기지 말고 개별로 전달받습니다** |

```powershell
tailscale status                                   # JH PC가 목록에 있고 offline이 아님
Test-NetConnection <AIOPS_TAILSCALE_IP> -Port 24224  # 정상: TcpTestSucceeded : True
Test-NetConnection <AIOPS_TAILSCALE_IP> -Port 24225  # 정상: TcpTestSucceeded : True
```

`False`가 나오면 다음 중 하나입니다.
- **JH 장치가 GC 계정에 공유되지 않음** (§2, 가장 먼저 확인)
- JH의 AIOps 미기동
- JH tailnet ACL

JH가 [REMOTE_DEPLOYMENT.md §3](../../docs/remote/REMOTE_DEPLOYMENT.md#3-jh-pc-실행-절차)를 확인합니다.

## 2. Tailscale 연결 방향 (GC와 JH는 서로 다른 tailnet)

GC와 JH는 **각자 다른 tailnet**이고, 장치를 공유해서 연결합니다(2026-10-24 JH에서 확인). Tailscale은 공유받은 장치가 **들어오는 연결만 받고 먼저 연결을 시작하지 못하게** 합니다(quarantine, [Tailscale 문서](https://tailscale.com/kb/1084/sharing)).

| 공유 방향 | 가능한 연결 | 용도 |
|---|---|---|
| GC 장치 → JH 계정에 공유 (현재 상태) | JH → GC | Leafy 화면 접속, (합의 시) 메트릭 수집 |
| **JH 장치 → GC 계정에 공유 (필요)** | **GC → JH** | **로그 전송 24224/24225** |

JH 패킷 필터를 실측한 결과입니다. 현재는 tailnet 대역 전체를 허용하면서 **GC 주소 하나만 제외**하고 있습니다. 따라서 GC가 온라인이어도 지금은 24224/24225에 접속할 수 없습니다.

**JH가 할 일** (JH tailnet 관리자 콘솔):
1. Machines → JH 장치 → `…` → **Share** → GC 계정 이메일로 초대(또는 공유 링크 전달)
2. 공유 장치에 대한 접근은 **JH tailnet의 ACL**이 적용됩니다. 기본 정책(모두 허용)이면 GC가 JH의 다른 열린 포트에도 닿을 수 있으므로 수집 포트만 허용합니다.
   ```jsonc
   // JH tailnet > Access controls. 이메일은 실제 값으로 바꾼다 (저장소에는 넣지 않는다)
   "acls": [
     { "action": "accept", "src": ["autogroup:member"], "dst": ["*:*"] },                    // JH 자신의 장치 (기본 정책 대체)
     { "action": "accept", "src": ["autogroup:shared"], "dst": ["<JH 계정 이메일>:24224,24225"] } // 공유받은 사용자(GC) -> 수집 포트만
   ]
   ```

**GC가 할 일**: 초대 메일이나 링크를 수락합니다. 그러면 GC 쪽 `tailscale status`에 JH 장치가 보여야 합니다.

확인:

```powershell
# GC
tailscale status                                     # JH 장치가 보이고 offline이 아님
Test-NetConnection <AIOPS_TAILSCALE_IP> -Port 24224  # JH가 AIOps(또는 임시 리스너)를 띄운 상태에서 True
```

JH 쪽에서는 [REMOTE_DEPLOYMENT.md §3](../../docs/remote/REMOTE_DEPLOYMENT.md#3-jh-pc-실행-절차)의 패킷 필터 확인 명령으로 GC 주소가 허용 목록에 들어왔는지 봅니다.

## 3. Leafy compose (`back/deploy/`) logging 설정

[leafy-compose-logging.example.yml](leafy-compose-logging.example.yml)의 `x-aiops-log-opts`와 서비스별 `logging` 블록을 기존 compose에 병합하고, `.env`에 `AIOPS_TAILSCALE_IP`를 추가합니다.

필수 확인:

1. **compose 서비스 이름이 `frontend`, `backend`, `minio`여야 합니다.** 이 이름이 그대로 Loki의 `service` 라벨이 됩니다. 다르면 JH에게 알려 주세요(JH의 `TARGET_SERVICE_MAP`과 탐지 규칙이 이 이름을 씁니다).
2. backend는 JSON 로그를 켭니다: `LOG_FORMAT=com.leafy.global.logging.LeafyJsonFormatter`.
3. **이미지 버전.** JH는 아래 digest 기준으로 Nginx JSON 필드(`"status":"$status"`)와 `request_id` 전달을 확인하고 탐지 규칙을 맞췄습니다. 실행 중인 이미지가 다르면 JH에게 알려 주세요.
   ```powershell
   docker image inspect gicks/ai-ops-leafy-frontend:latest --format "{{index .RepoDigests 0}}"
   # 확인한 값: gicks/ai-ops-leafy-frontend@sha256:86310f08d0a2f5013c6a90c71a31f5122d04f01086dece7a1d21dc98e67b50b1
   docker image inspect gicks/ai-ops-leafy-backend:latest --format "{{index .RepoDigests 0}}"
   # 확인한 값: gicks/ai-ops-leafy-backend@sha256:bb4b5c014c2278b2007a0727abc5d71e5ec174924c79183e6523f43760269d4a
   ```
   다르면 `docker run --rm --entrypoint cat <frontend 이미지> /etc/nginx/conf.d/default.conf`의 `log_format leafy_json` 부분을 JH에게 보냅니다.

적용과 확인:

```powershell
docker compose up -d                                         # back/deploy 에서. logging 변경은 컨테이너 재생성이 필요
docker inspect <backend 컨테이너> --format "{{json .HostConfig.LogConfig}}"
# 정상: {"Type":"fluentd","Config":{"fluentd-address":"100.x.y.z:24224","fluentd-async":"true","fluentd-request-ack":"true",...,"tag":"backend"}}
docker logs <backend 컨테이너> --tail 3
# 정상: {"timestamp":"...+09:00","level":"INFO","logger":...} 형태의 JSON (dual logging으로 로컬에서도 보입니다)
```

JH 확인 (Grafana Explore, Loki):

| 질의 | 정상 |
|---|---|
| `{service="backend", log_format="json"}` | backend JSON 로그 |
| `{service="frontend", log_format="json"}` | Nginx 액세스 로그 (`status`, `request_id`, `request_uri` …) |
| `{service=~"backend\|frontend", log_format="json_invalid"}` | 거의 0건 (많으면 로그 형식 문제) |

동작 특성 (JH 재현 실측):

- AIOps PC가 꺼져 있어도 Leafy는 정상 기동합니다(`fluentd-async`).
- 대신 Docker는 종료 시 아직 못 보낸 로그를 버립니다. 그래서 **기동 후 0.25초 안에 종료하면 0/5, 0.5초 이후에 종료하면 5/5**가 전달됐습니다.
  - 해당하는 경우: 기동 직후 바로 죽는 경우(예: nginx 설정 오류)뿐입니다.
  - 확인 방법: `docker logs <컨테이너>`에는 남습니다.
- 16KB가 넘는 로그(긴 stack trace)는 Docker가 나눠 보내고 JH가 다시 이어 붙입니다. 실제 업로드 예외 34,157B(3조각)가 원문 그대로 복원됐습니다.
- **(미검증)** Docker Desktop에서는 publish 포트로 들어온 외부 요청의 `remote_addr`이 Docker 게이트웨이 주소로 찍힐 수 있습니다(JH 재현에서 그렇게 찍힘). Tailscale 클라이언트 실제 IP가 보이는지 `{service="frontend"}`의 `remote_addr`로 확인해 주세요. 게이트웨이 주소만 보이면 IP 기반 탐지·상관분석의 한계로 기록합니다.

권장 (선택): `Hibernate: select ...` 줄은 `spring.jpa.show-sql=true`가 stdout에 직접 찍는 텍스트입니다. 양이 많고 JSON이 아니므로 운영 프로필에서는 끄는 것을 권장합니다.

## 4. PostgreSQL 17 jsonlog 설정

[postgresql/postgresql-logging.sql](postgresql/postgresql-logging.sql)을 superuser로 실행합니다. 실행 전에 현재 값을 기록해 두면 되돌리기 쉽습니다(파일 상단 주석 참고).

```powershell
psql -U postgres -f deploy\leafy-pc\postgresql\postgresql-logging.sql
# 마지막 SELECT 결과: pending_restart 가 t 인 행이 있으면 서비스 재시작
Restart-Service postgresql-x64-17
psql -U postgres -Atc "SHOW data_directory"          # 아래 경로 확인
Get-ChildItem "<data_directory>\log" -Filter *.json | Select-Object -Last 3
# 정상: postgresql-YYYY-MM-DD_HHMMSS.json 파일이 있고 크기가 0보다 큼
Get-Content (Get-ChildItem "<data_directory>\log\*.json" | Sort-Object LastWriteTime | Select-Object -Last 1) -Tail 1
# 정상: {"timestamp":"2026-.. ..:..:..... KST","user":...,"error_severity":"LOG","message":...}  (끝이 KST)
```

- 기존 텍스트 로그(`.log`)는 그대로 남고 `.json` 파일이 추가됩니다.
- `log_timezone`은 `Asia/Seoul`로 둡니다. JH는 `KST`/`UTC`/`GMT`/숫자 offset만 해석합니다. 그 외 timezone이면 수신 시각으로 저장되고 `log_time_parse_error`가 붙습니다.
- `log_min_duration_statement=200`이면 200ms 이상 걸린 SQL 원문이 JH로 전송됩니다. JH의 RCA 입력에서는 `PASSWORD '...'`, `token=` 같은 값이 가려집니다.
- PostgreSQL은 오래된 로그 파일을 지우지 않습니다. 예를 들어 14일이 지난 파일을 지우는 예약 작업을 등록합니다(관리자 PowerShell).

  ```powershell
  $a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -Command "Get-ChildItem ''<data_directory>\log'' -Include *.json,*.log -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddDays(-14) | Remove-Item"'
  Register-ScheduledTask -TaskName "pg-log-cleanup" -Action $a -Trigger (New-ScheduledTaskTrigger -Daily -At 4am) -User SYSTEM
  ```

## 5. Fluent Bit (Windows 서비스, PostgreSQL 로그 전송) — (미검증: Windows 바이너리)

설정은 Linux의 Fluent Bit 5.1.3으로 검증했습니다(같은 파일에서 Windows 경로 3줄만 교체). Windows에도 같은 버전(5.1.3)의 공식 Windows 패키지를 설치합니다. **포그라운드 실행부터** 확인합니다.

```powershell
New-Item -ItemType Directory -Force C:\fluent-bit\state\storage, C:\fluent-bit\conf
Copy-Item deploy\leafy-pc\postgresql\fluent-bit.conf, deploy\leafy-pc\postgresql\parsers.conf C:\fluent-bit\conf\
# data 디렉터리가 기본값과 다르면 C:\fluent-bit\conf\fluent-bit.conf 의 [INPUT] Path 를 고친다
[Environment]::SetEnvironmentVariable("AIOPS_TAILSCALE_IP", "<JH Tailscale IP>", "Machine")
[Environment]::SetEnvironmentVariable("FLUENTD_PG_SHARED_KEY", "<전달받은 키>", "Machine")
# 새 PowerShell 창(환경변수 반영)에서 포그라운드 실행 -> 1분 지켜본 뒤 Ctrl+C
& "C:\Program Files\fluent-bit\bin\fluent-bit.exe" -c C:\fluent-bit\conf\fluent-bit.conf
```

포그라운드 실행 로그:

| 로그 | 의미 | 조치 |
|---|---|---|
| `[input:tail:tail.0] inotify_fs_add` 또는 `stat`/파일 경로 관련 info | 정상 시작 | — |
| `[error] ... failed authorization: shared_key mismatch` | 키가 JH와 다름 | 키 재확인 |
| `[error] ... no upstream connections available` | JH 미기동, Tailscale/ACL 문제 | §1 재확인. 로그는 `C:\fluent-bit\state\storage`에 쌓였다가 재연결 후 전송 |
| `[warn] ... file ... skipped: line too long` | 1MB 넘는 줄을 건너뜀 | 빈번하면 JH에게 알림 |
| `[error] ... cannot open` / 권한 오류 | 서비스 계정이 PG log 폴더를 못 읽음 | 아래 서비스 등록(LocalSystem)으로 해결되는지 확인 |

확인 후 서비스로 등록합니다.

```powershell
New-Service -Name fluent-bit -StartupType Automatic `
  -BinaryPathName '"C:\Program Files\fluent-bit\bin\fluent-bit.exe" -c C:\fluent-bit\conf\fluent-bit.conf'
Start-Service fluent-bit; Get-Service fluent-bit         # 정상: Status Running
# 일부러 인증 실패를 만든다 (DB에 들어가지 않는 잘못된 계정)
psql -h 127.0.0.1 -U aiops_probe -d postgres -c "select 1"   # 비밀번호 아무거나 -> FATAL: password authentication failed
```

JH 확인: `{service="db", runtime="host"} |= "aiops_probe"` → `"error_severity":"FATAL"`, `"state_code":"28P01"` 줄 1건. 시각은 GC가 실행한 시각(KST)과 같아야 합니다.

- 처음 설치할 때 쌓여 있던 과거 로그는 보내지 않습니다(`Read_from_Head Off`). 이후 새로 생기는 파일은 처음부터 읽습니다.
- 로테이션, JH 중단 중 버퍼링(원래 시각으로 저장), 잘못된 키 거부는 JH 재현에서 확인했습니다.

## 6. Network Observer (Zeek) 이전

Zeek은 backend 컨테이너의 네트워크 namespace를 공유해야 하므로 GC에서 실행합니다.

```powershell
git clone <이 저장소>; cd <저장소>\deploy\leafy-pc\network-observer
copy .env.example .env      # AIOPS_TAILSCALE_IP, LEAFY_BACKEND_CONTAINER 채우기 (docker ps --format "{{.Names}}")
docker inspect <backend 컨테이너> --format "{{json .NetworkSettings.Networks}}"
#   -> 키(예: deploy_default)를 config\observer.yml 의 REPLACE_WITH_LEAFY_DOCKER_NETWORK 자리에
docker run --rm busybox nslookup host.docker.internal
#   -> Address(IPv4)를 config\observer.yml 의 host_endpoints ip 에 (기본값 192.168.65.254 와 같으면 그대로)
docker compose up -d --build
```

정상 결과:

```powershell
docker logs network-observer-enricher --tail 5
#   "Docker API 연결 성공", "Docker metadata 갱신: N개 IP 매핑" (N은 frontend·backend·minio 등 3 이상, 0이면 네트워크 이름이 틀림)
docker logs network-observer-zeek --tail 2        #   "listening on eth0"
docker logs network-events-shipper --tail 10      #   [error] 없음
```

JH 확인: `{log_type="network", src_service="frontend", dst_service="backend"}` 이벤트. `src_service`/`dst_service`가 전부 `unknown`이면 `docker_networks` 설정이 틀린 것입니다.

- backend를 다시 만들면(재배포) Zeek이 이전 namespace에 남습니다. 이때 `docker compose restart network-observer-zeek`를 실행합니다.
- 이 compose의 컨테이너 이름(`network-observer-zeek` 등)이 GC PC에 이미 있으면 충돌합니다. 예전 all-in-one 구성을 GC에서 돌린 적이 있다면 JH와 상의합니다.
- backend가 Docker 네트워크 여러 개에 붙어 있으면 Zeek의 `-i eth0`과 `observer.yml`의 `interface`를 앱 트래픽 쪽 인터페이스로 맞춥니다.

## 7. 통합 확인 (GC가 실행 → JH가 확인)

JH 재현에서 같은 조작으로 모든 항목을 확인했습니다. 탐지 규칙은 1~2분 창이라 GC가 실행한 직후 JH가 확인합니다.

| GC 실행 (PowerShell, frontend가 `localhost:80`인 경우) | JH 정상 결과 |
|---|---|
| `1..60 \| % { curl.exe -s -o NUL "http://localhost/.env?i=$_" }` | Loki alert `VulnerabilityScanningDetected`, `PathTraversalAttempt` 발화 |
| MinIO를 잠시 멈춘 상태(`docker stop <minio>`)에서 `1..12 \| % { curl.exe -s -o NUL http://localhost/files/x.png }` (끝나면 `docker start <minio>`) | `HighNginxErrorRate` 발화 (Nginx 502) |
| 로그인 5회 실패: `1..5 \| % { curl.exe -s -X POST http://localhost/api/v1/auth/login -H "Content-Type: application/json" -d '{\"login_id\":\"nobody\",\"password\":\"x\"}' -D - -o NUL }` | 응답 헤더 `X-Request-ID` 값으로 `{service=~"frontend\|backend"} \|= "<값>"` → Nginx 1줄 + Backend(AuthService·BLOCKED·ACCESS) |
| `psql`로 잘못된 비밀번호 4회 이상 | `UnauthorizedDBAccess` 발화, RCA 프롬프트에 `[db] FATAL … password authentication failed` |

Pipeline·Slack은 JH에서 확인합니다. 원격 조치는 비활성화돼 있어 **승인해도 GC 컨테이너는 바뀌지 않습니다**.

## 8. 메트릭 (선택 — 합의 후, 현재 미완료)

확정된 포트표(24224/24225)에는 메트릭 포트가 없습니다. JH의 Prometheus가 GC 지표를 수집하려면 아래 포트를 **GC의 Tailscale IP에만** 열어야 합니다. 열기 전에는 CPU·메모리·재시작 관련 Prometheus 규칙과 컨테이너 패널이 비어 있습니다.

| 대상 | 방법 |
|---|---|
| Spring Actuator 9090 | backend의 `9090`을 `<GC Tailscale IP>:9090:9090`으로 publish. `management.endpoints.web.exposure.include=health,prometheus`만 노출 |
| nginx-exporter 9113 | GC compose에 `nginx/nginx-prometheus-exporter` 추가 (frontend stub_status 대상. 이미지에 stub_status 설정이 있는지 확인 필요) |
| postgres-exporter 9187 | GC에서 실행해 `host.docker.internal:5432`에 접속 (5432를 JH에 열지 않음). 읽기 전용 모니터링 role 사용 |

JH 쪽 설정은 `monitoring/prometheus/targets/README.md`에 있습니다.

## 9. 되돌리기

| 항목 | 방법 |
|---|---|
| Docker 로그 | compose의 `logging` 블록을 지우고 `docker compose up -d` (기본 json-file로 복귀) |
| PostgreSQL | `ALTER SYSTEM RESET log_destination;` 등 바꾼 항목을 RESET한 뒤 `SELECT pg_reload_conf();` |
| Fluent Bit | `Stop-Service fluent-bit; sc.exe delete fluent-bit` |
| Network Observer | `docker compose down` (`-v`는 붙이지 않음: 쌓인 이벤트와 전송 위치 보존) |
