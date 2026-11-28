# 분리 구성 E2E 런북 (Leafy 장비 ↔ AIOps 장비)

Leafy 앱과 AIOps 스택을 서로 다른 장비에서 돌려 로그·CPU/메모리·Remediation 시나리오를 끝까지 확인한다 (#60·#61·#62).
1단계는 **각자 장비 + 맥**(예: 팀원 PC의 Leafy ↔ 내 맥의 AIOps), 2단계는 **최종 PC + PC**다. 절차는 같고 OS별 명령만 다르다.

## 0. 구성

| 장비 | 띄우는 것 | 여는 곳 |
|---|---|---|
| Leafy | Leafy compose + [로그 override](../../deploy/leafy-pc/leafy-compose-logging.example.yml) | - |
| Leafy | 지표 collector [compose.remote.yml](../../deploy/leafy-pc/telemetry/compose.remote.yml) | Tailscale IP:9108 |
| Leafy | Remediation Agent [compose.yml](../../deploy/leafy-pc/remediation-agent/compose.yml) | 127.0.0.1:8002 → Tailscale Serve https:443 |
| AIOps | `docker-compose.aiops.yml` (Fluentd·Loki·Prometheus·Pipeline·Remediation) | Tailscale IP:24224/24225 |

| 연결 | 시작하는 쪽 → 받는 쪽 |
|---|---|
| 로그 | Leafy → AIOps:24224 (호스트 PostgreSQL 로그는 24225) |
| 컨테이너 지표 | AIOps Prometheus → Leafy:9108 |
| 조치 | AIOps Remediation → Leafy Agent https:443 |

세 장비 값이 반드시 같아야 하는 것: **site**(= `LEAFY_SITE`), 컨테이너 이름, 컨테이너 id. 손으로 맞추지 않고
[tools/split_setup/split_setup.py](../../tools/split_setup/split_setup.py)가 Leafy 장비의 `docker inspect` 한 번으로 모두 만든다.

## 1. 공통 준비 (양쪽)

- Docker Desktop(Windows는 Linux containers), Python 3.11+, Tailscale 로그인. 같은 커밋의 저장소.
- `tailscale ip -4`로 각 장비 IP를 확인한다. Tailscale 관리 콘솔에서 MagicDNS·HTTPS를 켠다 (Agent의 `https://<장비>.<tailnet>.ts.net`에 필요).
- 서로 다른 tailnet이면 **연결을 시작하는 쪽에 상대 장비를 공유**해야 한다. 공유받은 장비는 먼저 연결을 시작할 수 없다(quarantine).
  위 표대로 양방향 연결이 있으므로 **두 장비를 서로 공유**한다. 공유·ACL 절차는 [deploy/leafy-pc/README.md §2](../../deploy/leafy-pc/README.md).

## 2. Leafy 장비

**L1. `.env`에 두 값을 넣고 컨테이너를 다시 만든다.** override가 `aiops.site`·`io.leafy.remediation=workload` 라벨을 붙이며, 라벨은 재생성해야 붙는다.

```dotenv
AIOPS_TAILSCALE_IP=<AIOps 장비 tailscale ip -4>
LEAFY_SITE=<이 장비 이름, 예: gc-pc>
```
override를 Leafy compose에 병합한 뒤 `docker compose up -d` (컨테이너 재생성).

**L2. Agent용 Tailscale Serve** (Windows는 관리자 터미널). 기존 Serve 설정을 덮어쓰지 않는지 먼저 `tailscale serve status`로 본다.
```bash
tailscale serve --bg --https=443 http://127.0.0.1:8002
```

**L3. 설정 생성.** 저장소 루트에서 실행한다. 컨테이너 이름이 `leafy-backend/frontend/minio`가 아니면 `--container backend=<이름>`으로 준다.
ISOLATE를 허용하려면 끊을 업무 네트워크와 남길 관리 네트워크를 둘 다 주고, 둘 다 붙은 컨테이너에만 허용된다.

macOS
```bash
python3 tools/split_setup/split_setup.py leafy --site gc-pc --aiops-ip <AIOps IP> --leafy-ip "$(tailscale ip -4)" \
  --agent-url https://<이 장비>.<tailnet>.ts.net
```
Windows (PowerShell)
```powershell
python tools\split_setup\split_setup.py leafy --site gc-pc --aiops-ip <AIOps IP> --leafy-ip (tailscale ip -4) `
  --agent-url https://<이 장비>.<tailnet>.ts.net
```
결과: `deploy/leafy-pc/remediation-agent/allowlist.yml`, `.../secrets/agent_hmac_key.txt`(없을 때만 생성, Git 제외),
`split-setup/<site>/leafy/`의 `leafy.env`·`telemetry-config.json`·`aiops-bundle.json`.

**L4. 지표 collector.** 실행·확인 명령은 [telemetry README "분리 구성 E2E"](../../deploy/leafy-pc/telemetry/README.md). `TELEMETRY_CONFIG`에는 L3의 `telemetry-config.json` 절대 경로를 준다.

**L5. Agent (disabled로 먼저).**
```bash
cd deploy/leafy-pc/remediation-agent
docker compose -f compose.yml up -d --build
curl -s http://127.0.0.1:8002/healthz      # Windows: Invoke-RestMethod http://127.0.0.1:8002/healthz
```
`mode=disabled`, `auth_configured=true`면 정상이다. 실제 조치를 할 때만 `-f compose.yml -f compose.live.yml`로 live 전환한다
([PHASE3_REMOTE_AGENT.md §9](PHASE3_REMOTE_AGENT.md)).

**L6. AIOps 장비로 전달.** `aiops-bundle.json`(비밀값 없음)과 HMAC 키 사본을 1:1로 보낸다. 키는 Git·단체 채널에 올리지 않는다.

## 3. AIOps 장비

**A1. 설정 생성** (저장소 루트, 받은 파일 경로를 준다)
```bash
python3 tools/split_setup/split_setup.py aiops --bundle <aiops-bundle.json> --aiops-ip "$(tailscale ip -4)" \
  --hmac-key-file <받은 키 파일 절대 경로>
```
Windows는 `python tools\split_setup\split_setup.py aiops ... --aiops-ip (tailscale ip -4) ...`.

**A2. 적용**
- `split-setup/<site>/aiops/aiops.env`의 값을 `.env`에 넣는다 (`AIOPS_TAILSCALE_IP`, `OBSERVATION_BINDINGS`, `REMEDIATION_TARGET_BINDINGS_LOCAL_PATH`, `REMEDIATION_AGENT_URL`, `AGENT_HMAC_KEY_LOCAL_PATH`).
- `leafy-telemetry.yml`을 `monitoring/prometheus/targets/`로 복사한다 (Git 제외).
- 기동: 원격 조치까지 쓰면 remote override를 함께 준다.
```bash
docker compose -f docker-compose.aiops.yml -f deploy/aiops-pc/remediation-remote.example.yml up -d --build
```

**A3. 연결 확인**

| 확인 | 방법 | 정상 |
|---|---|---|
| 로그 | Grafana Explore(Loki) `{site="<site>"}` | Leafy 로그가 보인다 |
| 지표 | Prometheus `up{job="leafy-telemetry"}`, `leafy_telemetry_collection_success` | 둘 다 1 |
| Agent | `curl -s https://<Leafy 장비>.<tailnet>.ts.net/healthz` | `auth_configured: true` |
| 바인딩 | `docker compose -f docker-compose.aiops.yml logs pipeline` 에 binding 파싱 오류 없음 | - |

**컨테이너를 다시 만들면 id가 바뀐다.** L3(`--force`) → L6 → A1·A2를 다시 하고 pipeline·remediation·Agent를 재시작한다.
바뀐 id로 조치하려는 요청은 Agent·Remediation이 거부한다(재승인 필요).

## 4. 2단계: 최종 PC + PC

1단계와 절차가 같다. 다른 점만 적는다.
- 두 장비 모두 Windows면 2·3장의 PowerShell 명령을 쓴다. Tailscale Serve는 관리자 터미널에서 실행한다.
- ACL은 위 연결 표의 포트만 허용한다. 태그를 쓰는 예 (각 tailnet 정책에 맞게 나눠 넣는다):
```json
{
  "grants": [
    {"src": ["tag:aiops"], "dst": ["tag:leafy"], "ip": ["tcp:443", "tcp:9108"]},
    {"src": ["tag:leafy"], "dst": ["tag:aiops"], "ip": ["tcp:24224", "tcp:24225"]}
  ]
}
```
  기존 전체 허용 규칙이 있으면 새 규칙만으로는 좁혀지지 않는다. 다른 장치에서 9108·443이 거부되는지 실제로 확인한다.
- **아직 실측하지 않은 것 (Windows)**: collector의 `resources=1`(WSL2 cgroup 경로), 공유받은 장비에서 Agent의 `*.ts.net` HTTPS 이름 접근, Windows 방화벽이 Docker publish 포트(9108)를 막는지.
  처음 띄울 때 A3 표로 먼저 확인한다.

## 5. 데모 리허설 체크리스트

시작 전
- [ ] 양쪽 `tailscale status` 연결, A3 표 4줄 모두 정상
- [ ] Leafy `.env`의 `LEAFY_SITE`, collector config의 `site`, AIOps 대상 파일 `site`가 같다 (스크립트로 만들었으면 같다)
- [ ] 컨테이너를 재생성했다면 L3·A1을 다시 했다
- [ ] Slack 앱 토큰을 쓰는 AIOps 스택이 하나만 떠 있다 (두 곳이면 승인 버튼 이벤트가 한쪽으로만 간다)
- [ ] Gemini 키·`LLM_PROVIDER` 설정, Pipeline 로그에 LLM 오류 없음
- [ ] Agent mode 확인: 조치 시연이면 live, 아니면 disabled

시나리오별 (한 번에 하나, 경보가 끝난 뒤 다음)
- [ ] 로그 시나리오: Loki 경보 라벨에 `site`·`target`, RCA가 `resolved`로 바인딩을 찾았다
- [ ] CPU·메모리 시나리오: Prometheus 경보 라벨에 `site`·`name`, RCA 근거에 원격 지표가 있다
- [ ] 조치 시나리오: Slack 승인 → Agent 실행 → 복구(UNPAUSE/RECONNECT/UNTHROTTLE)까지 확인

문제가 생기면
- 로그가 안 온다: Leafy → AIOps:24224 공유·ACL, `AIOPS_TAILSCALE_IP`
- 지표가 0/없다: collector `resources=0`이면 [telemetry README](../../deploy/leafy-pc/telemetry/README.md) 확인, `up=0`이면 9108 공유·ACL·방화벽
- RCA가 `source_unmapped`: 경보 site와 `OBSERVATION_BINDINGS` site가 다르다 → L3·A1 재실행
- 조치가 거부된다: 컨테이너 재생성으로 id가 바뀜 → L3·A1 재실행 후 재승인
