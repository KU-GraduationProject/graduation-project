# GC telemetry collector — candidate, not deployed

Read [OI-02/03/04](../../../docs/rulepack/OI_02_03_04_TELEMETRY.md) for identity, limitations, transport gates and read-only acceptance commands.

- `exporter.py`: Python 3.11+ standard library, GET-only Docker Unix socket + internal cAdvisor, `/metrics`.
- `config.example.json`: placeholders deliberately rejected. Fill from observed GC inventory outside the repository.
- `compose.candidate.yml`: standalone candidate. No published host ports; no application services are modified. Image digests and transport remain review inputs.
- `verify.py`: offline snapshot identity/quality checks, exit 1 on failure. Never deploys or restarts anything.
- `tests/`: synthetic Docker fixtures, local temporary Unix socket transport, native M2 PromQL using `OI_PROMTOOL`.
- `source-copy-manifest.json`: SHA256 of ten selected nonsecret untracked reference files copied from the original worktree; those reference files are unchanged.

```sh
PYTHONDONTWRITEBYTECODE=1 OI_PROMTOOL=/path/to/promtool \
  python3 -m unittest discover -s deploy/leafy-pc/telemetry/tests -v
python3 -B deploy/leafy-pc/telemetry/verify.py --config /private/config.json /private/snapshot.prom
python3 -B deploy/leafy-pc/telemetry/verify.py --config /private/config.json --captures /private/captures.json
```

Without `OI_PROMTOOL`, native tests explicitly SKIP; they are not reported as PASS. Install test dependencies only in an isolated environment. Sandbox environments may require permission to bind the temporary **Unix socket**; the tests do not open a TCP port or access the real Docker daemon.

## 분리 구성 E2E (`compose.remote.yml`, #61)

Leafy 장비(맥 또는 Windows)의 컨테이너 CPU·메모리·재시작 지표를 AIOps 장비 Prometheus(`leafy-telemetry` job)로 보낸다.
두 OS 모두 Docker Desktop의 Linux VM 안에서 컨테이너가 돌므로 같은 compose를 쓴다.

- cAdvisor는 Docker API 없이 raw cgroup 모드로 돌린다. Docker 29의 containerd 이미지 저장소에서는 cAdvisor Docker 모드가 컨테이너를 읽지 못한다(맥 실측).
- collector가 Docker 소켓(GET 전용)으로 이름·compose 서비스를 붙이고, `config.json`의 `site`·`source`를 모든 시계열에 붙인다.
- cAdvisor 샘플 시각은 그대로 보존한다. cAdvisor는 housekeeping 주기로만 값을 바꾸므로, 수집 시각으로 덮으면 `irate()`가 0이 된다.
- Docker Desktop 자체 cgroup(`/docker/buildx` 등)은 컨테이너가 아니므로 건너뛴다.

1. `config.example.json`을 저장소 밖에 복사해 채운다. `project`는 Leafy compose 프로젝트 이름(`docker inspect leafy-backend --format '{{ index .Config.Labels "com.docker.compose.project" }}'`), `targets`는 실제 컨테이너 이름, `site`는 Leafy 로그의 `LEAFY_SITE`와 같은 값이다.
2. 실행 (이 디렉터리에서)

   macOS
   ```bash
   LEAFY_TAILSCALE_IP=$(tailscale ip -4) TELEMETRY_CONFIG=$HOME/leafy-secrets/telemetry-config.json \
     docker compose -f compose.remote.yml up -d --build
   ```
   Windows (PowerShell)
   ```powershell
   $env:LEAFY_TAILSCALE_IP = (tailscale ip -4)
   $env:TELEMETRY_CONFIG = "C:\leafy-secrets\telemetry-config.json"
   docker compose -f compose.remote.yml up -d --build
   ```
3. 확인: 두 component 모두 `1`이어야 한다. `resources`가 `0`이면 cAdvisor 출력이 검증을 통과하지 못한 것이다.

   macOS
   ```bash
   curl -s "http://$(tailscale ip -4):9108/metrics" | grep leafy_telemetry_collection_success
   ```
   Windows (PowerShell)
   ```powershell
   (Invoke-WebRequest "http://$((tailscale ip -4)):9108/metrics" -UseBasicParsing).Content -split "`n" | Select-String leafy_telemetry_collection_success
   ```
4. AIOps 장비: `monitoring/prometheus/targets/leafy-telemetry.yml.example`을 `leafy-telemetry.yml`로 복사해 주소와 `site`를 채운다. Prometheus가 자동으로 다시 읽는다.

맥(Docker Desktop 29.0.1, cAdvisor v0.52.1)에서 위 구성으로 HighCpuUsage·HighMemoryUsage·ContainerRestarted 식이 `site`·`name`과 함께 평가되는 것을 확인했다.
**Windows(WSL2)는 아직 실측하지 않았다.** 처음 띄울 때 3번 확인에서 `resources=1`인지, AIOps 장비에서 9108에 닿는지(Windows 방화벽·Tailscale ACL) 먼저 본다.
