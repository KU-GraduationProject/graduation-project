# Prometheus 원격 수집 대상 (AIOps 단독 배포)

`prometheus.aiops.yml`의 file_sd가 이 디렉터리의 `<job>*.yml`을 읽는다. 파일이 없으면 해당 job은 수집하지 않는다.

실제 Tailscale 주소가 들어가므로 `*.yml`은 커밋하지 않는다 (`.gitignore`). 예시 파일을 복사해 쓴다.

```powershell
Copy-Item leafy-backend.yml.example leafy-backend.yml   # <LEAFY_TAILSCALE_IP> 를 실제 값으로 바꾼다
```

Prometheus가 파일 변경을 자동으로 다시 읽는다 (재시작 불필요).

| 파일 | 팀원 PC에서 열어야 하는 포트 | 상태 |
|---|---|---|
| `leafy-backend.yml` | Spring Actuator 9090 (`/actuator/prometheus`) | 팀원 PC에서 Tailscale IP로 publish 필요 |
| `nginx-exporter.yml` | nginx-prometheus-exporter 9113 | 팀원 PC에 exporter 배치 필요 |
| `postgres-exporter.yml` | postgres-exporter 9187 | 팀원 PC에 exporter 배치 필요 (5432를 AIOps PC에 열지 않기 위해) |

메트릭 포트는 확정된 포트표(24224/24225/3100/5432)에 없다. 열기 전에 팀과 합의한다.
