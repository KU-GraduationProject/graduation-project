# 탐지 룰 인계 초안 (RULES_HANDOFF) — 팀원(룰 작성자) 참고용

> 역할 분리: **시나리오(다변화 포함)는 내가, 탐지 룰은 팀원이** 맡는다.
> 룰에 맞춰 시나리오를 설계하던 순환을 끊기 위해, 배치 ① 과정에서 `feat/scenarios-v2` 가
> 손댔던 **탐지 룰·메트릭 수집 설정**을 이 브랜치에서 모두 **되돌렸다**. 내용은 지우지 않고
> 아래에 "초안"으로 옮긴다. 룰 작성자가 검토·수정해 적용 여부를 판단하면 된다.
>
> 이 문서는 **초안**이다. 임계값·식·수집 방식은 모두 룰 작성자가 정한다.
> 시나리오 쪽은 이 룰들의 이름이나 임계값에 **의존하지 않는다**. 무엇을 탐지해야 하는지는
> `THREAT_SPEC.md`(위협 정의·증거 채널·정답)를 기준으로 한다.

---

## 1. LoginBruteForce — 로그인 대입 탐지 (Loki / 대상 시나리오 S1-c)

**신호원:** backend 앱이 로그인 실패 시 남기는 실제 인증 실패 로그(앱이 정상적으로 남기는 것 — 시나리오가 심는 문자열 아님).

**확인된 로그 형식(backend jar AuthService):**
```
[AUTH] 로그인 실패 loginId={} userId={} reason=wrong_password
```
- 실패 사유 `reason=unknown_login_id` 도 같은 형식으로 남는다. 응답은 401 invalid_credentials.
- 앱에 계정 잠금·시도 제한 로직은 **없다** → 탐지는 로그 빈도로만 가능.

**초안 룰 식 (`monitoring/loki/rules/fake/security-rules.yml` 에 append 했던 것):**
```yaml
- alert: LoginBruteForce
  expr: |
    sum(count_over_time(
      {service="backend"} |~ "\\[AUTH\\] 로그인 실패" [2m]
    )) > 5
  for: 0m
  labels:
    severity: warning
    category: security
  annotations:
    summary: "로그인 실패 급증 (인증 대입 공격 의심)"
    container: "leafy-backend"
```

**근거·주의:**
- **평문 ID 노출 방지:** `loginId` 를 경보 라벨로 **올리지 않는다**(`sum()` 집계만, `by (loginId)` 금지).
- 임계값 `2분 > 5` 는 **잠정값**. 정상 오입력 대조(C-e)로 재검증해 고정할 것.

**측정 PC 확인 항목:**
- 이 줄이 Loki 에 **평문**으로 들어오는지, 아니면 JSON `message` 필드에 담기는지 확인.
  - substring 매치(`|~`)는 두 경우 모두 라인에 문자열이 있으면 잡힌다. JSON 이라 구조 파싱이 필요하면 `| json` 으로 보강.
- 정상 오입력 빈도 실측(대조 C-e) 후 임계 N 확정.
  - 11-01 기준 정상 오입력은 분당 약 1건 수준으로 관측됨(2분 창 ~2건). 미발화 보장 여유를 두고 N 결정.

---

## 2. MinioDown — 오브젝트 스토리지 중단 탐지 (Prometheus / 대상 시나리오 F2-a)

**신호원 선택지(룰 작성자가 결정):**
- (A) minio 를 Prometheus 수집 대상으로 만들고 `up{job="minio"} == 0` 으로 중단 탐지.
- (B) backend 가 남기는 오브젝트 스토리지 연결 오류 로그 기반(Loki).

아래는 (A)안 초안이다. (A)안은 **메트릭 수집 설정(§3)** 이 선행돼야 한다.

**초안 룰 식 (`monitoring/prometheus/rules/alert.rules.yml` 에 append 했던 것):**
```yaml
- alert: MinioDown
  expr: up{job="minio"} == 0
  for: 30s
  labels:
    severity: warning
    category: infra
  annotations:
    summary: "MinIO 오브젝트 스토리지 중단 (수집 대상 down)"
    container: "leafy-minio"
```

**근거·주의:**
- `for: 30s` — 일시적 scrape 실패 1회로 발화하지 않도록 한 잠정값.
- 분리 배포(`prometheus.aiops.yml`)에는 minio 잡이 없어 `up{job="minio"}` 시계열이 없다 → 그쪽에 적용하려면 file_sd 로 별도 추가 필요.

---

## 3. minio 메트릭 수집 설정 (MinioDown (A)안 선행 조건)

(A)안을 쓰려면 prometheus 가 minio 메트릭을 긁어야 한다. 배치 ① 에서 넣었다가 되돌린 설정:

**(3-1) `monitoring/prometheus/prometheus.yml` — minio 잡 추가:**
```yaml
  - job_name: "minio"
    static_configs:
      - targets: ["minio:9000"]
    metrics_path: /minio/v2/metrics/cluster
```

**(3-2) `docker-compose.yml` — minio 에 인증 공개 + 전용 수집망:**
- minio environment 에 `MINIO_PROMETHEUS_AUTH_TYPE: public` (토큰 없이 수집, 호스트 포트는 열지 않음).
- prometheus ↔ minio 전용 내부망 `minio-metrics-net` 신설:
```yaml
networks:
  minio-metrics-net:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 10.212.0.0/24
```
  - minio networks: `leafy-net` + `minio-metrics-net`
  - prometheus networks: `mgmt-net` + `minio-metrics-net`

**네트워크 설계 근거(중요 — 그대로 적용 권장):**
- **mgmt-net 공유를 쓰지 않는 이유:** minio 를 mgmt-net 에 넣으면 backend(leafy-net+mgmt-net)가
  minio 를 mgmt-net 주소로 찾아 backend→minio 트래픽이 leafy-net 밖으로 빠질 수 있고(Zeek 미관측·
  allowlist 밖 IP), 관리망에 S3 API 가 열린다. 전용 internal 망이 이 둘을 모두 피한다.
- **backend→minio 경로 불변:** `minio-metrics-net` 에는 **backend 가 없다**. backend 는 `leafy-net`+`mgmt-net`
  뿐이고 minio 도 `leafy-net` 을 유지하므로 backend→minio 는 **leafy-net 그대로** — Zeek 관측·allowlist 불변.
  prometheus→minio 메트릭만 전용망으로 흐른다.
- **서브넷 비겹침:** `10.212.0.0/24` 는 leafy-net `10.210.0.0/24`·sink-net `10.211.0.0/24`·앱단독
  `10.203.0.0/24` 와 겹치지 않고, mgmt-net 은 Docker 기본 풀(172.x)에서 자동 할당돼 10.212 와 안 겹친다.
- **기존 측정 영향 없음:** 새 시계열(`up{job="minio"}` + minio cluster metrics)만 추가하고 기존
  cadvisor/node/backend 시계열·룰은 불변. C-g(JVM working_set)·C-n(네트워크/aiops)은 다른 메트릭이라 영향 없음.

**측정 PC 확인 항목:**
- `docker compose config -q` 통과(네트워크·환경변수 문법).
- `promtool check rules monitoring/prometheus/rules/alert.rules.yml` 통과.
- prometheus `/targets` 에서 minio 잡이 UP 으로 수집되는지, `/minio/v2/metrics/cluster` 응답 확인.
- minio 중단 시 `up{job="minio"}` 가 0 으로 떨어지는지.

---

## 부록: 기존(사전 존재) 탐지 자산 — 시나리오가 참고만 하는 것 (룰 작성자가 소유)

아래는 내가 추가/수정하지 않은 **기존 룰**이다. 시나리오의 증거가 어디에 남는지 참고용으로만 적는다.
적용·수정 판단은 룰 작성자 몫이다.

- Prometheus(`alert.rules.yml`): `HighCpuUsage`, `HighMemoryUsage`, `ContainerRestarted`
  (현재 `name="leafy-backend"` 하드코딩 — F3-a 가 다른 서비스를 대상으로 하면 일반화 검토 필요),
  `HighNetworkReceive`, `HighNginxRequestRate`, `HighPostgresConnections`.
- Loki 보안(`security-rules.yml`): `UnauthorizedDBAccess`, `SQLInjectionAttempt`,
  `VulnerabilityScanningDetected`(4xx), `PathTraversalAttempt`, `HighNginxErrorRate`.
  - 자기신고 의존 룰(`SecretDumpAttempt`/`SuspiciousProcessExec`/`ContainerEscapeAttempt`)은
    시나리오가 심는 문자열에 의존 → **v2 시나리오는 이 방식을 쓰지 않는다**.
- Loki 네트워크(자동생성): `UnauthorizedDataTransfer`, `UnauthorizedTransferEarly`.
