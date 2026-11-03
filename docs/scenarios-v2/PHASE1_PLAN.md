# 1차 시나리오 (scenarios-v2) — 1단계 조사·계획

> 브랜치: `feat/scenarios-v2` (main 기준). 이 단계는 **읽기만** 했고 실행·구현·커밋은 하지 않았다.
> `feature/network-poc` 는 건드리지 않았다.

---

## A. 조사한 것과 근거

### A.1 시나리오 레지스트리 구조 (2곳)
- **`scenarios/run.py:62` `SCENARIO_REGISTRY`** — 인프라/보안 레거시 12개. 각 항목이 dict:
  `id / label / subtitle / category / owasp / mitre / container / loki_service /
  alert_name / alert_fires / blind_spot / module / custom_panel`.
  런처(`run_scenario`)가 이 메타로 ① 매트릭스 인트로 ② Before 메트릭 ③ 서브프로세스로
  `module.main()` 실행 ④ `/results` 폴링으로 LLM 결과 대기 ⑤ 조치 패널 ⑥ After/비교
  ⑦ 고유 패널을 그린다. `blind_spot=True` 면 LLM 폴링을 건너뛴다.
- **`scenarios/network_runner.py:63` `NETWORK_SCENARIO_REGISTRY`** — 준희의 네트워크 3개.
  `run.py` 레지스트리를 건드리지 않고 메뉴 뒤에 동적으로 붙는다. 항목에
  `kind:"network", run_s2, run_ca` 를 두고, `run.py:main` 이 `kind=="network"` 면
  `run_network_scenario()` 로 분기한다 — LLM 폴링 흐름을 타지 않고 자체 Verifier·결과 저장을 쓴다.

### A.2 준희의 네트워크 시나리오 3개 (깨끗한 레퍼런스)
| id | 내용 | 정답(GT) |
|---|---|---|
| `net_s2` | backend → **비인가** sink-b(10.210.0.31:8080) 대용량 전송 | `should_alert=True` (TP) |
| `net_ca` | backend → **인가** sink-a(10.210.0.30:8080) 동일 전송 | `should_alert=False` (TN) |
| `net_s2_ca` | 같은 전송 조건·목적지만 다름 — TP/TN 동시 | — |

핵심 설계(= v2가 따라야 할 규율):
- **자기 신고 없음.** 송신기는 실제 트래픽만 만들고, Zeek가 eth0(leafy-net)에서 관측 →
  Loki `{log_type="network"}` → Ruler `UnauthorizedDataTransfer`/`UnauthorizedTransferEarly`
  → Alertmanager. Sink 서버는 "공격받았다"는 로그를 남기지 않는다(`sink_server.py:14` 주석).
- **정답 레이블은 평가 측에만.** `RunSpec.should_alert` 는 GT 전용이고 송신 env·탐지기·LLM
  입력에 넣지 않는다(`transfer_spec.py:9`, `orchestrator.build_sender_env` 는 라벨 미포함).
- **E2 불변식:** S2/C-a 는 `TransferSpec`(크기·모드·분할·속도)을 **공유**하고 목적지만 다르다.
  "전송량"이 아니라 "목적지 허용 여부"가 정상/공격을 가른다.
- **검증(`network/verifier.py`):** A(Ruler firing)·B(AM 수신)·C(전달) 3단계를 독립 평가.
  MTTD = `activeAt(t2) − t0`. 실행 간 격리는 `wait_ruler_inactive` + Sink `/stats` 리셋.

### A.3 `experiment.py` 패턴
`build_plan`(S2/C-a 교차 배치) → `run_experiment`(런별: 쿨다운 → 전송 → 교차검증 → verify →
RunOutcome) → `ConfusionMatrix` → `write_results`(JSONL/CSV/summary). V2(held-out)는 동결
스냅샷(`freeze.py`)과 drift 검사를 강제. 순수 로직과 Docker/Loki 런타임을 분리해 단위 테스트한다.
결과만 `result_telemetry.publish_result_file` 로 Loki에 올린다(시나리오 트래픽과 분리된 채널).

### A.4 기존 탐지 자산 (재사용 후보)
- **Prometheus(`monitoring/prometheus/rules/alert.rules.yml`):** `HighCpuUsage`(>0.5, for 30s),
  `HighMemoryUsage`(working_set >0.85, **for 5m**), `ContainerRestarted`(10분 2회↑, **name=leafy-backend 하드코딩**),
  `HighNetworkReceive`, `HighNginxRequestRate`(>30/s), `HighPostgresConnections`(`pg_stat_activity_count>40`, for 30s).
- **Loki 보안(`monitoring/loki/rules/fake/security-rules.yml`):** `UnauthorizedDBAccess`
  (`{service="db"} |="authentication failed" >3/2m`), `SQLInjectionAttempt`(패턴 >5/2m),
  `VulnerabilityScanningDetected`(4xx >50/1m), `PathTraversalAttempt`(패턴 >0), `HighNginxErrorRate`(5xx>10/1m),
  그리고 **자기신고 의존** 룰 `SecretDumpAttempt`([ATTACK]), `SuspiciousProcessExec`(suspicious_outbound),
  `ContainerEscapeAttempt`(container_escape_attempt) — **v2에서 이 방식은 금지.**
- **Loki 네트워크(자동생성):** `UnauthorizedDataTransfer`(누적>1MB), `UnauthorizedTransferEarly`.
- **조치 정책(`aiops/policy/remediation_policy.yml`):** action 어휘는 **6개뿐** —
  `NONE/NOTIFY/THROTTLE/RESTART/PAUSE/ISOLATE`. LLM 프롬프트(`prompt/builder.py`)도 이 6개만 안다.

### A.5 자기 신고(anti-pattern) 현황 — v2가 피해야 할 것
- `data_exfil.py`, `category3/scenario_pgminer.py` → **Loki에 직접 push**(`/loki/api/v1/push`).
- `memory_leak.py`, `false_positive_cpu.py` → **pipeline 웹훅 직접 POST**(`/webhook/alert`) = 수동 주입.
- 위 3개 보안 룰 → 시나리오가 심는 문자열(`[ATTACK]` 등)에 의존.
→ **v2는 net_s2/net_ca처럼 "실제 부작용 → 기존 관측 → 룰"만 쓴다.** 레거시 12개·준희 3개·eval 8케이스는 그대로 둔다.

### A.6 정답 레이블 보관 (제안)
새 `SCENARIO_REGISTRY_V2` 한 곳에만 둔다. 필드:
`threat_level / expected_action(6개 중) / expected_action_ideal(아래) / targets`.
`expected_action_ideal` 의 `BLOCK_PATH/LOCK_ACCOUNT/RECREATE/KILL_SESSIONS/ROLLBACK` 는
**정책에 없는 조치**라 평가 메타(라벨)로만 두고, 프롬프트·로그·컨테이너명·경로·헤더에 새지 않게 한다.

---

## B. 13개 계획표

> 정답 표기: threat / **expected_action(현재 대체, 정책 6개 중)** / *ideal(비실행 라벨)* / 대상.
> MTTD 는 룰의 `for:` + ruler/scrape 주기 기준 **설계 목표 추정치**(측정값 아님. 측정 PC에서 확정).

### B.1 배치 ① — F2-a, F1-b, S1-a, S1-c

| id | 주입 방법 | 남는 증거(실제 부작용) | 탐지 룰 | 정답 | 정리(원복) | MTTD(추정) |
|---|---|---|---|---|---|---|
| **S1-a** 입력값 공격(앱 통과) | frontend에 주입 패턴 요청을 **2xx로 통과**하도록 다수 전송(검색 파라미터 등, 데이터 불변경) | frontend nginx **JSON 액세스 로그**의 페이로드+2xx (자기신고 문자열 없음) | 재사용 `SQLInjectionAttempt`(패턴>5/2m) 및/또는 `PathTraversalAttempt`(>0). 상태코드 무관·패턴 매칭이라 "앱 통과"도 잡힘 | critical / **NOTIFY**(WAF 경로차단 조치 없음) / *BLOCK_PATH* / nginx 경로 | 없음(GET/읽기성 요청, DB 변경 안 함) | 30~90s |
| **S1-c** 인증 공격(로그인 대입) | backend `/login` 에 **테스트 계정**으로 오답 비밀번호 반복 POST | backend 앱의 **로그인 실패 로그**(실제 인증 실패) | **신설 필요** — 로그인 실패 전용 Loki 룰(초안 §C). 기존 `UnauthorizedDBAccess`는 `service=db`용이라 부적합 | medium / **NOTIFY**(계정잠금 조치 없음) / *LOCK_ACCOUNT* / 대상 계정 | 계정 상태 불변(잠금 조치 미실행). 앱 잠금정책 있으면 테스트 계정으로만, 자동해제 확인. DB 실데이터 불변 | 60~120s |
| **F1-b** 메모리 압박·누수(서서히) | backend 내부에서 **점진적** 메모리 점유(working_set가 0.85 넘겨 **5분 유지**되는 속도로 설계) | Prometheus `container_memory_working_set_bytes` 상승 | 재사용 `HighMemoryUsage`(>0.85, for 5m) | medium / **RESTART** / *RESTART* / 해당 컨테이너 | 점유 프로세스 종료→메모리 회수, 컨테이너 원상 | ~300s+ (for 5m 지배). **급속 누수는 미탐(blind spot)** — 계획에 명시 |
| **F2-a** MinIO 중단 | `docker stop`(또는 pause) `minio` — **stop≠delete, 데이터 불변** | backend의 오브젝트스토리지 연결 오류 로그 / minio 컨테이너 down | **신설 필요** — MinIO 헬스/backend 오류로그 룰(기존엔 minio 다운 직접룰 없음) | medium / **RESTART** / *RESTART* / minio | `docker start minio` 로 복구 | 신설 룰 설계에 의존 |

### B.2 배치 ② — S2-a, F2-c, F3-a

| id | 주입 방법 | 남는 증거 | 탐지 룰 | 정답 | 정리(원복) | MTTD(추정) |
|---|---|---|---|---|---|---|
| **S2-a** 자원 탈취(채굴형 CPU) | backend 내부에서 **지속 CPU 점유 루프**(서비스는 생존). cpu_stress 방식 재사용하되 **자기신고 문자열 제거** | Prometheus `container_cpu_usage`(>0.5 for 30s) + 서비스 200 유지 | 재사용 `HighCpuUsage` | high / **THROTTLE**(생존→스로틀) / *RECREATE* / backend | 점유 프로세스 종료(지정 시간 후 자동 종료), 재시작 안 함 | 30~60s |
| **F2-c** DB 커넥션 풀 고갈 | DB에 **다수 연결 보유**(>40 동시, 데이터 조작 없이 연결만) | Prometheus `pg_stat_activity_count>40` + backend 커넥션 타임아웃 로그 | 재사용 `HighPostgresConnections`(>40, for 30s) | high / **RESTART**(backend) / *KILL_SESSIONS* / backend | 보유 연결 종료→풀 회복. DB 실데이터 불변 | 30~60s |
| **F3-a** 잘못된 이미지 배포 | 대상 서비스를 **깨진 이미지/태그로 재배포**(crashloop/헬스 실패 유발) | `ContainerRestarted`(10분 2회↑) 또는 기동 실패 로그 | 재사용 `ContainerRestarted` — 단 **룰이 name=leafy-backend 하드코딩**. 다른 서비스 대상이면 룰 일반화 필요(§C) | high / **NOTIFY**(롤백 조치 없음) / *ROLLBACK* / 배포 서비스 | **원본 이미지/태그로 재배포** 복구(완전 가역). 데이터 손상 금지 | 수 분(재시작 2회 누적 필요) |

### B.3 배치 ③ — 대조 5개 등록 (재사용)

| id | 재사용/주입 | 기대 관측 | 탐지 룰 | 정답 | 정리 | MTTD |
|---|---|---|---|---|---|---|
| **S2-c** 데이터 반출 | **net_s2 재사용** — registry id만 매핑, `experiment.py` 경로 그대로 | `UnauthorizedDataTransfer` firing(TP) | 기존 네트워크 룰 | critical / **ISOLATE** / *ISOLATE* / backend | experiment가 sink `/stats` 리셋 | 기존 net_s2 summary.json MTTD 사용 |
| **C-a** 인가 대량 전송 | **net_ca 재사용** | 경보 없음(TN) | — | low / **NONE** / *NONE* | 동일 | — |
| **C-c** 이미 차단된 공격(4xx 다발) | 기존 공격 생성기 재사용 OK. **검증 추가**: ① 요청이 nginx/앱에서 실제 4xx로 막히는지 확인 ② 자기신고 문자열 없는지 점검 | frontend JSON 4xx 로그 | 재사용 `VulnerabilityScanningDetected`(4xx>50/1m) | low / **NOTIFY** / *NOTIFY* | 없음(읽기성 요청) | 30~60s |
| **C-e** 비밀번호 오입력 | **외부도구 `traffic_gen.py --control wrong-password`**(정상 재시도 포함, S1-c 생성기와 공유 안 함) | backend 로그인 실패 로그(소수) | 발화 없음(S1-c 룰의 음성 대조) | low / **NONE** / *NONE* | 없음 | — |
| **C-g** JVM 평상시 메모리 | **외부도구 `traffic_gen.py --control none`** 장시간 실행 | working_set < 0.85 | 발화 없음(`HighMemoryUsage` 음성 대조) | low / **NONE** / *NONE* | 없음 | — |
| **C-n** AIOps 자체 부하(모델 다운로드) | **모델 pull + 외부도구 `replay_rule.py` 재생** | aiops-net 트래픽(src=backend 아님) | 발화 없음(`UnauthorizedDataTransfer`는 src=backend만) | low / **NONE** / *NONE* | 없음 | — |

---

## C. 신설/수정이 필요한 룰 초안 (1단계에서는 **만들지 않음**, 초안만)

1. **로그인 실패 룰(S1-c용) — 배치 ①에서 신설 완료** (`security-rules.yml` 의 `LoginBruteForce`).
   - 근거 문자열(확인됨, backend jar AuthService): `"[AUTH] 로그인 실패 loginId={} userId={} reason=wrong_password"`
     (`reason=unknown_login_id` 도 있음, 응답 401 invalid_credentials, 계정잠금·시도제한 로직 없음).
   - expr: `sum(count_over_time({service="backend"} |~ "\\[AUTH\\] 로그인 실패" [2m])) > 5`, severity warning → medium/NOTIFY.
   - **평문 ID 노출 방지:** `loginId` 를 경보 라벨로 올리지 않는다(`sum()` 만, `by (loginId)` 금지). 시나리오 출력에도 안 남김.
   - **측정 PC 확정 항목(룰 주석에도 기재):** 이 줄이 Loki 에 평문으로 들어오는지, JSON `message` 필드에 담기는지 확인.
     substring 매치는 두 경우 모두 잡히지만 JSON 파싱이 필요하면 `| json` 으로 보강. 임계 N(=5)은 C-e 보정(배치 ③)에서 확정 — 잠정값.
2. **MinIO 중단 룰(F2-a용)** — minio 헬스 메트릭 또는 backend 오브젝트스토리지 오류 로그 기반. 신설 또는 backend 오류로그 룰로 대체.
3. **`ContainerRestarted` 일반화(F3-a, 대상이 backend가 아닐 때)** — 현재 `name="leafy-backend"` 하드코딩. 대상 서비스에 맞게 라벨 일반화 검토.

---

## D. 지킬 원칙 체크리스트 (설계 반영)
- [x] 자기 신고 금지 — Loki 직접 push·웹훅 직접 POST·정답/공격 암시 문자열(로그·컨테이너명·경로·헤더) 금지. 실제 부작용만.
- [x] 정답 레이블은 `SCENARIO_REGISTRY_V2` 한 곳 — 프롬프트·로그로 누출 금지. `expected_action` 은 정책 6개 중에서만.
- [x] S1-c 로그인 실패 룰은 **초안만**(1단계 미구현).
- [x] F1-b 는 0.85/5m 룰로 잡히는 속도, 급속 누수는 미탐으로 명시.
- [x] 모든 시나리오 원상복구, DB·MinIO 실데이터 불변경, 실행은 측정 PC(이 단계 미실행).
- [x] 레거시 12개·eval 8케이스·준희 3개 유지.
- [x] commit/push/PR 은 승인 후.


---

## E. 배치 ① 구현 반영 (승인 후 구현 — commit 전)

구현물:
- `scenarios/v2/registry.py` — `SCENARIO_REGISTRY_V2` (정답 레이블 단일 소스). 배치 ① 4건 등록.
  `expected_action` 은 정책 6개만 허용하도록 로드 시 검증(`_validate`). ideal 은 라벨 전용.
- `scenarios/v2/f2a_minio_outage.py` — `leafy-minio` stop→hold→start. **정리에 재기동 + healthy 확인 포함**
  (remediation disabled 대응). stop≠delete, `minio_data` 불변. Loki/pipeline 에 아무것도 안 씀.
- `scenarios/v2/f1b_memory_leak.py` — 512MiB 안에서 working_set 0.88 목표(임계 0.85 위, OOM 가드 0.94 아래).
  보수 가정 baseline 0.72 → 추가 ~82MiB, step 16MiB×15s ramp 후 420s hold. `plan_allocation` 이 OOM 가드로 상한.
  급속 누수는 미탐(blind spot) 명시.
- `scenarios/v2/s1a_input_attack.py` — frontend 에 공격형 쿼리(읽기성 GET)로 2xx 통과 시도. 검증 기준 = nginx 비차단(2xx) + 앱 로그 기록.
  모든 페이로드가 `SQLInjectionAttempt` 정규식에 매칭됨을 테스트로 보장.
- `scenarios/v2/s1c_login_bruteforce.py` — 테스트 계정 오답 로그인 반복. 실제 자격증명 미사용, 계정상태 불변.
- `monitoring/loki/rules/fake/security-rules.yml` — `LoginBruteForce` 룰 추가(§C).
- `scenarios/v2/tests/test_v2_pure.py` — 순수 로직 19케이스(Docker/HTTP 불필요).

측정 PC 확정 필요(코드에 주석):
- S1-a `S1A_PATH`: 2xx로 앱까지 통과하는 실제 경로.
- S1-c `S1C_LOGIN_PATH` / 본문 형식 / 전용 테스트 계정(seed).
- F1-b: backend 이미지의 할당기(python3 유무·/dev/shm) — 바이트 산정은 이미지 무관(테스트됨).
- S1-c 룰: Loki 평문/JSON 여부, 임계 N.

열린 항목:
- **F2-a 탐지 룰 미추가(제안만).** `prometheus.yml` 에 minio 수집 대상이 없어(포트 미publish,
  MINIO_PROMETHEUS 미설정) `up{...minio...}` 가 존재하지 않는다. 사용자 지시대로 룰을 추가하지
  않고 방법만 제안한다. backend 오류 로그 룰은 만들지 않는다.

외부 대조 도구(측정 PC `D:\develop\leafy-baseline\tools\`, 나중에 저장소로 이동):
`traffic_gen.py`(정상+`--control wrong-password|not-found|mixed|none`), `replay_rule.py`,
`alert_recorder.py`, `collect.py`, `recon_prompt.py`. 배치 ③에서 C-c/C-e/C-g/C-n 을 이 경로 참조
레지스트리 항목으로 등록(§B.3 매핑 반영).


---

## F. 검토 반영 2차 (커밋 전)

1. **F1-b — 실제 working set 기반 + 가드 2단계.**
   - 주입 시점에 `current_working_set()`(docker stats: usage − inactive_file)으로 실측하고 그 값으로
     추가량을 정한다. 가정 baseline(0.79)은 **읽기 실패 시 폴백**으로만 쓴다.
   - **시작 가드:** 못 읽거나 이미 0.85 이상이면 주입하지 않고 중단(`should_abort_start`).
   - **증가 가드:** 할당기(컨테이너 내부 python3)가 매 step 전에 cgroup
     (`memory.current`/`memory.max` v2, `usage_in_bytes`/`limit_in_bytes` v1)을 읽어
     0.94(OOM 가드)에 닿으면 즉시 멈추고 해제한다. 정상 완료 시에만 hold 후 해제.
   - **python3 없으면 sh 할당기로 실행(중단 안 함).** `dd` 로 `/dev/shm` 에 4MiB chunk 씩 append →
     tmpfs=shmem 라 쓴 바이트가 working_set 에 잡힌다(inactive_file 로 안 빠짐). 매 chunk 전 cgroup 을
     정수 비교(`CUR*100 >= LIM*94`)로 읽어 0.94 이상이면 즉시 멈추고 파일 삭제. ramp 속도는 python 경로와
     맞춘다(16MiB/15s ≈ 4MiB/4s). **시작 df 가드:** 추가 필요량이 `/dev/shm` 여유보다 크면 주입 안 하고 exit 3.
     **trap(EXIT/INT/TERM)** 으로 `/dev/shm` 파일을 반드시 삭제하고, `cleanup()` 로 강제 삭제도 제공.
   - 순수 로직(`should_abort_start`/`plan_allocation`/할당기 소스 컴파일) 단위 테스트 추가.
2. **F2-a 탐지 룰 — A안 구현.** minio 를 Prometheus 수집 대상으로 만들고 `up{job="minio"}==0` 로 탐지.
   - `docker-compose.yml`: minio 에 `MINIO_PROMETHEUS_AUTH_TYPE: public`(토큰 없이 수집). **호스트 포트는 안 연다.**
     prometheus↔minio 전용 네트워크 `minio-metrics-net`(`internal: true`, subnet `10.212.0.0/24`)을 새로 만들어
     **prometheus 와 minio 만** 연결한다. minio 는 `leafy-net` + `minio-metrics-net`, prometheus 는 `mgmt-net` +
     `minio-metrics-net`.
     - **왜 mgmt-net 공유를 안 쓰나:** minio 를 mgmt-net 에 넣으면 backend(leafy-net+mgmt-net)가 minio 를
       mgmt-net 주소로 찾아 backend→minio 트래픽이 leafy-net 밖으로 빠질 수 있고(Zeek 미관측·allowlist 밖 IP),
       관리망에 S3 API 가 열린다. 전용 internal 망은 이 둘을 모두 피한다.
     - **backend→minio 경로 불변 근거:** `minio-metrics-net` 에는 **backend 가 없다**. backend 는 여전히
       `leafy-net`+`mgmt-net` 뿐이고 minio 도 `leafy-net` 을 유지하므로 backend→minio 는 **leafy-net 그대로** —
       Zeek 관측·allowlist(`dst_service=minio`) 불변. prometheus→minio 메트릭만 전용망으로 흐른다(backend 아님).
     - **서브넷 비겹침 근거:** `10.212.0.0/24` 는 leafy-net `10.210.0.0/24`·sink-net `10.211.0.0/24`·앱단독
       `10.203.0.0/24` 와 겹치지 않고, mgmt-net 은 Docker 기본 풀(172.x)에서 자동 할당돼 10.212 와 안 겹친다.
     - backend·frontend·zeek 등 다른 서비스의 네트워크는 건드리지 않았다.
   - `prometheus.yml`: `job_name: minio` / `targets: [minio:9000]` / `metrics_path: /minio/v2/metrics/cluster`.
   - `alert.rules.yml`: `MinioDown` — `up{job="minio"} == 0 for 30s`, severity warning(=medium)/category infra/
     annotation container `leafy-minio` (기존 룰 라벨·형식과 동일).
   - **C-g·C-n 등 기존 측정 영향 없음 근거:** 이 변경은 **새 시계열(`up{job="minio"}` + minio cluster metrics)만
     추가**하고 기존 cadvisor/node/backend 시계열과 룰은 한 글자도 안 바꾼다. C-g(JVM working_set)·C-n(네트워크/aiops)은
     전혀 다른 메트릭을 읽으므로 불변. 분리 배포(`prometheus.aiops.yml`)엔 minio 잡이 없어 `up{job="minio"}` 시계열이
     없고 룰은 발화하지 않는다(그쪽은 필요 시 file_sd 로 별도 추가).
   - **검증:** 구조(YAML/룰/compose) 로컬 통과. `promtool check rules` 와 `docker compose config -q` 는
     이 샌드박스에 promtool·docker 데몬이 없어 **측정 PC에서 실행**해야 한다.
3. **LoginBruteForce 임계 — 잠정·측정 기준 명시.** `2분 >5` 는 잠정. 정상 오입력 ~분당 1건(11-01 실측)이라
   2분 창 ~2건 → 5 밑 미발화 보장. 배치 ③ C-e(`traffic_gen --control wrong-password`)로 재검증 후 고정.
   **S1-c 주입 속도**는 임계의 4배(20회, 연속 전송이라 2분 창 내)로 올려 "최소 3배 이상" 충족.
4. **실행 진입점 추가.** `scenarios/v2/run.py` — `python -m scenarios.v2.run <id> [--dry-run]`, `--list`.
   `--dry-run` 은 Docker/HTTP 없이 정답 레이블과 주입 계획만 출력(S1-c 는 loginId 값 비노출).
   `scenarios/run.py`(레거시 런처)는 건드리지 않았다.
