# 1차 시나리오 (scenarios-v2) — 1단계 조사·계획

> 브랜치: `feat/scenarios-v2` (main 기준). 이 단계는 **읽기만** 했고 실행·구현·커밋은 하지 않았다.
> `feature/network-poc` 는 건드리지 않았다.

> **역할 분리 (업데이트).** 시나리오(다변화 포함)는 내가, **탐지 룰은 팀원(룰 작성자)이** 맡는다.
> 룰에 맞춰 시나리오를 설계하던 순환을 끊었다. 그 결과:
> - 아래 §A.4 의 탐지 자산 목록과 §B 표의 "탐지 신호" 칸은 **조사 기록**일 뿐, 시나리오 설계의 근거가
>   아니다. 어떤 룰로 어떤 임계로 탐지할지는 **룰 작성자**가 정한다.
> - 룰 초안(로그인 대입·MinIO 중단·minio 메트릭 수집)은 `RULES_HANDOFF.md` 로 옮겼다(이 브랜치에서 되돌림).
> - 룰 작성자에게 넘길 위협 스펙은 `THREAT_SPEC.md`, 다변화 설계는 `VARIANTS.md`.
> - 시나리오 강도는 **룰 임계가 아니라 위협 정의**(현실적인 공격·장애 속도/심각도)로 정한다 → 강도 파라미터(weak/medium/strong).

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
  Loki `{log_type="network"}` → Ruler → Alertmanager. Sink 서버는 "공격받았다"는 로그를 남기지 않는다(`sink_server.py:14` 주석).
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

### A.4 기존 탐지 자산 (조사 기록 — 이제 룰 작성자 소유)
> 아래는 **조사 결과**다. 시나리오 설계 근거가 아니라, 증거가 어느 채널에 남는지 참고용이다.
> 룰 이름·임계값은 모두 룰 작성자가 소유·결정한다(`RULES_HANDOFF.md` 부록 참조).
- **Prometheus(`monitoring/prometheus/rules/alert.rules.yml`):** CPU/메모리/재시작/네트워크/nginx/postgres
  관련 기존 룰이 있다. `ContainerRestarted` 는 현재 `name="leafy-backend"` 하드코딩.
- **Loki 보안(`monitoring/loki/rules/fake/security-rules.yml`):** DB 인증실패·SQLi 패턴·4xx 스캐닝·
  path traversal·5xx 관련 기존 룰이 있다. 자기신고 의존 룰(`[ATTACK]` 등)은 **v2에서 금지**.
- **Loki 네트워크(자동생성):** 누적 전송량 기반 네트워크 룰(준희).
- **조치 정책(`aiops/policy/remediation_policy.yml`):** action 어휘는 **6개뿐** —
  `NONE/NOTIFY/THROTTLE/RESTART/PAUSE/ISOLATE`. LLM 프롬프트(`prompt/builder.py`)도 이 6개만 안다.
  (이 6개는 **조치 정책**이지 탐지 룰이 아니다 → `expected_action` 매핑 근거로 계속 쓴다.)

### A.5 자기 신고(anti-pattern) 현황 — v2가 피해야 할 것
- `data_exfil.py`, `category3/scenario_pgminer.py` → **Loki에 직접 push**(`/loki/api/v1/push`).
- `memory_leak.py`, `false_positive_cpu.py` → **pipeline 웹훅 직접 POST**(`/webhook/alert`) = 수동 주입.
- 일부 보안 룰 → 시나리오가 심는 문자열(`[ATTACK]` 등)에 의존.
→ **v2는 net_s2/net_ca처럼 "실제 부작용 → 기존 관측 → 룰"만 쓴다.** 레거시 12개·준희 3개·eval 8케이스는 그대로 둔다.

### A.6 정답 레이블 보관
새 `SCENARIO_REGISTRY_V2` 한 곳에만 둔다. 필드:
`threat_level / expected_action(6개 중) / expected_action_ideal(비실행 라벨) / targets / evidence(증거 채널)`.
`expected_action_ideal` 의 `BLOCK_PATH/LOCK_ACCOUNT/RECREATE/KILL_SESSIONS/ROLLBACK` 는
**정책에 없는 조치**라 평가 메타(라벨)로만 두고, 프롬프트·로그·컨테이너명·경로·헤더에 새지 않게 한다.
레지스트리는 **탐지 룰 이름을 담지 않는다**(역할 분리) — `evidence` 로 증거 채널만 기록한다.

---

## B. 13개 계획표

> 정답 표기: threat / **expected_action(현재 대체, 정책 6개 중)** / *ideal(비실행 라벨)* / 대상.
> "탐지 신호" 칸은 **증거가 남는 채널**만 적는다 — 어떤 룰로 탐지할지는 룰 작성자 몫(THREAT_SPEC).
> MTTD 는 룰의 설계(임계·주기)에 의존하므로 **룰 작성자가 추정**한다(여기선 생략).

### B.1 배치 ① — F2-a, F1-b, S1-a, S1-c

| id | 주입 방법 | 남는 증거(실제 부작용) | 탐지 신호(채널) | 정답 | 정리(원복) |
|---|---|---|---|---|---|
| **S1-a** 입력값 공격(앱 통과) | frontend에 실제 공격형 입력을 **2xx로 통과**하도록 다수 전송(검색 파라미터 등, 데이터 불변경) | frontend nginx **JSON 액세스 로그**의 페이로드+2xx, 앱 로그 (자기신고 문자열 없음) | nginx_log, app_log | critical / **NOTIFY**(WAF 경로차단 조치 없음) / *BLOCK_PATH* / nginx 경로 | 없음(GET/읽기성 요청, DB 변경 안 함) |
| **S1-c** 인증 공격(로그인 대입) | backend `/login` 에 **테스트 계정**으로 오답 비밀번호 반복 POST. 횟수는 **강도(위협 볼륨)** 로 정함 | backend 앱의 **로그인 실패 로그**(실제 인증 실패) | app_log | medium / **NOTIFY**(계정잠금 조치 없음) / *LOCK_ACCOUNT* / 대상 계정 | 계정 상태 불변(잠금 조치 미실행). DB 실데이터 불변 |
| **F1-b** 메모리 압박·누수(서서히) | backend 내부에서 **점진적** 메모리 점유. 강도 = **누수 속도(MiB/분) × 지속**(실제 누수 패턴 기준). 상한은 OOM 안전 가드(실측 0.94 중단)가 막는다 — 룰과 무관한 안전장치 | Prometheus `container_memory_working_set_bytes` 상승 | metric | medium / **RESTART** / *RESTART* / 해당 컨테이너 | 점유 프로세스 종료→메모리 회수, 컨테이너 원상 |
| **F2-a** MinIO 중단 | `docker stop` `minio` — **stop≠delete, 데이터 불변** | backend의 오브젝트스토리지 연결 오류 로그 / minio 가용성 메트릭 | app_log, metric | medium / **RESTART** / *RESTART* / minio | `docker start minio` 재기동 + healthy 확인 |

### B.2 배치 ② — S2-a, F2-c, F3-a

| id | 주입 방법 | 남는 증거 | 탐지 신호(채널) | 정답 | 정리(원복) |
|---|---|---|---|---|---|
| **S2-a** 자원 탈취(채굴형 CPU) | backend 내부에서 **지속 CPU 점유 루프**(서비스 생존). **자기신고 문자열 없음** | Prometheus CPU 사용률 상승 + 서비스 200 유지 | metric, app_log | high / **THROTTLE**(생존→스로틀) / *RECREATE* / backend | 점유 프로세스 종료(지정 시간 후 자동 종료), 재시작 안 함 |
| **F2-c** DB 커넥션 풀 고갈 | DB에 **다수 연결 보유**(데이터 조작 없이 연결만) | Prometheus postgres 연결 수 상승 + backend 커넥션 타임아웃 로그 | metric, app_log | high / **RESTART**(backend) / *KILL_SESSIONS* / backend | 보유 연결 종료→풀 회복. DB 실데이터 불변 |
| **F3-a** 잘못된 이미지 배포 | 대상 서비스를 **깨진 이미지/태그로 재배포**(crashloop/헬스 실패 유발) | 컨테이너 재시작 증가 또는 기동 실패 로그 | metric, app_log | high / **NOTIFY**(롤백 조치 없음) / *ROLLBACK* / 배포 서비스 | **원본 이미지/태그로 재배포** 복구(완전 가역). 데이터 손상 금지 |

### B.3 배치 ③ — 대조 5개 등록 (재사용)

| id | 재사용/주입 | 기대 관측 | 탐지 신호(채널) | 정답 | 정리 |
|---|---|---|---|---|---|
| **S2-c** 데이터 반출 | **net_s2 재사용** — registry id만 매핑, `experiment.py` 경로 그대로 | 네트워크 전송 이벤트(TP) | network | critical / **ISOLATE** / *ISOLATE* / backend | experiment가 sink `/stats` 리셋 |
| **C-a** 인가 대량 전송 | **net_ca 재사용** | 경보 없음(TN) | network | low / **NONE** / *NONE* | 동일 |
| **C-c** 이미 차단된 공격(4xx 다발) | 기존 공격 생성기 재사용. **검증 추가**: ① 요청이 실제 4xx로 막히는지 ② 자기신고 문자열 없는지 | frontend JSON 4xx 로그 | nginx_log | low / **NOTIFY** / *NOTIFY* | 없음(읽기성 요청) |
| **C-e** 비밀번호 오입력 | **외부도구 `traffic_gen.py --control wrong-password`**(정상 재시도, S1-c 생성기와 공유 안 함) | backend 로그인 실패 로그(소수) | app_log | low / **NONE** / *NONE* (음성 대조: 발화 없음이 정답) | 없음 |
| **C-g** JVM 평상시 메모리 | **외부도구 `traffic_gen.py --control none`** 장시간 실행 | 평상시 working_set | metric | low / **NONE** / *NONE* (음성 대조) | 없음 |
| **C-n** AIOps 자체 부하(모델 다운로드) | **모델 pull + 외부도구 `replay_rule.py` 재생** | aiops-net 트래픽(src=backend 아님) | network | low / **NONE** / *NONE* (음성 대조) | 없음 |

---

## C. 탐지 룰 — 룰 작성자에게 인계

1단계에서 잡았던 룰 초안(로그인 대입·MinIO 중단·minio 메트릭 수집)은 이 브랜치에서 되돌리고
**`RULES_HANDOFF.md`** 로 옮겼다. 룰 식·근거·측정 PC 확인 항목이 거기에 있다.
룰 작성자는 `THREAT_SPEC.md`(위협 스펙, 룰 이름·임계 없음)를 받아 탐지 룰을 직접 설계한다.

---

## D. 지킬 원칙 체크리스트 (설계 반영)
- [x] 자기 신고 금지 — Loki 직접 push·웹훅 직접 POST·정답/공격 암시 문자열(로그·컨테이너명·경로·헤더) 금지. 실제 부작용만.
- [x] 정답 레이블은 `SCENARIO_REGISTRY_V2` 한 곳 — 프롬프트·로그로 누출 금지. `expected_action` 은 정책 6개 중에서만. 룰 이름 미포함.
- [x] 탐지 룰은 팀원 몫 — 시나리오는 룰 이름·임계에 의존하지 않는다(강도는 위협 정의로).
- [x] F1-b 강도는 누수 속도×지속으로 정하고(목표 비율 없음), OOM 안전 가드(실측 working set·0.94 중단·/dev/shm 여유·trap 정리)는 유지. 급속 누수는 형태 변형 fast-spike(VARIANTS).
- [x] 모든 시나리오 원상복구, DB·MinIO 실데이터 불변경, 실행은 측정 PC(이 단계 미실행).
- [x] 레거시 12개·eval 8케이스·준희 3개·`run.py` 유지.
- [x] commit/push/PR 은 승인 후.

---

## E. 배치 ① 구현물 (현재 상태)

- `scenarios/v2/registry.py` — `SCENARIO_REGISTRY_V2`(정답 레이블 단일 소스). 배치 ① 4건.
  `expected_action` 은 정책 6개만 허용(로드 시 `_validate`). `evidence` 는 증거 채널만(룰 이름 없음). ideal 은 라벨 전용.
- `scenarios/v2/f2a_minio_outage.py` — `leafy-minio` stop→hold→start. **정리에 재기동 + healthy 확인 포함**.
  stop≠delete, `minio_data` 불변. Loki/pipeline 에 아무것도 안 씀. 탐지 룰은 팀원 몫.
- `scenarios/v2/f1b_memory_leak.py` — **강도(weak/medium/strong) = 누수 속도(MiB/분) × 지속(분)**. 주입량 = min(속도×지속, OOM가드 − 실측 현재값), 여유가 있으면 항상 > 0.
  실측 working set 기반, OOM 가드(0.94)에서 중단·해제. python3/sh 두 할당기, /dev/shm df 가드 + trap 정리.
- `scenarios/v2/s1a_input_attack.py` — frontend 에 실제 공격형 쿼리(읽기성 GET)로 2xx 통과 시도.
  검증 기준 = nginx 비차단(2xx) + 앱 로그 기록. (페이로드가 어떤 룰에 걸리는지는 단정하지 않는다.)
- `scenarios/v2/s1c_login_bruteforce.py` — 테스트 계정 오답 로그인 반복. 횟수는 **강도**로 결정.
  실제 자격증명 미사용, 계정상태 불변, loginId 비노출.
- `scenarios/v2/run.py` — `python -m scenarios.v2.run <id> [--dry-run] [--list]`.
- `scenarios/v2/tests/test_v2_pure.py` — 순수 로직 단위 테스트(Docker/HTTP 불필요). 룰 이름·임계 비의존.

측정 PC 확정 필요(코드에 주석):
- S1-a `S1A_PATH`: 2xx로 앱까지 통과하는 실제 경로.
- S1-c `S1C_LOGIN_PATH` / 본문 형식 / 전용 테스트 계정(seed).
- F1-b: backend 이미지의 할당기(python3 유무·/dev/shm) — 바이트 산정은 이미지 무관(테스트됨).

외부 대조 도구(측정 PC `D:\develop\leafy-baseline\tools\`, 나중에 저장소로 이동):
`traffic_gen.py`(정상+`--control wrong-password|not-found|mixed|none`), `replay_rule.py`,
`alert_recorder.py`, `collect.py`, `recon_prompt.py`. 배치 ③에서 C-c/C-e/C-g/C-n 을 이 경로 참조
레지스트리 항목으로 등록(§B.3 매핑 반영).

---

## F. 변경 이력

- **배치 ① 1차 구현** — registry/시나리오 4개/run/tests + (당시) 룰·메트릭 설정 추가.
- **F2-a 메트릭 네트워크 분리** — minio 메트릭을 전용 internal 망으로.
- **역할 분리 정리 (현재)** — 탐지 룰·메트릭 수집 설정을 되돌리고 `RULES_HANDOFF.md` 로 이관.
  시나리오에서 룰 이름·임계 의존 제거(강도 파라미터화). `THREAT_SPEC.md`·`VARIANTS.md` 추가.
- **평가용 격리·F1-b 재정의** — 평가용 설계·분할 규칙을 `.gitignore` 대상 heldout 폴더로 분리(`HELDOUT_POLICY.md`),
  레지스트리는 heldout 이 있으면 선택적으로 로드. F1-b 강도를 목표 비율 → 누수 속도×지속으로 재정의.
