# 2차 A군 측정 PC 실행 순서·체크리스트

> 실제 주입은 측정 PC 에서만. 모든 명령은 저장소의 `scenarios/` 에서 `python -m v2.run <id> [--variant v --seed n]`.
> 먼저 `--dry-run` 으로 계획을 확인한다. `.env` 는 열지 않는다(compose 가 읽는다). remediation 은 disabled 유지.

## 0. 공통 준비
- [ ] `docker compose ps` — backend/db/minio/frontend/exporter 정상, remediation disabled 확인
- [ ] `docker compose -f docker-compose.yml -f docker-compose.s2.yml up -d sink-a sink-b` (S2-b·C-j 용 sink, 우리 소유)
- [ ] 네트워크 사이드카 이미지 `s2-sender:latest` 존재 확인(`docker images`). 없으면 `scenarios/network` 에서 빌드
- [ ] env: `V2_WORK_DIR`(저장소 밖), `V2_TRAFFIC_GEN`(traffic_gen.py 경로), `V2_COMPOSE_DIR`, `V2_COMPOSE_FILES`, `F3A_BACKUP_DIR`/`CH_BACKUP_DIR`(저장소 밖)
- [ ] DB 대상 env(호스트 PostgreSQL 기본): `SCEN_DB_MODE=host`(기본), `SCEN_PGHOST`(기본 `host.docker.internal`), `SCEN_PGPORT`, `SCEN_PGDATABASE`, `SCEN_PGADMIN`(백업·관리자 역할), `SCEN_PGUSER`(일반 앱 역할), `SCEN_EXPECTED_SYSTEM_ID`, `SCEN_CONFIRM_TARGET`, `SCEN_PGPASSFILE`. (기존 `F2C_*` 이름도 그대로 동작). F2-c·S2-e 가 공유하고 C-h·F3 백업은 `SCEN_PGADMIN` 으로 pg_dump 한다
- [ ] 컨테이너 DB 인 환경에서만 `SCEN_DB_MODE=container` + `F3A_DB_CONTAINER`
- [ ] 각 실행 후 경보 기록(`alert_recorder.py`)과 run 기록(`fixtures` run record) 남는지

## 1. 권장 순서 (위험 낮은 것부터)
1. **C-l → S1-b** (HTTP 읽기만, 원복 불필요)
2. **C-b → F1-a** (정상 경로 부하, 요청 중지 = 원복)
3. **C-j → S2-b → S2-d** (사이드카, `docker ps` 로 종료 확인)
4. **C-h → S2-e** (읽기 전용 DB)
5. **C-d → F1-c → F3-b** (재시작·한도·재생성 — 가장 마지막, 하나씩)

## 2. 시나리오별 체크리스트 (주입 / 증거 / 원상복구)
| id | 주입 확인 | 증거 확인 | 원상복구 확인 |
|---|---|---|---|
| C-l | 출력 `404=` 가 요청 수와 비슷 | nginx 로그에 산발적 404 | 해당 없음 |
| S1-b | 출력 `4xx` 다수, `2xx` 소수 | nginx 로그 한 출발지 다수 경로 4xx | 해당 없음 |
| C-b | 수십 초 뒤 종료 | CPU·요청량 짧은 상승 후 복귀 | 해당 없음 |
| F1-a | `F1A_PATHS` 가 실제 무거운 읽기 경로인지 먼저 확정 | CPU 포화 지속 + nginx 요청 급증, 컨테이너 안 낯선 프로세스 없음 | 종료 후 CPU 평소로, watchdog 로그 |
| C-j | `docker ps` 에 `v2net-*` 사이드카 | 네트워크 이벤트 dst=sink-a(인가) | 사이드카 사라짐 |
| S2-b | 사이드카 기동 | 네트워크 이벤트 dst=sink-b(비인가) 반복·소량, sink-b `/stats` 수신 건수 | 사이드카 사라짐, watchdog 취소 |
| S2-d | 사이드카 기동, `S2D_HOSTS` 내부 이름만 | 네트워크 이벤트 다수 목적지·포트 연결 시도 | 사이드카 사라짐 |
| C-h | 덤프 파일 생성·`pg_restore --list` OK(호스트 `pg_dump`, `SCEN_PGADMIN`) | DB 읽기량 1회 상승 | 덤프는 저장소 밖에 남음 |
| S2-e | `SCEN_CONFIRM_TARGET` 일치해야 시작, `failed=0` | postgres-exporter 반환 행·seq scan 증가, (DB 로그 수집 시) 세션 흔적 | 종료 후 세션 없음(`pg_stat_activity`), 데이터 불변 |
| C-d | restart 1회 | RestartCount +1, 곧 healthy | `image_same/config_same=True` |
| F1-c | `docker inspect` Memory 가 줄었는지, OOMKilled·RestartCount 증가 | 재시작 반복 + 메모리 한도 근접 | Memory/MemorySwap 원래 값, Running, watchdog 로그 |
| F3-b | DB 백업 OK 후 재생성, 이미지 digest 원본과 동일 | 재시작/헬스 실패 또는 스토리지 오류 로그 | override 없이 재생성, `image_ok/cmd_ok/healthy=True`, override 파일 삭제 |

## 3. 측정 PC 에서 먼저 확인할 것 (미검증)
- F1-c: `docker update --memory` 를 **현재 사용량보다 낮게** 줄 때 Docker Desktop(WSL2, cgroup v2)이 거부하지 않는지, PID 1 이 OOMKilled 되는지(할당기 없이 앱 자체가 죽는지).
- F3-b: `STORAGE_ENDPOINT` 오류로 앱이 기동은 하는지/실패하는지(어느 쪽이든 증거는 남지만 양상 기록), compose 서비스 이름이 `backend` 인지.
- S2-e·F2-c·C-h: 측정 PC 앱 DB 는 Windows 호스트 PostgreSQL 17 이므로 `SCEN_DB_MODE=host` 가 기본이다. C-h/F3 백업은 `SCEN_PGADMIN`(시퀀스 포함 전체 읽기 권한) 으로 호스트 `pg_dump` 한다 — 일반 앱 역할로는 시퀀스 권한이 없어 실패한다.
- S2-b·C-j·S2-d: 사이드카에서 서비스 이름(`sink-a`, `db` 등) DNS 해석이 되는지.
- 모든 장애형: 실행 중 세션을 강제로 끊어 보고 watchdog 이 max 시간 뒤 복구하는지 1회 확인.

## 4. 측정 PC 호스트 PostgreSQL 준비 (host 모드)
측정 PC 앱 DB 는 컨테이너가 아니라 Windows 호스트의 PostgreSQL 17 이다. 컨테이너(사이드카·스크립트)에서
`host.docker.internal:5432` 로 접속한다. 아래를 먼저 확인한다.
- [ ] **pg_hba.conf 접속 허용**: Docker Desktop 가상 네트워크 대역(WSL2 의 `host.docker.internal` 출발지)에서
      대상 DB·역할의 접속을 허용하는 `host` 줄이 있는지. 없으면 추가 후 `pg_ctl reload`(또는 관리도구에서 reload).
- [ ] **Windows 방화벽 5432**: PostgreSQL 5432 인바운드가 Docker/WSL2 대역에 허용되는지(기본 차단일 수 있음).
- [ ] **pg_dump 경로·버전**: C-h/F3 백업은 사이드카/호스트에서 `pg_dump` 를 쓴다. `SCEN_PG_DUMP`/`SCEN_PG_RESTORE`
      로 경로 지정 가능. **서버가 17 이므로 pg_dump 도 17 이상**이어야 한다(하위 버전은 거부). `pg_dump --version` 확인.
- [ ] **PGPASSFILE 위치**: 비밀번호는 `SCEN_PGPASSFILE`(또는 `PGPASSFILE`)이 가리키는 파일로만 전달한다.
      Windows 는 보통 `%APPDATA%\postgresql\pgpass.conf`, 권한은 소유자 전용. 코드·로그·env 값에는 비밀번호를 넣지 않는다.
- [ ] **대상 DB 는 앱 DB**: `SCEN_PGDATABASE` 에 실제 앱 DB 이름을 넣는다. 미지정이면 시나리오가 실행을 거부한다.

## 5. 맥 개발·검증(선택) — 별도 테스트 DB
개발 중 로직 검증은 측정 PC 를 건드리지 않고 **별도 테스트 DB** 로 한다. 실데이터·실사용자 정보를 쓰지 않는다.
- 시드: `SCEN_PGHOST=127.0.0.1 SCEN_PGPORT=<포트> SCEN_PGADMIN=<슈퍼유저> SCEN_PGDATABASE=aiops_test
  SCEN_PGUSER=scen_app python3 tools/seed_aiops_test.py --confirm aiops_test`
  (가짜 데이터만, `aiops_test` 접두사·`--confirm` 일치 없이는 실행 거부, 대상 테스트 DB 외에는 손대지 않음)
- 검증 가능: S2-e·C-h·F2-c(Docker 불필요). F1-c·F3-a·F3-b·S2-d·S2-b 등은 Docker/앱 필요 — 측정 PC 에서.
- 주의: 맥 pg_dump 가 측정 PC(17)보다 낮으면 측정 PC 덤프는 불가 — 맥 검증은 맥 로컬 PG 로만.
