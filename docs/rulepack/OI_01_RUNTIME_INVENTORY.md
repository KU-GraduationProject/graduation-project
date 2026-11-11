# OI-01 — 실환경 인벤토리 및 관측 경로 확인

## 1. 결과와 판정 기준

점검일은 **2026-11-10(KST)**이다. **OI-01은 미완료이며, 현재 Mac의 직접 조사 완료 / 실제 PC 1·PC 2 인수는 UNVERIFIED인 상태**이다. 현재 Mac의 Leafy 저장·분석 서비스가 가동하지 않아 로그/메트릭 조회는 BLOCKED이다. 사용자 설명에 따른 역할은 **GC=PC 2(Leafy 서버), JH=PC 1(AIOps 관리 서버), 현재 Mac=JH 개발 환경**이다. Mac을 실제 배포된 PC 1 서버와 동일한 실행 환경으로 단정하지 않은 결과이다.

현재 Mac의 `desktop-linux` Docker context에서 `graduation-project` 컨테이너 **15개(created 9개, exited 6개, running 0개)**와 네트워크 2개를 직접 확인한 결과이다. Docker 전체에 다른 작업의 실행 중 컨테이너도 있지만 해당 서비스의 로그/메트릭을 Leafy 증거로 조회하지 않은 상태이다.

**VERIFIED 탐지 입력 로그·메트릭은 여전히 0개이다.** 이번에 VERIFIED로 기록한 Docker 상태·identity·이미지·네트워크·포트 결과는 인벤토리 증거이다. 컨테이너 설정이 남아 있다는 사실은 로그 전달·scrape 성공의 증거가 아닌 것이다.

| 상태 | 이 보고서의 의미 |
|---|---|
| VERIFIED | 이번 읽기 전용 조회에서 직접 확인한 값이다. `metadata`인 경우 실행 성공이나 탐지 입력 검증과 구분하는 상태이다. |
| CONFIGURED | 저장소의 설정/예시에 경로·값이 있는 상태이다. 실제 배포 적용 여부는 별도인 것이다. |
| MISSING | 명시한 조사 범위에서 대상/설정/값이 없는 것을 확인한 상태이다. 원격 PC 전체의 부재를 추정하는 상태는 아닌 것이다. |
| UNVERIFIED | 실제 실행 환경·접속 경로·표본을 확보하지 못한 상태이다. |
| BLOCKED | 현재 접근한 환경에서 서비스 미가동 등으로 해당 검증을 수행할 수 없는 상태이다. |

컨테이너·서비스 시작/재시작/삭제, 배포·룰 reload, 운영 룰/생성기·`.env`·DB/네트워크 변경, commit/push/PR 생성은 수행하지 않은 작업이다. 시나리오·Heldout은 열람하지 않은 작업이다. 원본 환경변수/inspect 전체/로그 본문·인증정보는 출력하지 않고 필요한 whitelist 필드만 기록한 결과이다.

## 2. 환경 구분·Git·근거 출처

### 2.1 PC별 구분

| 구분 | 확인한 역할·값 | 실제 실행 상태·접근 | 판정 |
|---|---|---|---|
| 현재 Mac | JH 개발 환경이라는 사용자 설명이며, 직접 조회한 OS는 `Darwin 24.6.0`, `arm64`인 결과이다. | 로컬 Unix Docker endpoint의 `desktop-linux` context만 직접 접근한 범위이다. Leafy 컨테이너는 모두 미가동인 상태이다. | OS/로컬 상태 VERIFIED, 역할은 사용자 확인 내용이다. |
| 통합 배포 환경 | 저장소 `docker-compose.yml`, project `graduation-project`인 구성이다. | 현재 Mac에 같은 project의 과거 컨테이너/네트워크가 남아 있으나 현행 설정과 차이가 있는 상태이다. 다른 실제 통합 측정 PC는 확인하지 못한 상태이다. | 로컬 metadata VERIFIED, 통합 환경 실행 성공 BLOCKED, 별도 측정 PC UNVERIFIED이다. |
| JH PC / PC 1 | Fluentd/Loki/Prometheus/Alertmanager/Grafana/Pipeline/Ollama/정책·대응 역할이라는 사용자 설명이다. | 실제 배포 OS·Tailscale IP·기존 원격 접속 방법은 미제공인 상태이다. `leafy-aiops` project는 현재 Mac context에 0개인 결과이다. | 서버 실배포·GC 수신·scrape·연동 UNVERIFIED이다. |
| GC PC / PC 2 | Leafy Frontend/Backend/MinIO, Windows 호스트 PG17, Zeek/Enricher/Fluent Bit 역할이라는 사용자 설명이다. | 정확한 OS 판본/버전·주소·원격 접속 방법을 제공받지 못하여 접속하지 않은 상태이다. | 서비스·로그 생성/전송·네트워크 연결 모두 UNVERIFIED이다. |

사용자는 현재 Mac의 로컬 상태를 먼저 확인하고 GC에서 직접 수행할 PowerShell 명령을 작성하며, 두 PC 사이의 전달/scrape/연결을 실측 전까지 UNVERIFIED로 유지하도록 명시한 상태이다. 임의의 IP/SSH host를 추정하거나 접속하지 않은 결과이다.

### 2.2 저장소 보존

브랜치는 `main...origin/main`, HEAD는 **`92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`**이며 최신 로컬 커밋 시각은 `2026-11-10T12:59:54+09:00`인 조회 결과이다. 작업 시작에 tracked diff는 없고 `docs/rulepack/`, `tools/rulepack/`은 기존 미커밋 산출물인 상태이다. 원격 GitHub main의 현재 HEAD를 이번 OI-01에서 추가 조회한 결과는 아닌 것이다.

기존 M1/M2/OI-1 문서·매핑·생성기·테스트와 관련 운영 설정 **27개 파일**의 SHA256을 시작 시 기록한 상태이다. 산출물은 이 보고서 한 파일이며 종료 검사에서 27개 파일의 해시 일치와 tracked 변경 없음을 확인한 결과이다.

### 2.3 실행 증거

시각은 모두 2026-11-10이다. 아래 조회는 현재 Mac에서 수행한 읽기 전용 작업이며 GC/JH 원격 서버에서 실행한 명령이 아닌 것이다.

| ID | KST / UTC | 실행 명령·조회 방식 | 직접 확인한 결과 |
|---|---|---|---|
| E01 | 15:18:28 / 06:18:28Z | `git status --short --branch`, `git log -1`, `git diff --name-only`, OS/PATH·파일명 점검이다. | 기준 커밋·clean tracked 상태, Darwin/arm64, PATH에 Tailscale/PowerShell CLI 미발견인 결과이다. |
| E02 | 15:20:28 / 06:20:28Z | `docker context show/inspect`, `docker ps -a`의 project/service/name/state projection, `docker inspect --format <whitelist>`, `docker image inspect --format '{{json .RepoDigests}}'`이다. | project 컨테이너 15개, running 0개, 이미지/identity/로그 driver·주소·포트 설정인 결과이다. |
| E03 | 15:20:46 / 06:20:46Z | 로컬 `/ready`, `/-/ready`, `/health` GET와 loopback 24224/24225 TCP connect, `lsof` listener 조회이다. | 세 HTTP와 두 TCP 모두 connection refused이며 조회 가능한 listener 목록도 빈 결과이다. |
| E04 | 15:24:14 / 06:24:14Z | 컨테이너의 logging 옵션·선별 mount·TARGET_SERVICE_MAP 존재 검사, project network inspect, process executable 이름 조회이다. | 앱 driver의 forwarded labels 미설정, network subnet 불일치, observer 미가동과 로컬 postgres 프로세스 발견인 결과이다. |
| E05 | 15:26:09 / 06:26:09Z | GET `:9090/api/v1/targets`, `:3100/loki/api/v1/labels`, `:8000/metrics`이다. | 모두 connection refused이며 target/label/metric 응답을 받지 못한 결과이다. |
| E06 | 15:26:08–15:27:17 / 06:26:08–06:27:17Z | postgres PID/comm, 확인된 설치 파일 `--version`, `127.0.0.1:5432` TCP connect이다. | PID 538의 comm은 `/Library/PostgreSQL/18/bin/postgres`, 해당 설치 바이너리는 `PostgreSQL 18.3`, local 5432 연결 성공인 결과이다. DB 접속/SQL은 수행하지 않은 상태이다. |

Docker/네트워크 조회는 해당 읽기 전용 접근이 가능한 실행으로 수행한 것이다. stdout에는 선택 필드만 반환한 결과이다. 서비스 상태를 바꾸는 동작은 없는 작업이다.

## 3. 현재 Mac의 실제 Docker 인벤토리

아래는 모두 project **`graduation-project`**의 직접 조회값이며 상태·image reference는 **VERIFIED(metadata)**이다. 이름의 앞 `/`는 표시에서 제거한 값이다.

| 컨테이너 이름 | Compose service | 상태 | 실제 container image reference |
|---|---|---|---|
| `nginx-exporter` | `nginx-exporter` | `created` | `nginx/nginx-prometheus-exporter:latest` |
| `leafy-frontend` | `frontend` | `created` | `gicks/leafy-frontend:latest` |
| `aiops-remediation` | `remediation` | `created` | `graduation-project-remediation` |
| `postgres-exporter` | `postgres-exporter` | `created` | `prometheuscommunity/postgres-exporter:latest` |
| `leafy-backend` | `backend` | `created` | `gicks/leafy-backend:latest` |
| `leafy-db` | `db` | `created` | `postgres:16` |
| `aiops-pipeline` | `pipeline` | `created` | `graduation-project-pipeline` |
| `grafana` | `grafana` | `created` | `grafana/grafana:latest` |
| `loki` | `loki` | `exited` | `grafana/loki:latest` |
| `fluentd` | `fluentd` | `exited` | `graduation-project-fluentd` |
| `prometheus` | `prometheus` | `exited` | `prom/prometheus:latest` |
| `alertmanager` | `alertmanager` | `exited` | `prom/alertmanager:latest` |
| `cadvisor` | `cadvisor` | `exited` | `gcr.io/cadvisor/cadvisor:latest` |
| `ollama` | `ollama` | `created` | `ollama/ollama:latest` |
| `node-exporter` | `node-exporter` | `exited` | `prom/node-exporter:latest` |

`created` 9개는 StartedAt이 zero time인 미시작 컨테이너이다. `exited` 6개는 2026-09-21 UTC의 종료 시각이 남아 있는 과거 컨테이너이다. 전체 15개의 Docker RestartCount 필드는 0이지만 이를 현재 Prometheus 재시작 메트릭의 0 또는 가용성 정상으로 판정하지 않은 결과이다. 실행 중 서비스의 network sandbox도 없는 상태이다.

`leafy-aiops`, `leafy-observer` project는 현재 context에서 각각 0개이다. 알려진 project/이름으로 식별한 범위에서 `leafy-minio`, `network-observer-zeek`, `network-observer-enricher`, `network-events-shipper` 컨테이너는 없는 상태이다. **MISSING의 범위는 현재 Mac context**이며 GC PC의 부재를 뜻하는 결과는 아닌 것이다.

### 3.1 이미지 ID와 RepoDigests

아래 ID와 RepoDigests는 Docker daemon의 실제 응답이다. **로컬 image ID와 registry manifest의 RepoDigest는 구분되는 값**이며, tag만으로 현재 main 빌드와 동일하다고 판정하지 않은 것이다. RepoDigests가 있어도 이번에 원격 registry provenance/실행 소스 커밋을 검증한 결과는 아닌 것이다.

| 컨테이너 | 로컬 image ID | Docker가 보고한 RepoDigests |
|---|---|---|
| `nginx-exporter` | `sha256:bf76e58df548a13e52bd543ac70f6d3d667e14884e8b51c149bd81994ca75ccd` | `nginx/nginx-prometheus-exporter@sha256:bf76e58df548a13e52bd543ac70f6d3d667e14884e8b51c149bd81994ca75ccd` |
| `leafy-frontend` | `sha256:cda2852afbe6dfe5fffe5268a3512f57a572d2c2b32dddd6cc7ace659253867f` | `gicks/leafy-frontend@sha256:cda2852afbe6dfe5fffe5268a3512f57a572d2c2b32dddd6cc7ace659253867f` |
| `aiops-remediation` | `sha256:b0b58253fa40d313d31fcf49a20efdad38396cecdd42f3ffebec444d11eb03a4` | `graduation-project-remediation@sha256:b0b58253fa40d313d31fcf49a20efdad38396cecdd42f3ffebec444d11eb03a4` |
| `postgres-exporter` | `sha256:ac5ec343104fae0e2d84a27bb8d69b38430a11910c5382cad85d478d2bab713e` | `prometheuscommunity/postgres-exporter@sha256:ac5ec343104fae0e2d84a27bb8d69b38430a11910c5382cad85d478d2bab713e` |
| `leafy-backend` | `sha256:ea3dc8ebe293a1108e9e094466c4fc355b2b21a665094555a8bddeff9232c7da` | `gicks/leafy-backend@sha256:ea3dc8ebe293a1108e9e094466c4fc355b2b21a665094555a8bddeff9232c7da` |
| `leafy-db` | `sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94` | MISSING(RepoDigests 비어 있음)이다. |
| `aiops-pipeline` | `sha256:fe57daf43108239aeca1a737d0bba5b96368445f153c20254447c9da826877ad` | `graduation-project-pipeline@sha256:fe57daf43108239aeca1a737d0bba5b96368445f153c20254447c9da826877ad` |
| `grafana` | `sha256:ac461fb352abc50da10a51c7d02462e9c05488f11f53f14b3ad79a8145f638a0` | `grafana/grafana@sha256:ac461fb352abc50da10a51c7d02462e9c05488f11f53f14b3ad79a8145f638a0` |
| `loki` | `sha256:1107dd5274e0ada47e42472b7a7e71f3b2a2fe878878108f3e2f9e51528f0193` | `grafana/loki@sha256:1107dd5274e0ada47e42472b7a7e71f3b2a2fe878878108f3e2f9e51528f0193` |
| `fluentd` | `sha256:74b49d4756b3979325a4e42ced49b208200366f44dae1f629979c7c0a39d4f2e` | `graduation-project-fluentd@sha256:74b49d4756b3979325a4e42ced49b208200366f44dae1f629979c7c0a39d4f2e` |
| `prometheus` | `sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0` | `prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0` |
| `alertmanager` | `sha256:e9733bafb1bdef9b00e25a21f8f99dc26a22224bf16641ad754d1649f4c3357a` | `prom/alertmanager@sha256:e9733bafb1bdef9b00e25a21f8f99dc26a22224bf16641ad754d1649f4c3357a` |
| `cadvisor` | `sha256:3de2bd5203120b866d74a9b283b2ffb8ec382fbf9dc321814700c6ea6f44ec57` | `gcr.io/cadvisor/cadvisor@sha256:3de2bd5203120b866d74a9b283b2ffb8ec382fbf9dc321814700c6ea6f44ec57` |
| `ollama` | `sha256:da6e0dc5651df159e45686fd663c4dbe1624a52c44d7280eeac1551d8f865532` | `ollama/ollama@sha256:da6e0dc5651df159e45686fd663c4dbe1624a52c44d7280eeac1551d8f865532` |
| `node-exporter` | `sha256:1b4e4438faca4dd7e001dd445d161a4a2091b0fededa84093b3a8dfeae1f1be0` | `prom/node-exporter@sha256:1b4e4438faca4dd7e001dd445d161a4a2091b0fededa84093b3a8dfeae1f1be0` |

`leafy-db`의 RepoDigests는 비어 있어 **MISSING(이 로컬 이미지 metadata 범위)**이다. image ID는 확인되었으므로 이를 임의의 registry digest로 대체하지 않은 상태이다. 중지 컨테이너의 digest는 현재 실행 중인 GC/JH 서버 이미지의 증거가 아닌 것이다.

## 4. 현재 Mac의 네트워크·수집 설정과 실제 차이

### 4.1 Docker 네트워크

| 네트워크 | 직접 조회한 subnet / gateway | 연결 컨테이너 수 | 현행 저장소와 비교 |
|---|---|---|---|
| `graduation-project_leafy-net` | `172.22.0.0/16`, `172.22.0.1`인 metadata이다. | 0개이다. | 현행 [Compose](../../docker-compose.yml)의 `10.210.0.0/24`와 다른 값이다. |
| `graduation-project_mgmt-net` | `172.21.0.0/16`, `172.21.0.1`인 metadata이다. | 0개이다. | 실제 현재 트래픽/연결은 없는 상태이다. |

두 네트워크는 bridge/local scope, internal=false인 VERIFIED metadata이다. 존재하는 bridge와 실제 앱 트래픽은 다른 사실이다. 현행 Observer의 `OBSERVE_SUBNET=10.210.0.0`·frontend 신뢰 프록시 값 등을 이 과거 네트워크에 그대로 대응시킬 수 있다고 가정하지 않은 결과이다. 수정/재생성은 수행하지 않은 상태이다.

### 4.2 이미지·driver·mount 차이

| 항목 | 실제 남은 컨테이너 metadata | 현행 설정/영향 | 판정 |
|---|---|---|---|
| Frontend/Backend image | `gicks/leafy-frontend:latest`, `gicks/leafy-backend:latest`이다. | 현행 Compose는 `gicks/ai-ops-leafy-frontend`, `gicks/ai-ops-leafy-backend`이다. 과거 이미지에 현재 Nginx/Java JSON 계약이 있다고 가정할 수 없는 차이이다. | 차이 VERIFIED, 실제 로그 schema UNVERIFIED이다. |
| Docker 로그 목적지 | frontend/backend/db가 `fluentd`, `localhost:24224`; tag는 frontend/backend/leafy-db이다. | driver 구성은 확인되었으나 컨테이너/Fluentd 미가동으로 전달 성공은 BLOCKED이다. | 설정 metadata VERIFIED, 전송 BLOCKED이다. |
| Compose service 전달 | 위 세 앱의 logging option `labels`가 빈 값이다. | 현재 [Docker 로그 필터](../../leafy/fluentd/plugins/filter_leafy_docker_log.rb)는 driver record의 `com.docker.compose.service`를 읽는 구현이다. 현재 필터와 이 driver 설정을 결합하면 `service=unknown`이 될 가능성이 있는 **조건부 정적 분석**이며 Loki에서 실측한 값은 아닌 것이다. | 불일치 VERIFIED(metadata), 실제 label UNVERIFIED이다. |
| async/ACK/sub-second 옵션 | 조회한 옵션은 모두 빈 값이다. | 현행 통합 Compose/원격 logging 예시의 옵션과 동일 적용을 증명할 수 없는 상태이다. 빈 옵션을 실제 유실률로 환산하지 않은 것이다. | metadata VERIFIED, 전송 품질 UNVERIFIED이다. |
| Fluentd mount | 현재 repo의 `fluent.conf` bind는 있으나 network observer JSONL mount·`/fluentd/log` mount는 없는 metadata이다. | 현재 파일 내용과 실제 빌드 이미지/프로세스 적용은 구분할 항목이다. JSONL 수집 경로가 이 과거 컨테이너에 준비되었다고 판정하지 않은 것이다. | metadata VERIFIED, 현재 수집 BLOCKED이다. |
| Prometheus/Loki mount | 현재 repo의 Prometheus 통합 config/rules 및 Loki config/rules bind 경로가 남은 상태이다. | 프로세스가 종료되어 파일의 실제 load/targets/ruler 평가는 확인하지 못한 상태이다. | mount metadata VERIFIED, 적용/데이터 BLOCKED이다. |
| Pipeline socket/map | 로컬 `/var/run/docker.sock` bind이며 `TARGET_SERVICE_MAP` 환경변수는 없는 상태이다. | 통합 Compose에도 map은 없으므로 이 점만으로 오류라고 볼 수 없는 것이다. 원격 Compose의 명시적 map이 실제 PC 1에 적용되었는지는 UNVERIFIED이다. | 로컬 metadata VERIFIED, 원격 map UNVERIFIED이다. |
| 과거 publish 설정 | frontend에 HostIp가 빈 80/443, remediation에 HostIp가 빈 8001 PortBindings가 남은 상태이다. 실제 ActivePorts는 빈 상태이다. | 현행 frontend는 기본 loopback 80만, remediation은 loopback 8001인 구성이다. 현재 외부 수신이 있다는 뜻은 아닌 설정 차이이다. | 설정 차이 VERIFIED, 실제 외부 접근/차단 UNVERIFIED이다. |

컨테이너의 Compose service 라벨은 실제로 frontend/backend/db 등과 일치하는 값이다. **컨테이너 자체의 라벨 존재와 로그 driver의 라벨 전달 옵션은 다른 항목**이다. 현재 소스의 플러그인이 과거 Fluentd/Pipeline 이미지에 내장되어 있다는 사실도 검증하지 못한 상태이다.

## 5. 로그·메트릭·호스트 서비스·Tailscale 판정

### 5.1 실제 응답과 정적 경로

| 조사 항목 | 직접 확인한 값 | 정적 설정 근거 | 확인 상태 |
|---|---|---|---|
| Prometheus target job/instance/health/lastScrape | `127.0.0.1:9090/api/v1/targets` 연결 거부이며 응답 row 미확보이다. | [통합 설정](../../monitoring/prometheus/prometheus.yml)의 7개 job, [원격 설정](../../monitoring/prometheus/prometheus.aiops.yml)의 self/Pipeline 및 file_sd job이다. | 로컬 API BLOCKED, 정적 job CONFIGURED, 실제 PC 1/PC 2 scrape UNVERIFIED이다. |
| Loki service/runtime/log_type·로그 도착 | `127.0.0.1:3100/loki/api/v1/labels` 연결 거부이다. | [Fluentd](../../leafy/fluentd/fluent.conf)의 앱·host PG·network 별도 라벨/route이다. | 로컬 API BLOCKED, 실제 라벨·표본 및 PC 간 전달 UNVERIFIED이다. |
| Pipeline `/metrics` | `127.0.0.1:8000/metrics` 연결 거부이다. | [main.py](../../aiops/pipeline/main.py)의 로컬 Docker metadata/restart 생성 경로이다. | 로컬 API BLOCKED, 실제 metric name/label/value UNVERIFIED이다. |
| 원격 file_sd | 현재 checkout의 `targets/*.yml` 실파일 0개이다. | `.yml.example`과 README만 있는 구성이다. | 이 checkout의 실파일 MISSING, 실제 PC 1 파일/targets UNVERIFIED이다. |
| 로컬 24224/24225 | `127.0.0.1`에서 두 TCP 연결 모두 거부이며 가시적인 listener 목록 0개이다. | 통합은 24224 TCP/UDP publish, 원격은 Tailscale IP의 24224/24225 TCP publish인 구성이다. | 로컬 loopback 미수신 VERIFIED, 실제 Tailscale bind/PC 간 연결/ACL UNVERIFIED이다. |
| 로컬 Tailscale | PATH 및 점검한 `/Applications`·Homebrew의 알려진 CLI 경로에서 미발견인 결과이다. | Tailscale 경유 전달은 배포 설계이다. whitelist 주소 변수에서 사용할 literal IP도 확보하지 못한 상태이다. | CLI 경로 부재 VERIFIED, 설치/접속/peer·ACL 전체 상태는 UNVERIFIED이다. |
| GC PG17/Windows Fluent Bit | 원격 접속/명령 실행을 수행하지 못한 상태이다. | [PG Fluent Bit](../../deploy/leafy-pc/postgresql/fluent-bit.conf)의 `C:\Program Files\PostgreSQL\17\data\log\*.json` → 24225, tag `postgresql.jsonlog`이다. | 경로 CONFIGURED, 서비스·파일·읽기 권한·인증/도착 UNVERIFIED이다. |
| GC Zeek/Enricher/Network shipper | 해당 GC 실행 상태·namespace·파일은 미확인이다. | [Observer Compose](../../deploy/leafy-pc/network-observer/docker-compose.yml), [shipper](../../deploy/leafy-pc/network-observer/fluent-bit/fluent-bit.conf)의 JSONL → 24224/tag `network.event`이다. | CONFIGURED, GC 실행/전달 UNVERIFIED이다. |

listener 조회의 가시성·loopback 테스트만으로 다른 인터페이스 전체의 차단을 확정하지 않은 결과이다. TCP 성공도 forward 인증·Loki 저장·ACL 거부 정책의 증거를 대신하지 않는 것이다. 두 PC 간 실제 전달/scrape/연결은 사용자 지시대로 모두 UNVERIFIED로 유지한 상태이다.

### 5.2 현재 Mac에서 발견한 PostgreSQL은 GC PG17 증거가 아닌 것이다

PID 538의 실행 경로는 `/Library/PostgreSQL/18/bin/postgres`이며, 같은 설치 경로의 `postgres --version` 출력은 **`postgres (PostgreSQL) 18.3`**이다. `127.0.0.1:5432` TCP 접속도 성공한 결과이다. 이 세 항목은 VERIFIED이며 **프로세스 경로·설치 바이너리 버전·해당 포트의 연결성**에 대한 각각의 증거이다.

PID별 lsof 결과는 비어 있어 5432와 해당 PID의 소유 관계를 확정하지 못한 상태이다. 실행 중 서버의 SQL `server_version`이나 실행 inode를 읽어 확인한 결과도 아닌 것이다. 이 Mac의 PG18 설치/프로세스를 GC의 PG17이나 Leafy 연결 DB로 대체하지 않은 결과이다. DB 로그인·SQL·설정/데이터 변경은 수행하지 않은 상태이다.

현재 Mac의 process executable 이름 검사에서 Fluent Bit/Zeek/Tailscale은 발견하지 못한 결과이다. 이 제한된 local 조회로 GC 서비스 부재나 Tailscale 전체 미설치를 단정하지 않은 것이다.

## 6. M2 매핑과 실제 관측 환경 비교

| 매핑 | 매핑의 값 | 직접 비교한 결과 | 남은 차이·판정 |
|---|---|---|---|
| [M2-1 targets.yml](m2/targets.yml) | frontend/db 서비스, Nginx exporter job, leafy-frontend/db 분석 대상이다. | 현재 Mac에 같은 container/service 이름은 있으나 모두 created인 상태이다. | Docker driver의 service 라벨 전달 옵션이 없고 앱 이미지도 달라 JSON/service 계약 일치를 판정할 수 없는 상태이다. 실제 Loki·scrape UNVERIFIED이다. |
| [M2-2 infra_targets.yml](m2/infra_targets.yml) | `cadvisor:8080`, `pipeline:8000`의 통합 job/instance; CPU 4개, restart Backend이다. | 이름상 frontend/backend/db 3개는 존재하고 MinIO는 현재 context에 없는 상태이다. cAdvisor/Pipeline은 미가동이다. | 이름 metadata 일부 일치이며 `/docker/` id·cpu total·metadata join/실표본은 UNVERIFIED이다. 현재 로컬 검증 BLOCKED이다. |
| [M2-3 resource_targets.yml](m2/resource_targets.yml) | 같은 통합 source, memory 전체 해당 name, network 4개 name과 root fallback이다. | 실제 metric label·memory limit/working_set·network name/interface/id를 조회하지 못한 상태이다. | 전체 라벨 나눗셈과 fallback 분기 인수 UNVERIFIED이며 PC 2 source로 사용할 근거가 없는 상태이다. |
| 원격 TARGET_SERVICE_MAP | 저장소는 `leafy-frontend=frontend,leafy-backend=backend,leafy-minio=minio,leafy-db=db:host`인 설정이다. | 현재 Mac의 미시작 Pipeline에는 환경변수가 없고 실제 PC 1 config는 미확인이다. | GC 실제 이름과 alias/service/runtime 대응은 UNVERIFIED이다. 특히 host DB는 Docker 컨테이너 이름과 구분할 항목이다. |
| 업무망 identity | 현행 subnet은 `10.210.0.0/24`이다. | 남아 있는 로컬 bridge는 `172.22.0.0/16`이다. | 현재 repo와 과거 컨테이너/네트워크가 다른 환경임을 보여 주는 VERIFIED 차이이다. GC subnet/NIC/netns는 UNVERIFIED이다. |

이 비교를 이유로 매핑이나 생성 룰을 자동 변경하지 않은 결과이다. 최신 역할/이미지/실제 라벨을 확보한 뒤 해당 OI 항목에서 조정 여부를 판단할 사항이다.

## 7. 우선 후속 작업

[OI-1 추적표](OBSERVABILITY_INFRA_MILESTONE.md)의 기존 상태를 이 보고서 외 파일에서 변경하지 않은 작업이다. 이번 근거를 바탕으로 다음 우선순위가 필요한 상태이다.

1. **OI-01 원격 증거 수령**이 우선인 단계이다. GC/PC 2에서 §8의 결과를 확보하고 PC 1 실제 배포 위치·OS·주소·접속 경로를 확정할 작업이다. 현재 Mac의 중지된 과거 구성을 실제 운영 배포로 취급하지 않을 기준이다.
2. **OI-02/OI-03**은 PC 2 자원/metadata·재시작 전달 경로가 실제로 있는지 먼저 확인할 P0 항목이다. PC 1 Docker 값으로 대체하지 않을 작업이다.
3. **OI-04/OI-09**는 원격 데이터 확보와 함께 진행할 P0 항목이다. image/schema/service 전달, 실제 id·name·scope·alias와 host/container 소비 경로를 대조할 작업이다.
4. **OI-05/OI-06**은 실제 PG17/Fluent Bit/Actuator 및 인증/Nginx 필드 확인이 필요한 P0 항목이다. 현재 Mac의 PG18이나 과거 이미지로 검증을 대신할 수 없는 상태이다.
5. **OI-08**은 PC 간 전송 확인과 병행할 항목이다. Tailscale/24224·24225·인증·ACL·시간/연속성의 실제 적용 증거가 필요한 상태이다. **OI-07**의 MinIO/HTTP/Blackbox는 원격 앱 인벤토리를 확보한 뒤 관측 경로를 결정할 항목이다.

이번 조사만으로 exporter 배치/포트 개방/컨테이너 재생성을 실행하지 않은 상태이다.

## 8. 실제 PC에서 수행할 읽기 전용 점검 명령

아래는 **실측 전의 수동 절차**이며 이번 세션에서 GC/PC 1에 실행한 결과가 아닌 것이다. PowerShell 실행 검증도 현재 Mac에 실행기가 없어 UNVERIFIED이다. `<...>`는 운영자가 확인한 실제 값으로 대체하는 부분이다. 주소·OS·프로젝트명·컨테이너명을 임의로 채우지 않을 절차이다. 출력에는 필요한 metadata/키/집계만 포함하는 형식이다.

### 8.1 GC/PC 2: OS·컨테이너·이미지·driver·identity

```powershell
[DateTimeOffset]::UtcNow.ToString('o')
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
docker context show
docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
function OI-Container([string]$Name) {
    # 원본 inspect는 변수에만 받고 전체를 출력하지 않는 절차이다.
    $c = @(docker inspect --type container $Name 2>$null | ConvertFrom-Json)[0]
    if ($LASTEXITCODE -ne 0 -or $null -eq $c) { throw 'Container inspect failed' }
    $im = @(docker image inspect $c.Image 2>$null | ConvertFrom-Json)[0]
    $imageInspectOk = ($LASTEXITCODE -eq 0 -and $null -ne $im)
    $mapLines = @($c.Config.Env | Where-Object { $_ -like 'TARGET_SERVICE_MAP=*' })
    $map = if ($mapLines.Count -gt 0) { $mapLines[0].Substring(19) } else { '<not set>' }
    if ($map -ne '<not set>' -and $map -notmatch '^[A-Za-z0-9_.,=:\- ]*$') { $map = '<invalid; omitted>' }
    [pscustomobject]@{
        name=$c.Name; project=$c.Config.Labels.'com.docker.compose.project'
        service=$c.Config.Labels.'com.docker.compose.service'; state=$c.State.Status
        imageRef=$c.Config.Image; imageId=$c.Image; imageInspectOk=$imageInspectOk
        repoDigests=($im.RepoDigests -join ',')
        startedAt=$c.State.StartedAt; restarts=$c.RestartCount
        networkMode=$c.HostConfig.NetworkMode; driver=$c.HostConfig.LogConfig.Type
        logAddress=$c.HostConfig.LogConfig.Config.'fluentd-address'
        forwardedLabels=$c.HostConfig.LogConfig.Config.labels
        targetServiceMap=$map
    }
    $c.NetworkSettings.Networks.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{network=$_.Name; address=$_.Value.IPAddress; gateway=$_.Value.Gateway}
    }
    $c.Mounts | Where-Object { $_.Destination -match 'zeek|observer|fluent|prometheus|docker.sock' } |
        Select-Object Type, Source, Destination, RW
}
OI-Container '<실제 frontend 이름>'
OI-Container '<실제 backend 이름>'
OI-Container '<실제 MinIO 이름>'
```

목적은 GC의 실제 앱 이름·Compose service·image digest·driver·주소/라벨 전달과 관측 mount 확인이다. 기대 결과는 실제 실행 중인 Leafy 서비스와 운영자가 사용하는 수집 주소인 것이다. 없는 이름/Created/Exited/빈 service·forwardedLabels는 차이 또는 미수집 후보이며 실행을 시도하여 보완하지 않을 절차이다. Project 이름이나 image tag만으로 최신 main과 동일하다고 판정하지 않을 항목이다.

### 8.2 GC/PC 2: PostgreSQL 17·Windows Fluent Bit

```powershell
Get-Service | Where-Object { $_.Name -match 'postgres|fluent' } | Select-Object Name, Status
Get-CimInstance Win32_Process -Filter "Name='postgres.exe' OR Name='fluent-bit.exe'" |
    Select-Object Name, ProcessId, ExecutablePath
# 실제 관측 계정·DB·포트를 확인한 뒤 비밀번호는 비표시 프롬프트로 입력하는 절차이다.
$OiPgUser = '<읽기 전용 DB 계정>'
$OiPgDb = '<실제 DB 이름>'
$OiPgPort = '<실제 PG17 포트>'
psql -X -W -h 127.0.0.1 -p $OiPgPort -U $OiPgUser -d $OiPgDb -c "SHOW server_version; SHOW port; SHOW logging_collector; SHOW log_destination; SHOW data_directory; SHOW log_directory;"
$OiPgLogDir = '<위 설정에서 확인한 실제 로그 디렉터리>'
$OiPgFile = Get-ChildItem -LiteralPath $OiPgLogDir -Filter *.json |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
$OiPgFile | Select-Object Name, Length, LastWriteTimeUtc
if ($null -ne $OiPgFile) {
    try {
        $OiPgRow = Get-Content -LiteralPath $OiPgFile.FullName -Tail 1 | ConvertFrom-Json -ErrorAction Stop
        $OiPgRow.PSObject.Properties.Name | Sort-Object
    } catch { Write-Output 'PG JSON parse failed; content omitted' }
}
```

목적은 실행 서비스/파일 경로와 **실제 접속한 서버**의 버전/jsonlog 상태 확인이다. 기대 결과는 PG17 server_version, 실행 중 서비스/Fluent Bit, 새 JSON 파일과 키 목록이다. 바이너리/psql 클라이언트 버전만으로 서버 버전을 확정하지 않을 절차이다. 접속/권한/파일 부재는 UNVERIFIED/보완 필요이며 raw SQL/로그 message·사용자/토큰 값을 공유하지 않을 절차이다. 이 명령은 SHOW만 수행하며 스키마·설정·데이터를 변경하지 않는 절차이다.

### 8.3 GC/PC 2: Zeek·Enricher·Network Fluent Bit

먼저 `docker ps`에서 실제 이름을 확인하고 `OI-Container`로 각 컨테이너의 state/mount/networkMode를 확인할 절차이다. 아래 exec는 이미 running인 컨테이너에만 읽기 명령을 실행하는 단계이다.

```powershell
$OiBackend = '<실제 backend 컨테이너>'
$OiZeek = '<실제 Zeek 컨테이너>'
$OiEnricher = '<실제 Enricher 컨테이너>'
$OiShipper = '<실제 network Fluent Bit 컨테이너>'
foreach ($n in @($OiZeek,$OiEnricher,$OiShipper)) { OI-Container $n }
# 위 state가 running인 경우에만 수행하는 읽기 전용 조회이다.
docker exec $OiBackend readlink /proc/self/ns/net
docker exec $OiZeek readlink /proc/self/ns/net
docker exec $OiBackend cat /proc/net/route
docker exec $OiZeek ls -ln /zeek-logs/conn.log /zeek-logs/conn_threshold.log
docker exec $OiEnricher ls -ln /var/log/network-observer/network-events.jsonl
```

목적은 backend/Zeek의 실제 namespace 일치와 관측 NIC/파일 존재·진행 상태 확인이다. 기대 결과는 같은 netns와 유효한 업무망 route, conn/JSONL의 현재 시각/크기인 것이다. 파일/도구 부재나 namespace 불일치는 미검증·공백이며 컨테이너를 재시작하지 않을 절차이다. 원격 예시는 eth0 고정과 `REPLACE_WITH_LEAFY_DOCKER_NETWORK`를 포함하므로 실제 설정과 대조할 항목이다. 파일 크기만으로 PC 1 Loki 도착을 VERIFIED로 처리하지 않는 기준이다.

### 8.4 GC/PC 2: Tailscale·PC 1 수신 경로·시간

```powershell
$OiTs = tailscale status --json | ConvertFrom-Json
[pscustomobject]@{backendState=$OiTs.BackendState; selfOnline=$OiTs.Self.Online; selfIPs=($OiTs.TailscaleIPs -join ',')}
$OiPc1Ip = '<운영자가 확인한 실제 PC 1 Tailscale IPv4>'
foreach ($p in @(24224,24225)) {
    [pscustomobject]@{port=$p; tcpReachable=(Test-NetConnection -ComputerName $OiPc1Ip -Port $p -InformationLevel Quiet)}
}
[DateTimeOffset]::UtcNow.ToString('o')
w32tm /query /source
w32tm /query /status
```

목적은 GC 자신의 tailnet 상태와 실제 PC 1 포트 도달성·시각 기준 확인이다. 기대 결과는 online·실제 Tailscale IP·해당 경로 TCP 성공과 유효한 시간 source인 것이다. 실패 시 listener/라우팅/ACL/방화벽/미배포를 구분할 추가 증거가 필요한 상태이다. TCP 성공만으로 PG forward 인증·로그 저장·scrape·다른 peer 차단을 VERIFIED로 승격하지 않을 기준이다. resync/방화벽·Tailscale 설정 변경은 없는 절차이다.

### 8.5 실제 PC 1: 수신 컨테이너·map·Prometheus targets

PC 1의 실제 OS는 미제공인 상태이다. 다음은 PowerShell을 사용할 수 있는 운영 환경에서의 절차이며 Windows라고 확정한 명령은 아닌 것이다. `OI-Container` helper를 같은 세션에 정의한 뒤 Fluentd/Prometheus/Loki/Pipeline의 실제 이름으로 조회할 항목이다.

```powershell
OI-Container '<실제 PC 1 Fluentd 이름>'
OI-Container '<실제 PC 1 Prometheus 이름>'
OI-Container '<실제 PC 1 Loki 이름>'
OI-Container '<실제 PC 1 Pipeline 이름>'
$OiProm = 'http://127.0.0.1:9090' # 실제 publish 주소와 대조할 값이다.
$OiLoki = 'http://127.0.0.1:3100'
function OI-Get([string]$Url) {
    $r = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 15 -ErrorAction Stop
    if ($null -ne $r.status -and $r.status -ne 'success') { throw 'API status failed' }
    return $r
}
$OiTargets = @((OI-Get ($OiProm + '/api/v1/targets')).data.activeTargets)
$OiTargets | ForEach-Object {
    [pscustomobject]@{job=$_.labels.job; instance=$_.labels.instance; site=$_.labels.site;
        health=$_.health; lastScrape=$_.lastScrape; hasLastError=(-not [string]::IsNullOrEmpty($_.lastError))}
}
# 실제 등록된 job에 대해서만 저장된 metric name을 발견하는 단계이다.
foreach ($j in @($OiTargets | ForEach-Object { $_.labels.job } | Sort-Object -Unique)) {
    $sel = '{job=' + ($j | ConvertTo-Json -Compress) + '}'
    $names = (OI-Get ($OiProm + '/api/v1/label/__name__/values?match%5B%5D=' + [uri]::EscapeDataString($sel))).data
    $names | Where-Object { $_ -match '^(container_|aiops_docker_|node_|nginx_|pg_|hikaricp_)' } |
        ForEach-Object { [pscustomobject]@{job=$j; metric=$_} }
}
```

목적은 실제 source·job/instance·health/scrape 시각과 계측명 발견이다. 기대 결과는 현재 scrape 성공/최근 시각과 해당 PC 2 지표의 존재인 것이다. 빈 target은 등록 부재일 수 있으며 이름 API의 과거 이름만으로 최신 표본을 VERIFIED로 판정하지 않을 기준이다. 발견한 정확한 metric/selector의 최신 값·라벨·원본 간격은 [M1 §8.4](M1_OBSERVABILITY_AUDIT.md#84-발견된-시계열의-라벨값연속성) 방식으로 확인할 항목이다.

PC 1이 Windows인 경우에만 `Get-NetTCPConnection -State Listen`에서 LocalPort 24224/24225와 LocalAddress를 선별할 절차이다. 현재 Mac에서 수행한 Shell 조회는 `lsof -nP -iTCP:24224 -iTCP:24225 -sTCP:LISTEN`이며 그 결과는 E03에 기록한 사실이다. 수신 주소·TCP 성공·공유 키 인증·실제 Loki 저장을 각각 구분하는 절차이다.

### 8.6 실제 PC 1: Loki 라벨·도착·민감값 없는 표본 schema

```powershell
$OiEnd = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$OiStart = $OiEnd - 1800
$OiWindow = '?start=' + [string]$OiStart + '000000000&end=' + [string]$OiEnd + '000000000'
(OI-Get ($OiLoki + '/loki/api/v1/labels' + $OiWindow)).data
foreach ($label in @('service','runtime','log_type','log_format','event_type','src_service','dst_service')) {
    $v = (OI-Get ($OiLoki + '/loki/api/v1/label/' + $label + '/values' + $OiWindow)).data
    [pscustomobject]@{label=$label; values=($v -join ',')}
}
$OiSelector = '<위에서 실제 존재를 확인한 stream selector>'
$OiStreams = @((OI-Get ($OiLoki + '/loki/api/v1/query_range?query=' +
    [uri]::EscapeDataString($OiSelector) + '&since=30m&limit=200&direction=backward')).data.result)
$OiTimes = @(); $OiKeys = @(); $OiRows = 0; $OiBad = 0
foreach ($s in $OiStreams) {
    foreach ($entry in $s.values) {
        $OiRows++; $OiTimes += [long]$entry[0]
        try {
            $o = $entry[1] | ConvertFrom-Json -ErrorAction Stop
            if ($o -isnot [pscustomobject]) { throw 'Not an object' }
            $OiKeys += $o.PSObject.Properties.Name
        } catch { $OiBad++ }
    }
}
[pscustomobject]@{streams=$OiStreams.Count; rows=$OiRows; invalidJson=$OiBad;
    latestEntryNs=($OiTimes | Sort-Object -Descending | Select-Object -First 1)}
$OiKeys | Sort-Object -Unique
```

목적은 실제 라벨·최근 도착과 JSON 키의 확보이다. 앱·PG host·network 각각 실제 발견한 selector로 확인할 항목이다. 기대 결과는 관련 stream과 최근 entry이며 source/경로에 맞는 service/runtime/log_type·필드가 있는 상태이다. 0건/최대 200줄 표본은 전체 기간 무트래픽/수집 정상의 증거가 아닌 것이다. 로그 내용·요청 값·사용자·비밀번호·토큰은 출력하지 않는 절차이다.

API 형식의 보조 근거는 [Prometheus targets 문서](https://prometheus.io/docs/prometheus/latest/querying/api/#targets), [Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/), [Docker inspect 문서](https://docs.docker.com/reference/cli/docker/inspect/)이다. 실제 실행값은 E01–E06 또는 이후 해당 PC 결과로만 판정할 기준이다.

## 9. OI-01 완료 여부 및 다음 증거

| 확인 항목 | 상태 | 이번 결론 |
|---|---|---|
| Git·현재 Mac OS·Docker identity·이미지 | VERIFIED | 로컬 현재값을 확보한 결과이다. |
| 기존 산출물·운영 파일 보존 | VERIFIED | 기존 27개 해시 일치와 tracked 변경 없음을 확인한 결과이다. 이 보고서만 신규 작성한 범위이다. |
| 현재 Mac AIOps 가동 여부 | VERIFIED | 조사 시 Leafy 컨테이너 running 0개, API/TCP 연결 거부인 결과이다. |
| 현재 Mac의 현행 통합 구성 일치 | VERIFIED | 이미지·subnet·driver 옵션·수집 mount가 현행 repo와 다른 차이를 확보한 결과이다. |
| PC 1/PC 2 실제 서비스·주소·연결 | UNVERIFIED | 역할만 사용자에게 확인하였고 실제 접속/실행 증거는 없는 상태이다. |
| Loki 실제 로그/라벨·Prometheus 실제 metric/targets | BLOCKED(현재 Mac), UNVERIFIED(PC 간) | VERIFIED 탐지 입력은 0개인 상태이다. |
| GC PG17/Fluent Bit/Zeek/Enricher 실측 | UNVERIFIED | §8의 수동 출력이 필요한 상태이다. |
| 원격 M2 매핑/alias 인수 | UNVERIFIED | 실제 이름·라벨·target map을 확보한 뒤 비교할 항목이다. |
| OI-01 전체 완료 | BLOCKED | 현재 Mac 조사와 수동 절차 작성은 완료이며 실제 배포 인수는 미완료인 상태이다. |

다음 증거는 GC의 OS/서비스·앱/observer 컨테이너 metadata·jsonlog 파일/키·Tailscale/24224·24225 결과와 PC 1의 실제 배포 위치·targets·Loki schema/도착·Pipeline map인 것이다. 결과가 제공되면 실측 시각과 함께 항목별로 재판정할 사항이다. 현재 Mac의 PostgreSQL 18.3/과거 Docker 자원을 GC PG17 또는 PC 2 자원으로 대체하지 않는 기준이다.

OI-02~OI-09 구현이나 배포는 이번에 수행하지 않은 상태이다. OI-01은 **실제 로그 전달·scrape·PC 간 연결 확인 전까지 완료로 승격할 수 없는 결과**이다.
