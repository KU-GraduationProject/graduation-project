# Phase 3 검증 기록 — 2026-10-29

브랜치: `feature/s2_scenario`. 시작 HEAD `0ed75b9`, 선행 안전 기반 `b640060`.
최종 Phase 3 커밋은 `git log -1 --format='%H %s'`로 확인한다.

## 실행 결과

| 검증 | 결과 |
| --- | --- |
| `testing/run_isolated.py remediation` | **270 tests / OK**, exit 0 |
| `testing/run_isolated.py pipeline` | **98 tests / OK**, exit 0 |
| `testing/run_isolated.py network` | **100 tests / OK**, exit 0 |
| `testing/run_isolated.py observer` | **12 tests / OK**, exit 0 |
| 합계 | **480 tests / 실패·skip 없음** |
| `testing/test_zeek_supervisor.sh` | PASS: subnet 소실, 새 NIC 재연결, 같은 이름의 ifindex 교체 |
| Remediation Python AST 파싱 | 37개 파일 PASS |
| 배포 YAML 파싱/안전 기본값 검사 | PASS |
| `git diff --check` | PASS |

Python 3.13.5, 저장소의 기존 `.venv-readme`를 사용했다. 컨테이너 이미지는 Python 3.11이며
이 작업에서는 실제 이미지 빌드/컨테이너 기동을 하지 않았다. 기존 scenario 테스트에 필요한
`rich`가 가상환경에 없어 테스트 실행 밖에서 설치했다. 애플리케이션 의존성 파일은 바꾸지 않았다.

기존 remediation 195개를 먼저 격리 환경에서 통과시켰고, Phase 2.1 보완 후 201개,
Phase 3 신규 69개를 더해 최종 270개를 통과했다. 기존 테스트는 삭제·skip하지 않았다.
기존 기대값 변경은 기본 disabled, 이제 지원되는 remote 대신 invalid-mode 오류 검증이며,
FakeNetwork에 실제 SDK처럼 network ID를 추가해 강화된 ID 검증을 수행했다.

## 요구사항 대응

| 요구사항 | 검증 근거 |
| --- | --- |
| 유효 HMAC | Agent TestClient 요청 → FakeDocker 실행·verified 확인 |
| 위조·만료·재전송 | raw body/method/path/controller/timestamp/nonce 변조, 미래/과거, 재시작 후 replay 거부 |
| Allowlist 외 대상 | 미등록·관리용·명시 등록한 관리 대상 거부, image/ID/name/label 불일치 거부 |
| 미승인 high-risk | RESTART/PAUSE/ISOLATE 및 원격 자동 THROTTLE 거부, Docker factory 0회 |
| 중복 1회 실행 | 중복 POST, 12개 동시 요청, 서로 다른 승인 요청이 같은 ID를 가리키는 경우 |
| 재시작 후 멱등성 | 같은 SQLite를 새 Ledger/Agent 인스턴스로 열어 완료·미완료 실행/복구 재실행 차단 |
| 검증 실패 성공 금지 | disconnect 미반영, reconnect IP 불일치, 교체된 network/container, 미검증 SUCCESS 응답 |
| timeout 후 조회/재시도 | 응답만 유실, 전달 전 timeout+404, 전체 단절, 동일 ID 재전송, recovery 응답 불확실성 |
| RECONNECT IP·alias | 기존 IPv4·alias 및 management network 보존/복원, network ID 교체 시 거부 |
| TTL·복구 | PC 1 없는 Agent quota/period 복원, disabled·기한 전 보존, ISOLATE/PAUSE 자동복구 0회 |
| Zeek 관측 연계 | 임시 route/ifindex shell fixture + capture-interface 소실/새 NIC 갱신 테스트 |
| Phase 0~2.1 회귀 | 전체 4개 suite 통과, 기존 HMAC·정책·LocalDockerExecutor·복구 테스트 유지 |

추가 검증: SQLite 손상, evidence 저장 실패, process lock, 미복구 대상의 새 ID 차단,
다른 remediation이 점유한 lease에 대한 오래된 복구 거부, 오래된 상태 응답의 PC 1 상태
덮어쓰기 차단, 원래 paused인 대상 인수 금지, 기존 CPU 제한을 완화하는 THROTTLE 차단,
역조치 권한이 없는 가역 조치 차단, 한 TTL 레코드 오류가 나머지 복구를 막지 않음.

## 실제 컨테이너 비조작 근거

- 테스트 import/수집 전에 `testing/run_isolated.py`가 Docker factory와 두 클라이언트 생성자를
  차단한다. `socket.connect/getaddrinfo/sendto`, subprocess, Docker socket/pipe 파일 접근에도
  Python audit hook을 적용한다. guard 자체에 대한 Docker·socket 실패 self-check 후 수집한다.
- Windows asyncio 내부 socketpair만 정확한 소켓과 임시 listener 주소로 허용한다.
  network suite의 로컬 HTTP 테스트만 테스트 프로세스가 생성한 임시 `127.0.0.1` listener에
  연결할 수 있다. 2375/2376, 기존 localhost 서비스, 실제 LAN/Tailscale 주소는 허용하지 않는다.
- Agent/Controller HTTP는 TestClient와 httpx.MockTransport로 처리한다. FakeDocker는 dict와
  호출 목록만 변경한다. 인증 실패 테스트는 Docker factory 호출 0과 mutation 0을 모두 검사한다.
- 테스트의 Slack URL은 비우고 통합 테스트의 notifier도 AsyncMock으로 대체한다. Mock 범위를
  벗어나더라도 외부 IO 차단이 남는다. 실제 PC 2 Agent URL과 운영 키를 테스트에 쓰지 않는다.
- Zeek shell 테스트는 임시 디렉터리의 fake zeek, fake route/ifindex만 사용한다.
- 이 작업에서 Docker CLI/실제 Docker SDK에 의한 컨테이너 inspect/변경, compose up/build,
  실제 Slack 전송, PC 2 접속은 실행하지 않았다.

이것은 신뢰된 테스트를 위한 **Python 프로세스 차단 장치**이며 악성 native 코드까지 봉쇄하는
OS sandbox라고 주장하지 않는다. 실제 Leafy의 전후 inspect 결과를 수집한 검증도 아니다.

## 배포 정적 검증과 미실측 항목

PyYAML로 base/live/PC 1 override/allowlist와 aiops compose를 파싱했다.
base mode=disabled, 포트 `127.0.0.1:8002:8002`, base/PC 1의 socket 미마운트,
기본 allowlist의 빈 targets를 assert했다. 실제 Compose 엔진 검증은 실행하지 않았다.

PC 2 Windows Docker Desktop 동작, Serve/ACL/방화벽 노출, 실제 Docker CPU 복원,
실제 IP·alias 및 Zeek conn.log 관측은 **Phase 4 미검증 항목**이다.
배포·키·중단·장애 처리 절차는 [Phase 3 운영 문서](PHASE3_REMOTE_AGENT.md)에 있다.
