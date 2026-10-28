# Phase 2.1 안전 기반 재구성 (2026-10-29)

시작 HEAD는 `0ed75b907121f58612f80fcaa25a2f1a6caa34de`였다. 작업 트리는 깨끗했고,
`feature/s2_scenario`는 실제 원격 HEAD `831dfd58be23e599602f9bbd3da19f6b9b749e9d`보다
3개 커밋 앞섰다. 전달된 Phase 2.1 커밋은 이 체크아웃에 없었다.

확인된 결함: 기본 docker 모드, 전역 테스트 IO 차단 부재, 시작 시에만 NIC 탐지,
복구 선점 부재, 손상 저장소를 빈 상태로 덮을 가능성, 중단된 실행의 재조정 부재,
TTL 복구 승인 버튼 부재. 이 선행 커밋은 해당 부분을 보완하며 기존 커밋은 재작성하지 않는다.

- 기본 disabled. 기존 local docker 명시 모드는 유지한다.
- `testing/run_isolated.py`가 테스트 import 전에 Docker 생성자·socket·DNS·subprocess·pipe를 차단한다.
  Windows asyncio 내부 socketpair 및 network 테스트가 직접 만든 임시 loopback HTTP 포트만 예외다.
  실제 컨테이너/Slack/PC 2에는 연결하지 않는다. 무방비한 unittest 직접 실행은 사용하지 않는다.
- 상태 파일 fsync, 저장 실패 실행 거부, 손상 파일 덮어쓰기 금지.
- 복구 선점으로 중복 복구 차단, disabled는 대기 레코드를 소비하지 않는다.
- 재시작 시 EXECUTING/RECOVERING/실패 후 증거 보유 레코드는 NEEDS_REVIEW로 남긴다.
  자동 재실행하지 않는다. 기존 VERIFIED 복구 일정 누락은 복구 승인 대기로 전환한다.
- 복구 버튼은 원 레코드 조치·대상·상태와 일치해야 한다.
- Zeek는 업무 /24 subnet route와 ifindex를 주기적으로 검사한다. NIC 소실 때 관측 이름을 지우고,
  재연결 때 새 NIC로 다시 기동한다. backend 컨테이너 자체 교체에 따른 netns 변경은 운영자가
  observer 컨테이너를 재생성해야 한다. NIC 재연결만으로 이 netns 문제까지 해결되지는 않는다.

검증: 기존 remediation 195개를 격리 실행해 통과한 뒤 보완 테스트 포함 201개 통과.
pipeline 98개, network 100개, observer 12개 회귀 검증. Zeek shell fixture는 실제 Zeek 대신
임시 스텁을 사용하며 subnet 소실·새 NIC·같은 이름의 ifindex 변경을 검증한다.

이 기반은 원격 운영 검증 완료를 뜻하지 않는다. 실제 활성화는 Phase 4로 남긴다.
