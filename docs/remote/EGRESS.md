# BLOCK_EGRESS와 승인 해제

`executor/egress.py`는 현재 사건에서 관측된 **목적지 IPv4·포트·TCP/UDP 한 조합**만
지정 컨테이너의 OUTPUT에서 차단한다. 코드나 설정 예제에 비인가 IP를 박아 두지 않는다.
정상/공격 판정은 현재 목적지 허용 정책과 사건 관측에 의해 결정되며, IP 자체가 정답이 아니다.
시나리오 ID·attack/benign 레이블·고정 C2 주소는 실행기에 전달하지 않는다.

## 계약

- `BLOCK_EGRESS` 파라미터: `destination_ip`, `destination_port`, `protocol`, `flow_id`.
  `flow_id`는 Zeek 연결 ID를 임의로 고르는 값이 아니라 해당 경보의 fingerprint다.
  Controller는 IP/port/protocol이 signed alert의 관측 labels와 동일한지 검사한다.
- `UNBLOCK_EGRESS` 파라미터: `parent_id`. Controller가 VERIFIED 원래 조치에서 도출한 ID만
  허용한다. 별도 승인과 same-target 검증이 필요하며 독립적인 일반 제안으로 해제할 수 없다.
- 계획에는 exact container ID·image ID·StartedAt·network ID·현재 IP/gateway,
  private config hash·현재 allowlist hash·해당 tuple·owned-rule tag가 동결된다.
- 승인 후 실행 직전에 정책과 namespace를 다시 읽는다. helper 생성이 지연되는 경우에도
  helper.start 직전에 승인 만료·컨테이너 identity를 한 번 더 검사한다.
- `enabled=false`, config 미설정, helper image 미설치, 관측 tuple 불일치, namespace/정책 변경은
  fail closed다. 실제 차단을 하려면 운영자가 private inventory를 설치하고 명시적으로 켜야 한다.

`REMEDIATION_EGRESS_CONFIG_PATH`가 가리키는 파일의 예제는
`aiops/policy/remediation_egress.example.yml`이다. `policy_file`은 현재 실행의 공유 허용 정책이다.
목적지를 회전시키는 평가에서는 룰 생성·Pipeline 정책 해석·egress 실행기가 **같은 현재 정책**을
읽도록 준비해야 한다. 한쪽만 주소를 바꾸면 정책 불일치이며 LLM 성능 검증으로 해석하면 안 된다.

## 커널 실행 범위

이미 로컬에 존재하는 digest-pinned helper image에서 `/sbin/iptables`를 실행한다.
이미지를 pull/build하거나 사용자 명령을 실행하지 않는다. helper는 exact target ID의 network
namespace를 공유하고 `cap_drop=ALL`, `cap_add=NET_ADMIN`, read-only rootfs, no-new-privileges,
명시 자원 상한을 사용한다. host network/PID·privileged·Docker socket mount는 사용하지 않는다.
`/run`에는 dedicated `leafy-egress-locks` volume을 공유해 helper들 간 xtables lock을 사용한다.

helper image는 운영자가 검토한 Dockerfile로 사전에 빌드하고 실제 image ID를 고정해야 한다.
예시 구조는 Linux 최소 이미지에 iptables만 설치하고 `/sbin/iptables`를 제공하는 것이다.
특정 배포판 tag만으로 검증 완료로 간주하지 말고 image digest와 netfilter backend 호환성을 인수한다.
Docker Desktop에서는 **Linux VM 안의 대상 컨테이너 namespace**를 조작한다.
Windows 호스트 방화벽·공유 브리지 전체·다른 컨테이너의 네트워크를 변경하지 않는다.
IPv6·CIDR 범위 차단·도메인 해석·프로세스별 차단은 이 버전 범위 밖이다.

실행은 fixed argv로 `-S OUTPUT` 확인, exact spec `-C`, 첫 위치 `-I` 또는 owned rule `-D`,
다시 `-C` 확인 순서다. Allowlist의 endpoint 또는 동적으로 inspect한 정상 service IP를 거부한다.
현재 자기 IP·gateway·management network subnet·loopback/link-local/multicast/unspecified 주소도 보호한다.
다른 규칙을 flush하거나 순서를 재배열하지 않으며, 예상치 못한 기존 동일 tag를 자기 것으로 채택하지 않는다.

## 복구·멱등성

Controller/Agent claim 외에 SQLite 일회성 실행 journal과 검증된 block plan을 보존한다.
승인받은 동일 ID·동일 내용의 재전송에는 저장 결과를 돌려주고 iptables를 재실행하지 않는다.
동일 ID의 다른 내용은 거부하며 원래 저장 결과를 덮어쓰지 않는다.
응답 유실·부분 실행은 UNKNOWN이며 자동 재시도·자동 해제를 하지 않는다.
원래 block이 verified이고 container/network snapshot이 그대로일 때만 해당 tag를 지울 수 있다.
TTL이 끝났다는 이유로 공격 목적지 연결을 자동 재개하지 않는다.

SUCCESS는 **정확한 방화벽 rule의 존재/제거를 재조회한 결과**다. 실제 외부 트래픽 차단·정상
DB 통신 유지·애플리케이션 복구를 자동으로 증명하지 않으며 결과의
`network_connectivity_verified`는 false로 남긴다. 실제 flow probe·Zeek 재관측·서비스 SLO는 별도 인수다.

## 검증

`tests/test_egress.py` 10개는 FakeDocker와 fake helper만 사용한다. 실제 Docker daemon·iptables를
호출하지 않는다. 서로 다른 TEST-NET 주소로 목적지를 바꿔도 같은 정책/관측 계약으로 작동함,
정상 endpoint/service/management·자기 IP/gateway 보호, 교체된 대상·변경 정책·만료 승인 거부,
helper 생성 중 승인 만료, 원래 rule 소유권, 차단·별도 해제, UNKNOWN no-retry를 검증한다.
이 검사는 Linux 커널이나 Docker Desktop의 native netfilter 검증이 아니다.

실환경에서는 별도의 승인된 테스트 namespace에서 임의 시험 목적지 2개를 회전시키고,
인가 목적지와 DB·MinIO·관리 통신 유지, 비인가 tuple 차단, Slack 승인 해제 후 재개,
helper/Controller 장애 시 UNKNOWN 보존과 중복 실행 0회를 확인해야 한다.

참고: [Docker run의 namespace·capability](https://docs.docker.com/engine/containers/run/),
[iptables upstream manual](https://git.netfilter.org/iptables/tree/iptables/iptables.8.in).
