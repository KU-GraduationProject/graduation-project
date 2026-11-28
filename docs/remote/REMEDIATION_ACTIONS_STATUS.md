# Remediation 조치 확장과 배포 인수 (#88)

기준 문서: [remediation 모듈 수정방안](https://app.notion.com/p/406e7f8a345d8023b958f20a35bc70e6).
이 변경은 새 실행기와 기존 Controller·Slack·Agent·영속 기록을 연결한다.
`executor_ready=true`는 코드상 어댑터가 있다는 뜻이며, 실제 환경의 권한·도구·API 계약·복구 검증을
통과했다는 뜻이 아니다. 기본 실행 모드 disabled, private 설정 enabled=false를 유지한다.

## 요청과 승인

새 조치는 기존 signed `POST /action`의 `propose_manual_action` 또는 `propose_plan`을 사용한다.
`force_manual=true`, 분석 근거·신뢰도, 원래 경보 fingerprint/startsAt, 정확한
site/source/service/runtime/target을 가진 plan이 필요하다. Controller는 설정·현재 상태를 읽어
실행 계획을 영속 저장하고 Slack 승인을 요청한다. 승인 뒤 계획/정책/자원/시각을 다시 검사한다.
현재 새 조치는 모두 수동 승인 전용이며 기존 CPU THROTTLE 자동 opt-in 동작은 바꾸지 않는다.

LLM 프롬프트·출력 스키마는 담당 팀원 소관으로 변경하지 않았다. 이 때문에 새 action_type을
현재 LLM이 자동으로 출력한다고 주장하지 않는다. Pipeline 테스트만 새 Controller 전용 조치와
LLM 어휘의 분리 계약에 맞췄으며, 새 조치가 LLM enum에 섞이지 않는지도 검사한다.
문서의 정책 자동 조사 트리거까지 자동 활성화한 것은 아니다.

복구는 signed `POST /recovery/request`의 `operation=request_recovery`, 검증된 원조치
remediation_id, 명시적 reason으로 요청한다. Controller가 원조치에서 대상과 parent_id를 도출하며
별도 Slack 복구 승인을 받는다. 일반 제안에 UNBLOCK_EGRESS·RESTORE_NGINX 등을 넣어
복구를 가장할 수 없다. 로그 레벨의 TTL은 실행기 자체 영속 lease와 CAS로 자동 원복한다.

## 지원 범위

| 영역 | 구현 |
|---|---|
| 메모리 THROTTLE | `{resource: memory}`로 CPU와 구분. 승인 binding의 `memory_limit_bytes`, 원래 MemorySwap, 현재 사용량 여유를 검사. CPU 변경 없음. 원조치 값 소유권을 확인한 뒤 기존 TTL로 원복 |
| BLOCK_EGRESS | 현재 경보의 목적지 tuple·fingerprint와 승인 계획 일치, 현재 공유 allowlist 확인, 고정 컨테이너 namespace의 owned rule만 추가·별도 승인 해제 |
| DB 관리 | 검증 manifest 기반 격리 복원·별도 승인 서비스 DB 전환·원본 보존·승인 rollback, 일반 로그인 전용 역할 NOLOGIN 및 승인 LOGIN 복구. [DB 관리](DATABASE_ADMIN.md)·[서비스 전환](DATABASE_PROMOTION.md) |
| 로그·캡처 | 조건부 버전 관리자 API로 로그 상세도 변경·영속 TTL 원복, 크기·시간·패킷수 제한 pcap, 정확한 대상의 기간제 silence·소유한 silence 해제 |
| nginx | 관리 전용 include의 경로 차단·요청률 제한·점검 전환. 고정 컨테이너에서 설정 검사·reload·재조회. 원래 snippet 승인 복구 |
| MinIO | anonymous bucket 접근 제거·승인 복구, 허용된 non-root 서비스 계정 비활성화·승인 복구 |
| 호스트 | native Windows의 명시된 PostgreSQL 서비스 재시작, 명시한 오래된 닫힌 로그만 삭제 |
| 사건 기록 | private token 참조·허용 GitHub 저장소·정확한 사건 키로 중복 확인/기록/재조회 |

비공개 설정 예제는 `aiops/policy/remediation_*example.yml`에 있다. 예제를 그대로 실행하지 말고
실제 대상·권한·도구 hash를 확인해 저장소 밖에서 작성한다. 요청에는 명령·접속 주소·SQL·
파일 경로·이미지·인증정보를 받지 않는다. 원문 로그·pcap·비밀값은 감사 이벤트에 넣지 않는다.

## 원격 Agent

Controller가 extended 모드에서 원격 Docker를 선택한 경우 컨테이너 관리 조치는 동일 Agent로
보낸다. `REMEDIATION_REMOTE_MANAGED_ENABLED=true`가 명시적으로 필요하며 양쪽 target binding의
허용 action 목록도 맞아야 한다. 꺼져 있어도 PC1 로컬 Docker로 fallback하지 않는다.

새 endpoint는 `/v1/managed/plans`, `/v1/managed/executions`다. 기존 HMAC의 method/path/body,
nonce 영속 검사, exact Agent·컨테이너 ID·image·labels, 수동 승인, portable plan digest,
SQLite claim/ledger가 적용된다. 응답 유실은 동일 명령을 재전송하지 않고 ledger GET으로 확인한다.
알려진 거부는 BLOCKED, dispatch 이후 결과가 불확실하면 UNKNOWN이다. UNKNOWN을 임의 성공이나
자동 재시도로 바꾸지 않는다. native adapter도 첫 변경 전에 별도 영속 journal을 남긴다.

`deploy/aiops-pc/remediation-managed.example.yml`,
`deploy/leafy-pc/remediation-agent/compose.managed.example.yml`은 필요한 read-only 설정과
private artifact mount 예제다. 이 override만으로 실행 모드·승인·허용 목록은 켜지지 않는다.
패킷 캡처는 helper와 Agent가 공유하는 **전용 named volume**이 필요하다. 컨테이너 안의 경로를
Docker 호스트의 같은 경로로 오인하지 않는다. helper에는 Agent secret/state 전체를 공유하지 않는다.

Windows PostgreSQL 서비스 재시작·호스트 로그 삭제는 Windows-native 실행 경계 전용이다.
Linux Docker Agent가 Windows SCM을 제어한다고 가정하지 않는다. 호스트용 실행 위치/계정을
별도로 설치·검증해야 하며 현재 split 구성에 자동으로 설치되지 않는다.

## 고정 IP와 평가 누출 방지

공격 목적지 IP를 코드에 고정하지 않는다. BLOCK_EGRESS는 실제 signed alert의 관측값만 받고
현재 정책에 허용된 endpoint/service·관리 subnet·자기 IP/gateway를 거부한다. 승인이 끝났더라도
정책·주소·namespace가 달라졌으면 새 승인이 필요하다. 평가에서는 주소를 회전시킬 수 있다.

```sh
python tools/rulepack/prepare_release.py \
  --profile /absolute/private/inventory.json \
  --scenario-profile /absolute/private/scenario-v2.json \
  --allowlist /absolute/private/current-allowlist.yml \
  --output /absolute/new-review-bundle
```

생성 bundle의 allowlist.yml은 Pipeline에 같은 경로로 mount된다. Agent의 egress private
`policy_file`도 같은 실행의 정책을 사용해야 한다. 한쪽만 목적지를 바꾸면 정책 불일치이며
그 결과를 LLM의 일반화 성능으로 해석하면 안 된다. 시나리오 이름·정답 attack/benign 표시는
실행기/LLM 입력에 추가하지 않는다. 임계값은 별도 정상 데이터로 평가·동결해야 한다.

## 실제 인수 조건과 제한

- DB isolated restore만으로 서비스 DB가 복구됐다고 표시하지 않는다. PROMOTE_RESTORED_DB가 같은 클러스터에서 원본을 보존하는 별도 승인 전환을 제공한다. 앱 health·업무 데이터 정합성은 별도 검증이다.
- MinIO anonymous 차단은 인증된 앱 계정 전체의 읽기전용 전환과 다르다. 앱 전용 계정 분리가 선행돼야 한다.
- 로그 레벨은 ETag/If-Match 관리자 API 계약이 필요하다. plain Actuator에는 이 계약이 없어 해당 경로는 차단된다.
- PACKET_CAPTURE는 `Dockerfile.capture-helper`, egress는 `Dockerfile.egress-helper`를 검토·사전 빌드한 로컬 image ID가 필요하다. 자동 pull/build하지 않는다.
- nginx는 managed include 설치와 동일 파일 bind mapping이 필요하다. RATE_LIMIT zone은 URI/토큰 단위이며 NAT IP를 정답으로 쓰지 않는다.
- 방화벽 rule 존재, 설정 reload, DB 객체 복원은 서비스 정상 복구와 별도로 기록한다. 실제 정상 트래픽·상대 목적지 차단·서비스 SLO는 실측해야 한다.
- 파일 삭제는 논리 파일/byte 제거만 확인한다. 실제 디스크 여유 증가를 확인했다고 주장하지 않는다.
- 새 조치의 사람 제안 경로와 문서의 자동 조사 트리거 연결을 구분한다. 영구 계정 잠금은 기존 시간제 잠금의 범위를 확대하지 않았다.

검증은 모의 HTTP/Docker/DB/방화벽·임시 파일과 실제 서명/SQLite/Controller/Agent 상태 전이를
사용한다. 실제 운영 자원·비밀값·Slack 메시지·패킷·DB 변경은 사용하지 않는다.

참고: [Docker 네트워크](https://docs.docker.com/engine/network/),
[Docker 실행·capabilities](https://docs.docker.com/engine/containers/run/).
