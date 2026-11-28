# 관측 조치: 로그 TTL·패킷 캡처·경보 억제

`ObservabilityExecutor`는 기존 signed proposal·영속 계획·Slack 승인 흐름 뒤에서만
동작한다. `REMEDIATION_OBSERVABILITY_CONFIG_PATH`의 private 운영자 파일을 읽고,
기본은 미설정/비활성이다. 예제는 `aiops/policy/remediation_observability.example.yml`이다.
주소·로그인 비밀값은 요청/LLM에서 받지 않는다. 토큰은 지정 환경변수 참조로만 읽는다.

## 계약

- `SET_LOG_LEVEL`: `{logger, level, duration_seconds}`. 운영자 allowed_loggers 목록에서만
  TRACE/DEBUG/INFO/WARN/ERROR/OFF를 선택한다. duration은 1~3600초다.
- `RESTORE_LOG_LEVEL`: `{source_record_id}`. 검증된 원조치의 영속 lease에서만 원래 레벨을 읽는다.
- `PACKET_CAPTURE`: `{duration_seconds, packet_limit, snaplen}`. 각각 최대 60초/10000개/512바이트,
  snaplen은 최소 64다. `(snaplen+16)*packet_limit+24`가 운영자 max_bytes 이하여야 한다.
- `SILENCE_ALERT`: `{alertname,duration_seconds}`. 지정 Alertmanager에 정확한 alertname과
  site/source/service/runtime/target를 모두 일치시키는 비정규식 matcher를 생성한다.
- `EXPIRE_SILENCE`: `{source_record_id}`. 원조치가 만든 silence ID와 matcher/comment를 확인하고
  해당 silence만 만료시킨다. 기존 운영자 silence를 수정하거나 삭제하지 않는다.

## 로그 TTL

Logger API는 HTTPS `/actuator/loggers/{allowed logger}` GET/POST 계약이며,
GET에 `ETag`, POST에 강제 `If-Match`를 구현한 관리자 gateway가 필요하다.
**기본 Spring Boot Actuator만으로 이 조건부 갱신 계약을 보장하지 않는다.**
`conditional_updates_verified=true`는 실제 서버가 stale If-Match에 412를 반환하는지
검증한 뒤 설정한다. 버전 없는 API에는 실행하지 않는다.

SQLite의 FULL 동기 lease를 POST 이전에 저장한다. 동일 사건 중복은 다시 쓰지 않고,
미해결 lease가 있으면 같은 대상/logger의 새 조치를 막는다. 적용 후 configuredLevel과
새 ETag를 확인한다. `run_due(store=None)`는 TTL 만료 lease를 복구하며 안전한 감사 이벤트
목록을 반환한다. Controller 스캐너와 Agent 스캐너가 이 hook을 정기 호출해야 한다.

TTL 복구 시 현재 레벨과 ETag가 원조치의 적용 결과와 모두 같아야 한다.
운영자가 중간에 값을 바꾸거나 API/정책이 바뀌면 덮어쓰지 않고 NEEDS_REVIEW로 남긴다.
복구 중 프로세스가 죽으면 RESTORING/UNKNOWN을 자동 재시도하지 않는다. 상태 디렉터리는
영속 볼륨으로 유지하고 변경·삭제 전 남은 TTL lease를 수동 확인해야 한다.

## 패킷 캡처

검증한 전체 컨테이너 ID·이미지·라벨·시작 시각과 로컬에 이미 설치한 helper 이미지 ID를
승인 계획에 고정한다. helper를 pull하거나 host 네트워크에서 실행하지 않는다.
Docker Desktop에서도 Linux 컨테이너 namespace를 공유하는 helper를 사용한다.
네트워크 모드는 `container:<full-id>`, cap_drop=ALL/cap_add=NET_RAW, rootfs 읽기 전용,
no-new-privileges, pids/memory 한도를 사용한다. `tcpdump -p -nn -i any`와 고정 argv만 쓰며
LLM의 필터·명령 문자열은 받지 않는다. helper 이미지에는 timeout과 tcpdump가 있어야 한다.

원본 패킷은 private state의 captures/난수ID/traffic.pcap에 0600, 상위 디렉터리 0700으로
남긴다. 감사 이벤트는 artifact ID·크기·해시만 포함한다. pcap magic·최종 파일 크기를 확인하며
단일/총 보관 용량을 모두 제한한다. 총량이 차면 새 캡처를 거부한다. 운영자는 공개 저장소에
업로드하지 말고 조사 종료 뒤 조직의 보존 정책대로 private artifact를 정리해야 한다.
캡처 시간 종료는 비파괴 관측 종료이므로 역조치는 없다.

## 메모리 THROTTLE

`executor/memory_limit.py`의 두 helper를 기존 CPU 경로와 구분해 호출한다.
`apply_memory_limit(executor,target,evidence,limit)`에서 limit은 운영자 설정이며 LLM 값이 아니다.
기존 유한 메모리 한도를 줄이되 현재 전체 사용량보다 max(32MiB,25%) 이상 여유가 있어야 한다.
원래 MemorySwap=0(미지정)은 복원 의미가 모호하므로 거부한다. MemorySwap을 명시한 환경만
지원한다. 적용은 mem_limit=memswap_limit로 swap 확장을 막으며 CPU 값은 바꾸지 않는다.

실제 Controller의 불변 target binding `container.memory_limit_bytes`에 운영자 한도를 넣어
승인 전에 고정한다. 이 필드가 없으면 bound 메모리 조치는 거부한다. Agent도 검증된 Target의
같은 필드를 사용한다. `REMEDIATION_MEMORY_LIMIT_BYTES`는 직접 생성한 로컬 실행기의
기본 설정만 정하며, 승인된 binding 값을 덮어쓸 수 없다.

snapshot.resources에는 `memory`와 `memory_swap`가 있어야 하고, 결과 after의
`applied_memory`/`applied_memory_swap`를 `evidence.memory_throttle`에 영속 저장해야 한다.
`restore_memory_limit`는 현재 한도가 원조치 값과 같은지 먼저 확인한다. 운영자가 변경했다면
자동으로 원래 값을 덮어쓰지 않는다. 기존 TTL 스캐너와 원격 Agent도 이 구분을 보존해야 한다.

## 검증 범위

테스트는 fake HTTP/Docker·임시 private 상태만 사용한다. 실제 API 토큰·로그·네트워크 패킷·
서비스 변경은 사용하지 않는다. 실제 조건부 API, helper 실행·pcap, TLS/권한, TTL 스캐너 연결은
검증 환경에서 별도로 인수해야 한다.

### Docker로 실행하는 Controller/Agent의 캡처 출력

Docker socket을 쓰는 컨테이너 안의 `/app/state`는 Docker 호스트의 같은 경로가 아니다.
`deploy/leafy-pc/remediation-agent/compose.managed.example.yml`처럼 캡처 전용 named volume을
`state_dir/captures`에 마운트하고, `packet_capture.artifact_volume`에 실제 volume 이름을 지정한다.
helper에는 그 캡처 volume만 `/capture`로 붙이며 `/capture/<artifact-id>/traffic.pcap`에 쓴다.
Agent 전체 state나 secret volume을 공유하지 않는다. 이름 없는 host-path 방식은 실행 프로세스와
Docker daemon이 같은 파일시스템 경로를 보는 native 환경에서만 사용한다.
`Dockerfile.capture-helper`를 검토·사전 빌드한 실제 image ID를 private config에 고정한다.
