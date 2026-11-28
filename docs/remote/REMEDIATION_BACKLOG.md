# 추가 조치 구현 현황 (#88)

원래 후보 16개 중 CAPTURE·BACKUP_DB는 기존 정책 선행 단계로 구현돼 있었고,
나머지 14개에는 이번에 운영자 설정·불변 계획·승인·사후 확인을 갖춘 실행기를 추가했다.
단순히 executor_ready만 바꾼 것이 아니다. 기본 REMEDIATION_MODE=disabled,
각 private 설정 enabled=false이며 실제 서비스 변경은 별도 배포 인수가 필요하다.

| 조치 | 구현 범위와 남은 조건 |
|---|---|
| CAPTURE | 기존 실행 전 로그·프로세스·네트워크 증거 보존. 독립 LLM 조치가 아님 |
| BACKUP_DB | 기존 pg_dump 및 manifest 검증 선행 단계. 독립 LLM 조치가 아님 |
| BLOCK_EGRESS | 관측된 현재 IPv4·포트·TCP/UDP tuple만 정확한 컨테이너 namespace에서 차단, 별도 승인 해제 |
| RESTORE_DB | 검증한 백업을 격리된 빈 restore_* DB로 복원. 별도 PROMOTE_RESTORED_DB 승인으로 같은 클러스터의 서비스 DB 이름으로 전환·원본 보존·승인 rollback 지원 |
| DISABLE_DB_ROLE | 허용된 비관리·비소유 로그인 전용 역할 NOLOGIN, 원조치 승인 복구. 기존 세션 종료는 별도 |
| SET_LOG_LEVEL | ETag/If-Match 조건부 관리자 API 변경·영속 TTL 원복. 해당 API 계약이 필요하며 plain Actuator는 미지원 |
| PACKET_CAPTURE | 검증된 컨테이너 netns에서 시간·패킷수·크기 제한, private pcap. 로컬에 고정한 helper image 필요 |
| SILENCE_ALERT | 정확한 사건 대상 identity·경보에 한정한 기간제 Alertmanager silence와 소유한 silence만 조기 해제 |
| BLOCK_PATH / RATE_LIMIT / MAINTENANCE_MODE | frontend의 관리 전용 nginx include 변경, nginx -t/-T/reload와 이전 설정 승인 복구 |
| RESTRICT_BUCKET | MinIO 버킷 anonymous 접근 제거 및 원래 정책 승인 복구. 앱 전용 계정 권한 전체의 읽기전용 전환은 범위 밖 |
| DISABLE_KEY | 허용된 non-root 서비스 계정 키 비활성화, 원조치 승인 재활성화. 루트 키 금지 |
| RESTART_HOST_SVC | Windows-native 실행 경계에서 고정한 PostgreSQL 서비스만 재시작. Linux Docker Agent로 Windows 호스트를 제어하지 않음 |
| CLEAN_DISK | 정확히 허용된 오래된 닫힌 .log 파일만 삭제. 경로/링크/열린 파일/해시 검증, DB 볼륨·임의 이미지 삭제 금지 |
| RECORD_INCIDENT | 지정 GitHub 저장소에 사건 키로 중복 확인·기록·재조회. 외부 쓰기 opt-in과 별도 승인 필요 |

메모리 THROTTLE도 기존 CPU 경로와 구분해 추가했다. 승인한 binding의 운영자 한도만 사용하고
실사용량 여유·원래 MemorySwap·CPU 값 보존을 검증한다. 기존 TTL로 원래 한도를 복구하며,
운영자가 중간에 바꾼 한도를 덮어쓰지 않는다.

새 관리 조치는 현재 모두 signed 계획과 수동 승인을 요구한다. 문서의 자동 조사 트리거까지
자동으로 활성화한 것은 아니다. SET_LOG_LEVEL의 TTL 원복과 memory THROTTLE의 기존 TTL은
실행 뒤 자동으로 동작한다. Pipeline의 LLM 프롬프트·출력 스키마는 팀원 소관으로 유지하므로
새 action_type은 현재 사람이 제출하는 기존 signed manual proposal 경로로 요청한다.

상세 문서: [전체 연결](REMEDIATION_ACTIONS_STATUS.md), [목적지 차단](EGRESS.md),
[DB 관리](DATABASE_ADMIN.md), [DB 서비스 전환·원복](DATABASE_PROMOTION.md), [관측·메모리](OBSERVABILITY_ACTIONS.md),
[nginx·MinIO·호스트](EDGE_STORAGE_HOST_ACTIONS.md).

별도 SCALE 실행기는 여전히 미구현이다. REVOKE_SESSION은 기존 구현이며 토큰을 부활시키는 역조치는 없다.
