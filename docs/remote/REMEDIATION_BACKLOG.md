# 미구현 추가 조치 16개

출처: [Notion 개선안 §7.4/7.5 토글](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85).
이는 구현 우선순위 제안이며 완료 판정이 아니다. 위험도는 현 정책의 고정값,
비용은 현재 실행기 재사용 가능성을 검토한 상대 추정(소/중/대)이다.
모두 `proposed_actions.*.executor_ready=false`로 차단된다. 위험도를 낮춰 실행 경로를 열지 않는다.

| 우선순위 | 조치 | 위험도 | 비용 | 기존 기능과의 관계 / 필요한 구현 |
|---|---|---|---|---|
| 1 | CAPTURE | low | 중 | (#51 구현) PAUSE·ISOLATE·RECREATE·ROLLBACK 정책 선행 단계로 로그·프로세스·Loki 네트워크 이벤트를 크기 제한·마스킹해 state `captures/`에 0600 저장(기본 14일). LLM 이 고르는 조치로는 여전히 차단 |
| 1 | RECORD_INCIDENT | low | 소 | JSON 감사 레코드·Loki 기록 있음. GitHub 사건 생성·중복 키·민감정보 제거·실패 복구 없음 |
| 1 | SILENCE_ALERT | high | 중 | Pipeline 분석 중복 제거와 다름. Alertmanager 범위·만료·해제 검증 없음 |
| 2 | BACKUP_DB | medium | 중 | 배포 전 기존 백업 파일 해시/목록 검사는 있음. 직접 백업 생성·복원 가능성 검증 없음 |
| 2 | SET_LOG_LEVEL | low | 중 | 관측 로그 조회와 다름. 실제 로그 레벨 관리자 API, 기존 값 보존·TTL 원복 없음 |
| 2 | RATE_LIMIT | medium | 중 | CPU THROTTLE과 다름. Nginx 요청 제한 설정·검사·원복 없음 |
| 2 | BLOCK_PATH | medium | 중 | 전체 컨테이너 ISOLATE과 다름. 경로별 Nginx 설정·검사·원복 없음 |
| 2 | BLOCK_EGRESS | high | 대 | ISOLATE는 네트워크 전체 분리. 목적지/CIDR별 차단·관리 통신 보존·복구 없음 |
| 2 | MAINTENANCE_MODE | high | 중 | 앱 기능 차단과 다름. Nginx 유지보수 라우팅·접근 검증·원복 없음 |
| 3 | PACKET_CAPTURE | medium | 대 | 연결 스냅샷은 패킷 캡처가 아님. 대상·시간·크기 한도, 개인정보 통제·증거 보관 없음 |
| 3 | DISABLE_DB_ROLE | high | 중 | 앱 LOCK_ACCOUNT/JWT 회수와 다름. DB NOLOGIN·현재 세션 처리·명시 복구 없음 |
| 3 | RESTRICT_BUCKET | medium | 중 | MinIO 컨테이너 격리와 다름. 버킷 정책 백업·조건부 변경·원복 없음 |
| 3 | DISABLE_KEY | high | 중 | 앱 세션 회수와 다름. MinIO 키 식별·비활성화·별도 재승인 복구 없음 |
| 3 | RESTART_HOST_SVC | high | 대 | Docker RESTART로 Host 서비스를 조작하지 않음. 별도 Host 인증 실행 경계·서비스 허용 목록 없음 |
| 4 | RESTORE_DB | high | 대 | 배포 ROLLBACK은 DB 복원이 아님. 격리 복원 검증·복원 지점·쓰기 차단·데이터 손실 승인 없음 |
| 4 | CLEAN_DISK | high | 대 | 보존한 이전 컨테이너를 자동 삭제하지 않음. 경로/파일 타입 허용 목록·열린 파일 확인·삭제 전 검토 없음 |

별도 기존 미지원 `SCALE`도 실행기는 없다(위 16개에 합산하지 않음).
`REVOKE_SESSION`에는 과거 JWT를 되살리는 역조치가 없다. 새 로그인으로만 새 세션을 발급한다.

권장 순서: 먼저 제한된 읽기 전용 CAPTURE와 사건 기록, 다음 명시 계약이 있는 소규모
관측·트래픽 제어를 검토한다. DB 복원·디스크 삭제는 복구 리허설과 별도 승인 설계가
완료되기 전까지 구현/운영 활성화 우선순위를 올리지 않는다. 이번 테스트에서 실행하지 않았다.
