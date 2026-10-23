-- 팀원 PC PostgreSQL 17: jsonlog 출력 설정 (superuser로 psql에서 실행)
--   psql -U postgres -f postgresql-logging.sql
-- ALTER SYSTEM은 postgresql.auto.conf에 기록한다. 되돌리기: ALTER SYSTEM RESET <name>; 후 reload/restart.
-- 적용 전 현재 값 기록:  SHOW logging_collector; SHOW log_destination; SHOW log_directory; SHOW log_filename;

-- jsonlog는 logging_collector가 켜져 있어야 파일로 남는다. Windows 설치본 기본값은 on이다.
-- off였다면 이 항목만은 PostgreSQL 서비스 재시작이 필요하다.
ALTER SYSTEM SET logging_collector = on;

-- 기존 텍스트 로그(.log)는 사람이 보던 그대로 유지하고 .json을 추가한다.
-- log_filename이 .log로 끝나면 jsonlog 파일은 같은 이름에 .json 확장자로 만들어진다.
ALTER SYSTEM SET log_destination = 'stderr,jsonlog';

-- 날짜·시각이 들어간 이름으로 새 파일을 만들며 로테이션한다 (같은 파일을 비우고 재사용하지 않는다).
-- Fluent Bit은 *.json을 찾아 파일마다 읽은 위치를 기록하므로 덮어쓰기 방식보다 안전하다.
-- 오래된 파일 삭제는 PostgreSQL이 하지 않는다. README의 정리 작업을 참고한다.
ALTER SYSTEM SET log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log';
ALTER SYSTEM SET log_rotation_age = '1d';
ALTER SYSTEM SET log_rotation_size = '100MB';
ALTER SYSTEM SET log_truncate_on_rotation = off;

-- jsonlog의 timestamp는 "2026-10-23 14:01:02.123 KST"처럼 이 timezone의 약어로 찍힌다.
-- 중앙 Fluentd는 KST/UTC/GMT와 숫자 offset만 해석한다. 다른 timezone이면 수신 시각으로 저장되고 log_time_parse_error가 붙는다.
ALTER SYSTEM SET log_timezone = 'Asia/Seoul';

-- 기존 컨테이너 DB(docker-compose.yml의 db)와 같은 탐지 근거를 남긴다.
-- 인증 실패(FATAL 28P01)는 이 설정과 무관하게 기록된다 (UnauthorizedDBAccess 규칙의 근거).
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
-- 200ms 이상 걸린 SQL을 기록한다. statement 원문(파라미터 포함)이 AIOps PC로 전송된다는 점에 유의한다.
ALTER SYSTEM SET log_min_duration_statement = 200;

SELECT pg_reload_conf();

-- 확인: logging_collector가 pending_restart이면 서비스를 재시작해야 한다.
SELECT name, setting, pending_restart
  FROM pg_settings
 WHERE name IN ('logging_collector', 'log_destination', 'log_directory', 'log_filename',
                'log_rotation_age', 'log_rotation_size', 'log_truncate_on_rotation', 'log_timezone',
                'log_connections', 'log_disconnections', 'log_min_duration_statement');
