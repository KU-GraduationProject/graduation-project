# 승인된 PostgreSQL 복원·역할 로그인 차단

`DatabaseAdminExecutor`는 `REMEDIATION_DATABASE_ADMIN_CONFIG_PATH`가 가리키는 private
운영자 설정과 원본 사건에 묶인 승인 계획을 사용한다. 기본은 미설정/비활성이며 실제 SQL·
pg_restore 실행은 발생하지 않는다. 운영자 예제는 `aiops/policy/remediation_database_admin.example.yml`이다.

## 동작과 요청

- `RESTORE_DB`: `{backup_id, confirm_database, allow_data_loss:true}`. backup_id는 설정에서
  선택한 검증 manifest 식별자다. 요청에 파일명·SQL·접속 주소·비밀번호를 받지 않는다.
- `DISABLE_DB_ROLE`: `{role_id}`. 허용된 일반 로그인 전용 역할에 `ALTER ROLE ... NOLOGIN`을 적용한다.
  기존 세션은 종료하지 않는다. 세션 종료는 별도 KILL_SESSIONS 조치다.
- `ENABLE_DB_ROLE`: `{role_id}`. 검증된 차단 조치의 같은 역할을 별도 승인으로 LOGIN 복구한다.
  Controller는 이 동작을 직접 LLM 제안으로 열지 않고 원조치 복구 요청으로 연결해야 한다.

모든 조치는 high 위험·수동 승인이다. 시스템 식별자·숫자 서버 주소/포트·DB 이름·실행 역할을
계획 전과 실행 직전에 재조회한다. 현재 노드가 standby이거나 실행 역할이 superuser,
replication, bypassrls이면 거부한다. 접속 변수는 운영자가 지정한 환경변수 참조이며,
PGPASSFILE 내용이나 libpq 오류 원문을 계획/감사/채팅에 넣지 않는다.

## 복원 범위

**현재 지원은 기존 서비스 DB를 덮어쓰는 복원이 아니라, 운영자가 분리한 빈 `restore_*`
DB에 복원하는 경로다.** 실제 서비스 DB에 바로 덮어쓰거나 `--clean`, `--create`로
운영 데이터를 지우는 경로는 구현하지 않는다. 서비스 데이터 되돌리기는 장애 격리·쓰기 중지·
검증된 전환/원복 절차와 별도 승인이 필요하다. [PROMOTE_RESTORED_DB](DATABASE_PROMOTION.md)가
같은 클러스터에서 원본을 보존하는 서비스 DB 전환과 별도 승인 rollback을 제공한다.

운영자는 목적지 DB를 미리 만들고 전용 일반 역할에 소유권을 준다. `isolated_restore=true`는
실제 네트워크/운영 격리를 확인한 운영자 선언이다. 코드가 이름만 보고 격리를 증명하지 않는다.
검증 시 DB에 다른 세션이 없고 사용자 테이블/partition/matview/foreign table이 없어야 한다.
승인 뒤 목적지 OID·owner·내용·세션 상태가 달라지면 실행하지 않는다.

백업 manifest는 다음 필드를 요구한다. 모든 경로와 내용은 private 저장소에 둔다.

```json
{
  "artifact_path": "/absolute/private/reviewed.dump",
  "format": "postgres-custom",
  "verified": true,
  "restore_list_verified": true,
  "database_id": "verified-source-database-id",
  "bytes": 12345,
  "sha256": "verified-file-sha256"
}
```

파일이 실제 PGDMP custom archive인지, 크기·SHA256이 일치하는지, `pg_restore --list`가
성공하고 일반 TABLE 항목이 있는지 재검증한다. 최소 지원 범위는 일반 테이블 archive이며,
확장 객체·materialized view·foreign table 등의 사후 관계 수가 예상과 다르면 성공으로
기록하지 않는다. 신뢰하지 않는 임의 dump를 실행하면 안 된다. manifest는 운영자의 검토를
대체하지 않는다.

실제 복원에는 해시가 같은 anonymous private 복사본을 stdin으로 전달한다. 검증 뒤 파일
경로가 바뀌어 다른 dump를 읽는 문제를 방지한다. 추가 디스크 용량은 archive 크기만큼 필요하다.
`pg_restore --single-transaction --exit-on-error --no-owner --no-privileges --no-password`를
고정 argv로 사용한다. 비밀번호는 환경변수가 참조하는 전용 passfile로만 전달한다.
실행 timeout은 운영자 한도와 남은 승인 시간 중 짧은 값이다. 실제 commit·효과가 불명확하면
UNKNOWN으로 유지하고 자동 재시도하지 않는다.

완료 후 cluster/DB OID·owner·다른 세션 없음·복원 관계 수를 확인한다. 이것은 DB 객체 복원의
확인이며 애플리케이션 업무 데이터 무결성이나 서비스 복구 성공을 자동으로 뜻하지 않는다.

## 역할 차단 범위

`roles`에 명시한 역할만 허용한다. postgres/pg_*와 실행 역할 자신, superuser·replication·
createrole·createdb·bypassrls, DB/테이블 소유자, 권한 높은 역할의 멤버는 거부한다.
역할 OID와 원래 LOGIN 상태를 계획에 고정한다. SQL identifier는 검증된 단일 이름만 사용하며
NOLOGIN/LOGIN 이외 SQL을 요청에서 구성하지 않는다. 적용과 사후 OID·상태 확인은 같은
트랜잭션에서 수행하고 commit 직전에도 승인 만료를 확인한다.

연결이 끊기거나 commit 응답이 사라지면 실제 결과를 추정하지 않고 UNKNOWN으로 남긴다.
동일 remediation ID는 영속 SQLite journal로 재실행하지 않는다. conflicting ID 요청이
기존 성공 결과를 덮어쓰거나 다른 조치의 lease를 해제하지 않도록 한다.

## 운영 인수

임시 테스트는 fake DB·fake runner·검증된 작은 합성 archive만 사용한다. 실제 PG17 전용
권한(관측 함수 실행 포함), TLS/인증서, passfile 권한, pg_restore 호환 버전, 격리 DB,
백업/복원 리허설과 서비스 전환은 별도로 확인해야 한다. UNKNOWN은 운영자가 서버 상태와
transaction 로그를 조사한 뒤 조정하며, 같은 요청을 강제로 반복하지 않는다.
