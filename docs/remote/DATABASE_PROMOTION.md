# 검증된 staged DB를 서비스 이름으로 전환

`RESTORE_DB`는 별도 `restore_*` DB에 archive를 복원한다. 그것만으로 현재 서비스 DB가
복구되지는 않는다. `executor/database_promotion.py`는 이를 보완하는 별도 고위험·승인 전용
전환 실행기다. 기존 서비스 DB와 복원 DB를 모두 보존하고 **같은 클러스터의 DB 이름**을
교환해 애플리케이션이 원래 DB 이름으로 복원본에 연결하게 한다. 자동 운영 활성화는 하지 않는다.

## 지원 경계

- PostgreSQL 16/17 primary, 같은 `system_identifier`·server 주소·port.
- 원격 연결은 인증서 검증 `sslmode=verify-full`을 요구한다. `require`는 loopback 리허설에서만 허용한다.
- 연결은 `postgres` maintenance DB로만 열어 두 DB 이름을 바꾼다. 작업 대상이
  postgres/template0/template1이거나 `pg_*`이면 거부한다.
- 운영자가 지정한 non-superuser CREATEDB 역할이 두 DB의 실제 owner여야 한다.
  CREATERole/replication/bypassrls·superuser 역할은 거부한다. 실행 역할에는 pg_control_system
  관측 권한, 필요한 통계 조회와 제한된 세션 signal 권한을 운영자가 검토·부여해야 한다.
- 새로운 서버 생성·cross-cluster 복제·테이블스페이스 이동·확장/외부 시스템 복원·DB 삭제는 하지 않는다.
  애플리케이션 업무 데이터의 올바름, OAuth/캐시/외부 저장소와의 정합성은 별도 검증이다.

## staged 복원본의 입증

`PROMOTE_RESTORED_DB` 파라미터는
`{source_record_id, confirm_database, allow_data_loss:true}`다.
기존 Controller의 서명·정확한 사건 identity·명시적 승인·실행 선점 계약을 사용한다.
호출자가 DB 이름·OID·연결 주소·SQL을 정하지 못하며 config의 값과 정확히 일치해야 한다.

`REMEDIATION_DATABASE_PROMOTION_CONFIG_PATH`의 예제는
`aiops/policy/remediation_database_promotion.example.yml`이다. 다음을 운영자가 확인해야 한다.

1. source_record_id가 private DatabaseAdmin journal의 **검증된 성공 RESTORE_DB**여야 한다.
   대상 restore target·고정 plan digest·복원 DB OID·archive hash·source cluster/server/owner·
   manifest hash·원본 database_id가 모두 일치해야 한다. metadata가 없는 오래된 journal은
   성공 기록만 믿고 승격하지 않는다.
2. manifest의 원본 database_id는 현재 `system_identifier:service_database`여야 한다.
   다른 서비스의 archive나 다른 클러스터에서 우연히 같은 OID인 복원본을 사용하지 않는다.
3. staging DB는 `restore_*` 이름, 실제 owner와 고정 OID, PUBLIC CONNECT 없음,
   application role CONNECT 없음, 다른 application 세션 없음이어야 한다.
   복원 후 운영자가 검증하는 동안에도 stage의 workload 접근을 차단해야 한다.
4. RESTORE_DB가 `--no-privileges`를 쓰므로 애플리케이션의 schema/table/sequence 권한을
   별도로 준비해야 한다. `application_access`에 열거한 정확한 권한을 stage에 연결해
   `has_*_privilege`로 확인한다. 이 목록을 통과하는 것만으로 앱 전체 권한을 보장하지 않는다.
   필요한 모든 접근과 데이터 검증을 포함한 maintenance 준비가 끝나야
   `maintenance_confirmed=true`로 설정한다.
5. application_roles는 일반 역할만 허용한다. 현재 DB의 세션이 예상치 못한 사용자,
   superuser, background worker이거나 prepared transaction이 있으면 전환하지 않는다.

지원하는 전환은 **같은 owner 역할의 검토된 권한 전환**이다. RESTORE_DB 단계에서는 이 역할의
CREATEDB가 false여야 하며, staged 복원 검증 후 운영자가 같은 역할에 CREATEDB를 명시적으로
부여하고 maintenance 단계로 전환한다. promotion은 restore_owner와 executor_role의 동일성을
검증하므로 다른 유지보수 역할로 갈아타거나 복원 후 DB owner를 임의 변경하는 경로는 지원하지 않는다.
두 DB가 이미 이 동일한 역할의 소유여야 한다. 실행기가 superuser로 승격하거나 ownership·
CREATEDB 권한을 자동 부여하지 않는다.

## 전환 순서와 장애 시 행동

1. Controller와 실행기가 승인·계획·현재 cluster/DB OID/owner/roles를 다시 확인한다.
   별도 SQLite 일회성 journal과 대상 lease, 예측 가능한 retained 이름을 첫 변경 전에 저장한다.
2. 원래 service DB와 stage DB의 `ALLOW_CONNECTIONS=false`를 설정하고 **먼저 commit**한다.
   새 application 연결이 다시 들어오지 못하도록 하는 fence다.
3. exact database OID·PID·사용자·backend_start를 재검증한 allowlisted application 세션만
   `pg_terminate_backend(pid,1000)`로 종료하고 zero sessions를 다시 확인한다.
   통계 cache를 반복마다 지워 오래된 pg_stat_activity를 실제 세션으로 오인하지 않는다.
   예상치 못한 세션은 종료하지 않는다.
4. 단일 트랜잭션에서 service DB를 `leafy_retained_<deterministic hash>`로 rename하고,
   stage DB를 원래 service 이름으로 rename한다. 지정 application roles에 CONNECT만 부여하고
   새 service DB의 ALLOW_CONNECTIONS를 켠다. 이전 DB는 연결 차단 상태로 보존한다.
5. commit 후 별도 maintenance 연결로 새 service OID·retained OID·연결 상태를 읽어 확인한다.
   SUCCESS는 이름/접속 fence 전환의 검증이며 `application_service_recovery_verified=false`다.
   앱 재연결·health·업무 검증은 기존 service verification/운영 인수에서 확인한다.

PG 문서는 DB rename에 owner/CREATEDB가 필요하고 current DB는 rename할 수 없다고 명시한다.
트랜잭션 금지 조건이 있는 SET TABLESPACE·CREATE/DROP DATABASE는 이 실행기에 없다.
실제 PG16/17에서 두 RENAME의 원자성과 운영 설정 호환성을 검증하는 rehearsal이 필요하다.

Fence commit 뒤 실패하면 서비스 연결이 막힌 채 남을 수 있다. rename commit 응답 유실 시
실제 이름 전환 여부도 불확실할 수 있다. 이런 경우 **UNKNOWN, lease 유지, 자동 재시도 없음**으로
남기고 저장된 OID·retained 이름으로 운영자가 정확한 서버 상태를 조사해야 한다.
이전/복원 DB를 삭제하거나 불확실한 상태를 자동으로 열지 않는다.

## 별도 승인 rollback

`ROLLBACK_DB_PROMOTION {parent_id}`는 Controller가 검증된 promotion 부모에서 도출한다.
부모 journal이 SUCCESS이고 identity가 같아야 한다. 현재 service DB의 OID가 부모가
승격한 OID인지, retained DB가 부모가 보존한 OID인지, owner·fence 상태가 그대로인지 확인한다.
새 승인을 받아 같은 fence/drain/rename 순서로 이전 DB를 원래 service 이름에 되돌린다.
현재 복원본도 다른 retained 이름으로 보존하며 두 DB를 drop하지 않는다.

Rollback 역시 현재 서비스 DB에 promotion 이후 기록된 쓰기가 활성 이름에서 사라지는
데이터 손실 선택이다. 자동 rollback이나 TTL rollback은 없고, 운영자가 손실 범위와
서비스 정합성을 검토한 별도 승인이 필요하다.

## 검증

`tests/test_database_promotion.py` 12개는 fake transactional PostgreSQL과 임시 SQLite journal만
사용한다. 실 DB 연결·세션 종료·rename을 하지 않는다. 정상 전환과 별도 rollback에서 OID 보존,
이전 DB retain, app-role-only drain, 잘못된 archive/cluster/OID/권한·PUBLIC stage 접속·prepared tx
거부, 승인 만료, fence 뒤 만료/특권 세션 출현, commit 응답 유실 후 UNKNOWN no-retry를 확인한다.
실제 DatabaseAdminExecutor가 생성한 성공 결과와 SQLite journal을 promotion에 연결하는 fake 통합 회귀도 포함한다.

참고: [PostgreSQL 17 ALTER DATABASE](https://www.postgresql.org/docs/17/sql-alterdatabase.html),
[PG17 관리 함수의 signal 권한·종료 확인](https://www.postgresql.org/docs/17/functions-admin.html).
