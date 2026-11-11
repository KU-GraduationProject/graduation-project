# F2-c 실행 환경과 검증

## 호출 경로와 변경 설계

이 문서는 F2-c만 다룬다. `run.py`의 기본/변형 실행 모두
`f2c_db_pool_exhaustion.main → inject → hold → finally cleanup`으로 들어간다.
변형의 `strength`, `hold_seconds`를 그대로 전달하고 실패 종료 코드를 보존한다.
다른 시나리오의 dispatch는 기존 동작을 유지한다.

기존 Docker SDK `containers.get`/분리 `sh` 실행 횟수는 성공한 DB 연결 수가
아니었다. 새 `f2c_runtime.Psql`은 각 클라이언트를 추적하고 DB의 실행별 실제
세션 수 증가를 확인한다. Docker는 `docker exec <container> env … psql`의 로컬
소켓, Host는 로컬 `psql.exe`/`psql`의 명시한 TCP 주소를 사용한다. Host 모드에서
Docker SDK/CLI, `sh`, `pkill`을 사용하지 않는다. Python 표준 라이브러리만 필요하다.

## 사전 조건과 대상 확인

실험 전용 클러스터를 운영자가 확인해야 한다. 자동으로 Leafy 컨테이너나 기본
PostgreSQL 서비스를 찾아 주입하지 않는다. Host 주입기는 GC Windows에서 실행하고,
Docker의 Leafy 애플리케이션은 기존 Host DB 접속 설정을 유지한다. JH 관측 환경에는
주입용 DB 인증정보를 전달할 필요가 없다.

필수 환경변수:

| 변수 | 의미 |
| --- | --- |
| `F2C_DB_MODE` | `host` 또는 `docker`, 기본값 없음 |
| `F2C_DB_HOST` | Host: 단일 TCP 주소, Docker: 컨테이너 내부 소켓 디렉터리 |
| `F2C_DB_PORT` | 명시한 PostgreSQL 포트 |
| `F2C_DB_NAME` | 실험 DB 이름, URI/접속 문자열 금지 |
| `F2C_ADMIN_USER` | 기존 superuser 관리자 계정, 조회·복구 전용 |
| `F2C_DB_USER` | 기존 일반 LOGIN 계정, 점유와 신규 연결 검증에 동일하게 사용 |
| `F2C_EXPECTED_SYSTEM_ID` | 미리 확인한 실험 클러스터의 `system_identifier` |
| `F2C_CONFIRM_TARGET` | 아래 형식의 대상 확인 문자열과 정확히 일치해야 함 |
| `F2C_DB_CONTAINER` | Docker 모드에서만 필수, 예: `leafy-db` |
| `F2C_PSQL` | 선택: Host `psql.exe` 절대 경로 / Docker 내부 `psql` 경로 |
| `F2C_PGPASSFILE` | 선택: 기존 libpq 비밀번호 파일 경로. Docker는 컨테이너 내부 경로 |
| `F2C_MAX_SECONDS` | 선택: 충전·유지·복구 시간의 Watchdog 상한, 기본 420초 |

대상 확인 문자열:

- Host: `host:<host>:<port>:<database>:<system_identifier>`
- Docker: `docker:<container>:<database>:<system_identifier>`

클러스터 ID는 해당 실험 장비의 관리자가 기존 승인된 접속 경로에서 다음 읽기
전용 쿼리로 확인하고, 장비·포트·클러스터와 대조한다. 대상 확인 문자열만으로
운영/실험 환경을 추론하지 않는다. ID 조회 외에는 주입기를 실행할 필요가 없다.

```sql
SELECT current_database(), inet_server_addr(), inet_server_port(),
       (pg_control_system()).system_identifier;
SHOW max_connections;
SHOW reserved_connections;
SHOW superuser_reserved_connections;
```

관리자와 점유 계정은 달라야 한다. 점유 계정은 superuser 및
`pg_use_reserved_connections`의 유효 권한이 없어야 하며, 해당 계정과 DB의
연결 한도는 `-1`이어야 한다. 그렇지 않으면 전역 슬롯 고갈과 계정/DB별 한도를
구분할 수 없어 주입 전에 중단한다. 기존 superuser 예약 슬롯이 최소 1개 필요하다.
조건이 맞지 않아도 코드가 역할·권한·비밀번호·설정을 생성하거나 변경하지 않는다.

비밀번호는 argv, 출력, Watchdog 파일에 저장하지 않는다. 기존 libpq 비밀번호
파일 또는 기존 소켓 인증을 사용하며 `-w`로 대화형 암호 입력을 금지한다.
`.psqlrc`는 `-X`로 비활성화한다. 주변 `PGHOSTADDR`, `PGSERVICE`, `PGOPTIONS`,
`PGPASSWORD` 등 접속·권한 관련 변수는 제거하여 명시한 대상을 우회하지 못하게 한다.
오류의 원문 stdout/stderr는 로그에 출력하지 않는다. Windows에서 비밀번호 파일은
기존 `%APPDATA%\postgresql\pgpass.conf` 또는 명시한 파일을 사용할 수 있다.

## 설정 예시와 실행

다음은 설정 예시이며 자동 실행하지 않는다. 이름과 ID는 실제 실험용 값으로 바꾼다.
실제 연결 고갈 실행은 운영자가 별도로 수행한다.

Windows PowerShell (GC Host):

```powershell
$env:F2C_DB_MODE = 'host'
$env:F2C_DB_HOST = '127.0.0.1'
$env:F2C_DB_PORT = '5432'
$env:F2C_DB_NAME = 'leafy'
$env:F2C_ADMIN_USER = 'existing_admin'
$env:F2C_DB_USER = 'existing_ordinary_login'
$env:F2C_EXPECTED_SYSTEM_ID = '<실험 클러스터 ID>'
$env:F2C_PSQL = 'C:\Program Files\PostgreSQL\17\bin\psql.exe'
$env:F2C_CONFIRM_TARGET = "host:127.0.0.1:5432:leafy:$($env:F2C_EXPECTED_SYSTEM_ID)"
```

Docker 예시: `F2C_DB_MODE=docker`, `F2C_DB_CONTAINER=leafy-db`,
`F2C_DB_HOST=/var/run/postgresql`, `F2C_DB_PORT=5432`와 위 공통 변수를 설정한다.
확인 문자열은 `docker:leafy-db:leafy:<실험 클러스터 ID>`이다. 점유 계정은
기존 `POSTGRES_USER`를 무조건 재사용하지 않고 위의 일반 사용자 조건을 확인한다.
`docker exec`와 컨테이너 내부 `env`/`psql`이 필요하다. 호스트 OS에는 `sh`가 필요 없다.

공통 진입점은 저장소 루트에서 `PYTHONPATH`를 `scenarios`로 설정한 뒤 실행한다.
기존 진입점의 `from v2` import 경로를 유지했다.

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'scenarios')
# 읽기 전용 계획. DB/Docker에 연결하지 않는다.
python -m v2.run f2_c_db_pool_exhaustion --dry-run
# 실제 실행은 운영자가 별도로 승인한 측정 시간에 수행한다.
# python -m v2.run f2_c_db_pool_exhaustion
# python -m v2.run f2_c_db_pool_exhaustion --variant fill-burst --seed 1
```

## 슬롯·거부·유지·복구 판정

일반 사용자 한도 = `max_connections - reserved_connections - superuser_reserved_connections`.
현재 연결 수는 **클러스터 전체 client backend**를 세되, 조회 자신의
`pid = pg_backend_pid()`는 제외한다. 조회 연결이 닫힌 뒤 실제 점유/검증을 하므로
기존의 한 슬롯 부족 문제가 없다. 관리 조회 자체는 일시적으로 superuser 예약
슬롯 하나를 사용할 수 있다. 점유 계정은 두 종류의 예약 슬롯 모두 사용할 수 없다.

`held`는 프로세스 기동 횟수가 아니라 실행 표식과 DB·사용자가 일치하는 실제
세션 수다. medium/strong은 슬롯 점유 확인과 **새 일반 사용자 접속의 거부**를
각각 확인해야 한다. psql/libpq 접속 초기 오류에는 SQLSTATE가 항상 노출되지 않아
PostgreSQL의 알려진 전역 고갈 메시지와 점유 수를 함께 검사한다. 인증·네트워크·
계정별 한도 오류 및 인식할 수 없는/현지화된 메시지는 성공으로 처리하지 않는다.
현지화된 서버 메시지는 실환경에서 먼저 확인해야 하며, 불명확하면 FAIL한다.

마지막 점유 연결 확인과 고갈 확인이 끝난 이후부터 유지 시간을 측정한다.
각 클라이언트는 `hold_seconds` 대신 `max_seconds` 동안 `pg_sleep`을 실행한다.
충전 시간 + 유지 시간 + 복구 여유가 Watchdog 상한 안에 들어가지 않으면 중단한다.
따라서 먼저 생성한 연결의 sleep이 일찍 끝나 유지 시간이 짧아지는 일을 PASS로
처리하지 않는다. 유지 중 5초 이하 간격으로 점유 수와 신규 연결 결과를 재검증한다.
샘플 사이의 짧은 변동은 GC DB 로그 및 JH 관측 자료와 대조해야 한다.

모든 연결에는 실행별 128-bit 임의 ID가 포함된 application_name을 부여한다.
점유 세션은 `connhold-<ID>`, 조회/프로브는 같은 ID의 `-ctl`/`-probe`이다.
종료 SQL은 점유 표식의 **정확한 일치 + 사용자 + DB**로 범위를 제한한다.
정리 확인은 해당 세션 0개와 새 일반 사용자 연결 성공을 모두 요구한다.
전체 연결 수의 기준치 복귀만으로 다른 실행의 세션까지 종료하지 않는다.

별도 Python Watchdog은 인증·대상을 확인하고 ready 신호를 보낸 뒤에만 주입을
허용한다. 부모가 종료되면 상한 시간에 같은 실행을 복구하며 실패 시 재시도한다.
충전·유지 중 Watchdog이 예기치 않게 종료되면 실행을 실패 처리하고 정리한다.
정상 cleanup의 복구 검증에 성공한 경우에만 취소한다. Watchdog 시작 실패, 부분
주입, 예외, Ctrl+C에도 생성한 클라이언트를 추적하여 정리한다. 부모와 Watchdog이
모두 죽어도 유한한 서버 측 sleep이 끝나면 psql은 종료한다. 서버/네트워크 장애에서
정확한 복구 시각은 실환경 확인 대상이다. Backend 재시작은 하지 않는다.

Watchdog 파일은 `work_dir > V2_WORK_DIR > OS 임시폴더/v2_watchdog`에 실행별로
남는다. 비밀번호는 쓰지 않는다. Windows 분리 프로세스는
`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`, POSIX는 새 세션으로 기동한다.
배경 트래픽은 Windows `taskkill /T`, POSIX 프로세스 그룹 종료로 정리한다.

종료 코드: `0` = 고갈 확인·전체 유지·복구 PASS, `1` = 검증/복구 실패,
`3` = weak의 압박만 확인(고갈 PASS 아님), `130` = Ctrl+C.
기본 Watchdog 상한은 420초다. 느린 충전으로 시간이 부족하면 FAIL하며,
필요하면 측정 전에 `F2C_MAX_SECONDS` 또는 Python API의 `max_seconds`를
명시적으로 늘려 계획한다. 오래 걸리는 Docker exec 환경에서는 충전 시간도 포함한다.

## 안전한 로컬 검증과 Windows 후속 확인

```text
python -m unittest discover -s scenarios/v2/tests -v
python -m unittest discover -s scenarios/v2/tests -p test_f2c_runtime.py -v
```

새 테스트는 모의 DB와 모의 psql/Docker 프로세스만 사용한다. 실제 프로세스 검사는
모의 DB를 주입한 Python 복구 worker의 부모 정상 종료/강제 종료뿐이다.
실제 DB 고갈, Docker 컨테이너 조작, Backend 재시작은 실행하지 않는다.
Windows/POSIX 생성·종료 분기는 모의 테스트로 검증하며 네이티브 Windows 실행을
대신하지 않는다. 기존 평가용 테스트 1개는 해당 폴더가 없어서 skip되며, 평가 자료는
필요하지 않다.

Windows PostgreSQL 17 실측 시 별도 확인할 항목:

1. 지정 `psql.exe`, 기존 비밀번호 파일, 관리자/일반 계정 권한과 클러스터 ID가
   GC의 실험 DB에 일치하는지. 앱 컨테이너가 동일 DB에 연결하는지.
2. 두 예약 값, observer 제외 수, 실제 점유 수, 일반 신규 연결의 거부 메시지 및
   JH의 탐지·관측 시각. 기존 앱 연결이 정상이어도 신규 연결 거부를 따로 확인한다.
3. 마지막 연결/거부 확인 후 지정 유지 시간 전체와 변형의 `hold_seconds` 반영.
4. 정상 정리, 충전 중 예외/Ctrl+C, 부모 강제 종료, 일시적인 관리자 접속 실패 후
   Watchdog 재시도. 동시 실행의 다른 ID와 기존 앱 세션은 유지되는지.
5. 회복 후 해당 실행 세션 0개, 일반 신규 접속 성공, 기존 서비스 정상화.
   Windows 보안 프로그램/Job Object/콘솔 종료가 독립 worker에 미치는 영향.

PostgreSQL 근거: [예약 연결](https://www.postgresql.org/docs/17/runtime-config-connection.html),
[psql](https://www.postgresql.org/docs/17/app-psql.html),
[libpq 환경변수](https://www.postgresql.org/docs/17/libpq-envars.html).

이번 로컬 검증 기준은 `origin/main`의 `0443c6f`(PR #23 merge)다.
macOS의 Python 3.11.15와 3.14.2에서 각각 145개 테스트 중 144개 통과,
평가용 폴더 부재로 1개 skip을 확인했다. 새 F2-c 테스트 46개가 포함된다.
Windows 네이티브/실제 PostgreSQL/Docker 고갈 측정은 실행하지 않았다.
