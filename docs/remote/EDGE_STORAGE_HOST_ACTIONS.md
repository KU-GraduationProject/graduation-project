# Edge·MinIO·호스트·사건 기록 실행기

`executor/edge_storage_host.py`의 `EdgeStorageHostExecutor(name="operations")`는
현재 사건 identity 하나와 운영자 허용 목록에 묶인 변경만 계획한다. 사용자나 LLM이
실행 명령, 서비스명, 파일 경로, API 주소, 인증정보를 직접 공급할 수 없다.
`REMEDIATION_OPERATIONS_CONFIG_PATH`로 지정한 private 파일의 `enabled=true`와
실제 inventory가 없으면 모든 동작은 차단된다. 예제는
`aiops/policy/remediation_edge_storage_host.example.yml`이며 기본값은 비활성이다.
생성자에서는 Docker·호스트·MinIO·GitHub에 연결하지 않는다.

## 실행·승인 계약

`plan_record(identity, targets, action_type, parameters)`는 source/site/service/runtime/target,
정확한 자원과 현재 설정의 hash, tool binary 또는 image ID를 동결한다. 승인 직전·실행 직전에
계획을 다시 생성해 변화를 거부한다. 실제 실행에는 Controller의 영속 EXECUTING 선점,
유효한 승인 시각 순서, 승인자, 정확한 action hash와 evidence binding이 필요하다.
실행기에도 private state_dir에 0600의 일회성 journal을 첫 변경 전에 fsync한다.
결과 유실·부분 변경은 UNKNOWN이며 같은 ID로 재실행하지 않는다. 임의 재시도는 없다.
Controller/Agent의 single-worker 및 대상별 lease 계약을 유지해야 한다.

| 조치 | 요청 파라미터 | 구현 범위·검증 |
|---|---|---|
| BLOCK_PATH | `{path}` | nginx literal exact location의 403 반환 |
| RATE_LIMIT | `{path, burst}` | literal exact location, 사전에 설정된 `leafy_remediation` zone, 운영자 고정 upstream |
| MAINTENANCE_MODE | `{}` | 관리 include에 `/` 503 반환 location 추가 |
| RESTORE_NGINX | `{parent_id}` | 같은 identity의 VERIFIED journal에 있는 이전 include로 복구; 중간 변경 있으면 차단 |
| RESTRICT_BUCKET | `{bucket}` | 허용 bucket의 **anonymous 접근 정책 제거**. 인증 사용자의 전체 읽기전용 전환은 이번 범위가 아님 |
| RESTORE_BUCKET | `{parent_id}` | 이전 anonymous policy 복구, 현재 policy와 transport hash가 이전 조치 직후와 같을 때만 |
| DISABLE_KEY | `{resource}` | 운영자 지정 MinIO 서비스 계정만 disable. root·관리자 소유 계정은 거부 |
| ENABLE_KEY | `{parent_id}` | 같은 자원의 VERIFIED disable을 별도 승인으로 이전 상태에 복구 |
| RESTART_HOST_SVC | `{}` | Windows-native worker에서 정확히 허용한 PostgreSQL 서비스만 stop→STOPPED→start→새 PID/RUNNING 검증 |
| CLEAN_DISK | `{}` | 전용 log 디렉터리의 **명시된 오래된 닫힌 `.log` 파일만 실제 삭제**. glob·재귀·DB/MinIO data·이미지 삭제 없음 |
| RECORD_INCIDENT | `{incident_key}` | 고정 GitHub 저장소에 deterministic marker를 가진 Issue 조회·생성. 원시 분석/로그·인증정보는 본문에 넣지 않음 |

복구 endpoint가 parent_id를 caller에게 임의 선택하게 두면 안 된다. Controller는 자신의
VERIFIED 부모 레코드에서 parent_id를 도출하고 same-incident/same-target 연결과 새 승인을
검증해야 한다. 복구 실행기도 자기 journal의 identity·완료 상태·직후 상태를 다시 확인한다.
CLEAN_DISK는 비가역이므로 복구 조치가 없고 반드시 별도 high-risk 승인이 필요하다.

## nginx 설치 전제

nginx가 존재하는 **고정 container ID·image ID·workload labels**를 검사한 뒤 그 ID 안에서
fixed argv로 `nginx -t`, `nginx -T`, `nginx -s reload`를 호출한다. host nginx나 비슷한
이름의 다른 컨테이너를 조작하지 않는다. privileged/host PID·network/Docker socket mount를 거부한다.

운영자가 다음 구조를 **새 이미지·명시적 bind mount**로 사전에 설치해야 한다.

```nginx
http {
    # IP 주소로 분류하지 않는다. $uri는 경로별 합계, $http_authorization은 토큰별 제한이다.
    limit_req_zone $uri zone=leafy_remediation:10m rate=5r/s;
    server {
        include /etc/nginx/remediation/managed.conf;
        # 다른 일반 location·server 설정은 기존 운영자 설정을 유지한다.
    }
}
```

초기 managed.conf의 유일한 내용은 `# Leafy remediation managed v1`와 개행이다.
전용 디렉터리를 frontend와 executor에 동일한 파일로 mount하고 `shared_include_verified`를
실측 후 설정한다. target inspect의 bind source·destination이 바뀌면 차단한다.
`nginx -T`에서 해당 include가 실제로 참조되는지 확인하며, 알려지지 않은 directive가
managed 파일에 있으면 계획하지 않는다. 설정 백업은 bounded managed snippet만 journal에
보관하고 원시 nginx 전체 설정은 감사 레코드에 남기지 않는다.

Reload 명령 성공·디스크 config readback은 HTTP 실제 트래픽에서의 403/429/503 검증과 다르다.
동일 경로에 이미 운영 location이 있으면 `nginx -t`가 실패할 수 있다. reload 전 문법 검사에 실패하면 자신이 쓴 candidate가 그대로일 때에만 이전 파일로 되돌린다.
실행 결과는 보수적으로 UNKNOWN이며, reload 결과가 불확실한 경우 자동 재시도·재로드하지 않는다.
원복 전 운영자의 정확한 상태 확인이 필요하다. 이 구현은 nginx upstream이나 비밀 파일을
자동으로 새로 만들지 않는다. 실제 정책 효과는 별도 HTTP acceptance가 필요하다.

## MinIO 설치 전제

검토한 `mc` binary의 SHA256과 private `MC_CONFIG_DIR`을 운영자가 설치한다. alias는 HTTPS
origin만 허용하며 private config 파일 hash를 계획에 포함해 다른 서버·인증정보 변경을
같은 승인으로 사용하지 않는다. mc stdout/stderr 원문이나 private config의 값은 감사로 보존하지 않는다.

서비스 계정은 **실제 non-root 부모 사용자 아래 발급된 별도 서비스 계정**이어야 한다.
`key_id_env`, `owner_env`, `root_key_env`는 변수 이름뿐이며 값은 예제·계획·결과에 넣지 않는다.
mc 명령에 전달되는 서비스 계정 식별자도 출력하지 않는다. 원래 status와 식별자 hash만
보존한다. 앱이 root 계정을 직접 사용하는 기존 배포에서는 이 기능을 켤 수 없다.
Anonymous bucket policy 형식은 대상 mc/MinIO 버전의 get-json/set-json 계약과 일치해야 한다.
NoSuchBucketPolicy 또는 미지원 CLI 출력 형식은 추정하지 않고 fail closed/UNKNOWN으로 남는다.

## 호스트·디스크 경계

Windows 서비스는 native Windows worker에서만 실행한다. Docker Desktop의 Linux Agent는
Windows Service Control Manager를 대신 조작할 수 없으며 `platform != win32`이면 차단된다.
서비스 binary·config hash와 현재 RUNNING/PID를 승인 전에 읽고 재검증한다. 다른 서비스로
fallback하거나 taskkill로 프로세스를 죽이지 않는다.

CLEAN_DISK는 `psutil`로 모든 프로세스의 open-file inventory를 읽을 수 있어야 한다.
권한 부족으로 프로세스별 조회를 완전히 할 수 없으면 차단한다. 각 파일의 경로·inode·device·mtime·
size·hash·hardlink 수·나이를 승인 전에 기록하고 삭제 직전에 다시 확인한다. Symlink와
최근/열린 로그를 거부한다. 지정 디렉터리는 작업 부하가 새 파일을 생성하지 않는 전용 회전 로그
영역이어야 한다. OS의 파일 열기와 unlink 사이의 경합을 커널에서 원자적으로 봉쇄한다고 주장하지 않는다.
삭제한 논리 byte 수를 검증하지만 filesystem 자유 공간 증가를 확인한 것으로 기록하지 않는다.
Copy-on-write·스냅샷·아직 열려 있는 descriptor 등은 공간 반납과 별개다.

## GitHub 경계

런타임에서 RECORD_INCIDENT를 쓰려면 고정 저장소·token 환경변수·명시적 승인·enabled 설정이
모두 필요하다. 코드 테스트에서는 실제 GitHub에 요청하지 않는다. 본문은 incident marker와
관측 identity만 포함한다. marker 검색이 불완전하거나 여러 Issue에 일치하면 차단한다.
생성 응답이 불확실하면 재생성하지 않는다. GitHub 검색 인덱스는 eventual consistency이므로
local incident claim을 별도로 유지하고, 생성 직후에는 반환한 번호를 직접 GET해 marker를 검증한다.
다른 독립 deployment가 같은 key를 동시에 생성하는 경우의 전역 원자성을 보장하지 않는다.

## 검증

`test_edge_storage_host.py`는 fake Docker·mc·SCM·HTTP transport와 임시 파일만 사용한다.
16개 테스트에서 승인 만료, 컨테이너 교체, 다른 MinIO 서버, 경로 주입, root 키, 중간 운영자
정책 변경, 열린 로그·symlink, 부분 실패·재실행 거부, Issue dedup와 정상 적용·별도 복구를 검증했다.
이 결과는 실제 nginx/MinIO/Windows/GitHub 운영 인수가 아니다.

참고: [nginx CLI](https://nginx.org/en/docs/switches.html),
[MinIO anonymous policy](https://docs.min.io/aistor/reference/cli/mc-anonymous/),
[MinIO service-account 구현](https://github.com/minio/mc/blob/master/cmd/admin-user-svcacct-info.go),
[Windows Service Control](https://learn.microsoft.com/en-us/windows/win32/services/controlling-a-service-using-sc).
