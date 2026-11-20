# 실제 실행기와 Leafy 백엔드 검증 기록

> 이전 단계의 759개 검사 기록이다. 이후 통합 변경·현재 판정은 [통합 구현 보고](REMEDIATION_INTEGRATION.md)를 참조한다.

검증일: 2026-11-12 KST. 사용자 요청에 따라 Notion의 후속 후보였던 DB·배포·앱 API에
실제 실행 코드를 추가하고 사용자가 제공한 Leafy 백엔드 소스와 연결했다.

## 변경 소스와 범위

- AIOps 작업 폴더: `remediation-improvement-20261111`, 브랜치 `feat/35-remediation-improvements`.
  기준 `49245e120191b84642e17a910ca9278e368f7966` (Socket Mode PR #32).
  [작업 Issue #35](https://github.com/KU-GraduationProject/graduation-project/issues/35).
- 백엔드 작업 폴더: `leafy-api-remediation-20261111`, 브랜치 `feat/remediation-admin-api`.
  사용자 제공 [Project-Leafy/api-server](https://github.com/Project-Leafy/api-server)의
  기준 `6dab427f25f2a0192d085da9347ebcaf73dc067b`.
- 노션 기준: [Remediation 개선안](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85),
  7.4/7.5의 토글과 현재 코드. 이번 추가 요청으로 실제 구현 범위를 확장했다.

실제 SQL을 수행하는 PostgreSQL 어댑터, Docker SDK 배포 어댑터, HTTPS 관리자 API 어댑터를 구현했다.
Controller의 영속 계획·수동 승인·만료·대상 검증·실행 선점·결과 검증에 연결했다.
백엔드에는 관리자 API뿐 아니라 실제 JWT 잠금/회수 검사와 진단·식별·추천 기능 차단도 구현했다.

## 최종 결과

Python 3.11.15와 psycopg/psycopg-binary 3.3.8 import 환경에서 검사했다.
드라이버는 `/tmp` 별도 패키지 디렉터리에 설치했으며 원본 작업 환경을 변경하지 않았다.
Java 검사는 JDK 17과 Gradle 8.14.3의 캐시된 의존성으로 수행했다.

| 검사 | 결과 | 수 |
|---|---|---:|
| `python testing/run_isolated.py remediation` | PASS | 437 |
| `python testing/run_isolated.py pipeline` | PASS | 143 |
| `python testing/run_isolated.py network` | PASS | 100 |
| `python testing/run_isolated.py observer` | PASS | 12 |
| `python -m unittest discover -s .github/scripts/tests` | PASS | 36 |
| 백엔드 `./gradlew --offline test --tests 'com.leafy.remediation.*'` | PASS | 31 |
| 합계 | PASS, 실패·오류·skip 없음 | 759 |

추가 정적 검사: 양쪽 `git diff --check`, Python compileall, 기본 all-in-one Compose,
AIOps Compose + extended override의 `config --quiet` PASS. Compose는 실제 비밀값 없는
placeholder 환경에서 문법만 확인했으며 어떤 컨테이너도 시작하지 않았다.
집중 테스트 수는 위 합계에 이미 들어 있으므로 중복 합산하지 않는다.

Python 격리 실행기는 실제 Docker 생성자·socket/DNS·subprocess·pipe 접근을 차단한다.
네트워크 suite만 자신이 만든 임시 loopback fixture를 사용한다. psycopg의 native libpq는
Python audit 밖에서 연결할 수 있으므로 `psycopg.connect`도 테스트 수집 전에 차단한다.
실제 드라이버를 import한 뒤 연결 차단 자체도 확인했다.

백엔드 기존 외부 데이터 수집/전체 application context 테스트를 실행하지 않았다.
이번 31개는 해당 기능에 대한 좁은 보안·서비스·영속성 suite이며 외부 DB/OAuth/AI 호출이 없다.
이를 전체 백엔드 기능의 검증이나 실제 운영 환경 인수로 표현하지 않는다.

## 검증한 주요 동작

- DB: 실제 SQL 문자열·바인딩, 역할/DB/클러스터/주소/세션 범위, PID 재사용·쿼리 변경 거부,
  연결·cursor 정리, 승인 만료, SQLite 재시작·동시 중복 요청, 응답 유실 UNKNOWN.
- 배포: 실제 SDK 인자 직렬화, 같은 이미지 재생성/known-good 롤백, 백업 DB/해시·호환 조건,
  첫 변경 전 디스크의 승인·실행 선점·계획 증거, 기존 컨테이너 보존, 새 ID/설정/헬스 검증,
  설정 변경·부분 실패·UNKNOWN 뒤 중복 실행 차단.
- 앱 API: 실제 HTTP 경로/메서드/JSON/토큰 참조/If-Match/Idempotency-Key,
  Leafy 전용 예제의 세 경로·리소스/상태 재조회, 만료·역할·리다이렉트·변조·UNKNOWN.
- 백엔드 보안 15개: 실제 Spring Security 필터 체인, 현재 DB의 관리자 역할, 잠금/만료,
  기존 JWT·refresh JWT 거부, 새 로그인 후 재회수, 실제 업무 handler의 기능 차단.
- 백엔드 서비스 9개: 대상·자원·버전·멱등 키·관리자 보호·잠금 기간·수동 복구 경계.
- 실제 H2/JPA/트랜잭션 7개: 사용자 flush 뒤 receipt 저장 실패 시 원자적 rollback,
  영속 버전/인증 epoch, 동시 요청의 row lock과 단일 효과, 새 토큰 발급 상태의 영속 반영.
- 실제 MockMvc JSON 응답에서 `lock_expires_at`가 ISO 문자열인지 확인했다.
  숫자로 직렬화되는 계약 불일치를 발견해 DTO에 명시적 문자열 형식을 적용했고,
  `Instant.parse`와 승인한 잠금 기간 범위까지 검증했다.

## 배포 전 남은 인수

1. 백엔드 패치와 검토한 `docs/remediation-admin-schema.sql` 마이그레이션 적용이 필요하다.
   SQL을 실제 DB에 실행하지 않았다. 운영 Hibernate 설정은 validate로 변경했으며,
   기존 dev create-drop 프로필을 보존된 DB에 적용하면 안 된다.
2. 새로운 백엔드 이미지·HTTPS 관리자 경로·ADMIN access JWT와 실제 대상 허용 목록을 검증해야 한다.
   현재 배포 이미지가 이미 이 관리자 API를 제공한다고 주장하지 않는다.
3. PostgreSQL 17의 전용 역할/권한·예약 연결 슬롯·클러스터·클라이언트 범위와 TLS를 확인해야 한다.
   세션/쿼리 효과 검증과 서비스 전체 정상 복구는 별도다. PG 신호 함수의 짧은 검사/신호 경쟁은 남는다.
4. 배포 어댑터는 검증한 Docker 호스트의 로컬 Unix socket만 사용한다.
   다른 PC의 Docker를 자동으로 조작하지 않는다. private env·백업 파일은 명시적으로 마운트해야 한다.
5. Slack→승인→실제 DB/Docker/API 변경→결과·복구의 실환경 E2E는 수행하지 않았다.

기본 실행 모드, RCA 알림 opt-in, 모든 자원/대상 목록은 비활성 또는 빈 상태다.
커밋·푸시·PR·병합·운영 활성화·실제 계정/DB/배포 변경은 수행하지 않았다.
원본 작업 폴더·Worktree·미커밋 작업·인증정보·비공개 평가 자료는 보존했다.

설정 계약은 [실행기 설명](EXTENDED_EXECUTORS.md),
[배포 안내](DEPLOYMENT_EXECUTOR.md), [앱 API 계약](APP_API_EXECUTOR_CONTRACT.md)을 따른다.
