"""
RCA 프롬프트 LOGS 섹션 회귀 테스트 (prompt/log_line.py).

fixture는 실측 원문이다.
  - PostgreSQL 17 jsonlog: 테스트 컨테이너(postgres:17-alpine, log_timezone=Asia/Seoul)가 실제로 쓴 줄
  - Backend JSON: 팀 제공 부록B (LeafyJsonFormatter)
  - Nginx JSON: gicks/ai-ops-leafy-frontend 이미지 default.conf의 leafy_json log_format
Loki line은 Fluentd(leafy_docker_log / leafy_postgres_log)가 만든 본문 형태 그대로다.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collector.network import NetworkContext  # noqa: E402
from prompt.builder import MAX_PROMPT_CHARS, PromptBuilder  # noqa: E402
from prompt.log_line import LINE_CHARS, is_priority, mask_secrets, render_log_line  # noqa: E402
from prompt.network_section import build_network_section  # noqa: E402


# ── 수정 전 동작 (builder.py 변경 전 코드 그대로) ─────────────────────
def legacy_render(entry):
    return f"[{entry['labels'].get('container', '?')}] {entry['line'][:200]}"


def legacy_priority(entry):
    return any(kw in entry["line"].lower() for kw in ["error", "exception", "fatal", "warn"])


# ── fixture ───────────────────────────────────────────────────────────
PG_LABELS = {"service": "db", "runtime": "host", "log_format": "json"}
BACKEND_LABELS = {"container": "backend", "service": "backend", "container_name": "leafy-backend",
                  "source": "stdout", "runtime": "container", "log_format": "json"}
FRONTEND_LABELS = dict(BACKEND_LABELS, container="frontend", service="frontend", container_name="leafy-frontend")
DOCKER_META = {"container_id": "c0ffee" * 10 + "abcd", "container_name": "/leafy-backend", "source": "stdout",
               "com.docker.compose.service": "backend"}
PG_FILE = r"C:\Program Files\PostgreSQL\17\data\log\postgresql-2026-10-24_001752.json"

PG_AUTH_FAIL = {"timestamp": "2026-10-24 00:18:05.053 KST", "user": "attacker", "dbname": "postgres", "pid": 81,
                "remote_host": "172.21.0.7", "remote_port": 59156, "session_id": "6adb7aad.51", "line_num": 2,
                "ps": "authentication", "session_start": "2026-10-24 00:18:05 KST", "vxid": "2/1", "txid": 0,
                "error_severity": "FATAL", "state_code": "28P01",
                "message": "password authentication failed for user \"attacker\"",
                "detail": "Role \"attacker\" does not exist.\nConnection matched file \"/var/lib/postgresql/data/pg_hba.conf\" line 128: \"host all all all scram-sha-256\"",
                "backend_type": "client backend", "query_id": 0, "pg_log_file": PG_FILE}
PG_CONN_LOG = {"timestamp": "2026-10-24 00:17:51.941 KST", "pid": 57, "remote_host": "[local]",
               "session_id": "6adb7a9f.39", "line_num": 1, "ps": "", "session_start": "2026-10-24 00:17:51 KST",
               "txid": 0, "error_severity": "LOG", "message": "connection received: host=[local]",
               "backend_type": "not initialized", "query_id": 0, "pg_log_file": PG_FILE}
PG_SLOW = {"timestamp": "2026-10-24 00:18:08.940 KST", "user": "postgres", "dbname": "postgres", "pid": 86,
           "remote_host": "172.21.0.7", "remote_port": 59198, "session_id": "6adb7ab0.56", "line_num": 4,
           "ps": "SELECT", "session_start": "2026-10-24 00:18:08 KST", "vxid": "7/0", "txid": 0,
           "error_severity": "LOG",
           "message": "duration: 301.379 ms  statement: select pg_sleep(0.3); select pg_rotate_logfile();",
           "application_name": "psql", "backend_type": "client backend", "query_id": 0, "pg_log_file": PG_FILE}

BACKEND_AUTH_FAIL = {"timestamp": "2026-09-22T15:40:40.484+09:00", "level": "WARN",
                     "logger": "com.leafy.auth.service.AuthService", "thread": "http-nio-8080-exec-5",
                     "message": "[AUTH] 로그인 실패 loginId=reporter userId=1 reason=wrong_password",
                     "http_method": "POST", "uri": "/api/v1/auth/login", "source_ip": "100.64.0.66"}
BACKEND_ACCESS_401 = {"timestamp": "2026-09-22T15:40:40.501+09:00", "level": "INFO", "logger": "ACCESS",
                      "thread": "http-nio-8080-exec-6",
                      "message": "method=GET uri=/api/v1/notifications status=401 duration_ms=1 source_ip=172.19.0.1 principal=anonymous user_agent=\"curl/8.7.1\" query=\"access_token=***&q=x%0aFAKE\" query_decoded=\"access_token=***&q=x\\nFAKE\"",
                      "duration_ms": 1, "principal": "anonymous", "query_decoded": "access_token=***&q=x\\nFAKE",
                      "http_method": "GET", "query": "access_token=***&q=x%0aFAKE", "uri": "/api/v1/notifications",
                      "user_agent": "curl/8.7.1", "source_ip": "172.19.0.1", "status": 401}
BACKEND_UNHANDLED = {"timestamp": "2026-09-22T15:40:48.956+09:00", "level": "ERROR",
                     "logger": "com.leafy.global.exception.GlobalExceptionHandler", "thread": "http-nio-8080-exec-8",
                     "message": "[UNHANDLED] POST /api/images/upload 처리 중 예외 발생", "http_method": "POST",
                     "uri": "/api/images/upload", "source_ip": "100.64.0.11",
                     "exception_class": "software.amazon.awssdk.core.exception.SdkClientException",
                     "exception_message": "Unable to execute HTTP request: Connect to minio:9000 [minio/172.19.0.2] failed: Connect timed out (SDK Attempt Count: 4)",
                     "stack_trace": "software.amazon.awssdk.core.exception.SdkClientException: Unable to execute HTTP request\n"
                                    + "\tat software.amazon.awssdk.core.internal.http.pipeline.stages.RetryableStage.execute(RetryableStage.java:73)\n" * 300}
NGINX_502 = {"time_iso8601": "2026-10-24T01:10:00+09:00", "msec": 1792771800.123, "request_id": "8f14e45fceea167a5a36dedd4bea2543",
             "remote_addr": "100.64.0.66", "realip_remote_addr": "100.64.0.66", "http_x_forwarded_for": "",
             "request_method": "GET", "request_uri": "/api/v1/plants?id=1%20UNION%20SELECT%201--", "uri": "/api/v1/plants",
             "args": "id=1%20UNION%20SELECT%201--", "status": "502", "upstream_status": "502", "request_time": 0.004,
             "upstream_response_time": "0.004", "http_user_agent": "sqlmap/1.8.4#stable (https://sqlmap.org)",
             "body_bytes_sent": 157}
HIBERNATE_TEXT = "Hibernate: update users set current_plants_count=?,email=?,kakao_access_token=?,password_hash=?,refresh_token=? where user_id=?"


def app(record, labels=BACKEND_LABELS, ts=1.0):
    return {"ts": ts, "labels": dict(labels), "line": json.dumps(dict(record, docker=DOCKER_META), ensure_ascii=False)}


def pg(record, ts=1.0):
    return {"ts": ts, "labels": dict(PG_LABELS), "line": json.dumps(record, ensure_ascii=False)}


def text(raw, ts=1.0, fmt="text"):
    return {"ts": ts, "labels": dict(BACKEND_LABELS, log_format=fmt),
            "line": json.dumps({"message": raw, "docker": DOCKER_META}, ensure_ascii=False)}


def legacy_kv(raw, ts=1.0):
    """Fluentd JSON 전환 이전 key_value 줄 (log_format 라벨 없음)"""
    labels = {k: v for k, v in BACKEND_LABELS.items() if k != "log_format"}
    return {"ts": ts, "labels": labels, "line": f'message="{raw}"'}


class PostgresRcaInputTest(unittest.TestCase):
    def test_auth_failure_message_now_reaches_the_prompt(self):
        entry = pg(PG_AUTH_FAIL)
        before, after = legacy_render(entry), render_log_line(entry)
        # 수정 전: 앞 200자가 메타데이터뿐이고 message가 잘렸다. 접두어도 container 라벨이 없어 [?]
        self.assertNotIn("password authentication failed", before)
        self.assertTrue(before.startswith("[?] "))
        # 수정 후
        self.assertTrue(after.startswith("[db] FATAL 2026-10-24 00:18:05.053 KST password authentication failed"), after)
        self.assertIn("state_code=28P01", after)
        self.assertIn("dbname=postgres remote_host=172.21.0.7", after)
        self.assertNotIn("user=attacker", after)   # 같은 값이 message에 이미 있어 예산을 쓰지 않는다
        self.assertNotIn("\n", after)              # detail의 개행이 프롬프트 줄을 쪼개지 않는다
        self.assertLessEqual(len(after), len("[db] ") + LINE_CHARS)

    def test_only_severe_postgres_lines_are_prioritized(self):
        # 수정 전: 키 이름 error_severity에 "error"가 들어 있어 모든 PostgreSQL 줄이 에러로 선별됐다
        self.assertTrue(legacy_priority(pg(PG_CONN_LOG)))
        self.assertTrue(legacy_priority(pg(PG_SLOW)))
        self.assertFalse(is_priority(pg(PG_CONN_LOG)))
        self.assertFalse(is_priority(pg(PG_SLOW)))
        self.assertTrue(is_priority(pg(PG_AUTH_FAIL)))

    def test_fatal_lines_survive_selection_among_many_log_lines(self):
        logs = [pg(PG_CONN_LOG, ts=i) for i in range(60)] + [pg(PG_AUTH_FAIL, ts=100 + i) for i in range(4)]
        before = self._logs_section(logs, legacy=True)
        after = self._logs_section(logs, legacy=False)
        # 수정 전: 64줄 전부 "에러"라 앞의 30줄(LOG)만 들어가고 FATAL 4줄이 빠졌다
        self.assertEqual(before.count("password authentication failed"), 0)
        self.assertEqual(after.count("password authentication failed"), 4)

    @staticmethod
    def _logs_section(logs, legacy):
        prio, render = (legacy_priority, legacy_render) if legacy else (is_priority, render_log_line)
        errors = [l for l in logs if prio(l)]
        others = [l for l in logs if not prio(l)]
        selected = sorted(errors[:30] + others[:20], key=lambda x: x["ts"])
        return "\n".join(render(l) for l in selected)


class ExistingSourcesTest(unittest.TestCase):
    def test_backend_auth_failure(self):
        after = render_log_line(app(BACKEND_AUTH_FAIL))
        self.assertEqual(
            after,
            "[backend] WARN 2026-09-22T15:40:40.484+09:00 [AUTH] 로그인 실패 loginId=reporter userId=1 reason=wrong_password"
            " | http_method=POST uri=/api/v1/auth/login source_ip=100.64.0.66",
        )
        self.assertTrue(is_priority(app(BACKEND_AUTH_FAIL)))

    def test_backend_access_line_does_not_repeat_fields_already_in_message(self):
        after = render_log_line(app(BACKEND_ACCESS_401))
        self.assertIn("status=401", after)
        self.assertEqual(after.count("status=401"), 1)
        self.assertTrue(is_priority(app(BACKEND_ACCESS_401)))

    def test_backend_exception_keeps_class_and_message_not_stack_frames(self):
        entry = app(BACKEND_UNHANDLED)
        self.assertGreater(len(entry["line"]), 30000)
        after = render_log_line(entry)
        self.assertIn("[UNHANDLED] POST /api/images/upload", after)
        self.assertIn("exception_class=software.amazon.awssdk.core.exception.SdkClientException", after)
        self.assertNotIn("\tat ", after)
        self.assertLessEqual(len(after), len("[backend] ") + LINE_CHARS)

    def test_nginx_json_actual_schema(self):
        entry = app(NGINX_502, labels=FRONTEND_LABELS)
        after = render_log_line(entry)
        self.assertTrue(after.startswith("[frontend] 2026-10-24T01:10:00+09:00 | status=502 request_method=GET "
                                         "request_uri=/api/v1/plants?id=1%20UNION%20SELECT%201--"), after)
        self.assertIn("sqlmap", after)
        self.assertTrue(is_priority(entry))

    def test_text_line_shows_raw_text_not_json_envelope(self):
        entry = text(HIBERNATE_TEXT)
        before, after = legacy_render(entry), render_log_line(entry)
        self.assertTrue(before.startswith('[backend] {"message": "Hibernate'))
        self.assertTrue(after.startswith("[backend] Hibernate: update users set"))
        self.assertFalse(is_priority(entry))
        self.assertTrue(is_priority(text("java.lang.IllegalStateException: boom")))

    def test_pre_migration_key_value_lines_are_unchanged(self):
        entry = legacy_kv("2026-09-22T15:39:45.970+09:00  WARN 1 --- [leafy] AuthService : [AUTH] 로그인 실패")
        self.assertEqual(render_log_line(entry), legacy_render(entry))
        self.assertEqual(is_priority(entry), legacy_priority(entry))


class MaskingTest(unittest.TestCase):
    def test_secrets_are_masked(self):
        cases = {
            "GET /cb?code=x&access_token=abc.def&refresh_token=zzz": "GET /cb?code=x&access_token=***&refresh_token=***",
            'login body {"password":"hunter2","id":"u"}': 'login body {"password":***,"id":"u"}',
            "ALTER ROLE leafy WITH LOGIN PASSWORD 'p@ss'": "ALTER ROLE leafy WITH LOGIN PASSWORD '***'",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part": "Authorization: Bearer ***",
            "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part": "jwt=***",
            "jdbc:postgresql://leafy:s3cret@db:5432/leafy": "jdbc:postgresql://leafy:***@db:5432/leafy",
            "api_key: AKIA123 secret=xyz": "api_key: *** secret=***",
        }
        for raw, expected in cases.items():
            self.assertEqual(mask_secrets(raw), expected, raw)

    def test_ordinary_text_is_untouched(self):
        for raw in ('password authentication failed for user "attacker"',
                    "[AUTH] 로그인 실패 loginId=reporter userId=1 reason=wrong_password",
                    "select u1_0.password_hash from users u1_0 where u1_0.login_id=?"):
            self.assertEqual(mask_secrets(raw), raw)

    def test_masking_applies_to_rendered_lines(self):
        stmt = dict(PG_SLOW, message="duration: 210.0 ms  statement: ALTER ROLE app PASSWORD 'TopSecret!'")
        self.assertIn("PASSWORD '***'", render_log_line(pg(stmt)))
        self.assertNotIn("TopSecret", render_log_line(pg(stmt)))
        self.assertNotIn("abc123", render_log_line(text("callback?access_token=abc123")))


class PromptRegressionTest(unittest.TestCase):
    """PromptBuilder 전체: 길이 상한과 Network 섹션은 그대로, PostgreSQL 핵심 정보만 새로 들어간다."""

    class _Labels:
        alertname, severity, container = "UnauthorizedDBAccess", "critical", None

    class _Alert:
        startsAt = "2026-10-24T00:18:30Z"
        annotations = {"summary": "비인가 DB 직접 접속 시도 탐지", "container": "leafy-db"}

    def setUp(self):
        self._Alert.labels = self._Labels()
        base = datetime(2026, 10, 23, 15, 15, tzinfo=timezone.utc)
        self.network = NetworkContext(service="db", start=base, end=base + timedelta(minutes=10), events=(
            {"src_service": "backend", "dst_service": "db", "protocol": "tcp", "connection_state": "rejected",
             "bytes_sent": None, "bytes_received": None, "duration_ms": None},))
        self.logs = ([pg(PG_CONN_LOG, ts=i) for i in range(40)]
                     + [pg(PG_AUTH_FAIL, ts=50 + i) for i in range(7)]
                     + [pg(PG_SLOW, ts=60)])

    def test_prompt_keeps_limits_and_network_section(self):
        prompt = PromptBuilder().build(alert=self._Alert(), metrics={}, logs=self.logs,
                                       container_name="leafy-db", network=self.network)["user"]
        section = build_network_section(self.network)
        self.assertIn(section, prompt)                       # Network 섹션은 한 글자도 바뀌지 않는다
        self.assertLessEqual(len(prompt), MAX_PROMPT_CHARS + len("\n...(truncated)") + 1 + len(section))
        self.assertEqual(prompt.count("password authentication failed"), 7)
        logs_part = prompt.split("=== LOGS")[1]
        for line in logs_part.splitlines()[1:]:
            if line.startswith("["):
                self.assertLessEqual(len(line), len("[db] ") + LINE_CHARS)


if __name__ == "__main__":
    unittest.main()
