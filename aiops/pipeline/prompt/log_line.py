"""
Loki 로그 한 줄 -> RCA 프롬프트용 한 줄.

JSON 로그는 앞부분이 메타데이터(timestamp, pid, session_id, thread …)라 line[:200]으로 자르면 핵심이 빠진다.
  예: PostgreSQL jsonlog의 message("password authentication failed …")는 약 250자 뒤에 있다.
그래서 JSON이면 핵심 필드를 우선순위대로 골라 같은 길이 예산(LINE_CHARS) 안에 담는다.
  [service] SEVERITY TIMESTAMP MESSAGE | key=value …
텍스트 로그(log_format=text/json_invalid)는 원문을, Fluentd JSON 전환 이전 줄(log_format 라벨 없음)은 기존처럼 line을 쓴다.

LLM에 넘기기 전에 비밀번호·토큰을 가린다 (mask_secrets). Pipeline에는 기존 마스킹이 없었다.
"""

import json
import re

LINE_CHARS = 200   # 기존 line[:200]과 같은 예산
VALUE_CHARS = 300  # 필드 하나를 조립 전에 자르는 길이 (예산 계산 비용 제한)

_SEVERITY_KEYS = ("error_severity", "level")
_MESSAGE_KEYS = ("message",)
_TIME_KEYS = ("timestamp", "@timestamp", "time_iso8601", "time")
# 메시지 뒤에 붙일 필드. 같은 묶음의 다른 이름(PostgreSQL/Backend/Nginx)은 처음 찾은 하나만 쓴다.
_DETAIL_GROUPS = (
    ("state_code", "sql_state_code"),
    ("status",),
    ("request_method", "http_method"),
    ("request_uri", "uri"),
    ("exception_class",),
    ("exception_message",),
    ("user", "principal"),
    ("dbname",),
    ("source_ip", "remote_addr", "remote_host"),
    ("query_decoded",),
    ("http_user_agent", "user_agent"),
    ("duration_ms", "request_time"),
    ("request_id",),
    ("detail",),   # PostgreSQL detail은 길고 여러 줄이라 식별 정보 뒤에 둔다
)
_WHITESPACE = re.compile(r"\s+")

# 기존 선별 기준 (텍스트 줄에만 적용). JSON 줄에 쓰면 키 이름 error_severity 때문에 모든 PostgreSQL 줄이 걸린다.
_TEXT_KEYWORDS = ("error", "exception", "fatal", "warn")
_SEVERE = {"WARN", "WARNING", "ERROR", "FATAL", "PANIC", "CRITICAL", "SEVERE"}

_SECRET_KEY = r"[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential)s?"
_SECRET_PATTERNS = (
    # key=value, key: value, "key":"value"  (password, token, secret, api_key …)
    (re.compile(r"(?i)(\b" + _SECRET_KEY + r"[\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&,;\"'|]+)"), r"\1***"),
    # SQL: CREATE/ALTER ROLE … PASSWORD 'xxx'
    (re.compile(r"(?i)\b(PASSWORD\s+)'[^']*'"), r"\1'***'"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1***"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "***"),   # JWT
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+@"), r"\1***@"),                            # scheme://user:pass@
)


def mask_secrets(text: str) -> str:
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _record(entry: dict) -> dict | None:
    """Fluentd JSON 전환 이후 줄이면 dict, 그 이전(log_format 라벨 없음) 줄이면 None."""
    if "log_format" not in entry.get("labels", {}):
        return None
    try:
        rec = json.loads(entry["line"])
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def _raw_text(rec: dict) -> str:
    """log_format=text/json_invalid 줄의 원문 (앱 로그: message, Fluent Bit 파싱 실패 PostgreSQL: log)"""
    return str(rec.get("message", rec.get("log", "")))


def _first(rec: dict, keys) -> tuple[str, object] | None:
    for key in keys:
        if rec.get(key) not in (None, "", "-"):
            return key, rec[key]
    return None


def _summarize(rec: dict) -> str:
    head = []
    for keys in (_SEVERITY_KEYS, _TIME_KEYS):
        found = _first(rec, keys)
        if found:
            head.append(str(found[1]))
    message = _first(rec, _MESSAGE_KEYS)
    message_text = str(message[1])[:VALUE_CHARS] if message else ""
    if message_text:
        head.append(message_text)

    details = []
    for keys in _DETAIL_GROUPS:
        found = _first(rec, keys)
        if not found:
            continue
        value = str(found[1])[:VALUE_CHARS]
        # Backend ACCESS 로그처럼 message가 이미 같은 값을 담고 있으면 예산을 쓰지 않는다
        if message_text and value in message_text:
            continue
        details.append(f"{found[0]}={value}")

    text = " ".join(head)
    if details:
        text += " | " + " ".join(details)
    return text


def render_log_line(entry: dict) -> str:
    """프롬프트 LOGS 섹션의 한 줄. 접두어는 기존 container 라벨, 없으면(호스트 PostgreSQL) service."""
    labels = entry.get("labels", {})
    prefix = labels.get("container") or labels.get("service") or "?"
    rec = _record(entry)
    if rec is None:
        return f"[{prefix}] {mask_secrets(entry['line'])[:LINE_CHARS]}"
    if labels.get("log_format") in ("text", "json_invalid"):
        body = _raw_text(rec)[:VALUE_CHARS]
    else:
        body = _summarize(rec)
    # 값 안의 개행(PostgreSQL detail, stack trace)이 프롬프트 한 줄을 여러 줄로 쪼개지 않게 한다
    return f"[{prefix}] {mask_secrets(_WHITESPACE.sub(' ', body).strip())[:LINE_CHARS]}"


def is_priority(entry: dict) -> bool:
    """에러/경고 우선 선별. JSON은 심각도·HTTP 상태·예외 필드로, 텍스트는 기존 키워드로 판단한다."""
    rec = _record(entry)
    labels = entry.get("labels", {})
    if rec is None:
        text = entry["line"]
    elif labels.get("log_format") in ("text", "json_invalid"):
        text = _raw_text(rec)
    else:
        severity = _first(rec, _SEVERITY_KEYS)
        if severity and str(severity[1]).upper() in _SEVERE:
            return True
        if rec.get("exception_class") or rec.get("stack_trace"):
            return True
        try:
            return int(str(rec.get("status", 0))) >= 400
        except ValueError:
            return False
    return any(kw in text.lower() for kw in _TEXT_KEYWORDS)
