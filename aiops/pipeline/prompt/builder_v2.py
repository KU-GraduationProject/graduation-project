"""
프롬프트 조립 v2 (PROMPT_BUILDER=v2).

legacy(prompt/builder.py) 대비 바뀐 점 — 11-01 측정에서 드러난 결함:
  - ALERT: 룰 이름·라벨·severity·startsAt·수신 시각·룰 식의 startsAt 값·임계값·시간 창.
    값을 못 가져오면 "value lookup failed" 로 밝힌다.
  - LOGS: 경보 룰과 관련된 줄(룰의 line filter·label filter 일치) 우선, 같은 패턴은
    개수 + 대표 줄로 묶고, 줄은 필요한 필드만 남긴다(prompt/log_line.render_compact).
  - 섹션별 토큰 예산. 넘치면 "N lines omitted" 를 쓰고 truncated 로 기록한다
    (6,000자 일괄 절단 없음).
  - 모든 증거 항목에 ID(A1, M1, L1, N1)를 붙인다. LLM 은 evidence 에 이 ID 만 인용한다.
  - 시각은 모두 UTC(Z) 로 표기한다.

입력에는 경보 시점 관측만 들어간다. 시나리오 이름·정답·변형 정보는 이 모듈에 전달되지 않는다.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone

from correlation import to_instant
from prompt.log_line import is_priority, pattern_key, render_compact
from prompt.network_section import build_network_section_v2
from schemas.actions import ACTION_TARGETS, ACTION_TYPES, INCIDENT_CLASSES, NO_TARGET_ACTIONS, THREAT_LEVELS

# 섹션별 토큰 예산 (num_ctx 4096 - num_predict 400 = 3696 안에 system 포함)
SECTION_BUDGETS = {"alert": 300, "metrics": 350, "logs": 1300, "network": 500}
CHARS_PER_TOKEN = 3          # 보수적 추정 (로그·숫자는 영어 산문보다 토큰이 많다)
MAX_SERIES_PER_METRIC = 2
REPS_PER_PATTERN = 2

SYSTEM_PROMPT_V2 = f"""You are an AIOps incident analyst for a containerized web service. Read the ALERT, METRICS, LOGS and NETWORK sections and return one JSON object only. Respond in English.

Every evidence item in the input starts with an ID in brackets, such as [A1], [M2], [L3], [N1]. All times are UTC.

FIELDS (all required):
- root_cause: at most 2 sentences (max 400 characters): the cause and why the chosen action fits.
- incident_class: one of {" | ".join(INCIDENT_CLASSES)}. benign = normal activity or a false positive.
- action_type: one of {" | ".join(ACTION_TYPES)}.
- action_targets: container names from {", ".join(ACTION_TARGETS)}. Must be [] when action_type is {" or ".join(NO_TARGET_ACTIONS)}.
- threat_level: one of {" | ".join(THREAT_LEVELS)}.
- evidence: the IDs (1 to 5) of the input items you relied on, e.g. ["A1","L2"]. Only IDs that appear in the input.
- confidence: number from 0.0 to 1.0.

ACTION GUIDE:
- NONE: benign activity, a false positive, or the problem has already recovered.
- NOTIFY: a human must decide, or the fitting fix is not one of the automated actions.
- THROTTLE: resource pressure while the service still answers requests.
- RESTART: the service failed or is degraded and a restart is expected to restore it.
- PAUSE: a compromised container whose state must be frozen for forensics.
- ISOLATE: active data exfiltration or network attack from a container.

Input marked "truncated", "omitted" or "value lookup failed" is incomplete: say so and lower confidence instead of guessing."""


# 관측 대상이 호스트(예: 호스트 PostgreSQL)일 때. Docker 조치 대상이 아니다.
HOST_NOTE = ("\n\nThe alert target is a host, not a Docker container: action_targets must be [] and "
             "action_type must be NONE or NOTIFY. Missing evidence is unknown, never healthy.")


def est_tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def utc(value) -> str:
    """epoch 초 / datetime / ISO 문자열 -> 'YYYY-MM-DDTHH:MM:SSZ'."""
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        dt = to_instant(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hms(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%SZ")


def _num(v) -> str:
    return f"{v:.4g}" if isinstance(v, (int, float)) and math.isfinite(v) else str(v)


def _dur(seconds) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


def _labels(alert) -> dict:
    labels = alert.labels
    if hasattr(labels, "model_dump"):
        d = labels.model_dump()
    elif isinstance(labels, dict):
        d = dict(labels)
    else:
        d = dict(vars(labels))
    return {k: v for k, v in d.items() if v not in (None, "")}


# ─── 룰 식 -> 관련 로그 판정 ──────────────────────────────────────────────────
_LIT = r'("(?:[^"\\]|\\.)*"|`[^`]*`)'
_POS_FILTER = re.compile(r'(\|=|\|~)\s*' + _LIT)
# != / !~ 는 앞 필터나 selector 바로 뒤에 올 때만 줄 필터다 (bytes_sent!="" 같은 label filter 제외)
_NEG_FILTER = re.compile(r'[}\)"`]\s*(!=|!~)\s*' + _LIT)
_CONJUNCT = re.compile(r'^([A-Za-z_]\w*)\s*(>=|<=|==|!=|=~|!~|>|<|=)\s*("(?:[^"\\]|\\.)*"|`[^`]*`|[\w.]+)$')
# 줄을 그대로 둔 채 판정할 수 없는 단계 (필드 추출·가공). 이런 룰은 관련 줄 판정을 하지 않는다.
_UNSUPPORTED_STAGES = ("label_format", "line_format", "regexp", "pattern", "template")
_PASS_STAGES = ("json", "logfmt", "unwrap", "drop", "keep", "decolorize", "unpack")


def _pipeline_stages(expr: str) -> list[str]:
    """LogQL 파이프라인을 문자열 밖의 '|' 로 나눈 단계들 (첫 조각 = selector, 줄 필터 단계 제외)."""
    stages, buf, quote = [], [], None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote != "`" and i + 1 < len(expr):
                buf.append(expr[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"`":
            quote = ch
            buf.append(ch)
        elif ch == "|":
            stages.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    stages.append("".join(buf))
    return [st.strip() for st in stages[1:] if st.strip() and st.strip()[0] not in "=~"]


def _label_filters(expr: str):
    """label filter 목록 [(필드, 연산자, 값)]. 판정할 수 없는 단계가 있으면 None."""
    out = []
    for stage in _pipeline_stages(expr):
        stage = re.split(r"\s\[\d", stage)[0].rstrip(") ")      # '... [2m]))' 꼬리 제거
        word = stage.split(None, 1)[0] if stage else ""
        if word in _UNSUPPORTED_STAGES:
            return None
        if word in _PASS_STAGES:
            if word in ("json", "logfmt") and len(stage.split()) > 1:
                return None                                        # json x="y" 필드 추출
            continue
        if re.search(r"\bor\b", stage) or stage.startswith("("):
            return None                                            # or 결합은 흉내 내지 않는다
        for conj in re.split(r"\band\b|,", stage):
            m = _CONJUNCT.match(conj.strip())
            if not m:
                return None
            k, op, v = m.groups()
            v = _unquote(v) if v[0] in "\"`" else v
            if k.startswith("__") or v == "":
                continue                                           # __error__="" / bytes_sent!=""
            out.append((k, op, v))
    return out


def _unquote(lit: str) -> str:
    if lit.startswith("`"):
        return lit[1:-1]
    try:
        return json.loads(lit)
    except ValueError:
        return lit[1:-1]


def rule_log_matcher(expr: str | None):
    """
    LogQL 룰 식의 line filter(|= |~ != !~)와 label filter(| status >= 400 and status < 500)로 만든
    판정 함수. 필터가 없거나(Prometheus 룰), 줄 그대로는 판정할 수 없는 룰(label_format·json 필드
    추출·or 결합)이면 None — 이때 LOGS 는 관련 줄 표시 없이 심각도 우선으로만 고른다.
    """
    if not expr:
        return None
    line_filters = []
    for op, lit in _POS_FILTER.findall(expr) + _NEG_FILTER.findall(expr):
        text = _unquote(lit)
        if op in ("|~", "!~"):
            try:
                line_filters.append((op, re.compile(text)))
            except re.error:
                continue
        else:
            line_filters.append((op, text))
    label_filters = _label_filters(expr)
    if label_filters is None:
        return None
    if not line_filters and not label_filters:
        return None

    def compare(actual, op, expected) -> bool:
        try:
            a, e = float(actual), float(expected)
        except (TypeError, ValueError):
            a, e = str(actual), str(expected)
        if op in ("=~", "!~"):
            hit = re.fullmatch(str(expected), str(actual)) is not None
            return hit if op == "=~" else not hit
        return {">=": a >= e, "<=": a <= e, ">": a > e, "<": a < e,
                "==": a == e, "=": a == e, "!=": a != e}[op]

    def match(entry: dict) -> bool:
        line = entry.get("line", "")
        for op, f in line_filters:
            hit = bool(f.search(line)) if op in ("|~", "!~") else f in line
            if hit != (op in ("|~", "|=")):
                return False
        if label_filters:
            try:
                rec = json.loads(line)
            except ValueError:
                return False
            if not isinstance(rec, dict):
                return False
            for k, op, v in label_filters:
                if k not in rec or not compare(rec[k], op, v):
                    return False
        return True

    return match


# ─── 섹션 ─────────────────────────────────────────────────────────────────────
def _alert_section(alert, container_name, rule, received_at, budget, identity=None, evidence_sources=None):
    labels = _labels(alert)
    name = labels.get("alertname", "?")
    host = identity is not None and getattr(identity, "runtime", None) == "host"
    target = f"host_target={container_name or 'N/A'}" if host else f"container={container_name or 'N/A'}"
    lines = ["=== ALERT (all times UTC) ==="]
    src = f" source={rule.source}" if rule and rule.source else ""
    lines.append(f"[A1] rule={name}{src} severity={labels.get('severity', 'unknown')} {target}")
    lines.append(f"starts_at={utc(alert.startsAt)} received_at={utc(received_at) if received_at else 'unknown'}")
    if rule is None:
        lines.append("rule value: value lookup failed (rule context not collected)")
    else:
        if len(rule.conditions) == 1:
            cond = f"threshold: {rule.conditions[0][0]} {_num(rule.conditions[0][1])}"
        elif rule.conditions:
            cond = "conditions (any): " + " | ".join(f"{op} {_num(th)}" for op, th in rule.conditions)
        else:
            cond = "threshold: unknown"
        value = (f"value_at_start={_num(rule.value)}" if rule.value is not None
                 else f"value_at_start=value lookup failed ({rule.error or 'unknown'})")
        lines.append(f"{value} {cond}")
        timing = (f"window={_dur(rule.window_seconds)} (ranges={','.join(rule.ranges) or 'none'}, "
                  f"for={_dur(rule.for_seconds)}")
        if rule.keep_firing_seconds:
            timing += f", keep_firing_for={_dur(rule.keep_firing_seconds)}"
        if rule.eval_interval_seconds:
            timing += f", eval_every={_dur(rule.eval_interval_seconds)}"
        lines.append(timing + ")")
    extra = {k: v for k, v in labels.items() if k not in ("alertname", "severity")}
    optional = []
    if identity is not None:
        # legacy 와 같은 JSON 표기 (identity 계약 테스트와 Loki 기록 형식에 맞춘다)
        optional.append("observation identity: " + json.dumps(identity.to_dict()))
        status = {n: (r or {}).get("status", "?") for n, r in (evidence_sources or {}).items()}
        if status:
            optional.append("evidence availability: " + ", ".join(f"{n}={v}" for n, v in status.items()))
    if extra:
        optional.append("labels: " + ", ".join(f"{k}={v}" for k, v in sorted(extra.items())))
    summary = (getattr(alert, "annotations", None) or {}).get("summary")
    if summary:
        optional.append(f"summary: {summary}")
    truncated = False
    for line in optional:
        if est_tokens("\n".join(lines + [line])) > budget:
            truncated = True
            lines.append("(alert details truncated)")
            break
        lines.append(line)
    return "\n".join(lines), ["A1"], truncated, 0


def _metric_unit(name: str):
    if name.startswith("net_"):
        return 1 / 1024, "KiB/s"
    if name.startswith("memory_"):
        return 1 / (1024 * 1024), "MiB"
    return 1, ""


def _metrics_section(metrics: dict, anchor_epoch: float, budget):
    header = "\n=== METRICS ==="
    lines, ids, omitted = [header], [], 0
    n = 0
    for name, series_list in (metrics or {}).items():
        for series in (series_list or [])[:MAX_SERIES_PER_METRIC]:
            pts = [p for p in series.get("values", []) if p.get("v") is not None]
            if not pts:
                continue
            scale, unit = _metric_unit(name)
            vals = [p["v"] * scale for p in pts]
            at = min(pts, key=lambda p: abs(p["t"] - anchor_epoch))["v"] * scale
            n += 1
            line = (f"[M{n}] {name}{' (' + unit + ')' if unit else ''}: at_start={_num(at)} "
                    f"latest={_num(vals[-1])} peak={_num(max(vals))} min={_num(min(vals))} "
                    f"(n={len(vals)}, {_hms(pts[0]['t'])}~{_hms(pts[-1]['t'])})")
            if est_tokens("\n".join(lines + [line])) > budget - 10:
                omitted += 1
                continue
            lines.append(line)
            ids.append(f"M{n}")
    if n == 0:
        lines.append("no metric samples collected")
    if omitted:
        lines.append(f"({omitted} metric series omitted: budget)")
    return "\n".join(lines), ids, bool(omitted), omitted


def _logs_section(logs: list, rule, log_meta: dict | None, budget):
    meta = log_meta or {}
    window = (f", {utc(meta['start'])} ~ {utc(meta['end'])}" if meta.get("start") and meta.get("end") else "")
    status = (getattr(logs, "report", None) or {}).get("status")
    status = f", collector status={status}" if status else ""
    header = f"\n=== LOGS ({len(logs)} lines fetched{window}{status}; rule-matching first, newest first) ==="
    lines = [header]
    if meta.get("limit") and len(logs) >= meta["limit"]:
        lines.append(f"(fetch limit {meta['limit']} reached: older lines in the window were not fetched)")
    if not logs:
        lines.append("no log lines in this window")
        return "\n".join(lines), [], False, 0

    matcher = rule_log_matcher(rule.expr if rule else None)
    groups = defaultdict(list)
    for e in logs:
        groups[pattern_key(e)].append(e)

    def score(entries):
        if matcher and any(matcher(e) for e in entries):
            return 2
        return 1 if any(is_priority(e) for e in entries) else 0

    ranked = []
    for entries in groups.values():
        entries.sort(key=lambda e: e["ts"], reverse=True)
        ranked.append((score(entries), entries))
    ranked.sort(key=lambda se: (-se[0], -se[1][0]["ts"]))

    ids, omitted_lines, omitted_groups = [], 0, 0
    for i, (sc, entries) in enumerate(ranked, start=1):
        tag = " [rule-match]" if sc == 2 else ""
        first = render_compact(entries[0])
        if len(entries) == 1:
            block = [f"[L{i}] {_hms(entries[0]['ts'])} {first}{tag}"]
        else:
            block = [f"[L{i}] x{len(entries)} {_hms(entries[-1]['ts'])}~{_hms(entries[0]['ts'])} {first}{tag}"]
            seen = {first}
            for e in entries[1:]:
                if len(block) > REPS_PER_PATTERN - 1:
                    break
                r = render_compact(e)
                if r not in seen:
                    seen.add(r)
                    block.append(f"    e.g. {_hms(e['ts'])} {r}")
        if est_tokens("\n".join(lines + block)) > budget - 15:
            omitted_lines += len(entries)
            omitted_groups += 1
            continue
        lines.extend(block)
        ids.append(f"L{i}")
    if omitted_lines:
        lines.append(f"({omitted_lines} lines omitted in {omitted_groups} patterns: budget)")
    return "\n".join(lines), ids, bool(omitted_lines), omitted_lines


def _network_section(network, policy, budget):
    if network is None or not getattr(network, "service", None):
        return "\n=== NETWORK CONTEXT ===\nnot collected (service unknown)", [], False, 0
    text, ids, hidden = build_network_section_v2(
        network, policy=policy, max_chars=budget * CHARS_PER_TOKEN,
        fmt_ts=lambda ts: utc(ts) if ts else ts)
    return text, ids, bool(hidden), hidden


class PromptBuilderV2:
    def build(self, alert, metrics: dict, logs: list[dict], container_name: str | None = None,
              network=None, rule=None, received_at=None, log_meta: dict | None = None,
              policy=None, identity=None, evidence_sources=None) -> dict:
        """
        반환: system, user, evidence_ids(프롬프트에 붙인 ID), truncated(섹션 하나라도 잘림),
        sections(섹션별 추정 토큰·예산·잘림·생략 수), builder="v2".
        """
        if policy is None:
            from prompt.builder import _load_policy
            policy = _load_policy()
        anchor = to_instant(alert.startsAt).timestamp()
        parts = {
            "alert": _alert_section(alert, container_name, rule, received_at, SECTION_BUDGETS["alert"],
                                    identity, evidence_sources),
            "metrics": _metrics_section(metrics, anchor, SECTION_BUDGETS["metrics"]),
            "logs": _logs_section(logs if logs is not None else [], rule, log_meta, SECTION_BUDGETS["logs"]),
            "network": _network_section(network, policy, SECTION_BUDGETS["network"]),
        }
        sections, evidence_ids, texts = {}, [], []
        for name, (text, ids, truncated, omitted) in parts.items():
            texts.append(text)
            evidence_ids.extend(ids)
            sections[name] = {"tokens_est": est_tokens(text), "budget": SECTION_BUDGETS[name],
                              "truncated": truncated, "omitted": omitted}
        user = "\n".join(texts) + "\n\nAnalyze the above data and respond with JSON only."
        system = SYSTEM_PROMPT_V2
        if identity is not None and getattr(identity, "runtime", None) == "host":
            system += HOST_NOTE
        return {
            "system": system,
            "user": user,
            "evidence_ids": evidence_ids,
            "truncated": any(s["truncated"] for s in sections.values()),
            "sections": sections,
            "builder": "v2",
        }
