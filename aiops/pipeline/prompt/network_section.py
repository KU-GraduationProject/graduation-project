"""
NetworkContext(#10) -> RCA 프롬프트용 Network Context 섹션 (#11, P4 개선).

flow 단위 요약이되, "목적지가 다르면 다른 flow"가 되도록 (src, dst_service, dst_ip,
dst_port, protocol)로 집계한다. IP/포트가 다른 흐름을 하나로 합치지 않는다.

LLM 에 제공하는 근거 (P4):
  출발지 서비스 · 실제 목적지 IP:포트 · 전송 바이트 · 프로토콜 · 연결 상태 ·
  Allowlist 위반 여부(정책 평가기) · 전송 중 임계 이벤트 시각(P6 조기 신호).

중복 집계 방지 (P6):
  최종(event_type=connection)과 조기(event_type=connection_threshold)는 같은 연결의
  다른 이벤트다. bytes_sent 합계는 최종 이벤트만 더하고, 조기 이벤트는 "early" 신호로만
  따로 표기한다 (두 바이트를 단순 합산하지 않는다).

주의: Allowlist 위반 여부는 정책(사람이 쓴 allowlist)에서 유도한 "증거"다. 시나리오
정답(Ground Truth)이 아니며, [ATTACK]/정답 라벨을 주입하지 않는다.

크기 제한: NETWORK_MAX_CHARS 안에서만 만든다. 넘치면 flow 줄을 아래부터 빼고 개수만
남긴다. 수집 상태/해석 규칙은 절대 자르지 않는다.
"""

from collections import Counter, defaultdict

NETWORK_MAX_CHARS = 1600
MAX_FLOWS = 8

_THRESHOLD = "connection_threshold"

_RULES = (
    "Interpretation rules:",
    "- Supplementary evidence only: do not determine the root cause from network data alone; "
    "use it together with METRICS and LOGS.",
    "- Missing events do NOT mean traffic was absent: a connection is recorded when it closes, "
    "so long-lived connections (e.g. DB connection pools) can be missing from this window, "
    "and the observer can miss traffic.",
    '- "unknown" = endpoint identity could not be resolved; not by itself evidence of an attack.',
    "- allowlist=VIOLATION: destination not on the human-authored allowlist (policy evidence, "
    "not a verdict); a large transfer to an allowlisted destination is expected and NOT an attack.",
    "- early=...: an in-flight transfer crossed a byte threshold before the connection closed; "
    "its bytes are excluded from bytes_sent (no double count). If sources conflict, state it.",
)


def build_network_section(nc, policy=None) -> str:
    """NetworkContext -> 프롬프트 섹션 문자열. policy 가 주어지면 flow 별 Allowlist 위반을 표기."""
    header = (f"\n=== NETWORK CONTEXT (supplementary, service={nc.service}, "
              f"{nc.start:%Y-%m-%dT%H:%M:%SZ} ~ {nc.end:%Y-%m-%dT%H:%M:%SZ}) ===")
    status = _status_lines(nc)

    if not nc.events:
        body = [
            f"0 network events recorded for {nc.service} in this window.",
            "This does NOT mean that traffic was absent or that the network was normal.",
        ]
        return "\n".join([header, *body, *status])

    flows = _aggregate(nc.events)
    intro = f"{len(nc.events)} connections in {len(flows)} flows (src -> dst, protocol):"

    reserve = len("\n(+999 more flows, 999999 connections not shown)")
    budget = NETWORK_MAX_CHARS - len(header) - len(intro) - len("\n".join(status)) - reserve - 2
    lines, used = [], 0
    for key, st in flows[:MAX_FLOWS]:
        line = _flow_line(key, st, policy)
        if used + len(line) + 1 > budget:
            break
        lines.append(line)
        used += len(line) + 1

    hidden = flows[len(lines):]
    if hidden:
        lines.append(f"(+{len(hidden)} more flows, {sum(st['conns'] for _, st in hidden)} connections not shown)")

    return "\n".join([header, intro, *lines, *status])


def _aggregate(events) -> list:
    flows = defaultdict(lambda: {"conns": 0, "states": Counter(), "apps": Counter(),
                                 "sent": [], "recv": [], "dur": [],
                                 "early_ts": [], "early_bytes": [],
                                 "src": None, "dst": None, "dst_ip": None,
                                 "dst_port": None, "proto": None})
    for e in events:
        src = e.get("src_service") or "unknown"
        dst = e.get("dst_service") or "unknown"
        dst_ip = e.get("dst_ip")
        dst_port = e.get("dst_port")
        proto = e.get("protocol") or "other"
        st = flows[(src, dst, dst_ip, dst_port, proto)]
        st["src"], st["dst"], st["dst_ip"], st["dst_port"], st["proto"] = (
            src, dst, dst_ip, dst_port, proto)

        if e.get("event_type") == _THRESHOLD:
            # 조기 이벤트: 바이트는 합산하지 않고 진행 신호로만 기록
            if e.get("timestamp"):
                st["early_ts"].append(e["timestamp"])
            meta = e.get("observer_meta") or {}
            b = meta.get("bytes_threshold")
            if b is None:
                b = e.get("bytes_sent")
            if isinstance(b, (int, float)):
                st["early_bytes"].append(b)
            continue

        # 최종(연결) 이벤트
        st["conns"] += 1
        st["states"][e.get("connection_state") or "unknown"] += 1
        if e.get("app_protocol"):
            st["apps"][e["app_protocol"]] += 1
        for field, bucket in (("bytes_sent", "sent"), ("bytes_received", "recv"), ("duration_ms", "dur")):
            if isinstance(e.get(field), (int, float)):
                st[bucket].append(e[field])

    # connection 수가 많은 flow 먼저, 동률이면 안정적 정렬 (None 비교 오류 방지)
    def order(kv):
        st = kv[1]
        return (-st["conns"], st["src"], st["dst"], str(st["dst_ip"] or ""),
                str(st["dst_port"] or ""), st["proto"])

    return sorted(flows.items(), key=order)


def _flow_line(key, st, policy) -> str:
    src, dst, proto = st["src"], st["dst"], st["proto"]
    app = "/" + ",".join(a for a, _ in st["apps"].most_common(2)) if st["apps"] else ""
    states = " ".join(f"{s}={n}" for s, n in st["states"].most_common())
    sent = sum(st["sent"]) if st["sent"] else "n/a"
    recv = sum(st["recv"]) if st["recv"] else "n/a"
    dur = (f"avg={sum(st['dur']) / len(st['dur']):.0f} max={max(st['dur'])}" if st["dur"] else "n/a")
    base = (f"- {src} -> {dst} {proto}{app}: conns={st['conns']} states[{states}] "
            f"bytes_sent={sent} bytes_recv={recv} duration_ms[{dur}]")

    # 추가 근거 (데이터가 있을 때만 덧붙인다 — 없으면 기존 형식 그대로)
    extras = []
    if st["dst_ip"] and st["dst_port"] is not None:
        extras.append(f"dst={st['dst_ip']}:{st['dst_port']}")

    if policy is not None:
        decision = policy.evaluate({
            "src_service": src, "dst_service": dst,
            "dst_ip": st["dst_ip"], "dst_port": st["dst_port"],
        })
        if decision.applicable:
            if decision.authorized:
                extras.append("allowlist=ok")
            else:
                extras.append(f"allowlist=VIOLATION({decision.reason})")

    if st["early_ts"]:
        earliest = min(st["early_ts"])
        peak = max(st["early_bytes"]) if st["early_bytes"] else None
        tag = f"early={len(st['early_ts'])}@{earliest}"
        if peak is not None:
            tag += f"(>={peak}B)"
        extras.append(tag)

    return base + ("".join(f" | {x}" for x in extras) if extras else "")


def _status_lines(nc) -> list:
    lines = [
        "\n=== NETWORK COLLECTION STATUS ===",
        f"query_complete={str(nc.query_complete).lower()} truncated={str(nc.truncated).lower()} "
        f"skipped={nc.skipped} errors={len(nc.errors)}",
    ]
    if not nc.query_complete:
        lines.append("WARNING: network context is INCOMPLETE; some events may be missing.")
    if nc.truncated:
        lines.append("Event limit reached: some events in this window are not included.")
    if nc.errors:
        more = f" (+{len(nc.errors) - 1} more)" if len(nc.errors) > 1 else ""
        lines.append(f"Collection error: {nc.errors[0][:120]}{more}")
    if nc.skipped:
        lines.append(f"{nc.skipped} malformed network events were ignored.")
    lines.extend(_RULES)
    return lines
