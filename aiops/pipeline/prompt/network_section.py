"""
NetworkContext(#10) -> RCA 프롬프트용 Network Context 섹션 (#11).

raw event를 넣지 않고 (src_service, dst_service, protocol) flow 단위로 요약한다.
수집 상태와 해석 규칙은 항상 함께 넣는다 — network data는 supplementary / best-effort이기 때문이다.

크기 제한:
  llama3.2:3b가 num_ctx=4096 토큰으로 돌고 있어 기존 system+user만으로도 최대 ~3200 토큰이다.
  이 섹션은 NETWORK_MAX_CHARS 안에서만 만든다. 넘치면 flow 줄을 아래부터 빼고
  "(+N more flows ...)"로 개수만 남긴다. 수집 상태/해석 규칙은 절대 자르지 않는다.
"""

from collections import Counter, defaultdict

NETWORK_MAX_CHARS = 1200
MAX_FLOWS = 8

_RULES = (
    "Interpretation rules:",
    "- Supplementary evidence only: do not determine the root cause from network data alone; "
    "use it together with METRICS and LOGS.",
    "- Missing events do NOT mean traffic was absent: a connection is recorded when it closes, "
    "so long-lived connections (e.g. DB connection pools) can be missing from this window, "
    "and the observer can miss traffic.",
    '- "unknown" = endpoint identity could not be resolved; not by itself evidence of an attack.',
)


def build_network_section(nc) -> str:
    """NetworkContext -> 프롬프트 섹션 문자열 (앞에 빈 줄 포함, 기존 '=== X ===' 형식)"""
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

    # 고정 부분(header/intro/status/생략 안내 여유)을 먼저 빼고 남은 만큼만 flow 줄을 넣는다
    reserve = len("\n(+999 more flows, 999999 connections not shown)")
    budget = NETWORK_MAX_CHARS - len(header) - len(intro) - len("\n".join(status)) - reserve - 2
    lines, used = [], 0
    for key, st in flows[:MAX_FLOWS]:
        line = _flow_line(key, st)
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
                                 "sent": [], "recv": [], "dur": []})
    for e in events:
        st = flows[(e.get("src_service") or "unknown", e.get("dst_service") or "unknown",
                    e.get("protocol") or "other")]
        st["conns"] += 1
        st["states"][e.get("connection_state") or "unknown"] += 1
        if e.get("app_protocol"):
            st["apps"][e["app_protocol"]] += 1
        for field, bucket in (("bytes_sent", "sent"), ("bytes_received", "recv"), ("duration_ms", "dur")):
            if isinstance(e.get(field), (int, float)):
                st[bucket].append(e[field])
    # connection 수가 많은 flow 먼저, 같으면 이름 순 (결과가 항상 같도록)
    return sorted(flows.items(), key=lambda kv: (-kv[1]["conns"], kv[0]))


def _flow_line(key, st) -> str:
    src, dst, proto = key
    app = "/" + ",".join(a for a, _ in st["apps"].most_common(2)) if st["apps"] else ""
    states = " ".join(f"{s}={n}" for s, n in st["states"].most_common())
    sent = sum(st["sent"]) if st["sent"] else "n/a"
    recv = sum(st["recv"]) if st["recv"] else "n/a"
    dur = (f"avg={sum(st['dur']) / len(st['dur']):.0f} max={max(st['dur'])}" if st["dur"] else "n/a")
    return (f"- {src} -> {dst} {proto}{app}: conns={st['conns']} states[{states}] "
            f"bytes_sent={sent} bytes_recv={recv} duration_ms[{dur}]")


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
