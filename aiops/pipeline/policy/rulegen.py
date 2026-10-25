"""
Allowlist -> Loki Ruler LogQL 규칙 생성기 (P3).

Loki Ruler 는 Allowlist YAML 을 직접 읽지 않는다. 정책이 바뀌면 이 생성기를 돌려
LogQL 규칙 파일을 다시 만들고, 검증한 뒤 monitoring/loki/rules/ 에 커밋한다.

생성 규칙(UnauthorizedDataTransfer):
  backend 가 출발지이고, Allowlist(service/endpoint) 에 없는 목적지로,
  분할된 여러 연결의 전송 바이트를 window 안에서 누적해 임계값을 넘으면 경보.

LogQL 설계:
  - service 허용(db/minio/frontend): 스트림 라벨에서 제외 (dst_service!~"...")
  - endpoint 허용(sink-a ip:port): json 이후 (dst_ip!=.. or dst_port!=..) 로 제외
  - 누적: sum by (dst_ip,dst_port) (sum_over_time(... unwrap bytes_sent [window]))
  - JSON/unwrap 오류 처리: | __error__="" , bytes_sent 존재 확인
  - 정상 내부 통신(db 풀 등)은 애초에 제외되어 오탐하지 않는다

CLI:
  python -m policy.rulegen <allowlist.yml> <out_rules.yml>
"""

from __future__ import annotations

import re
import sys

import yaml

from .allowlist import PolicyEvaluator

ALERT_NAME = "UnauthorizedDataTransfer"       # 누적(최종 conn) 기반
ALERT_NAME_EARLY = "UnauthorizedTransferEarly"  # P6 조기(threshold) 기반
GROUP_NAME = "network-allowlist-alerts"
EVENT_CONNECTION = "connection"
EVENT_THRESHOLD = "connection_threshold"

_IDENT = re.compile(r"^[A-Za-z0-9_.-]+$")


class _LiteralStr(str):
    """YAML 에 리터럴 블록 스칼라(|)로 출력될 문자열 (여러 줄 expr 가독성용)."""


def _repr_literal(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


yaml.add_representer(_LiteralStr, _repr_literal, Dumper=yaml.SafeDumper)
_GENERATED_HEADER = (
    "# ⚠ 자동 생성 파일 — 손으로 고치지 말 것.\n"
    "# 정책 변경은 aiops/policy/allowlist.yml 을 고친 뒤 재생성한다:\n"
    "#   cd aiops/pipeline && python -m policy.rulegen ../policy/allowlist.yml "
    "../../monitoring/loki/rules/fake/network-allowlist.yml\n"
)


def _esc_ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"안전하지 않은 식별자: {name!r}")
    return name


def _stream_selector(ev: PolicyEvaluator, event_type: str) -> str:
    """{log_type="network", event_type=..., src_service=..., dst_service!~...} 생성."""
    sources = [_esc_ident(s) for s in ev.sources]
    src_sel = (f'src_service="{sources[0]}"' if len(sources) == 1
               else 'src_service=~"' + "|".join(sources) + '"')
    sel = f'{{log_type="network", event_type="{event_type}", {src_sel}'
    svc_allows = [_esc_ident(s) for s in ev.service_allows()]
    if svc_allows:
        sel += ', dst_service!~"' + "|".join(svc_allows) + '"'
    return sel + "}"


def _endpoint_filters(ev: PolicyEvaluator) -> list[str]:
    """endpoint 허용(ip:port)을 json 이후 라인 필터(제외)로."""
    return [f'| (dst_ip!="{ip}" or dst_port!={int(port)})' for ip, port in ev.endpoint_allows()]


def build_logql(ev: PolicyEvaluator) -> str:
    """
    누적 기반 탐지 (최종 conn.log, event_type=connection).
    분할된 여러 연결의 전송 바이트를 window 안에서 합산해 임계 초과 시 경보.
    event_type=connection 으로 한정해 조기(threshold) 이벤트와 중복 집계하지 않는다.
    """
    stream = _stream_selector(ev, EVENT_CONNECTION)
    pipeline = [
        "| json",
        '| __error__=""',
        *_endpoint_filters(ev),
        '| bytes_sent!=""',
        "| unwrap bytes_sent",
    ]
    inner = f"{stream} " + " ".join(pipeline) + f" [{ev.window}]"
    return (
        f"sum by (dst_ip, dst_port) (\n"
        f"  sum_over_time(\n"
        f"    {inner}\n"
        f"  )\n"
        f") > {ev.min_transfer_bytes}"
    )


def build_early_logql(ev: PolicyEvaluator) -> str:
    """
    조기 탐지 (P6, event_type=connection_threshold).
    비인가 목적지로 가는 "단일 연결"이 Zeek 바이트 임계값을 넘은 순간의 중간 이벤트가
    하나라도 나타나면 즉시 경보. 전송 완료(연결 종료) 전에 탐지한다.
    event_type=connection_threshold 로 한정해 누적 규칙과 분리 — 중복 집계하지 않는다.
    """
    stream = _stream_selector(ev, EVENT_THRESHOLD)
    pipeline = [
        "| json",
        '| __error__=""',
        *_endpoint_filters(ev),
    ]
    inner = f"{stream} " + " ".join(pipeline) + f" [{ev.window}]"
    return (
        f"sum by (dst_ip, dst_port) (\n"
        f"  count_over_time(\n"
        f"    {inner}\n"
        f"  )\n"
        f") > 0"
    )


def build_rule_group(ev: PolicyEvaluator) -> dict:
    return {
        "groups": [
            {
                "name": GROUP_NAME,
                "rules": [
                    {
                        "alert": ALERT_NAME,
                        "expr": _LiteralStr(build_logql(ev)),
                        "for": "0m",
                        "labels": {"severity": "critical", "category": "security",
                                   "detection": "cumulative"},
                        "annotations": {
                            "summary": "비인가 목적지로의 대용량 데이터 전송 탐지",
                            "description": (
                                "backend 가 Allowlist 에 없는 목적지로 임계 초과 전송 "
                                "(dst {{ $labels.dst_ip }}:{{ $labels.dst_port }}, "
                                "누적 {{ $value }} bytes)"
                            ),
                        },
                    },
                    {
                        "alert": ALERT_NAME_EARLY,
                        "expr": _LiteralStr(build_early_logql(ev)),
                        "for": "0m",
                        "labels": {"severity": "critical", "category": "security",
                                   "detection": "early"},
                        "annotations": {
                            "summary": "비인가 목적지로의 전송 중 조기 탐지 (연결 종료 전)",
                            "description": (
                                "backend 의 단일 연결이 Allowlist 에 없는 목적지로 바이트 임계값을 "
                                "초과함 (dst {{ $labels.dst_ip }}:{{ $labels.dst_port }})"
                            ),
                        },
                    },
                ],
            }
        ]
    }


def render_yaml(ev: PolicyEvaluator) -> str:
    body = yaml.safe_dump(build_rule_group(ev), allow_unicode=True, sort_keys=False)
    return _GENERATED_HEADER + body


def validate(rendered: str) -> list[str]:
    """생성 결과의 구조·필수 요소를 점검한다. 문제 목록(빈 리스트면 통과)."""
    problems: list[str] = []
    try:
        doc = yaml.safe_load(rendered)
    except yaml.YAMLError as exc:
        return [f"YAML 파싱 실패: {exc}"]

    try:
        rules = {r["alert"]: r["expr"] for r in doc["groups"][0]["rules"]}
    except (KeyError, IndexError, TypeError):
        return ["groups[0].rules 구조가 없음"]

    if ALERT_NAME not in rules:
        problems.append(f"{ALERT_NAME} 규칙 없음")
    if ALERT_NAME_EARLY not in rules:
        problems.append(f"{ALERT_NAME_EARLY} 규칙 없음")

    acc = rules.get(ALERT_NAME, "")
    for token in ('{log_type="network"', 'event_type="connection"', "| json",
                  '| __error__=""', "| unwrap bytes_sent", "sum_over_time",
                  "sum by (dst_ip, dst_port)", " > "):
        if token not in acc:
            problems.append(f"누적 규칙 expr 에 필수 토큰 누락: {token}")

    early = rules.get(ALERT_NAME_EARLY, "")
    for token in ('event_type="connection_threshold"', "count_over_time", "> 0"):
        if token not in early:
            problems.append(f"조기 규칙 expr 에 필수 토큰 누락: {token}")

    for name, expr in rules.items():
        if expr.count("(") != expr.count(")"):
            problems.append(f"{name} expr 괄호 불균형")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: python -m policy.rulegen <allowlist.yml> <out_rules.yml>", file=sys.stderr)
        return 2
    ev = PolicyEvaluator.from_file(argv[1])
    rendered = render_yaml(ev)
    problems = validate(rendered)
    if problems:
        print("규칙 검증 실패:", file=sys.stderr)
        for p in problems:
            print("  -", p, file=sys.stderr)
        return 1
    with open(argv[2], "w", encoding="utf-8") as fh:
        fh.write(rendered)
    print(f"규칙 생성 완료: {argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
