#!/usr/bin/env python3
"""
scenarios/run.py
────────────────
AIOps 시나리오 통합 런처

공통 파이프라인:
  ① 매트릭스 레인 인트로
  ② Before 메트릭 스냅샷
  ③ 공격 실행 + 실시간 로그 스트림
  ④ LLM 분석 결과 (타이프라이터 효과)
  ⑤ 조치 결과 패널
  ⑥ After 메트릭 + Before/After 비교 테이블
  ⑦ 시나리오별 고유 패널

고유 패널 보유 시나리오:
  memory_leak      — 재시작 이벤트 타임라인
  brute_force      — 2막 구조 (인증실패 → 크레덴셜 → RCE)
  data_exfil       — 탐지 사각지대 + 탈취 데이터 reveal
  secret_dump      — 탈취 환경변수 + 공격 체인
  lateral_movement — 소스 IP 비교 (정상 vs 공격자)
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.parse
from datetime import datetime

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

console = Console()

PIPELINE_URL  = os.getenv("PIPELINE_URL", "http://localhost:8000")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
LOKI_URL       = os.getenv("LOKI_URL", "http://localhost:3100")
SCENARIOS_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR       = os.path.join(SCENARIOS_DIR, "logs")

# 컨테이너 이름 → Prometheus docker id 캐시 (첫 조회 시 채워짐)
_CONTAINER_ID_CACHE: dict[str, str] = {}

# ── 시나리오 레지스트리 ────────────────────────────────────────────────────────
SCENARIO_REGISTRY = [
    {
        "id": "cpu_stress", "label": "CPU 스트레스",
        "subtitle": "dd/stress-ng로 leafy-backend CPU 고갈",
        "category": "인프라", "owasp": None, "mitre": None,
        "container": "leafy-backend", "loki_container": "leafy-backend",
        "alert_name": "HighCpuUsage", "alert_fires": True, "blind_spot": False,
        "module": "category1_infra.cpu_stress", "custom_panel": None,
    },
    {
        "id": "http_flood", "label": "HTTP Flood",
        "subtitle": "300 workers × 300s  ·  FloodBot/1.0",
        "category": "인프라", "owasp": "A05:2021", "mitre": None,
        "container": "leafy-frontend", "loki_container": "frontend",
        "alert_name": "HighNginxErrorRate", "alert_fires": True, "blind_spot": False,
        "module": "category1_infra.http_flood", "custom_panel": None,
    },
    {
        "id": "memory_leak", "label": "메모리 누수 (OOM 시뮬)",
        "subtitle": "leafy-backend 90초 주기 4회 강제 재시작",
        "category": "인프라", "owasp": None, "mitre": None,
        "container": "leafy-backend", "loki_container": "leafy-backend",
        "alert_name": "ContainerRestarted", "alert_fires": False, "blind_spot": False,
        "module": "category1_infra.memory_leak", "custom_panel": "memory_leak",
    },
    {
        "id": "redos_attack", "label": "ReDoS (HTTP 폭주)",
        "subtitle": "300 workers  ·  ReDoSBot/1.0  ·  Nginx CPU 고갈",
        "category": "인프라", "owasp": "A05:2021", "mitre": None,
        "container": "leafy-frontend", "loki_container": "frontend",
        "alert_name": "HighNginxErrorRate", "alert_fires": True, "blind_spot": False,
        "module": "category1_infra.redos_attack", "custom_panel": None,
    },
    {
        "id": "brute_force", "label": "DB 브루트포스 + RCE",
        "subtitle": "postgres 1000회 → 크레덴셜 탈취 → COPY FROM PROGRAM",
        "category": "보안", "owasp": None, "mitre": "TA0006 + TA0002",
        "container": "leafy-db", "loki_container": "leafy-db",
        "alert_name": "HighCpuUsage", "alert_fires": True, "blind_spot": False,
        "module": "category2_security.brute_force", "custom_panel": "brute_force",
    },
    {
        "id": "data_exfil", "label": "데이터 탈취 (탐지 사각지대)",
        "subtitle": "leaked_users 전체 덤프 → CSV  ·  alert 없음",
        "category": "보안", "owasp": "A01:2021", "mitre": "TA0010",
        "container": "leafy-db", "loki_container": "leafy-db",
        "alert_name": "없음 (탐지 사각지대)", "alert_fires": False, "blind_spot": True,
        "module": "category2_security.data_exfil", "custom_panel": "data_exfil",
    },
    {
        "id": "lateral_movement", "label": "컨테이너 횡적 이동",
        "subtitle": "침해 컨테이너 → DB 직접 접속 (backend 우회)",
        "category": "보안", "owasp": None, "mitre": "TA0008",
        "container": "leafy-db", "loki_container": "leafy-db",
        "alert_name": "LateralMovement", "alert_fires": False, "blind_spot": False,
        "module": "category2_security.lateral_movement", "custom_panel": "lateral_movement",
    },
    {
        "id": "n_plus_one_attack", "label": "N+1 쿼리 공격",
        "subtitle": "100 연결 × pg_sleep(30) → PostgreSQL 연결 고갈",
        "category": "보안", "owasp": "A04:2021", "mitre": None,
        "container": "leafy-db", "loki_container": "leafy-db",
        "alert_name": "HighPostgresConnections", "alert_fires": True, "blind_spot": False,
        "module": "category2_security.n_plus_one_attack", "custom_panel": None,
    },
    {
        "id": "secret_dump", "label": "환경변수 덤프 (탐지 사각지대)",
        "subtitle": "env / printenv / /proc/1/environ  ·  alert 없음",
        "category": "보안", "owasp": "A02:2021", "mitre": "TA0006",
        "container": "leafy-backend", "loki_container": "leafy-backend",
        "alert_name": "없음 (탐지 사각지대)", "alert_fires": False, "blind_spot": True,
        "module": "category2_security.secret_dump", "custom_panel": "secret_dump",
    },
    {
        "id": "sql_injection", "label": "SQL Injection 스캐닝",
        "subtitle": "sqlmap/1.7  ·  13가지 페이로드  ·  100 workers",
        "category": "보안", "owasp": "A03:2021", "mitre": None,
        "container": "leafy-frontend", "loki_container": "frontend",
        "alert_name": "HighNginxErrorRate", "alert_fires": True, "blind_spot": False,
        "module": "category2_security.sql_injection", "custom_panel": None,
    },
]

# ── HTTP 유틸 ─────────────────────────────────────────────────────────────────
def _get(url: str, timeout: int = 8):
    """GET 요청. 응답은 list 또는 dict 모두 가능."""
    try:
        r = urllib.request.urlopen(url, timeout=timeout)
        return json.loads(r.read().decode())
    except Exception:
        return None


def _resolve_container_id(container_name: str) -> str | None:
    """
    Pipeline /metrics 에서 container_name_info를 파싱해
    컨테이너 이름 → Prometheus id 레이블 값("/docker/abc...")을 반환.
    """
    if container_name in _CONTAINER_ID_CACHE:
        return _CONTAINER_ID_CACHE[container_name]
    try:
        r = urllib.request.urlopen(f"{PIPELINE_URL}/metrics", timeout=5)
        text = r.read().decode()
    except Exception:
        return None
    for line in text.splitlines():
        if "container_name_info" not in line or line.startswith("#"):
            continue
        if f'name="{container_name}"' in line:
            import re as _re
            m = _re.search(r'id="([^"]+)"', line)
            if m:
                _CONTAINER_ID_CACHE[container_name] = m.group(1)
                return m.group(1)
    return None


def fetch_metrics(container: str) -> dict:
    """Prometheus에서 컨테이너별 CPU/메모리를 직접 조회."""
    docker_id = _resolve_container_id(container)
    if not docker_id:
        return {}

    def _prom(query: str):
        try:
            url = f"{PROMETHEUS_URL}/api/v1/query?" + urllib.parse.urlencode({"query": query})
            r = urllib.request.urlopen(url, timeout=5)
            data = json.loads(r.read().decode())
            result = data.get("data", {}).get("result", [])
            return float(result[0]["value"][1]) if result else None
        except Exception:
            return None

    cpu = _prom(f'irate(container_cpu_usage_seconds_total{{id="{docker_id}",cpu="total"}}[30s])')
    mem = _prom(f'container_memory_usage_bytes{{id="{docker_id}"}}')
    mem_limit = _prom(f'container_spec_memory_limit_bytes{{id="{docker_id}"}}')

    snap = {}
    if cpu is not None:
        snap["cpu_usage"] = cpu
    if mem is not None:
        snap["memory_usage"] = mem
    if mem_limit and mem_limit > 0:
        snap["memory_limit"] = mem_limit
    return snap


def fetch_logs(loki_container: str, lines: int = 12) -> list[str]:
    """Loki에서 컨테이너 로그를 직접 조회."""
    try:
        end_ns   = int(time.time() * 1_000_000_000)
        start_ns = end_ns - 5 * 60 * 1_000_000_000  # 최근 5분
        params   = urllib.parse.urlencode({
            "query":     f'{{container="{loki_container}"}}',
            "start":     start_ns,
            "end":       end_ns,
            "limit":     lines,
            "direction": "backward",
        })
        url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
        r   = urllib.request.urlopen(url, timeout=6)
        data = json.loads(r.read().decode())
        streams = data.get("data", {}).get("result", [])
        rows = []
        for stream in streams:
            for ts_ns, line in stream.get("values", []):
                ts = datetime.utcfromtimestamp(int(ts_ns) / 1e9).strftime("%Y-%m-%d %H:%M:%S")
                # JSON 로그면 message 필드만 추출
                try:
                    obj = json.loads(line)
                    msg = obj.get("message") or obj.get("log") or line
                except Exception:
                    msg = line
                rows.append(f"{ts}  {str(msg)[:120]}")
        rows.sort(reverse=True)
        return rows[:lines] if rows else ["(최근 5분 로그 없음)"]
    except Exception as e:
        return [f"Loki 조회 실패: {e}"]


def get_result_count() -> int:
    """/results 가 list를 반환하므로 길이로 count 측정."""
    data = _get(f"{PIPELINE_URL}/results")
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict) and data.get("status") == "ok":
        return data.get("count", 0)
    return 0


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[mK]", "", text)


# ── 해커 기믹 ─────────────────────────────────────────────────────────────────
MATRIX_CHARS = "01アイウエオカキクケコサシスセソタチツテトBRACKETINFILTRATED▓▒░"

def matrix_rain(duration: float = 1.8):
    """매트릭스 레인 — 공격 시작 직전 연출"""
    width = shutil.get_terminal_size((100, 24)).columns
    end   = time.time() + duration
    while time.time() < end:
        line = "".join(random.choice(MATRIX_CHARS) for _ in range(width))
        console.print(line, style="bold green", highlight=False, end="\n")
        time.sleep(0.045)
    console.print()


def glitch_banner(text: str, style: str = "bold red", iterations: int = 4):
    """텍스트가 글리치 후 확정되는 효과"""
    glitch_pool = "!@#$%^&*<>?/\\|█▓▒░■□▪▫"
    width = len(text)
    for _ in range(iterations):
        g = "".join(random.choice(glitch_pool) if random.random() < 0.45 else c for c in text)
        print(f"\r  {g}", end="", flush=True)
        time.sleep(0.08)
    print(f"\r  {' ' * (width + 2)}\r", end="")
    console.print(f"  {text}", style=style)


def typewriter(text: str, style: str = "white", delay: float = 0.012, indent: str = "  "):
    """타이프라이터 효과로 한 글자씩 출력"""
    print(indent, end="", flush=True)
    for ch in text:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()


_ANSI = {
    "cyan":    "\033[36m",
    "magenta": "\033[35m",
    "green":   "\033[32m",
    "red":     "\033[31m",
    "yellow":  "\033[33m",
    "reset":   "\033[0m",
}

def scan_bar(label: str, duration: float = 1.2, color: str = "cyan"):
    """스캔 진행 바 효과 (ANSI 코드 사용 — 모든 터미널 호환)"""
    width  = 40
    c      = _ANSI.get(color, "")
    reset  = _ANSI["reset"]
    end    = time.time() + duration
    while time.time() < end:
        filled = int((1 - (end - time.time()) / duration) * width)
        bar    = "█" * filled + "░" * (width - filled)
        pct    = int(filled / width * 100)
        print(f"\r  {c}{label}{reset}  [{bar}] {pct:3d}%", end="", flush=True)
        time.sleep(0.04)
    full = "█" * width
    print(f"\r  {c}{label}{reset}  [{full}] 100%", flush=True)


# ── 스파크라인 ────────────────────────────────────────────────────────────────
_BLOCKS = "▁▂▃▄▅▆▇█"

def sparkline(values: list[float]) -> str:
    if not values:
        return "—"
    lo, hi = min(values), max(values)
    if hi == lo:
        return _BLOCKS[0] * min(len(values), 20)
    return "".join(_BLOCKS[int((v - lo) / (hi - lo) * 7)] for v in values[-20:])


def fmt_metric(key: str, val) -> str:
    """메트릭 값을 사람이 읽기 쉬운 형태로 포맷"""
    if val is None:
        return "[dim]N/A[/dim]"
    try:
        f = float(val)
        if key == "cpu_usage":
            color = "bold red" if f > 0.5 else ("yellow" if f > 0.2 else "green")
            return f"[{color}]{f*100:.1f}%[/{color}]"
        if "memory" in key:
            return f"{f/1024/1024:.1f} MB"
        if "net" in key:
            return f"{f/1024:.1f} KB/s"
        return f"{f:.3f}"
    except Exception:
        return str(val)


# ── 메트릭 스냅샷 컬렉터 (백그라운드) ────────────────────────────────────────
class MetricCollector:
    """공격 진행 중 10초마다 메트릭을 폴링해 시계열을 수집한다."""

    def __init__(self, container: str):
        self.container = container
        self.samples: list[tuple[float, dict]] = []
        self._stop = threading.Event()

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=6)

    def _loop(self):
        while not self._stop.wait(10):
            snap = fetch_metrics(self.container)
            if snap:
                self.samples.append((time.time(), snap))

    def get_spark(self, key: str) -> str:
        vals = [s.get(key) for _, s in self.samples if s.get(key) is not None]
        return sparkline([float(v) for v in vals])

    def peak(self, key: str):
        vals = [float(s[key]) for _, s in self.samples if s.get(key) is not None]
        return max(vals) if vals else None


# ── 서브프로세스 실행 ─────────────────────────────────────────────────────────
def launch_scenario(meta: dict) -> tuple[subprocess.Popen, str]:
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"{meta['id']}_run.log")
    script   = (
        f"import sys; sys.path.insert(0, {repr(SCENARIOS_DIR)}); "
        f"from {meta['module']} import main; main()"
    )
    log_file = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=log_file, stderr=log_file,
    )
    return proc, log_path


# ── LLM 폴링 + 실시간 로그 스트림 ────────────────────────────────────────────
def wait_for_llm(baseline: int, log_path: str, timeout: int = 240) -> dict | None:
    """LLM 결과 대기하면서 시나리오 로그를 터미널에 실시간 출력"""
    spinners = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    deadline = time.time() + timeout
    idx      = 0
    offset   = 0

    console.print()
    console.print(Rule("[dim cyan]공격 진행 중 — 실시간 로그[/dim cyan]", style="dim cyan"))

    while time.time() < deadline:
        # 새 LLM 결과 확인 (/results는 list를 직접 반환)
        data = _get(f"{PIPELINE_URL}/results")
        if isinstance(data, list) and len(data) > baseline:
            console.print()
            return data[-1]
        elif isinstance(data, dict) and data.get("status") == "ok":
            entries = data.get("data", [])
            if len(entries) > baseline:
                console.print()
                return entries[-1]

        # 로그 파일 tail
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                new = f.read()
                offset = f.tell()
            for line in new.splitlines()[-4:]:
                line = strip_ansi(line).strip()
                if not line:
                    continue
                low = line.lower()
                if any(k in low for k in ("error", "fail", "fatal", "exception")):
                    console.print(f"  [dim red]{line[:120]}[/dim red]")
                elif any(k in low for k in ("success", "ok", "완료", "found", "발견", "started")):
                    console.print(f"  [dim green]{line[:120]}[/dim green]")
                elif any(k in low for k in ("warn", "경고", "주의")):
                    console.print(f"  [dim yellow]{line[:120]}[/dim yellow]")
                else:
                    console.print(f"  [dim]{line[:120]}[/dim]")

        elapsed = int(time.time() - (deadline - timeout))
        print(
            f"\r  [{spinners[idx % len(spinners)]}] "
            f"Alert → AlertManager → Pipeline → LLM 대기...  "
            f"{elapsed}s / {timeout}s        ",
            end="", flush=True,
        )
        time.sleep(1)
        idx += 1

    console.print()
    return None


# ── 공통 패널 렌더러 ──────────────────────────────────────────────────────────
def panel_scenario_info(meta: dict, start_time: str):
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold cyan", no_wrap=True, min_width=14)
    t.add_column()
    t.add_row("시나리오",     meta["label"])
    t.add_row("설명",         meta["subtitle"])
    t.add_row("카테고리",     meta["category"])
    if meta.get("owasp"):
        t.add_row("OWASP",    meta["owasp"])
    if meta.get("mitre"):
        t.add_row("MITRE",    meta["mitre"])
    t.add_row("대상 컨테이너", meta["container"])
    t.add_row("예상 Alert",   meta["alert_name"])
    t.add_row("Alert 자동발화", "✅ 예" if meta["alert_fires"] else "⚠️  수동 웹훅 / 없음")
    t.add_row("실행 시각",    start_time)
    border = "red" if meta["blind_spot"] else "cyan"
    console.print(Panel(t, title="[bold]시나리오 정보[/bold]", border_style=border))


def panel_metrics(label: str, snapshot: dict, border: str = "blue"):
    if not snapshot:
        console.print(Panel("[dim]메트릭 없음 (Pipeline 미실행)[/dim]",
                            title=f"[bold]{label}[/bold]", border_style=border))
        return
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold green", no_wrap=True, min_width=20)
    t.add_column(justify="right")
    LABELS = {
        "cpu_usage":    "CPU 사용률",
        "memory_usage": "메모리 사용",
        "memory_limit": "메모리 한도",
        "net_rx_bytes": "네트워크 수신",
        "net_tx_bytes": "네트워크 송신",
        "host_cpu":     "호스트 CPU",
        "host_mem":     "호스트 메모리",
    }
    for k, v in snapshot.items():
        t.add_row(LABELS.get(k, k), fmt_metric(k, v))
    console.print(Panel(t, title=f"[bold]{label}[/bold]", border_style=border))


def panel_before_after(before: dict, after: dict, collector: MetricCollector):
    if not before and not after:
        return
    t = Table(box=box.DOUBLE_EDGE, show_header=True, header_style="bold cyan",
              padding=(0, 2), border_style="cyan")
    t.add_column("메트릭",    style="bold", no_wrap=True, min_width=18)
    t.add_column("공격 전",   justify="right", min_width=14)
    t.add_column("공격 후",   justify="right", min_width=14)
    t.add_column("Peak",     justify="right", min_width=14)
    t.add_column("추이",      justify="center", min_width=22)

    LABELS = {
        "cpu_usage": "CPU 사용률",
        "memory_usage": "메모리 사용",
        "net_rx_bytes": "네트워크 수신",
    }
    keys = list({**before, **after}.keys())
    for k in keys:
        if k not in LABELS:
            continue
        b   = fmt_metric(k, before.get(k))
        a   = fmt_metric(k, after.get(k))
        pk  = collector.peak(k)
        pks = fmt_metric(k, pk) if pk is not None else "[dim]—[/dim]"
        sp  = f"[green]{collector.get_spark(k)}[/green]" if collector.get_spark(k) != "—" else "[dim]—[/dim]"
        t.add_row(LABELS[k], b, a, pks, sp)

    console.print(Panel(t, title="[bold cyan]📊 Before / After 비교[/bold cyan]", border_style="cyan"))


def panel_llm_result(entry: dict):
    result     = entry.get("result", {})
    alert_name = entry.get("alert_name", "N/A")
    container  = entry.get("container",  "N/A")
    ts         = entry.get("timestamp",  "")[:19].replace("T", " ")

    tl      = result.get("threat_level", "").lower()
    tl_col  = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(tl, "white")
    ar      = result.get("action_risk", "").lower()
    ar_col  = {"high": "red", "medium": "yellow", "low": "green"}.get(ar, "white")

    console.print()
    console.print(Rule("[bold yellow]🤖  LLM 분석 결과[/bold yellow]", style="yellow"))
    console.print()

    fields = [
        ("Alert",        alert_name),
        ("Container",    container),
        ("분석 시각",    ts),
        ("",             ""),
        ("root_cause",   result.get("root_cause", "N/A")),
        ("threat_level", f"[{tl_col}]{result.get('threat_level','N/A')}[/{tl_col}]"),
        ("action_risk",  f"[{ar_col}]{result.get('action_risk','N/A')}[/{ar_col}]"),
        ("action",       f"[bold white]{result.get('action','N/A')}[/bold white]"),
        ("confidence",   str(result.get("confidence", "N/A"))),
    ]
    for idx, ev in enumerate(result.get("evidence", [])):
        fields.append(("evidence" if idx == 0 else "", f"· {ev}"))

    for key, val in fields:
        if not key and not val:
            console.print()
            continue
        label = f"  [bold green]{key:<14s}[/bold green]: " if key else " " * 18
        print(label, end="", flush=True)
        # 긴 텍스트는 타이프라이터 효과
        clean = strip_ansi(val)
        for ch in clean:
            print(ch, end="", flush=True)
            time.sleep(0.008)
        print()
        time.sleep(0.05)

    console.print()


def panel_remediation(result: dict):
    ar      = result.get("action_risk", "unknown").lower()
    action  = result.get("action", "N/A")
    ar_col  = {"low": "green", "medium": "yellow", "high": "red"}.get(ar, "white")

    if ar == "low":
        decision = "[bold green]✅  자동 조치 실행됨[/bold green]"
        detail   = f"Remediation Agent가 자동으로 [bold]{action}[/bold] 수행"
    elif ar == "medium":
        decision = "[bold yellow]⚠️   관리자 승인 대기 중[/bold yellow]"
        detail   = f"자동 실행 보류 · 제안된 조치: [bold]{action}[/bold]"
    else:
        decision = "[bold red]🚨  긴급 격리 요청 발송[/bold red]"
        detail   = f"즉시 조치 필요: [bold]{action}[/bold]"

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold magenta", no_wrap=True, min_width=14)
    t.add_column(overflow="fold")
    t.add_row("결정",        decision)
    t.add_row("상세",        detail)
    t.add_row("action_risk", f"[{ar_col}]{ar}[/{ar_col}]")
    t.add_row("action",      action)
    console.print(Panel(t, title="[bold magenta]🛡  조치 결과[/bold magenta]", border_style="magenta"))


def panel_logs(container: str, label: str = "Loki 로그 (최근 5분)"):
    logs = fetch_logs(container)
    content = Text()
    for line in logs:
        low = line.lower()
        if any(k in low for k in ("error", "fail", "fatal")):
            content.append(line + "\n", style="red")
        elif any(k in low for k in ("warn",)):
            content.append(line + "\n", style="yellow")
        else:
            content.append(line + "\n", style="dim")
    console.print(Panel(content, title=f"[bold green]{label}[/bold green]", border_style="green"))


# ── 시나리오별 고유 패널 ──────────────────────────────────────────────────────
def custom_panel_memory_leak(log_path: str):
    """재시작 이벤트를 타임라인으로 표시"""
    restarts = []
    starts   = []
    if os.path.exists(log_path):
        for line in open(log_path, encoding="utf-8", errors="replace"):
            line = strip_ansi(line).strip()
            if "재시작 시도" in line or "강제 재시작" in line:
                restarts.append(line[:80])
            if "started" in line.lower() or "재시작 후 상태" in line:
                starts.append(line[:80])

    content = Text()
    content.append("재시작 이벤트 타임라인\n\n", style="bold yellow")
    if not restarts:
        content.append("  로그 파싱 결과 없음 (시나리오 진행 중일 수 있음)\n", style="dim")
    for i, r in enumerate(restarts, 1):
        content.append(f"  [{i}] ", style="bold red")
        content.append(f"SIGKILL → {r}\n", style="red")
        if i <= len(starts):
            content.append(f"      ↳ ", style="dim")
            content.append(f"{starts[i-1]}\n", style="green")
    content.append(
        "\n  ⚠ HighMemoryUsage alert는 발화하지 않음\n"
        "  → 메모리 미상승, Loki의 'started' 키워드로 수동 탐지\n",
        style="dim yellow",
    )
    console.print(Panel(content, title="[bold yellow]🔄 재시작 타임라인[/bold yellow]", border_style="yellow"))


def custom_panel_brute_force(log_path: str):
    """1막(인증실패) → 전환(크레덴셜 발견) → 2막(RCE) 구조 표시"""
    lines = []
    if os.path.exists(log_path):
        lines = [strip_ansi(l).strip() for l in open(log_path, encoding="utf-8", errors="replace")]

    found_cred = next((l for l in lines if "크레덴셜 발견" in l or "leafy_secret" in l), None)
    rce_line   = next((l for l in lines if "COPY FROM PROGRAM" in l or "dd 프로세스" in l), None)

    content = Text()

    content.append("━━ 1막: 브루트포스 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold yellow")
    content.append("  대상: postgres 계정  ·  10개 패스워드 × 100회 = 1,000회 시도\n")
    content.append("  결과: ", style="bold")
    content.append("전부 실패 (postgres 패스워드는 리스트에 없음)\n\n", style="red")

    content.append("━━ 전환: 크레덴셜 발견 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold cyan")
    if found_cred:
        content.append(f"  {found_cred}\n", style="bold green")
    else:
        content.append("  leafy / leafy_secret  ← 후보 리스트 마지막 항목에 실제 패스워드 포함\n", style="bold green")
    content.append()

    content.append("━━ 2막: RCE — COPY FROM PROGRAM ━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold red")
    content.append("  CREATE TABLE abroxu;  →  OK\n")
    content.append("  COPY abroxu FROM PROGRAM\n", style="bold")
    content.append("    'for i in $(seq 1 $(nproc)); do dd if=/dev/zero of=/dev/null bs=1M & done'\n",
                   style="yellow")
    if rce_line:
        content.append(f"  {rce_line}\n", style="green")
    content.append("  → leafy-db CPU 100%  →  HighCpuUsage alert 발화\n", style="bold red")

    console.print(Panel(content, title="[bold red]⚔  공격 체인: 브루트포스 → 크레덴셜 → RCE[/bold red]",
                        border_style="red"))


def custom_panel_data_exfil(log_path: str):
    """탐지 사각지대 강조 + 탈취 데이터 reveal"""
    content = Text()

    content.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold red")
    content.append("         AIOps 파이프라인의 탐지 사각지대\n", style="bold red")
    content.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", style="bold red")

    checks = [("CPU", "정상"), ("메모리", "정상"), ("네트워크", "정상"),
              ("PostgreSQL 연결", "정상"), ("Nginx 요청수", "정상")]
    for label, status in checks:
        content.append(f"  {label:<20s}", style="white")
        content.append(f"{status}  ✓\n", style="green")

    content.append("\n  그러나 — SELECT 쿼리 한 줄로:\n\n", style="bold yellow")
    content.append("  SELECT id, username, email, password_hash, phone, role\n", style="bold white")
    content.append("  FROM leaked_users ORDER BY id;\n\n", style="bold white")

    rows = [
        ("admin",       "admin@leafy-corp.com",       "010-0000-0001", "admin"),
        ("kim_junho",   "junho.kim@leafy-corp.com",   "010-1234-5678", "user"),
        ("lee_soyeon",  "soyeon.lee@leafy-corp.com",  "010-2345-6789", "user"),
        ("park_minjae", "minjae.park@leafy-corp.com", "010-3456-7890", "user"),
        ("choi_yuna",   "yuna.choi@leafy-corp.com",   "010-4567-8901", "user"),
    ]
    content.append("  username       email                       phone          role\n", style="bold dim")
    content.append("  " + "─" * 66 + "\n", style="dim")
    for u, e, p, r in rows:
        content.append(f"  {u:<14s} {e:<28s} {p:<14s} {r}\n", style="red")

    content.append("\n  경보 없음 · LLM 분석 없음 · 자동 조치 없음\n", style="bold red")
    content.append("  → 탐지하려면 DB audit log 수집 또는 DLP 도구가 필요\n", style="dim yellow")

    console.print(Panel(content, title="[bold red]💀  데이터 탈취 — 탐지 사각지대[/bold red]",
                        border_style="red"))


def custom_panel_secret_dump(log_path: str):
    """마스킹된 환경변수 목록 + 탈취 시 공격 체인"""
    lines = []
    if os.path.exists(log_path):
        lines = [strip_ansi(l).strip() for l in open(log_path, encoding="utf-8", errors="replace")]

    masked = [l for l in lines if "MASKED" in l]
    count  = next((l for l in lines if "환경변수" in l and "개" in l), None)

    content = Text()
    content.append("━━ 덤프 실행 명령 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold yellow")
    for cmd in ["env", "cat /proc/1/environ | tr '\\0' '\\n'", "printenv"]:
        content.append(f"  $ {cmd}\n", style="bold green")

    if count:
        content.append(f"\n  {count}\n", style="yellow")

    content.append("\n━━ 탈취된 시크릿 (실제값 마스킹) ━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold red")
    secrets = [
        ("DB_PASSWORD",    "leafy-db 직접 접속 가능"),
        ("JWT_SECRET",     "모든 사용자 계정 JWT 위조 가능"),
        ("SPRING_DATASOURCE_URL", "DB 호스트/포트/DB명 노출"),
        ("OAUTH_CLIENT_SECRET", "외부 OAuth 서비스 사칭 가능"),
    ]
    for key, impact in secrets:
        masked_val = next((l for l in masked if key in l), f"{key}=***MASKED***")
        content.append(f"  {masked_val:<40s}", style="red")
        content.append(f"→ {impact}\n", style="dim yellow")

    content.append("\n━━ 공격 연쇄 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold cyan")
    content.append(
        "  secret_dump → DB_PASSWORD  → data_exfil → 사용자 PII 전체 탈취\n"
        "             → JWT_SECRET   → 모든 계정 사칭 (인증 체계 붕괴)\n"
        "             → DATASOURCE_URL → lateral_movement 경로 확인\n",
        style="cyan",
    )
    content.append("\n  경보 없음 · Falco 같은 런타임 보안 도구 없이 탐지 불가\n", style="bold red")

    console.print(Panel(content, title="[bold red]🔑  환경변수 덤프 — 탐지 사각지대[/bold red]",
                        border_style="red"))


def custom_panel_lateral_movement(log_path: str):
    """소스 IP 비교 + 자격증명 시도 현황"""
    lines = []
    if os.path.exists(log_path):
        lines = [strip_ansi(l).strip() for l in open(log_path, encoding="utf-8", errors="replace")]

    attacker_ip = next(
        (re.search(r"172\.\d+\.\d+\.\d+", l).group() for l in lines
         if "attacker" in l.lower() and re.search(r"172\.\d+\.\d+\.\d+", l)),
        "172.21.0.7 (추정)",
    )

    content = Text()
    content.append("━━ 소스 IP 비교 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold cyan")
    content.append("  정상 접속 (leafy-backend) : ", style="white")
    content.append("172.21.0.3\n", style="green")
    content.append("  공격자 컨테이너           : ", style="white")
    content.append(f"{attacker_ip}  ← 불일치!\n\n", style="bold red")

    content.append("━━ 자격증명 시도 현황 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold yellow")
    creds = [
        ("attacker", "password",     "FATAL: role does not exist"),
        ("admin",    "admin",         "FATAL: role does not exist"),
        ("leafy",    "wrongpass",     "FATAL: password authentication failed"),
        ("root",     "root",          "FATAL: role does not exist"),
        ("postgres", "postgres",      "FATAL: password authentication failed"),
        ("leafy",    "leafy_secret",  "✅ 접속 성공!"),
    ]
    for user, pw, result in creds:
        color = "green" if "성공" in result else "dim"
        content.append(f"  {user:<12s}/{pw:<16s}→ ", style="white")
        content.append(f"{result}\n", style=color)

    content.append("\n━━ 정찰 쿼리 실행 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", style="bold red")
    recon = [
        "SELECT current_user, current_database(), version();",
        "SELECT table_name FROM information_schema.tables WHERE table_schema='public';",
        "SELECT count(*) FROM my_plant;",
    ]
    for q in recon:
        content.append(f"  {q}\n", style="red")
    content.append(
        "\n  → 플랫 네트워크 구조: 모든 컨테이너가 leafy-db:5432 직접 접근 가능\n"
        "  → 네트워크 분리 없이는 횡적 이동을 막을 수 없음\n",
        style="dim yellow",
    )

    console.print(Panel(content, title="[bold red]🔀  횡적 이동 — 비인가 DB 직접 접속[/bold red]",
                        border_style="red"))


def dispatch_custom_panel(meta: dict, log_path: str):
    key = meta.get("custom_panel")
    if key == "memory_leak":
        custom_panel_memory_leak(log_path)
    elif key == "brute_force":
        custom_panel_brute_force(log_path)
    elif key == "data_exfil":
        custom_panel_data_exfil(log_path)
    elif key == "secret_dump":
        custom_panel_secret_dump(log_path)
    elif key == "lateral_movement":
        custom_panel_lateral_movement(log_path)


# ── 메인 파이프라인 ───────────────────────────────────────────────────────────
def run_scenario(meta: dict):
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    baseline   = get_result_count()

    # ① 매트릭스 레인 인트로
    os.system("cls" if os.name == "nt" else "clear")
    matrix_rain(duration=1.6)
    glitch_banner(f"[ INITIATING: {meta['label'].upper()} ]", style="bold green")
    console.print()
    time.sleep(0.4)

    # ② 시나리오 정보
    panel_scenario_info(meta, start_time)
    console.print()

    # ③ Before 메트릭 스냅샷
    console.print(Rule("[dim]Before 스냅샷[/dim]", style="dim"))
    scan_bar("Prometheus 메트릭 수집", duration=0.8, color="cyan")
    before_snap = fetch_metrics(meta["container"])
    panel_metrics(f"Before 메트릭  ({meta['container']})", before_snap, border="blue")
    console.print()

    # ④ 공격 실행 + 백그라운드 메트릭 수집
    collector = MetricCollector(meta["container"])
    collector.start()

    glitch_banner("[ ATTACK SEQUENCE INITIATED ]", style="bold red", iterations=5)
    console.print()

    proc, log_path = launch_scenario(meta)
    console.print(f"  [dim]▶ PID {proc.pid}  ·  로그: {os.path.relpath(log_path)}[/dim]\n")

    # blind_spot 시나리오는 LLM을 기다리지 않음
    if meta["blind_spot"]:
        scan_bar("공격 실행", duration=max(2.0, 1.0), color="red")
        time.sleep(3)  # 시나리오가 짧으므로 잠깐 대기
        collector.stop()
        after_snap = fetch_metrics(meta["container"])

        os.system("cls" if os.name == "nt" else "clear")
        panel_scenario_info(meta, start_time)
        console.print()
        dispatch_custom_panel(meta, log_path)
        console.print()
        panel_metrics(f"After 메트릭  ({meta['container']})", after_snap, border="blue")
        console.print()
        panel_before_after(before_snap, after_snap, collector)
        console.print()
        panel_logs(meta["loki_container"])
    else:
        # ⑤ LLM 폴링 + 실시간 로그 스트림
        entry = wait_for_llm(baseline, log_path, timeout=240)
        collector.stop()
        after_snap = fetch_metrics(meta["container"])

        # ⑥ 결과 화면 재구성
        os.system("cls" if os.name == "nt" else "clear")
        panel_scenario_info(meta, start_time)
        console.print()

        if entry:
            # Alert 탐지 글리치 효과
            glitch_banner("[ ANOMALY DETECTED — LLM ANALYZING ]", style="bold yellow", iterations=4)
            panel_llm_result(entry)
            console.print()
            panel_remediation(entry.get("result", {}))
        else:
            console.print(Panel(
                "[red]⚠  제한 시간 내 LLM 결과 없음[/red]\n"
                "[dim]  · alert 발화까지 더 시간이 필요할 수 있음\n"
                f"  · 수동 확인: {PIPELINE_URL}/results[/dim]",
                title="[bold red]분석 타임아웃[/bold red]", border_style="red",
            ))

        console.print()

        # ⑦ After 메트릭 + Before/After 비교
        console.print(Rule("[dim]After 스냅샷[/dim]", style="dim"))
        scan_bar("조치 후 메트릭 수집", duration=0.8, color="magenta")
        panel_metrics(f"After 메트릭  ({meta['container']})", after_snap, border="magenta")
        console.print()
        panel_before_after(before_snap, after_snap, collector)
        console.print()

        # ⑧ Loki 로그
        scan_bar("Loki 로그 수집", duration=0.6, color="green")
        panel_logs(meta["loki_container"])
        console.print()

        # ⑨ 고유 패널
        if meta.get("custom_panel"):
            dispatch_custom_panel(meta, log_path)
            console.print()

    if proc.poll() is None:
        console.print(f"  [dim]※ 시나리오 프로세스 진행 중 (PID {proc.pid})[/dim]")
    console.print()
    console.print(Rule("[dim green]시나리오 완료[/dim green]", style="dim green"))
    console.print()


# ── 메뉴 ──────────────────────────────────────────────────────────────────────
def select_scenario() -> dict | None:
    os.system("cls" if os.name == "nt" else "clear")
    console.print()
    console.print(Panel(
        "[bold cyan]  AIOps Scenario Runner  [/bold cyan]\n"
        "[dim]  시나리오 선택 → 실행 → 파이프라인 시각화[/dim]",
        border_style="cyan", width=54,
    ), justify="center")
    console.print()

    infra  = [m for m in SCENARIO_REGISTRY if m["category"] == "인프라"]
    sec    = [m for m in SCENARIO_REGISTRY if m["category"] == "보안"]
    all_sc = infra + sec

    console.print("  [bold cyan]── 카테고리 1: 인프라 ──────────────────────────────[/bold cyan]")
    for i, m in enumerate(infra, 1):
        tag = "[dim red]사각지대[/dim red]" if m["blind_spot"] else (
              "[dim yellow]수동 웹훅[/dim yellow]" if not m["alert_fires"] else "[dim green]자동 Alert[/dim green]")
        console.print(f"  [bold yellow]{i:2d}[/bold yellow].  {m['label']:<28s}  {tag}")
        console.print(f"       [dim]{m['subtitle']}[/dim]")

    console.print()
    console.print("  [bold cyan]── 카테고리 2: 보안 ────────────────────────────────[/bold cyan]")
    for i, m in enumerate(sec, len(infra) + 1):
        tag = "[dim red]사각지대[/dim red]" if m["blind_spot"] else (
              "[dim yellow]수동 웹훅[/dim yellow]" if not m["alert_fires"] else "[dim green]자동 Alert[/dim green]")
        console.print(f"  [bold yellow]{i:2d}[/bold yellow].  {m['label']:<28s}  {tag}")
        console.print(f"       [dim]{m['subtitle']}[/dim]")

    console.print()
    console.print("   [bold yellow]q[/bold yellow].  종료")
    console.print()

    while True:
        choice = console.input("  [bold white]번호 입력: [/bold white]").strip().lower()
        if choice == "q":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(all_sc):
            selected = all_sc[int(choice) - 1]
            console.print(f"\n  [bold green]✔  선택됨:[/bold green] {selected['label']}\n")
            time.sleep(0.5)
            return selected
        console.print("  [red]잘못된 입력입니다.[/red]")


# ── 진입점 ────────────────────────────────────────────────────────────────────
def main():
    sys.path.insert(0, SCENARIOS_DIR)
    try:
        while True:
            meta = select_scenario()
            if meta is None:
                console.print("\n[yellow]종료합니다.[/yellow]\n")
                break
            run_scenario(meta)
            again = console.input(
                "  [bold white]다른 시나리오를 실행하시겠습니까? (y/n): [/bold white]"
            ).strip().lower()
            if again != "y":
                console.print("\n[yellow]종료합니다.[/yellow]\n")
                break
    except KeyboardInterrupt:
        console.print("\n\n[yellow]중단됨.[/yellow]\n")


if __name__ == "__main__":
    main()
