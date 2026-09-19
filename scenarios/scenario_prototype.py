"""
AIOps Scenario Prototype
시나리오 선택 → 백그라운드 실행 → LLM 분석 대기 →
결과(LLM 응답 / 조치 내역 / Prometheus 메트릭 / Loki 로그)를
Rich 패널로 정리해 화면에 영구 표시.

cli_demo.py와 달리 애니메이션 없이 결과를 패널로 정리해 보여준다.
Prometheus/Loki는 Pipeline 경유로 조회 (macOS Docker 포트 이슈 우회).
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()

# ── 설정 ──────────────────────────────────────────────────────────────────────
PIPELINE_URL = os.getenv("PIPELINE_URL", "http://localhost:8000")

SCENARIO_CONFIGS = {
    "1": {
        "key":       "redos_attack",
        "label":     "HTTP Flood (OWASP A05 - Nginx CPU 고갈)",
        "container": "leafy-frontend",
        "module":    "category1_infra.redos_attack",
        "alert":     "HighCpuUsage",
    },
    "2": {
        "key":       "n_plus_one_attack",
        "label":     "N+1 Query 공격 (OWASP A04 - DB 커넥션 고갈)",
        "container": "leafy-db",
        "module":    "category2_security.n_plus_one_attack",
        "alert":     "HighPostgresConnections",
    },
    "3": {
        "key":       "db_bruteforce",
        "label":     "DB 브루트포스 (내부망 반복 인증 실패)",
        "container": "leafy-db",
        "module":    "category2_security.brute_force",
        "alert":     "HighPostgresConnections",
    },
    "4": {
        "key":       "lateral_movement",
        "label":     "컨테이너 Lateral Movement (비인가 DB 직접 접속)",
        "container": "leafy-db",
        "module":    "category2_security.lateral_movement",
        "alert":     "Loki 소스 IP 이상",
    },
    "5": {
        "key":       "cpu_stress",
        "label":     "크립토마이닝형 CPU/메모리 고갈 (1-A)",
        "container": "leafy-backend",
        "module":    "category1_infra.cpu_stress",
        "alert":     "HighCpuUsage",
    },
    "6": {
        "key":       "memory_leak",
        "label":     "메모리 누수 → OOMKill 반복 재시작 (1-B)",
        "container": "leafy-backend",
        "module":    "category1_infra.memory_leak",
        "alert":     "HighMemoryUsage + ContainerRestarted",
    },
}

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


# ── HTTP 유틸 ─────────────────────────────────────────────────────────────────
def _get(url: str, timeout: int = 8) -> dict | None:
    try:
        r = urllib.request.urlopen(url, timeout=timeout)
        return json.loads(r.read().decode())
    except Exception:
        return None


# ── Pipeline 경유 메트릭/로그 조회 ────────────────────────────────────────────
def fetch_metrics_via_pipeline(container: str) -> dict:
    """Pipeline /debug/metrics 경유로 Prometheus 메트릭 조회"""
    import urllib.parse
    url = f"{PIPELINE_URL}/debug/metrics?container={urllib.parse.quote(container)}"
    data = _get(url)
    if not data or data.get("status") != "ok":
        return {}
    return data.get("snapshot", {})


def fetch_logs_via_pipeline(container: str, lines: int = 15) -> list[str]:
    """Pipeline /debug/logs 경유로 Loki 로그 조회"""
    import urllib.parse
    url = f"{PIPELINE_URL}/debug/logs?container={urllib.parse.quote(container)}&lines={lines}"
    data = _get(url)
    if not data or data.get("status") != "ok":
        return ["Pipeline 경유 Loki 조회 실패"]
    logs = data.get("logs", [])
    if not logs:
        return ["최근 5분 내 로그 없음"]
    return [f"[dim]{e['timestamp']}[/dim]  {e['message']}" for e in logs]


def fetch_active_alerts() -> list[dict]:
    """Prometheus /api/v1/alerts — pipeline 헬스와 동일 URL 기반으로 시도"""
    # pipeline이 prometheus와 같은 mgmt-net에 있으므로 pipeline 경유
    url = f"{PIPELINE_URL}/debug/alerts"
    data = _get(url)
    if data and data.get("status") == "ok":
        return data.get("alerts", [])
    return []


# ── LLM 결과 폴링 (시작 이후 새 결과만) ──────────────────────────────────────
def get_current_result_count() -> int:
    data = _get(f"{PIPELINE_URL}/results")
    if data and data.get("status") == "ok":
        return data.get("count", 0)
    return 0


def poll_new_llm_result(baseline_count: int, timeout_sec: int = 200) -> dict | None:
    """
    baseline_count: 시나리오 시작 시점의 기존 결과 수
    시작 이후 새로운 결과가 추가될 때까지 폴링.
    """
    spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    deadline = time.time() + timeout_sec
    i = 0
    while time.time() < deadline:
        data = _get(f"{PIPELINE_URL}/results")
        if data and data.get("status") == "ok":
            current = data.get("count", 0)
            if current > baseline_count:
                # 새 결과 발생 — 가장 최신 것 반환
                entries = data.get("data", [])
                if entries:
                    return entries[-1]
        elapsed   = int(time.time() - (deadline - timeout_sec))
        remaining = int(deadline - time.time())
        # Rich console은 \r 처리 불안정 → 표준 print로 한 줄 덮어쓰기
        print(
            f"\r  {spinners[i % len(spinners)]}  "
            f"Alert 발화 및 LLM 분석 대기 중...  "
            f"경과 {elapsed}s / 최대 {timeout_sec}s  "
            f"(공격 진행 → Prometheus alert → AlertManager → Pipeline → Ollama)   ",
            end="", flush=True,
        )
        time.sleep(1)
        i += 1
    console.print()
    return None


# ── 시나리오 백그라운드 실행 (subprocess → 로그 파일로 출력 분리) ─────────────
def launch_scenario_subprocess(scenario_cfg: dict) -> subprocess.Popen:
    """
    시나리오를 별도 Python 프로세스로 실행.
    stdout/stderr를 로그 파일에 기록해 메인 터미널 화면과 분리.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"{scenario_cfg['key']}_run.log")

    scenarios_dir = os.path.dirname(os.path.abspath(__file__))
    script = (
        f"import sys; sys.path.insert(0, {repr(scenarios_dir)}); "
        f"from {scenario_cfg['module']} import main; main()"
    )
    log_file = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=log_file,
        stderr=log_file,
    )
    return proc, log_path


# ── 컨테이너 현재 상태 조회 ───────────────────────────────────────────────────
def get_container_status(container: str) -> dict:
    try:
        out = subprocess.check_output(
            ["docker", "inspect", container,
             "--format", "{{.State.Status}}|{{.RestartCount}}|{{json .NetworkSettings.Networks}}"],
            timeout=5, text=True,
        ).strip()
        parts = out.split("|", 2)
        status   = parts[0] if len(parts) > 0 else "unknown"
        restarts = parts[1] if len(parts) > 1 else "?"
        networks_raw = parts[2] if len(parts) > 2 else "{}"
        try:
            nets = json.loads(networks_raw)
            net_names = list(nets.keys())
        except Exception:
            net_names = []
        return {"status": status, "restarts": restarts, "networks": net_names}
    except Exception:
        return {"status": "조회 실패", "restarts": "?", "networks": []}


# ── Rich 출력 함수들 ──────────────────────────────────────────────────────────

def print_header(scenario_cfg: dict):
    console.print()
    console.print(Rule(
        f"[bold cyan]AIOps Scenario Prototype[/bold cyan]  ·  "
        f"[yellow]{scenario_cfg['label']}[/yellow]",
        style="cyan",
    ))
    console.print()


def print_scenario_info(scenario_cfg: dict, start_time: str):
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold green", no_wrap=True)
    t.add_column()
    t.add_row("시나리오",     scenario_cfg["label"])
    t.add_row("대상 컨테이너", scenario_cfg["container"])
    t.add_row("예상 Alert",   scenario_cfg["alert"])
    t.add_row("실행 시각",    start_time)
    console.print(Panel(t, title="[bold]시나리오 정보[/bold]", border_style="cyan"))


def print_llm_result(entry: dict):
    result     = entry.get("result", {})
    alert_name = entry.get("alert_name", "N/A")
    container  = entry.get("container", "N/A")
    timestamp  = entry.get("timestamp", "N/A")[:19].replace("T", " ")

    tl = result.get("threat_level", "").lower()
    tl_color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(tl, "white")
    ar = result.get("action_risk", "").lower()
    ar_color = {"high": "red", "medium": "yellow", "low": "green"}.get(ar, "white")

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold green", no_wrap=True, min_width=16)
    t.add_column(overflow="fold")

    t.add_row("alert_name",   alert_name)
    t.add_row("container",    container)
    t.add_row("분석 시각",    timestamp)
    t.add_row("", "")
    t.add_row("root_cause",   result.get("root_cause", "N/A"))
    t.add_row("threat_level", f"[{tl_color}]{result.get('threat_level','N/A')}[/{tl_color}]")
    t.add_row("action_risk",  f"[{ar_color}]{result.get('action_risk','N/A')}[/{ar_color}]")
    t.add_row("action",       f"[bold white]{result.get('action','N/A')}[/bold white]")
    t.add_row("confidence",   str(result.get("confidence", "N/A")))

    for idx, ev in enumerate(result.get("evidence", [])):
        t.add_row("evidence" if idx == 0 else "", f"[dim]· {ev}[/dim]")

    summary = result.get("summary", "")
    if summary:
        t.add_row("", "")
        t.add_row("summary", summary)

    console.print(Panel(t, title="[bold yellow]LLM 분석 결과[/bold yellow]", border_style="yellow"))


def print_remediation(result: dict):
    action_risk = result.get("action_risk", "unknown").lower()
    action      = result.get("action", "N/A")

    ar_color = {"low": "green", "medium": "yellow", "high": "red"}.get(action_risk, "white")

    if action_risk == "low":
        decision = "[bold green]✅  자동 조치 실행됨[/bold green]"
        detail   = f"Remediation Agent가 자동으로 [bold]{action}[/bold] 수행"
    elif action_risk == "medium":
        decision = "[bold yellow]⚠  관리자 승인 대기 중[/bold yellow]"
        detail   = f"자동 실행 보류. 제안된 조치: [bold]{action}[/bold]"
    else:
        decision = "[bold red]🚨  긴급 격리 요청[/bold red]"
        detail   = f"즉시 조치 필요: [bold]{action}[/bold]"

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold magenta", no_wrap=True, min_width=16)
    t.add_column(overflow="fold")
    t.add_row("결정",        decision)
    t.add_row("상세",        detail)
    t.add_row("action_risk", f"[{ar_color}]{action_risk}[/{ar_color}]")
    t.add_row("action",      action)

    console.print(Panel(t, title="[bold magenta]조치 결과[/bold magenta]", border_style="magenta"))


def print_container_state(container: str):
    state = get_container_status(container)
    status = state["status"]
    color  = "green" if status == "running" else "red"

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold green", no_wrap=True, min_width=16)
    t.add_column()
    t.add_row("컨테이너",   container)
    t.add_row("상태",       f"[{color}]{status}[/{color}]")
    t.add_row("재시작 횟수", state["restarts"])
    t.add_row("연결 네트워크", ", ".join(state["networks"]) or "N/A")

    console.print(Panel(t, title="[bold]조치 후 컨테이너 상태[/bold]", border_style="blue"))


def print_metrics(container: str):
    console.print(f"  [dim]Prometheus 메트릭 조회 중 (Pipeline 경유)...[/dim]")
    snapshot = fetch_metrics_via_pipeline(container)

    t = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 2))
    t.add_column("메트릭",   style="bold green", no_wrap=True)
    t.add_column("현재값",   justify="right")

    label_map = {
        "cpu_usage":    "CPU 사용률",
        "memory_usage": "메모리 사용 (bytes)",
        "memory_limit": "메모리 제한 (bytes)",
        "net_rx_bytes": "네트워크 수신 (bytes/s)",
        "net_tx_bytes": "네트워크 송신 (bytes/s)",
        "host_cpu":     "호스트 CPU",
        "host_mem":     "호스트 가용 메모리",
    }

    if not snapshot:
        t.add_row("[dim]데이터 없음[/dim]", "[dim]—[/dim]")
    else:
        for key, val in snapshot.items():
            label = label_map.get(key, key)
            if val is None:
                disp = "[dim]데이터 없음[/dim]"
            else:
                try:
                    fval = float(val)
                    if key == "cpu_usage":
                        disp = f"[{'bold red' if fval > 0.5 else 'white'}]{fval*100:.1f} %[/]"
                    elif "memory" in key:
                        disp = f"{fval/1024/1024:.1f} MB"
                    elif "net" in key:
                        disp = f"{fval/1024:.2f} KB/s"
                    elif key == "host_mem":
                        disp = f"{fval*100:.1f} % 가용"
                    else:
                        disp = f"{fval:.3f}"
                except Exception:
                    disp = str(val)
            t.add_row(label, disp)

    console.print(Panel(t, title=f"[bold]Prometheus 메트릭[/bold]  [dim]({container})[/dim]", border_style="blue"))


def print_logs(container: str):
    console.print(f"  [dim]Loki 최근 로그 조회 중 (Pipeline 경유)...[/dim]")
    logs = fetch_logs_via_pipeline(container, lines=15)

    content = Text()
    for line in logs:
        content.append_text(Text.from_markup(line + "\n"))

    console.print(Panel(
        content,
        title=f"[bold]Loki 로그[/bold]  [dim](최근 5분 · {container})[/dim]",
        border_style="green",
    ))


def print_all_results():
    data = _get(f"{PIPELINE_URL}/results")
    if not data or data.get("status") != "ok":
        console.print("[red]분석 이력 조회 실패[/red]")
        return

    entries = data.get("data", [])
    if not entries:
        console.print(Panel("[dim]저장된 분석 이력 없음[/dim]",
                            title="[bold]LLM 분석 이력[/bold]", border_style="yellow"))
        return

    t = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1))
    t.add_column("#",           style="dim",       width=3)
    t.add_column("시각",        no_wrap=True,      width=20)
    t.add_column("Alert",       style="bold red",  width=24)
    t.add_column("컨테이너",    no_wrap=True,      width=16)
    t.add_column("threat",      width=10)
    t.add_column("risk",        width=10)
    t.add_column("action",      overflow="fold")

    tl_c = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}
    ar_c = {"high": "red", "medium": "yellow", "low": "green"}

    for idx, entry in enumerate(reversed(entries), 1):
        r  = entry.get("result", {})
        tl = r.get("threat_level", "N/A").lower()
        ar = r.get("action_risk",  "N/A").lower()
        t.add_row(
            str(idx),
            entry.get("timestamp", "")[:19].replace("T", " "),
            entry.get("alert_name", "N/A"),
            entry.get("container",  "N/A"),
            f"[{tl_c.get(tl,'white')}]{r.get('threat_level','N/A')}[/]",
            f"[{ar_c.get(ar,'white')}]{r.get('action_risk','N/A')}[/]",
            r.get("action", "N/A"),
        )

    console.print(Panel(t, title="[bold]LLM 분석 이력 (최신순)[/bold]", border_style="yellow"))


# ── 시나리오 선택 메뉴 ────────────────────────────────────────────────────────
def select_scenario() -> dict | None:
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print()
    console.print(Panel(
        "[bold cyan]  AIOps Scenario Prototype  [/bold cyan]\n"
        "[dim]  결과가 사라지지 않는 분석 뷰어[/dim]",
        border_style="cyan", width=52,
    ), justify="center")
    console.print()

    for key, cfg in SCENARIO_CONFIGS.items():
        console.print(f"  [bold yellow]{key}[/bold yellow].  {cfg['label']}")

    console.print()
    console.print("  [bold yellow]h[/bold yellow].  분석 이력 조회")
    console.print("  [bold yellow]q[/bold yellow].  종료")
    console.print()

    while True:
        choice = console.input("  [bold white]번호를 입력하세요: [/bold white]").strip().lower()
        if choice == "q":
            return None
        if choice == "h":
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print()
            print_all_results()
            console.print()
            console.input("  [dim]Enter로 메뉴로 돌아가기...[/dim]")
            return select_scenario()
        if choice in SCENARIO_CONFIGS:
            cfg = SCENARIO_CONFIGS[choice]
            console.print(f"\n  [bold green]✔  선택됨:[/bold green] {cfg['label']}\n")
            time.sleep(0.5)
            return cfg
        console.print("  [red]잘못된 입력입니다.[/red]")


# ── 메인 실행 흐름 ────────────────────────────────────────────────────────────
def run_scenario(scenario_cfg: dict):
    start_time    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    baseline_count = get_current_result_count()

    os.system('cls' if os.name == 'nt' else 'clear')
    print_header(scenario_cfg)
    print_scenario_info(scenario_cfg, start_time)

    # 시나리오를 별도 프로세스로 실행 → stdout이 터미널에 섞이지 않음
    proc, log_path = launch_scenario_subprocess(scenario_cfg)
    console.print(
        f"  [dim]▶ 시나리오 실행 시작 (PID {proc.pid}) "
        f"— 출력: {os.path.relpath(log_path)}[/dim]\n"
    )

    # LLM 결과 폴링 (baseline 이후 새 결과 대기)
    console.print("  [bold]─── LLM 분석 대기 ───────────────────────────────────────────[/bold]")
    entry = poll_new_llm_result(baseline_count, timeout_sec=200)
    console.print()

    # 결과 화면 재구성
    os.system('cls' if os.name == 'nt' else 'clear')
    print_header(scenario_cfg)
    print_scenario_info(scenario_cfg, start_time)
    console.print()

    # ① LLM 분석 결과
    if entry:
        print_llm_result(entry)
        console.print()
        print_remediation(entry.get("result", {}))
    else:
        console.print(Panel(
            "[red]⚠ 제한 시간 내 LLM 분석 결과를 받지 못했습니다.[/red]\n"
            "[dim]  · Prometheus alert가 아직 발화되지 않았을 수 있음\n"
            "  · 시나리오 진행 시간이 더 필요할 수 있음 (alert for 1m)\n"
            f"  · 수동 확인: {PIPELINE_URL}/results/latest[/dim]",
            title="[bold red]분석 타임아웃[/bold red]", border_style="red",
        ))

    console.print()

    # ② 조치 후 컨테이너 상태
    print_container_state(scenario_cfg["container"])
    console.print()

    # ③ Prometheus 메트릭 (Pipeline 경유)
    print_metrics(scenario_cfg["container"])
    console.print()

    # ④ Loki 로그 (Pipeline 경유)
    print_logs(scenario_cfg["container"])
    console.print()

    # ⑤ 전체 분석 이력
    print_all_results()
    console.print()

    # 시나리오 프로세스가 아직 실행 중이면 알림
    if proc.poll() is None:
        console.print(
            f"  [dim]※ 시나리오 스크립트가 백그라운드에서 계속 실행 중입니다 (PID {proc.pid})\n"
            f"  ※ 로그 확인: tail -f {log_path}[/dim]"
        )
    console.print()
    console.print(Rule("[dim]분석 완료[/dim]", style="dim"))
    console.print()


# ── 진입점 ────────────────────────────────────────────────────────────────────
def main():
    try:
        while True:
            scenario_cfg = select_scenario()
            if scenario_cfg is None:
                console.print("\n[yellow]종료합니다.[/yellow]\n")
                break
            run_scenario(scenario_cfg)
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
