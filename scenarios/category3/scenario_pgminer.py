"""
Integrated PGMiner-style SOC demo scenario.

3단계 순차 실행:
  1. run_bruteforce()  — postgres 계정 패스워드 브루트포스
  2. run_dump()        — leafy-backend 환경변수 덤프 시뮬레이션
  3. run_rce()         — COPY FROM PROGRAM CPU 점유 + HighCpuUsage 탐지

각 단계 시작/완료 시 Loki timeline 이벤트 푸시.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# ── 경로 설정 ──────────────────────────────────────────────────────────────────
SCRIPT_DIR        = Path(__file__).resolve().parent
BASE_SCENARIO_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(BASE_SCENARIO_DIR))
sys.path.insert(0, str(BASE_SCENARIO_DIR / "category2_security"))

from brute_force import run_bruteforce, run_rce
from data_exfil import main as run_dump

GRAFANA_URL = os.getenv("GRAFANA_SOC_URL", "http://localhost:3000/d/leafy-aiops/leafy-aiops-soc-dashboard")
LOKI_URL    = os.getenv("LOKI_URL", "http://localhost:3100")
OPEN_GRAFANA = os.getenv("AIOPS_OPEN_GRAFANA", "1") != "0"

console = Console()

_STEPS = [
    ("bruteforce", "🔐", "yellow",  "DB 브루트포스 (auth failure 로그 생성)"),
    ("dump", "🔍", "magenta", "사용자 데이터 탈취 (leaked_users exfiltration)"),
    ("rce",        "🔥", "red",     "COPY FROM PROGRAM RCE + HighCpuUsage 탐지"),
]


# ── Loki timeline 푸시 ─────────────────────────────────────────────────────────
def _push_timeline(event: str, status: str = "INFO", **fields) -> None:
    ts_ns = str(int(time.time() * 1_000_000_000))
    body = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario":  "pgminer",
        "event":     event,
        "status":    status,
        **fields,
    }
    payload = {
        "streams": [{
            "stream": {
                "job":      "aiops-timeline",
                "scenario": "pgminer",
                "event":    event,
                "status":   status,
            },
            "values": [[ts_ns, json.dumps(body, ensure_ascii=False)]],
        }]
    }
    try:
        req = urllib.request.Request(
            f"{LOKI_URL}/loki/api/v1/push",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        pass


# ── 배너 / Grafana ─────────────────────────────────────────────────────────────
def _print_banner() -> None:
    console.print()
    console.print(Rule("[bold cyan]Leafy AIOps — SOC Orchestration Console[/bold cyan]", style="cyan"))
    console.print()

    grid = Table.grid(padding=(0, 4))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column(style="white")
    grid.add_row("Scenario",   "PGMiner (Integrated)")
    grid.add_row("Mode",       "Safe Simulation")
    grid.add_row("Steps",      "bruteforce  •  dump  •  rce")
    grid.add_row("Dashboard",  f"[link={GRAFANA_URL}]{GRAFANA_URL}[/link]")
    grid.add_row("Loki",       LOKI_URL)

    console.print(Panel(
        grid,
        title="[bold cyan]🛡  Mission Brief[/bold cyan]",
        border_style="cyan",
        padding=(1, 3),
    ))
    console.print()


def _open_grafana() -> None:
    console.print(Rule("[dim]Opening Grafana Dashboard[/dim]", style="dim"))
    console.print(f"  [cyan]URL →[/cyan] [link={GRAFANA_URL}]{GRAFANA_URL}[/link]")
    _push_timeline("grafana_dashboard_opened", url=GRAFANA_URL)
    if not OPEN_GRAFANA:
        console.print("  [dim](AIOPS_OPEN_GRAFANA=0 — skipping browser launch)[/dim]")
        return
    try:
        webbrowser.open(GRAFANA_URL)
        console.print("  [green]Browser launched ✓[/green]")
    except Exception as exc:
        console.print(f"  [yellow]Browser open skipped: {exc}[/yellow]")
    console.print()


# ── 단계 실행 래퍼 ─────────────────────────────────────────────────────────────
def _run_step(step_no: int, key: str, icon: str, color: str, desc: str, fn) -> tuple[str, float]:
    console.print()
    console.print(Rule(
        f"[bold {color}]{icon}  Step {step_no}/3 — {desc}[/bold {color}]",
        style=color,
    ))
    _push_timeline(f"{key}_started", status="STARTED", step=step_no, description=desc)
    t0 = time.time()

    status = "SUCCESS"
    try:
        fn()
    except KeyboardInterrupt:
        raise
    except Exception as e:
        console.print(f"  [red bold]Step {step_no} 오류: {e}[/red bold]")
        status = "FAILED"

    elapsed = time.time() - t0
    _push_timeline(f"{key}_completed", status=status, step=step_no, elapsed=round(elapsed, 1))

    badge = Text(f"{'✅ SUCCESS' if status == 'SUCCESS' else '❌ FAILED'}  —  {elapsed:.1f}s",
                 style=f"bold {'green' if status == 'SUCCESS' else 'red'}")
    console.print(Panel(
        Text.assemble((f"{icon} [{key}] ", f"bold {color}"), badge),
        border_style="green" if status == "SUCCESS" else "red",
        padding=(0, 2),
    ))
    return status, elapsed


# ── 최종 요약 ──────────────────────────────────────────────────────────────────
def _print_summary(results: list[tuple[str, str, str, float]], total: float) -> None:
    console.print()
    console.print(Rule("[bold cyan]SOC Orchestration — Final Report[/bold cyan]", style="cyan"))
    console.print()

    table = Table(
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        show_header=True,
        header_style="bold cyan",
        padding=(0, 2),
        title="[bold]📊  Scenario Results[/bold]",
    )
    table.add_column("Step",        justify="center")
    table.add_column("Scenario",    style="bold", no_wrap=True)
    table.add_column("Description")
    table.add_column("Status",      justify="center")
    table.add_column("Elapsed",     justify="right", style="dim")

    all_ok = True
    for no, key, status, elapsed in results:
        _, icon, color, desc = next(s for s in _STEPS if s[0] == key)
        ok = status == "SUCCESS"
        if not ok:
            all_ok = False
        table.add_row(
            str(no),
            f"[{color}]{icon} {key}[/{color}]",
            desc,
            "[green]SUCCESS ✅[/green]" if ok else "[red]FAILED ❌[/red]",
            f"{elapsed:.1f}s",
        )

    console.print(table)
    console.print()

    sc = "green" if all_ok else "red"
    si = "✅" if all_ok else "❌"
    console.print(Panel(
        Text.assemble(
            (f"{si}  All steps completed\n", f"bold {sc}"),
            ("Total elapsed: ", "bold"),
            (f"{total:.1f}s\n", "cyan"),
            ("Grafana: ", "bold"),
            (f"[link={GRAFANA_URL}]{GRAFANA_URL}[/link]", ""),
        ),
        title=f"[bold {sc}]PGMiner SOC Demo — Done[/bold {sc}]",
        border_style=sc,
        padding=(1, 3),
    ))
    console.print()


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main() -> int:
    _print_banner()
    _open_grafana()

    step_fns = [
        (1, "bruteforce", run_bruteforce),
        (2, "dump",       run_dump),
        (3, "rce",        run_rce),
    ]

    results: list[tuple[str, str, str, float]] = []
    total_start = time.time()
    exit_code = 0

    _push_timeline("pgminer_started", status="STARTED", steps=3)

    try:
        for no, key, fn in step_fns:
            _, icon, color, desc = next(s for s in _STEPS if s[0] == key)
            status, elapsed = _run_step(no, key, icon, color, desc, fn)
            results.append((str(no), key, status, elapsed))
            if status != "SUCCESS":
                exit_code = 1
    except KeyboardInterrupt:
        console.print()
        console.print(Panel(
            "[yellow bold]KeyboardInterrupt — 중단[/yellow bold]",
            border_style="yellow",
        ))
        _push_timeline("pgminer_interrupted", status="INTERRUPTED")
        exit_code = 130

    total_elapsed = time.time() - total_start
    _push_timeline(
        "pgminer_completed",
        status="SUCCESS" if exit_code == 0 else "FAILED",
        total_elapsed=round(total_elapsed, 1),
    )
    _print_summary(results, total_elapsed)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
