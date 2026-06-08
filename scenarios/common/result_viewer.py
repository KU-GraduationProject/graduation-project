"""
scenarios/common/result_viewer.py
"""

import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")
_console = Console()


class ResultViewer:
    def __init__(
        self,
        alert_name: str,
        scenario_name: str,
        lookback_sec: int = 3600,  # 1시간으로 확장
    ):
        self.alert_name    = alert_name
        self.scenario_name = scenario_name
        self.lookback_sec  = lookback_sec

    def show(
        self,
        mttd_seconds: float | None = None,
        mtta_seconds: float | None = None,
    ) -> None:
        _console.print()
        _console.rule(
            f"[bold cyan]🔍  AIOps 분석 결과 조회 — {self.scenario_name}[/bold cyan]",
            style="cyan",
        )

        # [FIX] LLM 분석 완료까지 최대 18docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi0초 대기 (5초 간격으로 재시도)
        llm_entry = self._fetch_llm_result_with_retry(timeout=180, poll_interval=5)
        remediation = self._fetch_remediation()

        self._print_llm_result(llm_entry)
        self._print_remediation(remediation)
        self._print_timeline(llm_entry, remediation, mttd_seconds, mtta_seconds)

    # ── Loki 조회 ──────────────────────────────────────────────────────────────

    def _fetch_llm_result_with_retry(
        self,
        timeout: int = 180,
        poll_interval: int = 5,
    ) -> dict | None:
        """LLM 분석 결과가 Loki에 나타날 때까지 재시도."""
        deadline = time.time() + timeout
        attempt  = 0

        while time.time() < deadline:
            attempt += 1
            entry = self._fetch_llm_result()
            if entry is not None:
                if attempt > 1:
                    _console.print(
                        f"  [green]→ LLM 결과 확인 완료 (시도 {attempt}회)[/green]"
                    )
                return entry

            remaining = max(0, int(deadline - time.time()))
            _console.print(
                f"  [dim]→ LLM 분석 대기 중... "
                f"(시도 {attempt}회 / 남은 시간 {remaining}초)[/dim]"
            )
            time.sleep(poll_interval)

        _console.print(f"  [yellow]→ LLM 결과 대기 타임아웃 ({timeout}초)[/yellow]")
        return None

    def _fetch_llm_result(self) -> dict | None:
        # 1차: alert 레이블로 정확히 조회
        query = f'{{job="aiops-llm",alert="{self.alert_name}"}}'
        streams = self._query_loki(query)
        if not streams:
            # 2차 fallback: 전체 조회
            streams = self._query_loki('{job="aiops-llm"}')

        latest_entry = None
        latest_ts    = 0.0

        for stream in streams:
            for ts_ns, line in stream.get("values", []):
                try:
                    entry = json.loads(line)
                    # ★ alert_name 필터를 latest_ts 비교 전에 먼저 적용
                    if entry.get("alert_name") != self.alert_name:
                        continue
                    ts = int(ts_ns) / 1e9
                    if ts > latest_ts:
                        latest_ts           = ts
                        latest_entry        = entry
                        latest_entry["_ts"] = ts
                except Exception:
                    continue
        return latest_entry

    def _fetch_remediation(self) -> dict | None:
        query = f'{{job="aiops-remediation",alert="{self.alert_name}"}}'
        streams = self._query_loki(query)
        if not streams:
            streams = self._query_loki('{job="aiops-remediation"}')

        latest_entry = None
        latest_ts    = 0.0

        for stream in streams:
            for ts_ns, line in stream.get("values", []):
                try:
                    entry = json.loads(line)
                    if entry.get("alert") == self.alert_name:
                        ts = int(ts_ns) / 1e9
                        if ts > latest_ts:
                            latest_ts            = ts
                            latest_entry         = entry
                            latest_entry["_ts"]  = ts
                except Exception:
                    continue
        return latest_entry

    def _query_loki(self, query: str) -> list:
        try:
            end_ns   = int(time.time() * 1e9)
            start_ns = end_ns - int(self.lookback_sec * 1e9)
            params = urllib.parse.urlencode({
                "query":     query,
                "start":     start_ns,
                "end":       end_ns,
                "limit":     100,
                "direction": "forward",
            })
            url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            return data.get("data", {}).get("result", [])
        except Exception as e:
            _console.print(f"  [dim red]→ Loki 조회 실패: {e}[/dim red]")
            return []

    # ── 출력 ───────────────────────────────────────────────────────────────────

    def _print_llm_result(self, entry: dict | None) -> None:
        _console.print()
        _console.rule("[bold yellow]🤖  LLM 분석 결과[/bold yellow]", style="yellow")

        if not entry:
            _console.print(Panel(
                "[yellow]LLM 분석 결과를 Loki에서 찾을 수 없습니다.\n"
                "Pipeline이 아직 분석 중이거나 lookback 범위를 벗어났습니다.[/yellow]",
                border_style="yellow",
            ))
            return

        result       = entry.get("result", {})
        action_type  = result.get("action_type", "NONE")
        threat_level = result.get("threat_level", "unknown")
        confidence   = result.get("confidence", 0.0)
        root_cause   = result.get("root_cause", "-")
        action_desc  = result.get("action_description", "-")
        evidence     = result.get("evidence", [])
        targets      = result.get("action_targets", [])

        threat_color = {
            "critical": "red bold", "high": "red",
            "medium": "yellow",     "low":  "green",
        }.get(threat_level, "white")

        action_color = {
            "RESTART": "red", "ISOLATE": "red bold",
            "SCALE":   "yellow", "NOTIFY": "cyan",
            "NONE":    "dim",    "PENDING": "yellow",
        }.get(action_type, "white")

        conf_color = (
            "green" if confidence >= 0.7
            else "yellow" if confidence >= 0.4
            else "red"
        )

        table = Table(
            box=box.DOUBLE_EDGE, border_style="yellow",
            show_header=False, padding=(0, 2),
            title=f"[bold yellow]🤖  LLM 분석 — {self.alert_name}[/bold yellow]",
        )
        table.add_column("항목", style="bold", no_wrap=True, min_width=14)
        table.add_column("값", justify="left")

        table.add_row("Alert",       f"[yellow]{self.alert_name}[/yellow]")
        table.add_row("Container",   entry.get("container", "-"))
        table.add_row("Root Cause",  root_cause)
        table.add_row("Threat",      f"[{threat_color}]{threat_level.upper()}[/{threat_color}]")
        table.add_row("Action",      f"[{action_color}]{action_type}[/{action_color}]")
        table.add_row("Targets",     ", ".join(targets) if targets else "-")
        table.add_row("Description", action_desc)
        table.add_row("Confidence",  f"[{conf_color}]{confidence:.0%}[/{conf_color}]")

        if evidence:
            table.add_row("Evidence", evidence[0])
            for e in evidence[1:]:
                table.add_row("", e)

        _console.print(table)

    def _print_remediation(self, entry: dict | None) -> None:
        _console.print()
        _console.rule("[bold red]🔧  Remediation 조치[/bold red]", style="red")

        if not entry:
            _console.print(Panel(
                "[dim]Remediation 조치 기록을 Loki에서 찾을 수 없습니다.\n"
                "action_risk=high인 경우 자동 실행 없이 승인 대기 상태일 수 있습니다.[/dim]",
                border_style="dim",
            ))
            return

        action_type = entry.get("action_type", "-")
        target      = entry.get("target", "-")
        status      = entry.get("status", "-")
        result_msg  = entry.get("result", "-")
        event       = entry.get("event", "-")

        status_color = "green" if status == "SUCCESS" else "red"
        action_color = {
            "RESTART": "red", "ISOLATE": "red bold",
            "SCALE":   "yellow", "NOTIFY": "cyan", "NONE": "dim",
        }.get(action_type, "white")

        table = Table(
            box=box.DOUBLE_EDGE, border_style="red",
            show_header=False, padding=(0, 2),
            title="[bold red]🔧  Remediation 실행 결과[/bold red]",
        )
        table.add_column("항목", style="bold", no_wrap=True, min_width=14)
        table.add_column("값", justify="left")

        table.add_row("Event",  event)
        table.add_row("Target", f"[bold]{target}[/bold]")
        table.add_row("Action", f"[{action_color}]{action_type}[/{action_color}]")
        table.add_row("Status", f"[{status_color} bold]{status}[/{status_color} bold]")
        table.add_row("Result", result_msg)

        _console.print(table)

    def _print_timeline(
        self,
        llm_entry:    dict | None,
        remediation:  dict | None,
        mttd_seconds: float | None,
        mtta_seconds: float | None,
    ) -> None:
        _console.print()
        _console.rule("[bold cyan]⏱  타임라인[/bold cyan]", style="cyan")

        def _c(s: float) -> str:
            if s < 30:  return "green bold"
            if s < 60:  return "yellow bold"
            return "red bold"

        table = Table(
            box=box.DOUBLE_EDGE, border_style="cyan",
            show_header=False, padding=(0, 2),
            title="[bold cyan]⏱  AIOps 타임라인[/bold cyan]",
        )
        table.add_column("이벤트", style="bold", no_wrap=True, min_width=16)
        table.add_column("시각 / 값", justify="left")

        if llm_entry and llm_entry.get("_ts"):
            ts = datetime.fromtimestamp(llm_entry["_ts"])
            table.add_row("LLM 분석 완료", ts.strftime("%H:%M:%S"))

        if remediation and remediation.get("_ts"):
            ts = datetime.fromtimestamp(remediation["_ts"])
            table.add_row("Remediation 실행", ts.strftime("%H:%M:%S"))

        if mttd_seconds is not None:
            c = _c(mttd_seconds)
            table.add_row("MTTD", f"[{c}]{mttd_seconds:.1f}초[/{c}]  ← 공격 시작 → Alert 발화")

        if mtta_seconds is not None:
            c = _c(mtta_seconds)
            table.add_row("MTTA", f"[{c}]{mtta_seconds:.1f}초[/{c}]  ← Alert 발화 → Slack 알림")

        if mttd_seconds is not None:
            if mttd_seconds < 60:
                grade = "[green bold]✅ 우수[/green bold]"
            elif mttd_seconds < 120:
                grade = "[yellow bold]⚠️ 보통[/yellow bold]"
            else:
                grade = "[red bold]❌ 개선 필요[/red bold]"
            table.add_row("탐지 성능", grade)

        _console.print(table)
        _console.print()