"""
scenarios/common/verifier.py
─────────────────────────────
시나리오 실행 결과를 자동으로 검증하는 공통 모듈.

Chaos Engineering 5단계를 코드로 자동화:
  1. Steady State 확인  → Prometheus 쿼리로 현재 메트릭 정상인지 체크
  2. Hypothesis 출력    → 터미널에 가설 표시
  3. 시나리오 실행      → 기존 공격 코드 (외부에서 호출)
  4. 측정              → Prometheus/AlertManager 반복 조회 → MTTD 자동 측정
  5. 결과 반영         → 성공/실패 + MTTD를 anomaly_log.json에 기록
"""

import http.client
import io
import contextlib
import json
import os
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from dataclasses import dataclass

from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

try:
    import plotext as plt
    _PLOTEXT_AVAILABLE = True
except ImportError:
    _PLOTEXT_AVAILABLE = False

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://localhost:9093")
LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")

_console = Console()


def _mttd_color(seconds: float) -> str:
    """30s 미만: green / 60s 미만: yellow / 초과: red"""
    if seconds < 30:
        return "green"
    elif seconds < 60:
        return "yellow"
    return "red"


# ── 결과 데이터 ────────────────────────────────────────────────────────────────
@dataclass
class VerifyResult:
    """검증 결과를 담는 데이터 클래스"""
    success: bool
    alert_name: str
    scenario_name: str
    mttd_seconds: float | None = None
    mttr_seconds: float | None = None
    mtta_seconds: float | None = None
    slack_notified: bool = False
    slack_status: str = ""
    slack_response_code: int | None = None
    slack_response_text: str = ""
    steady_state_ok: bool = True
    failure_reason: str = ""
    actual_value: float | None = None
    threshold: float | None = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ── 메인 클래스 ────────────────────────────────────────────────────────────────
class ScenarioVerifier:
    """
    시나리오 검증기.

    Parameters:
        scenario_name: 시나리오 이름 (e.g. "cpu_stress")
        alert_name: 발화 기대하는 Alert 이름 (e.g. "HighCpuUsage")
        hypothesis: 가설 문자열
        steady_state_query: Prometheus 쿼리 (정상 상태 확인용, 선택)
        steady_state_threshold: 정상 상태 메트릭 상한값 (선택)
    """

    def __init__(
        self,
        scenario_name: str,
        alert_name: str,
        hypothesis: str,
        steady_state_query: str = "",
        steady_state_threshold: float = 0.0,
        metric_label: str = "현재 값",
        metric_unit: str = "",
        metric_scale: float = 1.0,
    ):
        self.scenario_name = scenario_name
        self.alert_name = alert_name
        self.hypothesis = hypothesis
        self.steady_state_query = steady_state_query
        self.steady_state_threshold = steady_state_threshold
        self.metric_label = metric_label
        self.metric_unit = metric_unit
        self.metric_scale = metric_scale
        self._start_time: float = 0.0
        self._alert_firing_time: float | None = None
        self._last_slack_dispatch: dict = {}
        self._metric_samples: list[tuple[float, float]] = []
        self._mtta_timeout: int = 180

    # ── 1단계: Steady State 확인 ───────────────────────────────────────────────
    def check_steady_state(self) -> bool:
        _console.rule("[bold]1/5  Steady State 확인[/bold]")

        if not self.steady_state_query:
            _console.print("  [dim]→ 쿼리 미설정, 건너뜀[/dim]")
            return True

        try:
            value = self._query_prometheus_instant(self.steady_state_query)
            if value is not None:
                is_normal = value < self.steady_state_threshold
                status = "[green]정상 ✅[/green]" if is_normal else "[yellow]비정상 ⚠️[/yellow]"
                _console.print(
                    f"  → {self.metric_label}: [bold]{self._format_metric(value)}[/bold] "
                    f"/ 임계값: {self._format_metric(self.steady_state_threshold)}"
                )
                _console.print(f"  → 상태: {status}")
                if not is_normal:
                    _console.print(
                        "  [yellow]→ 경고: 이미 메트릭이 높은 상태. 이전 시나리오 잔여 효과일 수 있음[/yellow]"
                    )
                return is_normal
            else:
                _console.print("  [dim]→ 메트릭 데이터 없음 (컨테이너 미실행 가능)[/dim]")
                return True
        except Exception as e:
            _console.print(f"  [red]→ Prometheus 조회 실패: {e}[/red]")
            return True

    # ── 2단계: Hypothesis 출력 ─────────────────────────────────────────────────
    def print_hypothesis(self):
        _console.print(Panel(
            f"[bold]시나리오:[/bold]    {self.scenario_name}\n"
            f"[bold]목표 Alert:[/bold]  [yellow]{self.alert_name}[/yellow]\n"
            f"[bold]가설:[/bold]        {self.hypothesis}\n\n"
            f"[dim]성공 기준: MTTD < 2분, Alert FIRING 확인[/dim]",
            title="[bold cyan]📋  Hypothesis[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))

    # ── 3단계: 타이머 시작 ─────────────────────────────────────────────────────
    def start_timer(self):
        self._start_time = time.time()
        _console.print("[dim][3/5] 시나리오 실행 시작 — 타이머 시작[/dim]")

    # ── 4단계: Alert 발화 확인 + MTTD 측정 ────────────────────────────────────
    def verify(self, timeout: int = 120, poll_interval: int = 5) -> VerifyResult:
        if self._start_time == 0:
            self._start_time = time.time()

        _console.rule(f"[bold cyan]4/5  Alert 발화 확인 (최대 {timeout}초)[/bold cyan]")

        deadline = self._start_time + timeout
        check_count = 0
        metrics_text = self._render_metric_chart(force=True)
        metric_poll_interval = 2
        last_metric_time = time.time() - metric_poll_interval   # 첫 반복에서 즉시 수집
        last_check_time = time.time() - poll_interval
        fired = False
        mttd_val = 0.0
        alert_state = "NORMAL"
        _mtta_result: list[float | None] = []
        _mtta_thread: threading.Thread | None = None

        def _make_layout() -> Layout:
            now = time.time()
            elapsed = now - self._start_time
            remaining = max(0.0, deadline - now)

            left_text = Text()
            left_text.append("🔍 Alert 감지 중\n\n", style="bold cyan")
            left_text.append("Alert:     ", style="bold")
            left_text.append(f"{self.alert_name}\n", style="yellow")
            left_text.append("경과:      ", style="bold")
            left_text.append(f"{elapsed:.0f}s / {timeout}s\n")
            left_text.append("남은 시간: ", style="bold")
            left_text.append(f"{remaining:.0f}s\n")
            left_text.append("확인 횟수: ", style="bold")
            left_text.append(f"{check_count}회\n")
            left_text.append("Alert 상태: ", style="bold")
            state_style = {
                "FIRING": "red bold",
                "PENDING": "yellow bold",
                "NORMAL": "green",
            }.get(alert_state, "yellow")
            left_text.append(alert_state, style=state_style)

            layout = Layout()
            layout.split_row(
                Layout(
                    Panel(left_text, title="[bold]진행 상황[/bold]", border_style="cyan"),
                    name="left",
                ),
                Layout(
                    Panel(metrics_text, title="[bold]실시간 Prometheus 그래프[/bold]", border_style="blue"),
                    name="right",
                ),
            )
            return layout

        with Live(_make_layout(), console=_console, refresh_per_second=4) as live:
            while time.time() < deadline:
                now = time.time()

                # 짧은 간격으로 메트릭 수집
                if now - last_metric_time >= metric_poll_interval:
                    metrics = self._get_realtime_metrics()
                    if metrics:
                        self._metric_samples.append((now - self._start_time, metrics["value"]))
                        self._metric_samples = self._metric_samples[-72:]
                        metrics_text = self._render_metric_chart(metrics)
                    else:
                        metrics_text = self._render_metric_chart(metrics, force=True)
                    last_metric_time = now

                # poll_interval마다 Alert 확인
                if now - last_check_time >= poll_interval:
                    check_count += 1
                    last_check_time = now
                    alert_state = self._get_alert_state()
                    if alert_state == "FIRING":
                        fired = True
                        mttd_val = now - self._start_time
                        self._alert_firing_time = now
                        metrics = self._get_realtime_metrics()
                        if metrics:
                            self._metric_samples.append((now - self._start_time, metrics["value"]))
                            self._metric_samples = self._metric_samples[-72:]
                            metrics_text = self._render_metric_chart(metrics, force=True)
                        else:
                            metrics_text = self._render_metric_chart(force=True)
                        live.update(_make_layout())
                        break

                live.update(_make_layout())
                time.sleep(0.3)

        if fired:
            def _run_mtta():
                _mtta_result.append(self.verify_mtta(timeout=self._mtta_timeout))
            _mtta_thread = threading.Thread(target=_run_mtta, daemon=True)
            _mtta_thread.start()
            c = _mttd_color(mttd_val)
            if self._metric_samples:
                _console.print(Panel(
                    self._render_metric_chart(),
                    title="[bold blue]최종 Prometheus 추이[/bold blue]",
                    border_style="blue",
                ))
            _console.print(Panel(
                f"[bold]Alert:[/bold]  [yellow]{self.alert_name}[/yellow]\n"
                f"[bold]MTTD:[/bold]   [{c}]{mttd_val:.1f}초[/{c}]",
                title="[bold red blink]🚨  ALERT FIRING 감지!  🚨[/bold red blink]",
                border_style="red",
            ))
            _mtta_thread.join(timeout=self._mtta_timeout)
            mtta_val = _mtta_result[0] if (_mtta_result and not _mtta_thread.is_alive()) else None
            return VerifyResult(
                success=True,
                alert_name=self.alert_name,
                scenario_name=self.scenario_name,
                mttd_seconds=round(mttd_val, 1),
                mtta_seconds=mtta_val,
                slack_notified=mtta_val is not None,
            )

        _console.print(Panel(
            f"[bold]{timeout}초 내 Alert 미발화[/bold]",
            title="[bold yellow]⏱  TIMEOUT[/bold yellow]",
            border_style="yellow",
        ))
        if self._metric_samples:
            _console.print(Panel(
                self._render_metric_chart(),
                title="[bold blue]최종 Prometheus 추이[/bold blue]",
                border_style="blue",
            ))
        failure_reason, actual_value = self._diagnose_failure()
        return VerifyResult(
            success=False,
            alert_name=self.alert_name,
            scenario_name=self.scenario_name,
            failure_reason=failure_reason,
            actual_value=actual_value,
        )

    # ── 5단계: 결과 기록 ───────────────────────────────────────────────────────
    def log_result(self, result: VerifyResult):
        if self._last_slack_dispatch:
            result.slack_status = result.slack_status or self._last_slack_dispatch.get("status", "")
            result.slack_response_code = (
                result.slack_response_code
                if result.slack_response_code is not None
                else self._last_slack_dispatch.get("response_code")
            )
            result.slack_response_text = (
                result.slack_response_text or self._last_slack_dispatch.get("response_text", "")
            )
        entry = {
            "scenario": result.scenario_name,
            "alert_name": result.alert_name,
            "success": result.success,
            "mttd_seconds": result.mttd_seconds,
            "mtta_seconds": result.mtta_seconds,
            "slack_notified": result.slack_notified,
            "slack_status": result.slack_status,
            "slack_response_code": result.slack_response_code,
            "slack_response_text": result.slack_response_text,
            "failure_reason": result.failure_reason,
            "timestamp": result.timestamp,
            "category": "verification",
        }
        try:
            records = []
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 0:
                with open(LOG_PATH, "r", encoding="utf-8") as f:
                    records = json.load(f)
            records.append(entry)
            os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
            with open(LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2, ensure_ascii=False)
            _console.print("  [dim]→ anomaly_log.json 기록 완료[/dim]")
        except Exception as e:
            _console.print(f"  [red]→ 로그 기록 실패: {e}[/red]")

        _console.rule("[bold]5/5  최종 결과[/bold]")

        table = Table(
            box=box.DOUBLE_EDGE,
            border_style="bold",
            show_header=False,
            padding=(0, 2),
            title=f"[bold]📊  {result.scenario_name}[/bold]",
        )
        table.add_column("항목", style="bold", no_wrap=True, min_width=12)
        table.add_column("값", justify="left")

        table.add_row("시나리오", result.scenario_name)
        table.add_row("목표 Alert", f"[yellow]{result.alert_name}[/yellow]")
        table.add_row(
            "결과",
            "[green bold]SUCCESS ✅[/green bold]" if result.success else "[red bold]FAIL ❌[/red bold]",
        )

        if result.mttd_seconds is not None:
            c = _mttd_color(result.mttd_seconds)
            table.add_row("MTTD", f"[{c} bold]{result.mttd_seconds}초[/{c} bold]")

        if result.mtta_seconds is not None:
            c = _mttd_color(result.mtta_seconds)
            table.add_row("MTTA", f"[{c} bold]{result.mtta_seconds}초[/{c} bold]")
            table.add_row(
                "Slack",
                "[green]전송 완료 ✅[/green]" if result.slack_notified else "[red]미전송 ❌[/red]",
            )

        if result.slack_status:
            table.add_row("Slack 상태", result.slack_status)
        if result.slack_response_code is not None:
            table.add_row("Slack 응답", str(result.slack_response_code))

        if not result.success:
            if result.failure_reason:
                table.add_row("실패 원인", f"[red]{result.failure_reason}[/red]")
            if result.actual_value is not None:
                table.add_row("실제 값", self._format_metric(result.actual_value))

        _console.print(table)

        if _PLOTEXT_AVAILABLE and len(self._metric_samples) >= 2:
            timeline = self._render_plotext_chart(wide=True)
            _console.print(Panel(
                timeline,
                title="[bold blue]📈  전체 메트릭 추이 (공격 전 → 공격 중 → 공격 후)[/bold blue]",
                border_style="blue",
            ))

    # ── repeat_interval 사전 체크 ──────────────────────────────────────────────
    def check_repeat_interval(self) -> bool:
        try:
            url = f"{ALERTMANAGER_URL}/api/v2/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            alerts = json.loads(resp.read().decode())
            active = [
                a for a in alerts
                if a.get("labels", {}).get("alertname") == self.alert_name
                and a.get("status", {}).get("state") == "active"
            ]
            if active:
                _console.print(
                    f"  [yellow]⚠️  경고: {self.alert_name}이 이미 AlertManager에 active 상태[/yellow]"
                )
                _console.print("  [dim]→ repeat_interval 때문에 Pipeline에 재전송이 안 될 수 있음[/dim]")
                return False
            return True
        except Exception:
            return True

    def wait_for_alert_inactive(self, timeout: int = 90, poll_interval: int = 5) -> bool:
        """시나리오 시작 전 이전 Alert 상태가 사라질 때까지 짧게 대기한다."""
        _console.rule("[bold cyan]2-B  Alert 상태 확인[/bold cyan]")
        deadline = time.time() + timeout

        while time.time() < deadline:
            state = self._get_alert_state()
            if state == "NORMAL":
                _console.print(f"  [green]→ {self.alert_name}: inactive ✅[/green]")
                return True
            _console.print(
                f"  [yellow]⚠ 이전 Alert resolve 대기 중... {self.alert_name}: {state}[/yellow]"
            )
            time.sleep(poll_interval)

        _console.print(
            f"  [yellow]⚠ {self.alert_name}가 아직 inactive가 아닙니다. "
            "MTTD가 짧게 측정될 수 있습니다.[/yellow]"
        )
        return False

    # ── 실시간 메트릭 조회 ─────────────────────────────────────────────────────
    def _get_realtime_metrics(self) -> dict:
        """steady_state_query 결과 반환. 없으면 빈 dict."""
        if not self.steady_state_query:
            return {}
        value = self._query_prometheus_instant(self.steady_state_query)
        if value is None:
            return {}
        return {"query": self.steady_state_query, "value": value}

    def _render_plotext_chart(self, wide: bool = False) -> Text:
        """plotext 라인 그래프를 Rich Text로 변환해 반환한다."""
        if len(self._metric_samples) < 2:
            return Text("데이터 수집 중...", style="dim")

        xs = [t for t, _ in self._metric_samples]
        ys = [v * self.metric_scale for _, v in self._metric_samples]
        threshold_scaled = self.steady_state_threshold * self.metric_scale

        plt.clf()
        line_color = "red" if (threshold_scaled > 0 and ys[-1] >= threshold_scaled) else "green"
        plt.plot(xs, ys, color=line_color)
        plt.title(self.metric_label)
        plt.xlabel("경과 시간(초)")
        plt.ylabel(self.metric_unit or "값")
        if self.steady_state_threshold:
            plt.hline(threshold_scaled, color="yellow")
        plt.plotsize(60 if not wide else 60, 20 if wide else 15)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            plt.show()
        chart_str = buf.getvalue()

        try:
            result = Text.from_ansi(chart_str)
        except Exception:
            result = Text(chart_str)
        return result

    def _render_sparkline_chart(self) -> Text:
        """
        plotext 없이도 동작하는 유니코드 스파크라인 차트.
        Mac/Linux/Windows 모든 터미널에서 표시된다.
        """
        _BLOCKS = "▁▂▃▄▅▆▇█"
        CHART_W  = 50   # 가로 너비 (문자 수)
        CHART_H  = 8    # 세로 높이 (줄 수)

        samples = self._metric_samples
        values  = [v * self.metric_scale for _, v in samples]
        scaled_thresh = self.steady_state_threshold * self.metric_scale

        lo = min(values)
        hi = max(values)
        # y축 범위: 임계값이 hi보다 높으면 임계값까지 포함
        y_max = max(hi, scaled_thresh * 1.1) if scaled_thresh > 0 else (hi * 1.1 or 1.0)
        y_min = 0.0

        # CHART_W 폭에 맞게 다운샘플
        if len(values) <= CHART_W:
            pts = values
        else:
            step = len(values) / CHART_W
            pts  = [values[int(i * step)] for i in range(CHART_W)]

        def _norm(v: float) -> float:
            return (v - y_min) / (y_max - y_min) if y_max > y_min else 0.0

        # 2D 그리드 (행=위→아래, 열=왼→오른)
        grid: list[list[str]] = [[" "] * len(pts) for _ in range(CHART_H)]

        thresh_row = int((1 - _norm(scaled_thresh)) * CHART_H) if scaled_thresh > 0 else -1

        for col, v in enumerate(pts):
            bar_height = int(_norm(v) * CHART_H)
            for row in range(CHART_H):
                actual_row = CHART_H - 1 - row   # 아래부터 채움
                if row < bar_height:
                    is_over = scaled_thresh > 0 and v >= scaled_thresh
                    grid[actual_row][col] = "█" if is_over else "▓"

        text = Text()

        # y축 레이블 + 그리드
        for r, row in enumerate(grid):
            # y축 값 레이블 (0번째 행=최대, 마지막 행=0)
            y_val = y_max - (r / (CHART_H - 1)) * (y_max - y_min) if CHART_H > 1 else y_max
            label = f"{y_val:>7.1f}{self.metric_unit} │"
            text.append(label, style="dim")

            for c, cell in enumerate(row):
                is_thresh_line = (r == thresh_row)
                if cell == "█":
                    text.append(cell, style="bold red")
                elif cell == "▓":
                    text.append(cell, style="bold green")
                elif is_thresh_line:
                    text.append("─", style="yellow")
                else:
                    text.append(" ")
            text.append("\n")

        # x축
        text.append(" " * 9 + "└" + "─" * len(pts) + "\n", style="dim")

        # 범례
        current = values[-1]
        peak    = max(values)
        status  = "FIRING" if scaled_thresh > 0 and current >= scaled_thresh else "NORMAL"
        s_style = "bold red" if status == "FIRING" else "bold green"

        text.append(f"  현재값  : ", style="bold")
        text.append(f"{current:.1f}{self.metric_unit}\n", style=self._metric_style(self._metric_samples[-1][1]))
        if scaled_thresh > 0:
            text.append(f"  임계값  : ", style="bold")
            text.append(f"{scaled_thresh:.1f}{self.metric_unit}  ", style="yellow")
            text.append("── (노란 선)\n", style="dim yellow")
        text.append(f"  최고/최저: ", style="bold")
        text.append(f"{peak:.1f} / {lo * self.metric_scale:.1f}{self.metric_unit}\n")
        text.append(f"  Status  : ", style="bold")
        text.append(f"{status}\n", style=s_style)
        text.append(f"  샘플 {len(samples)}개  ·  [dim](█ FIRING  ▓ normal  ── threshold)[/dim]\n")

        return text

    def _render_metric_chart(self, metrics: dict | None = None, force: bool = False) -> Text:
        """Rich 텍스트로 Prometheus 샘플 추이를 그린다."""
        text = Text()
        if not self.steady_state_query:
            text.append("Prometheus 쿼리 미설정\n", style="dim")
            text.append("steady_state_query를 지정하면 실시간 그래프가 표시됩니다.", style="dim")
            return text

        # ── 샘플이 2개 이상이면 그래프 표시 (plotext 우선, 없으면 스파크라인) ──
        if len(self._metric_samples) >= 2:
            if _PLOTEXT_AVAILABLE:
                result = self._render_plotext_chart()
            else:
                result = self._render_sparkline_chart()
            value = self._metric_samples[-1][1]
            result.append("\n현재값: ", style="bold")
            result.append(self._format_metric(value), style=self._metric_style(value))
            if self.steady_state_threshold:
                result.append("  임계값: ", style="bold")
                result.append(self._format_metric(self.steady_state_threshold), style="yellow")
            result.append(f"  ({len(self._metric_samples)}샘플)\n")
            return result

        # ── 샘플 부족 시 대기 화면 ──
        query_short = self.steady_state_query[:76] + ("…" if len(self.steady_state_query) > 76 else "")
        text.append("Query\n", style="bold")
        text.append(f"{query_short}\n\n", style="dim")

        if metrics and metrics.get("value") is not None:
            value = metrics["value"]
        elif self._metric_samples:
            value = self._metric_samples[-1][1]
        else:
            if not force:
                text.append("Prometheus 샘플 수집 대기 중...", style="yellow")
                return text
            text.append("Prometheus 샘플 준비 중\n", style="yellow")
            text.append(f"{self.metric_label}\n", style="bold")
            self._append_pressure_bar(text, 0.0)
            text.append(f"  {self._format_metric(0.0)}\n", style="dim")
            if self.steady_state_threshold:
                text.append("Threshold: ", style="bold")
                text.append(f"{self._format_metric(self.steady_state_threshold)}\n", style="yellow")
            text.append("Status: ", style="bold")
            text.append("WAITING\n", style="yellow")
            text.append("  샘플 0개")
            return text

        threshold = self.steady_state_threshold
        status = "FIRING" if threshold and value >= threshold else "NORMAL"
        status_style = self._metric_style(value)
        peak = max(v for _, v in self._metric_samples) if self._metric_samples else value
        low  = min(v for _, v in self._metric_samples) if self._metric_samples else value

        text.append(f"{self.metric_label}\n", style="bold")
        self._append_pressure_bar(text, value)
        text.append(f"  {self._format_metric(value)}\n", style=status_style)
        if threshold:
            text.append("Threshold: ", style="bold")
            text.append(f"{self._format_metric(threshold)}\n", style="yellow")
        text.append("최고/최저: ", style="bold")
        text.append(f"{self._format_metric(peak)} / {self._format_metric(low)}\n\n")

        text.append("Status: ", style="bold")
        text.append(f"{status}\n", style=status_style)
        text.append(f"  샘플 {len(self._metric_samples)}개")
        return text

    def _append_pressure_bar(self, text: Text, value: float, width: int = 20) -> None:
        threshold = self.steady_state_threshold
        if self.metric_unit == "%":
            ratio = max(0.0, min(self._metric_percent(value) / 100.0, 1.0))
        elif threshold > 0:
            ratio = max(0.0, min(value / threshold, 1.0))
        else:
            peak = max((v for _, v in self._metric_samples), default=value) or 1.0
            ratio = max(0.0, min(value / peak, 1.0))

        filled = int(round(ratio * width))
        style = self._metric_style(value)
        text.append("[", style="dim")
        text.append("█" * filled, style=style)
        text.append("-" * (width - filled), style="dim")
        text.append("]", style="dim")

    def _metric_percent(self, value: float | None) -> float:
        if value is None:
            return 0.0
        return max(0.0, min(value * self.metric_scale, 100.0))

    def _metric_style(self, value: float | None) -> str:
        if self.metric_unit == "%":
            percent = self._metric_percent(value)
            if percent >= 80:
                return "red bold"
            if percent >= 50:
                return "yellow bold"
            return "green"
        if self.steady_state_threshold and value is not None and value >= self.steady_state_threshold:
            return "red bold"
        return "green"

    def _format_metric(self, value: float | None) -> str:
        if value is None:
            return "-"
        scaled = value * self.metric_scale
        suffix = self.metric_unit
        if suffix == "%":
            return f"{scaled:.1f}%"
        return f"{scaled:.4f}{suffix}"

    # ── 내부 유틸 ──────────────────────────────────────────────────────────────
    def _get_alert_state(self) -> str:
        try:
            url = f"{PROMETHEUS_URL}/api/v1/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            alerts = data.get("data", {}).get("alerts", [])
            states = [
                alert.get("state", "").upper()
                for alert in alerts
                if alert.get("labels", {}).get("alertname") == self.alert_name
            ]
            if "FIRING" in states:
                return "FIRING"
            if "PENDING" in states:
                return "PENDING"
            return "NORMAL"
        except Exception:
            return "UNKNOWN"

    def _check_alert_firing(self) -> bool:
        return self._get_alert_state() == "FIRING"

    def _query_prometheus_instant(self, query: str) -> float | None:
        try:
            params = urllib.parse.urlencode({"query": query})
            url = f"{PROMETHEUS_URL}/api/v1/query?{params}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            results = data.get("data", {}).get("result", [])
            if results:
                return float(results[0]["value"][1])
            return None
        except Exception:
            return None

    def _diagnose_failure(self) -> tuple[str, float | None]:
        try:
            url = f"{ALERTMANAGER_URL}/api/v2/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            alerts = json.loads(resp.read().decode())
            active = [a for a in alerts if a.get("labels", {}).get("alertname") == self.alert_name]
            if active:
                return "Alert이 AlertManager에 존재하지만 Prometheus에서 FIRING 아님 (repeat_interval 문제 가능)", None
        except Exception:
            pass

        try:
            url = f"{PROMETHEUS_URL}/api/v1/alerts"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            alerts = data.get("data", {}).get("alerts", [])
            for alert in alerts:
                if alert.get("labels", {}).get("alertname") == self.alert_name:
                    state = alert.get("state", "")
                    if state == "pending":
                        return "Alert이 PENDING 상태 (for 조건 미충족 — 지속 시간 부족)", None
        except Exception:
            pass

        if self.steady_state_query:
            value = self._query_prometheus_instant(self.steady_state_query)
            if value is not None:
                return (
                    f"메트릭 값({self._format_metric(value)})이 "
                    f"임계값({self._format_metric(self.steady_state_threshold)})에 미달",
                    value,
                )

        return "원인 미상 — Prometheus 쿼리 확인 필요", None

    def check_l7_health(self, host: str, port: int, path: str = "/health") -> bool:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=3)
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status == 200
        except Exception:
            return False

    def verify_recovery(self, target_host: str, target_port: int, timeout: int = 300) -> float:
        recovery_start = time.time()
        deadline = recovery_start + timeout

        _console.rule("[bold cyan]4-B  복구 확인 및 MTTR 측정[/bold cyan]")

        while time.time() < deadline:
            is_firing = self._check_alert_firing()
            is_healthy = self.check_l7_health(target_host, target_port)

            if not is_firing and is_healthy:
                mttr = time.time() - self._start_time
                c = _mttd_color(mttr)
                _console.print(f"  [green]→ 복구 완료 ✅  MTTR: [{c}]{mttr:.1f}초[/{c}][/green]")
                return round(mttr, 1)

            _console.print(
                f"  → 복구 대기 중... (Alert Firing: {is_firing}, L7 Healthy: {is_healthy})"
            )
            time.sleep(5)

        _console.print("  [red]→ 복구 확인 타임아웃 ❌[/red]")
        return -1.0

    # ── 4단계-B: MTTA 측정 ────────────────────────────────────────────────────
    def verify_mtta(self, timeout: int = 180, poll_interval: int = 5) -> float | None:
        _console.rule(f"[bold cyan]4-B  MTTA 측정 (Slack 알림까지, 최대 {timeout}초)[/bold cyan]")

        deadline = time.time() + timeout
        check_count = 0
        last_check_time = time.time() - poll_interval
        found = False
        mtta_val = 0.0

        def _render() -> Panel:
            remaining = max(0.0, deadline - time.time())
            content = Text()
            content.append("⏳ Slack 알림 대기 중...\n\n", style="bold cyan")
            content.append("Alert:     ", style="bold")
            content.append(f"{self.alert_name}\n", style="yellow")
            content.append("확인 횟수: ", style="bold")
            content.append(f"{check_count}회\n")
            content.append("남은 시간: ", style="bold")
            content.append(f"{remaining:.0f}초")
            return Panel(content, title="[bold cyan]MTTA 측정 중[/bold cyan]", border_style="cyan")

        with Live(_render(), console=_console, refresh_per_second=4) as live:
            while time.time() < deadline:
                now = time.time()
                if now - last_check_time >= poll_interval:
                    check_count += 1
                    last_check_time = now
                    dispatch = self._query_loki_slack_sent()
                    if dispatch is not None:
                        self._last_slack_dispatch = dispatch
                    # 수정 후
                    if dispatch is not None and dispatch.get("status") == "SUCCESS":
                        dispatch_ts = dispatch.get("timestamp", time.time())
                        baseline_ts = self._alert_firing_time or self._start_time
                        mtta_val = dispatch_ts - baseline_ts

                        # ── 음수 필터링: 이전 실행 잔여 로그 무시 ──
                        if mtta_val < 0:
                            continue  # ← 이전 실행 로그 → 건너뛰고 계속 폴링

                        found = True
                        break

                live.update(_render())
                time.sleep(0.3)

        if found:
            c = _mttd_color(mtta_val)
            code = self._last_slack_dispatch.get("response_code")
            _console.print(Panel(
                f"[bold]Alert:[/bold]  [yellow]{self.alert_name}[/yellow]\n"
                f"[bold]MTTA:[/bold]   [{c} bold]{mtta_val:.1f}초[/{c} bold]\n"
                f"[bold]Slack:[/bold]  [green]webhook delivered[/green]"
                + (f" ([green]{code}[/green])" if code is not None else ""),
                title="[bold green]✅  Slack notification dispatched[/bold green]",
                border_style="green",
            ))
            _console.print("[green]🎉 Slack 알림 전송 완료![/green]")
            celebrate = Text(justify="center")
            celebrate.append("🎉  Slack 알림이 성공적으로 전송되었습니다!\n\n", style="bold green")
            celebrate.append(f"   MTTA: {mtta_val:.1f}초", style=f"bold {c}")
            celebrate.append("  ·  AIOps 자동화 성공!", style="bold green")
            _console.print(Panel(
                celebrate,
                title="[bold green blink]🎉  알림 전송 완료!  🎉[/bold green blink]",
                border_style="green",
                padding=(1, 4),
            ))
            return round(mtta_val, 1)

        if self._last_slack_dispatch:
            _console.print(
                "[red]  → Slack webhook failed[/red] "
                f"(code={self._last_slack_dispatch.get('response_code')}, "
                f"text={self._last_slack_dispatch.get('response_text')})"
            )
        else:
            _console.print("[yellow]  → MTTA 측정 타임아웃 ❌[/yellow]")
        return None

    def _query_loki_slack_sent(self) -> dict | None:
        try:
            baseline = self._start_time - 60
            start_ns = int(baseline * 1_000_000_000)
            end_ns = int(time.time() * 1_000_000_000)
            query = '{job="aiops-slack"}'
            params = urllib.parse.urlencode({
                "query": query,
                "start": start_ns,
                "end": end_ns,
                "limit": 50,
                "direction": "forward",
            })
            url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            streams = data.get("data", {}).get("result", [])
            latest_dispatch = None
            for stream in streams:
                labels = stream.get("stream", {})
                alert_label = labels.get("alert")
                if alert_label and alert_label != self.alert_name:
                    continue
                for ts_ns, line in stream.get("values", []):
                    entry = json.loads(line)
                    if entry.get("event") != "slack_notification":
                        continue
                    entry_alert = entry.get("alert_name")
                    if entry_alert and entry_alert != self.alert_name:
                        continue
                    latest_dispatch = {
                        "timestamp": int(ts_ns) / 1_000_000_000,
                        "status": entry.get("slack_status", entry.get("status", "")),
                        "response_code": entry.get("slack_response_code"),
                        "response_text": entry.get("slack_response_text", ""),
                    }
                    if latest_dispatch["status"] == "SUCCESS":
                        return latest_dispatch
            return latest_dispatch
        except Exception:
            return None

    def verify_loki(
        self,
        log_query: str,
        keyword: str,
        timeout: int = 180,
        poll_interval: int = 5,
    ) -> float | None:
        _console.rule("[bold cyan]4-B  Loki 탐지 대기[/bold cyan]")
        _console.print(f"  키워드: [yellow]'{keyword}'[/yellow] / 최대 {timeout}초")

        deadline = time.time() + timeout
        check_count = 0
        last_check_time = time.time() - poll_interval
        found = False
        mttd_val = 0.0

        def _render() -> Panel:
            remaining = max(0.0, deadline - time.time())
            content = Text()
            content.append("🔎 로그 탐지 중...\n\n", style="bold cyan")
            content.append("키워드:    ", style="bold")
            content.append(f"{keyword}\n", style="yellow")
            content.append("확인 횟수: ", style="bold")
            content.append(f"{check_count}회\n")
            content.append("남은 시간: ", style="bold")
            content.append(f"{remaining:.0f}초")
            return Panel(content, title="[bold cyan]Loki 탐지 중[/bold cyan]", border_style="cyan")

        with Live(_render(), console=_console, refresh_per_second=4) as live:
            while time.time() < deadline:
                now = time.time()
                if now - last_check_time >= poll_interval:
                    check_count += 1
                    last_check_time = now
                    ts = self._query_loki_keyword(log_query, keyword)
                    if ts is not None:
                        mttd_val = ts - self._start_time
                        found = True
                        break
                live.update(_render())
                time.sleep(0.3)

        if found:
            c = _mttd_color(mttd_val)
            _console.print(Panel(
                f"[bold]키워드:[/bold]  [yellow]{keyword}[/yellow]\n"
                f"[bold]MTTD:[/bold]    [{c} bold]{mttd_val:.1f}초[/{c} bold]",
                title="[bold green]✅  Loki 탐지 성공![/bold green]",
                border_style="green",
            ))
            return round(mttd_val, 1)

        _console.print("[yellow]  → Loki 탐지 타임아웃 ❌[/yellow]")
        return None

    def _query_loki_keyword(self, log_query: str, keyword: str) -> float | None:
        try:
            start_ns = int(self._start_time * 1_000_000_000)
            end_ns = int(time.time() * 1_000_000_000)
            params = urllib.parse.urlencode({
                "query": log_query,
                "start": start_ns,
                "end": end_ns,
                "limit": 100,
                "direction": "forward",
            })
            url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            resp = urllib.request.urlopen(req, timeout=5)
            data = json.loads(resp.read().decode())
            streams = data.get("data", {}).get("result", [])
            for stream in streams:
                for ts_ns, line in stream.get("values", []):
                    if keyword.lower() in line.lower():
                        return int(ts_ns) / 1_000_000_000
            return None
        except Exception:
            return None
