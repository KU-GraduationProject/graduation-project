from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time
import webbrowser

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Center, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Select, Sparkline, Static

from .catalog import CATALOG, group
from .client import Airflow, Backend, Injector, clean
from .state import History, Run, STAGES, TERMINAL, instant, now


def plain(value):
    return Text(clean(value))


def seconds(value):
    return "—" if value is None else f"{value:.1f}s"


class Home(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="home"):
            yield Static("L E A F Y  /  A I O P S", id="brand")
            yield Static("OBSERVE  →  REASON  →  APPROVE  →  RECOVER", id="tagline")
            yield Static("발표자가 시작하고, 실제 이벤트가 화면을 바꿉니다.", classes="muted")
            with Center(classes="home-action"):
                yield Button("시나리오 실행", id="scenario", variant="success")
            with Center(classes="home-action"):
                yield Button("Airflow 배치 실행", id="airflow", variant="primary")
            yield Static(plain(f"환경 · {self.app.config.name}"), classes="muted")
        yield Footer()

    @on(Button.Pressed, "#scenario")
    def scenario(self):
        self.app.push_screen(ChooseScenario())

    @on(Button.Pressed, "#airflow")
    def airflow(self):
        self.app.push_screen(AirflowScreen())


class ChooseScenario(Screen):
    BINDINGS = [("escape", "back", "홈")]

    def compose(self):
        yield Header()
        with VerticalScroll(id="picker"):
            yield Label("시나리오 실행", classes="title")
            yield Select([("S · 보안 공격", "S"), ("F · 서비스 장애", "F"), ("C · 대조 시나리오", "C")], value="F", allow_blank=False, id="group")
            yield Select([], id="scenario-choice", prompt="시나리오 선택")
            yield Static(id="description", classes="panel")
            yield Static("이름·증거 채널·설명은 scenarios/v2/registry.py 기준입니다.\n대조군은 경보·승인이 없을 수 있습니다. 외부도구 항목은 실행을 지원하지 않습니다.", classes="muted")
            yield Button("실행", id="launch", variant="success", disabled=True)
            yield Button("홈", id="back")
        yield Footer()

    def on_mount(self):
        self.fill("F")

    def fill(self, letter):
        rows = group(letter)
        self.query_one("#scenario-choice", Select).set_options(
            [(f"{r['id']} · {r['label']}" + (" · 외부/별도 러너" if not r["module"] else ""), r["id"]) for r in rows])
        self.query_one("#launch", Button).disabled = True

    @on(Select.Changed, "#group")
    def changed_group(self, event):
        if event.value != Select.BLANK:
            self.fill(event.value)

    @on(Select.Changed, "#scenario-choice")
    def changed_scenario(self, event):
        row = next((r for r in CATALOG if r["id"] == event.value), None)
        if not row:
            return
        measured = row["id"] in {"s2_a_resource_theft", "f1_b_memory_leak", "f2_a_minio_outage"}
        description = (f"{row['label']}\n{row['id']}\n증거 · {', '.join(row['evidence'])}\n"
                       f"{row.get('description') or ''}\n"
                       f"{row.get('notes') or ''}\n"
                       + ("주입 확인 이벤트와 기존 inject/cleanup을 연결합니다." if measured else
                          "기존 v2 러너의 전체 생명주기를 실행합니다. 주입 시각 훅이 없어 TTD/TTR 평균 표본에 넣지 않습니다."))
        self.query_one("#description", Static).update(plain(description))
        self.query_one("#launch", Button).disabled = not bool(row["module"])

    @on(Button.Pressed, "#launch")
    def launch(self):
        selected = self.query_one("#scenario-choice", Select).value
        self.app.push_screen(ScenarioScreen(next(r for r in CATALOG if r["id"] == selected)))

    @on(Button.Pressed, "#back")
    def action_back(self):
        self.app.pop_screen()


class ScenarioScreen(Screen):
    BINDINGS = [("escape", "leave", "중지/뒤로"), ("o", "slack", "Slack 열기")]

    def __init__(self, row):
        super().__init__()
        self.row = row
        self.config = None
        self.run = None
        self.backend = None
        self.injector = None
        self.metrics = {}
        self.chart = []
        self.logs = []
        self.warning = ""
        self.evidence = None
        self.execution_logs = []
        self.frame = 0
        self.closing = False
        self.cleanup_unconfirmed = False

    def compose(self):
        yield Header()
        yield Static(plain(self.row["label"] + "  /  " + self.row["id"]), classes="title")
        yield Static("연결 확인 중", id="stage", classes="panel")
        yield Static(id="timings", classes="panel")
        with Horizontal(id="dashboard"):
            with VerticalScroll(id="observations"):
                yield Static("현재 관측", classes="section")
                yield Static(id="metrics")
                yield Sparkline([], id="spark")
                yield Static("최근 서비스 로그", classes="section")
                yield Static(id="logs")
            with VerticalScroll(id="reasoning"):
                yield Static("RCA · LLM 입력과 결과", classes="section")
                yield Static(id="rca")
                yield Static(id="slack", classes="panel")
                yield Button("Slack 메시지 열기 [O]", id="open-slack", disabled=True)
        with Horizontal(id="execution"):
            yield Static(id="pet")
            with VerticalScroll():
                yield Static(id="execution-logs")
        yield Static(id="notice", classes="muted")
        yield Button("중지 후 정리 / 뒤로", id="stop")
        yield Footer()

    def on_mount(self):
        self.set_class(self.size.width < 90, "narrow")
        self.set_interval(0.15, self.render_state)
        self.execute()

    def on_resize(self, event):
        self.set_class(event.size.width < 90, "narrow")

    def worker_event(self, event):
        kind = event.get("event")
        if kind == "injected":
            self.run.fault_at = event["at"]
            self.run.reason = "기존 주입기 실행 확인 · 경보 수신 대기"
            self.run.event("장애 발생 · " + event["at"])
        elif kind == "unmeasured_started":
            self.run.reason = "기존 시나리오 실행 중 · 주입 시각 미제공(시간 표본 제외)"
            self.run.event(self.run.reason)
        elif kind == "failed" and self.run.status not in TERMINAL:
            self.run.fail("장애 발생", event.get("reason", "scenario_failed"))
        elif kind == "safety_timeout" and self.run.status not in TERMINAL:
            self.run.fail(self.run.stage, "안전 상한 도달 · 주입기 자동 정리")
        elif kind == "cleanup":
            self.run.event("주입기 정리 · " + ("완료" if event.get("ok") else "실패"))
            if not event.get("ok"):
                self.warning = "주입기 정리 실패 · 대상 장비에서 확인하세요"
        elif kind == "scenario_finished":
            self.run.event("기존 시나리오 주입/자체 정리 완료")

    @work(exclusive=True, exit_on_error=False)
    async def execute(self):
        try:
            self.config = self.app.config.for_scenario(self.row["id"])
            self.run = Run(self.row["id"], self.config.identity)
            self.backend = Backend(self.config)
            self.injector = Injector(self.config, self.run, self.worker_event)
            status = await self.backend.status(self.run)
            await self.backend.get(self.config.pipeline_url, "/health")
            if status["capture_status"] != "ok":
                raise ValueError("CONTEXT_CAPTURE_DIR / PRESENTATION_CONTEXT_DIR 설정이 필요합니다")
            if status["mode"] == "disabled":
                raise ValueError("기존 remediation 실행 모드가 disabled입니다")
            if not status.get("slack_link_configured"):
                raise ValueError("Slack 메시지 링크를 위해 remediation에 SLACK_BOT_TOKEN을 설정하세요")
            # Scope checks happen before injecting a fault.
            self.metrics, self.logs = await asyncio.gather(
                self.backend.metrics(), self.backend.logs(self.config.log_selector, time.time() - 60))
            if not any(self.metrics.values()):
                raise ValueError("대상 지표가 비어 있습니다 · metric_selector를 확인하세요")
            await self.injector.start()
            while not self.closing and self.run.status not in TERMINAL:
                await self.poll()
                self.app.history.save(self.run)
                if time.time() - instant(self.run.started_at) > self.config.timeout and self.run.status not in TERMINAL:
                    if self.row["id"].startswith("c_") and not self.run.incident:
                        self.run.fail("탐지", "관측 구간 종료 · 새 경보 없음(복구 완료 표본 아님)", "NO_ALERT")
                    else:
                        self.run.fail(self.run.stage, "실행 제한 시간 초과 · 실제 이벤트를 확인하지 못했습니다")
                await asyncio.sleep(self.config.poll_seconds)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if self.run:
                self.run.fail(self.run.stage, clean(str(exc)) if isinstance(exc, ValueError) else type(exc).__name__)
            else:
                self.warning = "프로필 오류 · " + clean(str(exc))
        finally:
            if self.injector:
                try:
                    await self.injector.close()
                except RuntimeError as exc:
                    self.cleanup_unconfirmed = True
                    self.warning = str(exc)
                    if self.run.status not in TERMINAL:
                        self.run.fail(self.run.stage, self.warning)
            if self.run:
                self.app.history.save(self.run)
            if self.backend:
                await self.backend.close()

    async def poll(self):
        outputs = await asyncio.gather(self.backend.status(self.run), self.backend.rca(instant(self.run.started_at)),
            self.backend.metrics(), self.backend.logs(self.config.log_selector, max(instant(self.run.started_at), time.time() - 120)),
            return_exceptions=True)
        errors = []
        status, rca, metrics, logs = outputs
        for name, output in zip(("상태", "RCA", "지표", "로그"), outputs):
            if isinstance(output, Exception):
                errors.append(f"{name}: {type(output).__name__}")
        self.warning = " · ".join(errors)
        if not isinstance(status, Exception):
            self.run.attach_contexts(status["contexts"])
        if not isinstance(rca, Exception):
            self.run.attach_rca(rca)
            if self.run.rca and self.evidence is None:
                self.evidence = await self.backend.evidence(self.run) or ""
        if not isinstance(status, Exception) and status.get("record"):
            self.run.attach_record(status["record"])
            try:
                self.execution_logs = await self.backend.execution_logs(self.run)
            except Exception:
                self.warning = (self.warning + " · " if self.warning else "") + "조치 감사 로그 조회 지연"
            if self.run.stage == "복구 검증" and self.run.status not in TERMINAL:
                await self.backend.verify(self.run.remediation_id)
        if not isinstance(metrics, Exception):
            self.metrics = metrics
            cpu = next((v[0] for k, v in metrics.items() if k.startswith("CPU") and v), None)
            if cpu is not None:
                self.chart = (self.chart + [cpu])[-80:]
        if not isinstance(logs, Exception):
            self.logs = logs
        if self.injector.process and self.injector.process.returncode not in (None, 0) and self.run.status not in TERMINAL:
            self.run.fail("장애 발생", f"주입 프로세스 종료 코드 {self.injector.process.returncode}")

    def render_state(self):
        self.frame += 1
        if not self.run:
            self.query_one("#notice", Static).update(plain(self.warning))
            return
        run = self.run
        trail = "  →  ".join(("● " if s == run.stage else "") + s for s in STAGES)
        self.query_one("#stage", Static).update(plain(f"{run.status}  /  {run.stage}\n{trail}\n{run.reason}"))
        timings, average = run.timings(), self.app.history.summary()
        self.query_one("#timings", Static).update(plain(
            f"TTD {seconds(timings['ttd'])}    TTR {seconds(timings['ttr'])}    승인 대기 {seconds(timings['approval'])}    조치 {seconds(timings['action'])}\n"
            f"MTTD {seconds(average['mttd'][0])} (n={average['mttd'][1]})    MTTR {seconds(average['mttr'][0])} (n={average['mttr'][1]}) · 이 환경에 기록된 실행 평균\n"
            f"발생 {run.fault_at or '미기록'}  /  탐지 {run.detected_at or '미기록'}  /  복구 {run.recovered_at or '미기록'}"))
        metric_text = "\n".join(f"{k:<16} {v[0]:,.3f}  @ {v[1]}" if v else f"{k:<16} — (미수집/다중 시계열)" for k, v in self.metrics.items())
        self.query_one("#metrics", Static).update(plain(metric_text or "관측 대기"))
        self.query_one("#spark", Sparkline).data = self.chart
        self.query_one("#logs", Static).update(plain("\n".join(self.logs[-25:]) or "로그 없음 / 미수집"))
        result = run.rca.get("result", {})
        capture = run.context
        text = (f"원인 · {result.get('root_cause', 'LLM 결과 대기')}\n"
                f"제안 · {result.get('action_type', '—')} → {', '.join(result.get('action_targets', []))}\n"
                f"인용 증거 ID · {', '.join(result.get('evidence', [])) or '—'}\n\n"
                "경보 시점 LLM 수집 입력 (현재 관측과 별도)\n")
        if self.evidence:
            cited = set(result.get("evidence", []))
            for line in self.evidence.splitlines():
                hit = any(line.startswith("[" + key + "]") for key in cited)
                text += ("▶ " if hit else "  ") + line + "\n"
        else:
            text += "증거 ID 포맷 재현 대기/미지원 · 아래는 수집 입력 원문 요약입니다.\n"
            for name, series in capture.get("metrics", {}).items():
                text += name + " · " + json.dumps(series, ensure_ascii=False)[-1000:] + "\n"
            text += "\n".join(row.get("line", "") for row in capture.get("logs", [])[-12:])
        if capture.get("network", {}).get("events"):
            text += "\nNetwork · " + json.dumps(capture["network"]["events"][-5:], ensure_ascii=False)
        self.query_one("#rca", Static).update(plain(text))
        record = run.record
        verification = record.get("service_verification", {})
        slack_text = (f"승인 · {record.get('state', '아직 요청되지 않음')}\n"
                      f"{run.slack_url or '메시지 링크 대기'}\n"
                      f"복구 검증 · {verification.get('state', '대기')}  {verification.get('consecutive', 0)}/{verification.get('required_samples', '—')}")
        self.query_one("#slack", Static).update(plain(slack_text))
        self.query_one("#open-slack", Button).disabled = not bool(run.slack_url)
        # Original tiny pixel character inspired by the supplied terminal mood.
        # Only an animation: its position never implies execution progress.
        width = max(1, self.query_one("#pet").size.width - 12)
        active = run.stage == "조치" and run.status not in TERMINAL
        offset = abs((self.frame % (width * 2)) - width) if active else 0
        sprite = ("   ▄████▄\n  ██ ▀ ▀ █\n  ████████\n   ██  ██" if self.frame % 4 < 2 else
                  "   ▄████▄\n  ██ ▀ ▀ █\n  ████████\n  ██    ██")
        self.query_one("#pet", Static).update(Text("\n".join(" " * offset + line for line in sprite.splitlines()), style="#ee8658"))
        execution = [f"{e['at'][11:19]} {e['message']}" for e in run.events[-12:]]
        execution += self.execution_logs[-8:]
        execution += ["주입기 · " + line for line in (self.injector.output[-6:] if self.injector else [])]
        if record.get("results"):
            execution.append("실행 결과 · " + json.dumps(record["results"], ensure_ascii=False))
        self.query_one("#execution-logs", Static).update(plain("\n".join(execution)))
        self.query_one("#notice", Static).update(plain(self.warning or "시간: UTC · TTD=주입 확인→Pipeline 경보 수신 · TTR=주입 확인→서비스 복구 검증"))

    @on(Button.Pressed, "#open-slack")
    def action_slack(self):
        if self.run and self.run.slack_url:
            webbrowser.open(self.run.slack_url)

    @on(Button.Pressed, "#stop")
    async def action_leave(self):
        retry_cleanup = self.cleanup_unconfirmed
        self.closing = True
        if self.run and self.run.status not in TERMINAL:
            self.run.fail(self.run.stage, "발표자 중지 · 주입기 정리", "CANCELLED")
        # Wait for owned worker cleanup before allowing another injection.
        await self.workers.wait_for_complete()
        if retry_cleanup:
            try:
                await self.injector.close()
                self.cleanup_unconfirmed = False
            except RuntimeError as exc:
                self.warning = str(exc)
        if self.cleanup_unconfirmed:
            self.notify("주입기 정리 미확인 · 화면에 머물러 대상 호스트 상태를 확인하세요", severity="error")
            return False
        self.app.pop_screen()
        return True


class AirflowScreen(Screen):
    BINDINGS = [("escape", "back", "홈"), ("r", "refresh", "상태 조회")]

    def __init__(self):
        super().__init__()
        self.client = None
        self.run_id = None
        self.dag_id = None
        self.inflight = False
        self.finished = False

    def compose(self):
        yield Header()
        with VerticalScroll(id="airflow-body"):
            yield Label("Airflow 배치 실행", classes="title")
            yield Select([], id="dag", prompt="기존 DAG 불러오는 중")
            yield Input("{}", placeholder="dag_run.conf JSON", id="conf")
            with Horizontal(classes="buttons"):
                yield Button("Trigger", id="trigger", variant="primary", disabled=True)
                yield Button("상태 조회 [R]", id="refresh")
                yield Button("홈", id="airflow-back")
            yield Static(id="dag-state", classes="panel")
            yield Static(id="tasks", classes="panel")
        yield Footer()

    async def on_mount(self):
        self.client = Airflow(self.app.config)
        self.load_dags()
        self.set_interval(3, self.poll_interval)

    @work(exclusive=True, exit_on_error=False, group="load")
    async def load_dags(self):
        try:
            rows = await self.client.dags()
            self.query_one("#dag", Select).set_options([(r["dag_id"] + (" (paused)" if r.get("is_paused") else ""), r["dag_id"]) for r in rows])
            self.query_one("#trigger", Button).disabled = not bool(rows)
            self.query_one("#dag-state", Static).update(plain("기존 dp_* DAG 선택 후 Trigger · 자동 재시도 없음"))
        except Exception as exc:
            self.query_one("#dag-state", Static).update(plain(f"DAG 조회 실패 · {type(exc).__name__} · URL/인증/서비스 상태 확인"))

    @on(Button.Pressed, "#trigger")
    @work(exclusive=True, exit_on_error=False, group="trigger")
    async def trigger(self):
        if self.inflight or self.run_id and not self.finished:
            return
        selected = self.query_one("#dag", Select).value
        if selected == Select.BLANK:
            return
        try:
            conf = json.loads(self.query_one("#conf", Input).value)
            if not isinstance(conf, dict):
                raise ValueError()
        except ValueError:
            self.query_one("#dag-state", Static).update("conf는 JSON object여야 합니다")
            return
        self.inflight = True
        self.query_one("#trigger", Button).disabled = True
        self.dag_id = selected
        self.run_id, path, body = await self.client.trigger(selected, conf)
        self.finished = False
        self.query_one("#dag-state", Static).update(plain(f"SUBMITTING · {self.dag_id}\nRun ID · {self.run_id}"))
        try:
            await self.client.request("POST", path, json=body)
        except Exception as exc:
            self.query_one("#dag-state", Static).update(plain(f"실행 접수 미확인 · {type(exc).__name__}\nRun ID · {self.run_id}\n중복 Trigger 없이 상태 조회로 확인하세요"))
        finally:
            self.inflight = False
        self.action_refresh()

    def poll_interval(self):
        if self.run_id and not self.inflight and not self.finished:
            self.action_refresh()

    @on(Button.Pressed, "#refresh")
    @work(exclusive=True, exit_on_error=False, group="poll")
    async def action_refresh(self):
        if not self.run_id:
            self.load_dags()
            return
        try:
            row, tasks = await asyncio.gather(self.client.run(self.dag_id, self.run_id), self.client.tasks(self.dag_id, self.run_id))
            state = row.get("state", "unknown")
            self.finished = state in {"success", "failed"}
            self.query_one("#trigger", Button).disabled = not self.finished
            self.query_one("#dag-state", Static).update(plain(f"{state.upper()} · {self.dag_id}\nRun ID · {self.run_id}\n시작 {row.get('start_date') or '—'}  /  종료 {row.get('end_date') or '—'}"))
            self.query_one("#tasks", Static).update(plain("\n".join(f"{r['task_id']} [{r.get('map_index', -1)}] · {r.get('state') or '대기'}" for r in tasks.get("task_instances", []))))
        except Exception as exc:
            self.query_one("#dag-state", Static).update(plain(f"상태 조회 실패 · {type(exc).__name__}\nRun ID · {self.run_id}\n[R] 재조회 · 기존 실행은 계속됩니다"))

    @on(Button.Pressed, "#airflow-back")
    async def action_back(self):
        self.workers.cancel_all()
        if self.client:
            await self.client.close()
        self.app.pop_screen()


class LeafyApp(App):
    TITLE = "Leafy AIOps / LIVE DEMO"
    CSS_PATH = "presentation.tcss"
    BINDINGS = [("ctrl+q", "safe_quit", "종료")]

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.history = History(Path(config.history).expanduser())

    def on_mount(self):
        self.push_screen(Home())

    async def action_safe_quit(self):
        if isinstance(self.screen, ScenarioScreen):
            if not await self.screen.action_leave():
                return
        elif isinstance(self.screen, AirflowScreen):
            await self.screen.action_back()
        self.exit()

    def on_unmount(self):
        self.history.db.close()
