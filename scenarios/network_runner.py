#!/usr/bin/env python3
"""
scenarios/network_runner.py
───────────────────────────
S2/C-a 네트워크 탐지 시나리오 런처

run.py 메뉴에서 선택된 네트워크 시나리오를 검증된 실험 러너
(scenarios/network/experiment.py)에 subprocess 로 위임한다. 송신·Zeek/Loki 검증·
혼동행렬·MTTD·결과 저장·Loki 결과 전송은 전부 기존 러너가 수행하고, 이 모듈은
다음만 담당한다.

  ① 실행 옵션 입력      — V1/V2 · S2/C-a 반복 횟수 · V2 동결 스냅샷
  ② 실행 전 사전 조건 점검 — DB_PASSWORD / Docker / 컨테이너 / Sink / Loki / AM
  ③ experiment.py CLI 호출 — 출력은 그대로 터미널에 흘린다
  ④ 결과 경로·요약 표시 후 메뉴 복귀

기존 run_scenario() 의 LLM 폴링 흐름은 쓰지 않는다 — 네트워크 시나리오는 자체
Verifier 와 결과 저장 로직을 갖기 때문이다. 사전 점검은 "읽기만" 한다. 컨테이너를
자동 기동하거나 Docker 환경을 수정하지 않는다.
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

console = Console()

SCENARIOS_DIR  = Path(__file__).resolve().parent
NETWORK_DIR    = SCENARIOS_DIR / "network"
EXPERIMENT_PY  = NETWORK_DIR / "experiment.py"
RESULTS_DIR    = NETWORK_DIR / "results"
DEFAULT_FROZEN = RESULTS_DIR / "frozen.json"

LOKI_URL         = os.getenv("LOKI_URL", "http://localhost:3100")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://localhost:9093")

# docker-compose.s2.yml / docker-compose.yml 기준 (읽기 전용 점검 대상)
REQUIRED_CONTAINERS = ("leafy-backend", "s2-sink-a", "s2-sink-b")
SINK_HEALTH = (
    ("sink-a readout (인가, C-a)",   "http://127.0.0.1:8091/healthz"),
    ("sink-b readout (비인가, S2)",  "http://127.0.0.1:8092/healthz"),
)

# 메뉴에서 쓰는 V1 기본 반복. V2 는 experiment.py 의 기본값을 그대로 따른다.
MENU_V1_REPS = 1

VARIANTS = ("V1", "V2")

# ── 네트워크 시나리오 레지스트리 ──────────────────────────────────────────────
# run.py 의 SCENARIO_REGISTRY 는 건드리지 않는다. 메뉴 번호는 기존 항목 수 뒤로
# 동적으로 배정된다 (run.py:select_scenario).
NETWORK_SCENARIO_REGISTRY = [
    {
        "id": "net_s2", "kind": "network",
        "label": "S2 — 비인가 목적지 데이터 전송",
        "subtitle": "Backend → Sink B 10.210.0.31:8080  ·  허용목록 외 → 경보 발생(TP)",
        "category": "네트워크",
        "run_s2": True, "run_ca": False,
    },
    {
        "id": "net_ca", "kind": "network",
        "label": "C-a — 인가 목적지 대용량 전송",
        "subtitle": "Backend → Sink A 10.210.0.30:8080  ·  허용목록 내 → 경보 없음(TN)",
        "category": "네트워크",
        "run_s2": False, "run_ca": True,
    },
    {
        "id": "net_s2_ca", "kind": "network",
        "label": "S2/C-a — 비교 실험",
        "subtitle": "같은 전송 조건 · 목적지만 다름  ·  TP/TN 동시 확인",
        "category": "네트워크",
        "run_s2": True, "run_ca": True,
    },
]


# ── 순수 로직 (Docker 불필요 — 단위 테스트 대상) ──────────────────────────────
def experiment_default_reps(variant: str) -> dict:
    """
    experiment.py 의 기본 반복 횟수를 읽는다. 값을 여기서 중복 정의하면 CLI 기본값과
    어긋날 수 있으므로 모듈에서 직접 가져온다.
    """
    path = str(NETWORK_DIR)
    if path not in sys.path:
        sys.path.append(path)
    from experiment import DEFAULT_V1_REPS, DEFAULT_V2_REPS
    return DEFAULT_V2_REPS if variant == "V2" else DEFAULT_V1_REPS


def menu_default_reps(meta: dict, variant: str) -> tuple[int, int]:
    """선택된 메뉴 항목과 variant 에 대한 (S2, C-a) 기본 반복 횟수."""
    if variant == "V2":
        d = experiment_default_reps("V2")
        s2_default, ca_default = d["S2"], d["C-a"]
    else:
        s2_default = ca_default = MENU_V1_REPS
    return (s2_default if meta["run_s2"] else 0,
            ca_default if meta["run_ca"] else 0)


def parse_reps(raw: str, default: int) -> int:
    """반복 횟수 입력 파싱. 빈 입력은 기본값. 음수/비정수는 거부한다."""
    raw = (raw or "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        raise ValueError("정수를 입력해라 (예: 1, 5, 30)")
    if n < 0:
        raise ValueError("반복 횟수는 0 이상이어야 한다")
    return n


def build_command(variant: str, s2_reps: int, ca_reps: int, frozen=None) -> list[str]:
    """
    experiment.py 호출 커맨드. shell 을 쓰지 않고 현재 파이썬(sys.executable)과
    절대 경로로 구성한다. 선택하지 않은 시나리오는 반복 0 으로 명시해 실행되지 않게 한다.
    """
    if variant not in VARIANTS:
        raise ValueError(f"지원하지 않는 variant: {variant}")
    if s2_reps < 0 or ca_reps < 0:
        raise ValueError("반복 횟수는 0 이상이어야 한다")
    if s2_reps + ca_reps == 0:
        raise ValueError("전체 반복이 0회인 실행은 거부한다")
    if variant == "V2" and not frozen:
        raise ValueError("V2(held-out) 평가에는 동결 스냅샷이 필요하다")

    cmd = [sys.executable, str(EXPERIMENT_PY), "run", variant,
           "--s2-reps", str(s2_reps), "--ca-reps", str(ca_reps)]
    if frozen:
        cmd += ["--frozen", str(frozen)]
    return cmd


def child_env(base=None) -> dict:
    """
    기존 프로세스 환경을 자식에게 그대로 물려준다 (DB_PASSWORD 포함). 값을 읽어
    출력하거나 커맨드라인에 싣지 않는다 — env 로만 전달된다.
    """
    env = dict(os.environ if base is None else base)
    env.setdefault("LOKI_URL", LOKI_URL)
    env.setdefault("ALERTMANAGER_URL", ALERTMANAGER_URL)
    return env


@dataclass
class Check:
    name: str
    ok: bool
    hint: str = ""


def _http_ok(url: str, timeout: int = 3) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False


def running_containers() -> set | None:
    """실행 중인 컨테이너 이름. Docker 에 접근할 수 없으면 None (점검 실패로 처리)."""
    try:
        r = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                           capture_output=True, text=True, timeout=15)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    return {line.strip() for line in r.stdout.splitlines() if line.strip()}


def preflight(variant: str, frozen=None, containers=None,
              http_probe=_http_ok) -> list:
    """
    실험 실행에 필요한 사전 조건을 '읽기만' 해서 점검한다. containers/http_probe 는
    테스트에서 주입한다. 무엇이 부족한지 Check 리스트로 반환한다.
    """
    checks = [
        Check("DB_PASSWORD 환경변수", bool(os.getenv("DB_PASSWORD")),
              "set DB_PASSWORD=<비밀번호> 후 다시 실행 (값은 출력되지 않는다)"),
        Check("실험 러너 experiment.py", EXPERIMENT_PY.is_file(),
              f"{EXPERIMENT_PY} 를 찾을 수 없다"),
    ]

    names = running_containers() if containers is None else containers
    checks.append(Check("Docker 접근", names is not None,
                        "Docker 데몬이 응답하지 않는다 (Docker Desktop 실행 확인)"))
    missing = sorted(set(REQUIRED_CONTAINERS) - (names or set()))
    checks.append(Check(f"필수 컨테이너 ({len(REQUIRED_CONTAINERS)}개)",
                        names is not None and not missing,
                        "미실행: " + ", ".join(missing) if missing else
                        "Docker 접근 불가로 확인할 수 없다"))

    for label, url in SINK_HEALTH:
        checks.append(Check(label, http_probe(url), f"{url} 응답 없음"))

    checks.append(Check("Loki", http_probe(f"{LOKI_URL}/ready"),
                        f"{LOKI_URL}/ready 응답 없음"))
    checks.append(Check("Alertmanager", http_probe(f"{ALERTMANAGER_URL}/-/ready"),
                        f"{ALERTMANAGER_URL}/-/ready 응답 없음"))

    if variant == "V2":
        ok = bool(frozen) and Path(frozen).is_file()
        checks.append(Check("V2 동결 스냅샷", ok,
                            "동결 파일이 없다 — experiment.py freeze 로 먼저 생성해라 "
                            "(런처는 자동 생성하지 않는다)"))
    return checks


def new_result_files(since: float, out_dir=None) -> list:
    """실행 이후에 생성된 summary JSON 경로 (최신 우선)."""
    d = Path(out_dir) if out_dir else RESULTS_DIR
    if not d.is_dir():
        return []
    found = [p for p in d.glob("*_summary.json") if p.stat().st_mtime >= since - 1]
    return sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)


# ── 화면 ──────────────────────────────────────────────────────────────────────
def panel_network_info(meta: dict, variant: str, s2_reps: int, ca_reps: int):
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold cyan", no_wrap=True, min_width=14)
    t.add_column()
    t.add_row("시나리오",    meta["label"])
    t.add_row("설명",        meta["subtitle"])
    t.add_row("카테고리",    meta["category"])
    t.add_row("variant",     f"{variant}  " + ("[dim](held-out 최종 평가)[/dim]"
                                               if variant == "V2" else "[dim](튜닝용 분할 전송)[/dim]"))
    t.add_row("반복 횟수",   f"S2 {s2_reps}회  ·  C-a {ca_reps}회")
    t.add_row("실험 러너",   "scenarios/network/experiment.py")
    console.print(Panel(t, title="[bold]네트워크 시나리오[/bold]", border_style="cyan"))


def panel_preflight(checks: list) -> bool:
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 2))
    t.add_column("점검 항목", no_wrap=True, min_width=26)
    t.add_column("결과", justify="center", min_width=8)
    t.add_column("비고", overflow="fold")
    for c in checks:
        t.add_row(c.name,
                  "[green]OK[/green]" if c.ok else "[red]FAIL[/red]",
                  "" if c.ok else f"[dim]{c.hint}[/dim]")
    ok = all(c.ok for c in checks)
    console.print(Panel(t, title="[bold]실행 전 점검[/bold]",
                        border_style="green" if ok else "red"))
    return ok


def panel_summary(paths: list):
    if not paths:
        console.print(Panel("[yellow]새 결과 파일을 찾지 못했다 — experiment.py 출력을 확인해라[/yellow]",
                            title="[bold]결과[/bold]", border_style="yellow"))
        return
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="bold green", no_wrap=True, min_width=14)
    t.add_column(overflow="fold")
    newest = paths[0]
    t.add_row("결과 경로", str(newest))
    try:
        data = json.loads(newest.read_text(encoding="utf-8"))
        cm = data.get("confusion_matrix", {})
        t.add_row("판정", f"TP {cm.get('tp')}  ·  FP {cm.get('fp')}  ·  "
                          f"TN {cm.get('tn')}  ·  FN {cm.get('fn')}  ·  "
                          f"invalid {cm.get('invalid')}")
        mttd = cm.get("mttd") or {}
        t.add_row("MTTD", f"count {mttd.get('count')}  ·  mean {mttd.get('mean')}  ·  "
                          f"min {mttd.get('min')}  ·  max {mttd.get('max')}")
        if data.get("experiment_id"):
            t.add_row("experiment_id", data["experiment_id"])
    except Exception as exc:
        t.add_row("요약", f"[yellow]summary 파싱 실패: {exc}[/yellow]")
    console.print(Panel(t, title="[bold green]실험 결과[/bold green]", border_style="green"))


# ── 입력 ──────────────────────────────────────────────────────────────────────
def prompt_variant() -> str | None:
    console.print("  [bold cyan]── 실행 방식 ──────────────────────────────────────[/bold cyan]")
    console.print("   [bold yellow]1[/bold yellow].  V1  [dim]분할 전송 · 튜닝용 (기본)[/dim]")
    console.print("   [bold yellow]2[/bold yellow].  V2  [dim]저속 전송 · held-out 최종 평가 (동결 스냅샷 필요)[/dim]")
    console.print("   [bold yellow]q[/bold yellow].  메뉴로 돌아가기")
    while True:
        c = console.input("  [bold white]선택 (Enter=V1): [/bold white]").strip().lower()
        if c == "q":
            return None
        if c in ("", "1", "v1"):
            return "V1"
        if c in ("2", "v2"):
            return "V2"
        console.print("  [red]잘못된 입력입니다.[/red]")


def prompt_reps(meta: dict, variant: str) -> tuple | None:
    """선택한 시나리오의 반복 횟수만 입력받는다. 선택하지 않은 쪽은 0 으로 고정."""
    s2_default, ca_default = menu_default_reps(meta, variant)
    s2_reps, ca_reps = s2_default, ca_default

    while True:
        try:
            if meta["run_s2"]:
                s2_reps = parse_reps(
                    console.input(f"  [bold white]S2 반복 횟수 (Enter={s2_default}): [/bold white]"),
                    s2_default)
            if meta["run_ca"]:
                ca_reps = parse_reps(
                    console.input(f"  [bold white]C-a 반복 횟수 (Enter={ca_default}): [/bold white]"),
                    ca_default)
            if s2_reps + ca_reps == 0:
                raise ValueError("전체 반복이 0회인 실행은 거부한다")
            return s2_reps, ca_reps
        except ValueError as exc:
            console.print(f"  [red]{exc}[/red]")
        except (EOFError, KeyboardInterrupt):
            return None


def prompt_frozen() -> str | None:
    console.print()
    console.print("  [dim]V2 는 동결 스냅샷의 설정 지문과 일치해야 평가된다 "
                  "(drift 시 거부). 런처는 동결 파일을 만들지 않는다.[/dim]")
    raw = console.input(
        f"  [bold white]동결 스냅샷 경로 (Enter={DEFAULT_FROZEN.name}): [/bold white]"
    ).strip()
    path = Path(raw) if raw else DEFAULT_FROZEN
    if not path.is_file():
        console.print(Panel(
            f"[red]동결 스냅샷을 찾을 수 없다: {path}[/red]\n"
            "[dim]먼저 동결 파일을 생성해라 (자동 생성하지 않는다):\n"
            f"  cd scenarios/network\n"
            f"  python experiment.py freeze --out results/frozen.json --N 1048576 --T 60[/dim]",
            title="[bold red]V2 실행 중단[/bold red]", border_style="red"))
        return None
    return str(path)


# ── 실행 ──────────────────────────────────────────────────────────────────────
def run_network_scenario(meta: dict) -> int:
    """
    네트워크 시나리오 전용 실행 경로. 반환값은 experiment.py 의 종료 코드
    (-1 = 사용자 취소 / 사전 조건 미충족으로 실행하지 않음).
    """
    os.system("cls" if os.name == "nt" else "clear")
    console.print()
    console.print(Rule(f"[bold cyan]{meta['label']}[/bold cyan]", style="cyan"))
    console.print()

    variant = prompt_variant()
    if variant is None:
        return -1
    console.print()

    frozen = None
    if variant == "V2":
        frozen = prompt_frozen()
        if frozen is None:
            console.input("\n  [dim]Enter 를 눌러 메뉴로 돌아가기[/dim]")
            return -1

    console.print()
    reps = prompt_reps(meta, variant)
    if reps is None:
        return -1
    s2_reps, ca_reps = reps

    console.print()
    panel_network_info(meta, variant, s2_reps, ca_reps)
    console.print()

    if not panel_preflight(preflight(variant, frozen)):
        console.print(Panel(
            "[red]사전 조건이 충족되지 않아 실험을 실행하지 않았다.[/red]\n"
            "[dim]부족한 항목을 준비한 뒤 다시 선택해라. 런처는 컨테이너를 자동으로\n"
            "기동하거나 Docker 환경을 변경하지 않는다. (원격 PC 실행은 지원하지 않는다 —\n"
            "실험은 이 호스트의 Docker 환경에서만 동작한다.)[/dim]",
            title="[bold red]실행 중단[/bold red]", border_style="red"))
        console.print()
        console.input("  [dim]Enter 를 눌러 메뉴로 돌아가기[/dim]")
        return -1

    try:
        cmd = build_command(variant, s2_reps, ca_reps, frozen=frozen)
    except ValueError as exc:
        console.print(f"  [red]{exc}[/red]")
        console.input("\n  [dim]Enter 를 눌러 메뉴로 돌아가기[/dim]")
        return -1

    console.print()
    console.print(Rule("[dim cyan]experiment.py 실행 — 출력 그대로[/dim cyan]", style="dim cyan"))
    console.print(f"  [dim]$ {' '.join(cmd[1:])}[/dim]")
    console.print(f"  [dim]cwd: {NETWORK_DIR}[/dim]\n")

    started = time.time()
    try:
        rc = subprocess.run(cmd, cwd=str(NETWORK_DIR), env=child_env()).returncode
    except KeyboardInterrupt:
        console.print("\n  [yellow]사용자 중단 — 실험을 종료했다.[/yellow]")
        rc = 130
    except Exception as exc:
        console.print(Panel(f"[red]실험 러너를 실행할 수 없다: {type(exc).__name__}: {exc}[/red]",
                            title="[bold red]실행 실패[/bold red]", border_style="red"))
        rc = 1

    console.print()
    if rc == 0:
        panel_summary(new_result_files(started))
    else:
        console.print(Panel(
            f"[red]experiment.py 가 종료 코드 {rc} 로 실패했다.[/red]\n"
            "[dim]위 출력의 오류 메시지를 확인해라. 결과 파일은 생성되지 않았을 수 있다.[/dim]",
            title="[bold red]실험 실패[/bold red]", border_style="red"))

    console.print()
    console.print(Rule("[dim green]네트워크 시나리오 완료[/dim green]", style="dim green"))
    console.print()
    console.input("  [dim]Enter 를 눌러 메뉴로 돌아가기[/dim]")
    return rc
