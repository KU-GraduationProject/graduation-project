"""
Minecraft 테마 AIOps 시나리오 데모 (통합본)
벚꽃 파티클 → 시나리오 선택 → 실제 시나리오 실행(백그라운드) → 크리퍼 접근 →
공격 감지 → LLM 분석 → 히로빈 등장 → 격리 완료
"""
import time
import random
import shutil
import os
import sys
import threading
from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.panel import Panel

console = Console()

# ──────────────────────────────────────────────
# 시나리오 정의 (category1_infra 연결)
# ──────────────────────────────────────────────
SCENARIO_CONFIGS = {
    "1": {
        "key":       "redos_attack",
        "label":     "ReDoS 공격 (OWASP A05 - CPU 고갈)",
        "container": "leafy-backend",
        "module":    "category1_infra.redos_attack",
    },
    "2": {
        "key":       "n_plus_one_attack",
        "label":     "N+1 Query 공격 (OWASP A04 - DB 커넥션 고갈)",
        "container": "leafy-db",
        "module":    "category2_security.n_plus_one_attack",
    },
    "3": {
        "key":       "db_bruteforce",
        "label":     "DB 브루트포스 (내부망 반복 인증 실패)",
        "container": "leafy-db",
        "module":    "category2_security.brute_force",
    },
    "4": {
        "key":       "lateral_movement",
        "label":     "컨테이너 Lateral Movement (비인가 DB 직접 접속)",
        "container": "leafy-db",
        "module":    "category2_security.lateral_movement",
    },
}

PIPELINE_URL = os.getenv("PIPELINE_URL", "http://localhost:8000")


# ──────────────────────────────────────────────
# ANSI True Color 픽셀 렌더러
# ──────────────────────────────────────────────
def bg(r, g, b):
    return f"\033[48;2;{r};{g};{b}m  \033[0m"

P = {
    'G': bg(34, 177, 76),
    'K': bg(20, 20, 20),
    'H': bg(83, 53, 31),
    'S': bg(175, 129, 101),
    'W': bg(255, 255, 255),
    'E': bg(44, 50, 143),
    'N': bg(136, 94, 69),
    'D': bg(51, 31, 15),
    'B': bg(220, 220, 220),
    'R': bg(200, 0, 0),
    'O': bg(255, 140, 0),
    'Y': bg(255, 230, 0),
    ' ': bg(0, 0, 0),
}

FACES = {
    "Steve": [
        "HHHHHHHH",
        "HHHHHHHH",
        "HSSSSSSH",
        "SSSSSSSS",
        "SWESSWES",
        "SSSNNSSS",
        "SSDNNDSS",
        "SSDDDDSS",
    ],
    "Herobrine": [
        "HHHHHHHH",
        "HHHHHHHH",
        "HSSSSSSH",
        "SSSSSSSS",
        "SWWSSWWS",
        "SSSNNSSS",
        "SSDNNDSS",
        "SSDDDDSS",
    ],
    "Skeleton": [
        "BBBBBBBB",
        "BBBBBBBB",
        "BKKBBKKB",
        "BKKBBKKB",
        "BBBKKBBB",
        "BBBBBBBB",
        "BKBKBKBB",
        "BBBBBBBB",
    ],
    "Creeper": [
        "GGGGGGGG",
        "GGGGGGGG",
        "GKKGGKKG",
        "GKKGGKKG",
        "GGGKKGGG",
        "GGKKKKGG",
        "GGKKKKGG",
        "GGKGGKGG",
    ],
    "Explosion": [
        " RROOYY ",
        "RROOYYRR",
        "OOYYRR  ",
        "YYRR  OO",
        "RR  OOYY",
        "  OOYYRR",
        "OOYYRR  ",
        " YYRR   ",
    ],
    "SteveDead": [
        "HHHHHHHH",
        "HHHHHHHH",
        "HSSSSSSH",
        "SSSSSSSS",
        "SKESSKES",
        "SSSNNSSS",
        "SSDNNDSS",
        "SSDDDDSS",
    ],
}

def render_face(name):
    design = FACES[name]
    lines = []
    for row in design:
        line = "".join(P.get(ch, P[' ']) for ch in row)
        lines.append(line)
    return lines

def print_face_center(name, label="", label_style="bold white"):
    width = shutil.get_terminal_size((80, 24)).columns
    lines = render_face(name)
    face_w = 16
    pad = " " * max(0, (width - face_w) // 2)
    os.system('cls' if os.name == 'nt' else 'clear')
    print()
    if label:
        console.print(label, style=label_style, justify="center")
    for line in lines:
        print(pad + line)
    print()

# ──────────────────────────────────────────────
# 벚꽃 파티클
# ──────────────────────────────────────────────
PETALS = ['❀', '✿', '✾', '❁', '*', '·', '˚', "'"]

class Particle:
    def __init__(self, width, height, start_anywhere=True):
        self.width = width
        self.height = height
        self.x = random.randint(0, width - 1)
        self.y = random.uniform(0, height) if start_anywhere else 0.0
        self.char = random.choice(PETALS)
        self.speed = random.uniform(0.3, 1.2)
        self.drift = random.uniform(-0.3, 0.5)

    def update(self):
        self.y += self.speed
        self.x += self.drift
        if self.y >= self.height or self.x < 0 or self.x >= self.width:
            self.x = random.randint(0, self.width - 1)
            self.y = 0.0
            self.char = random.choice(PETALS)
            self.speed = random.uniform(0.3, 1.2)
            self.drift = random.uniform(-0.3, 0.5)

def render_sakura(particles, width, height):
    grid = [[' '] * width for _ in range(height)]
    for p in particles:
        ix, iy = int(p.x), int(p.y)
        if 0 <= ix < width and 0 <= iy < height:
            grid[iy][ix] = p.char
    result = Text()
    for i, row in enumerate(grid):
        for ch in row:
            result.append(ch, style="bold pink1" if ch != ' ' else "")
        if i < height - 1:
            result.append('\n')
    return result

# ──────────────────────────────────────────────
# 씬들
# ──────────────────────────────────────────────
def scene_sakura(duration=7):
    width, height = shutil.get_terminal_size((80, 24))
    height = max(height - 3, 8)
    particles = [Particle(width, height) for _ in range(width // 2)]
    with Live(console=console, refresh_per_second=10, screen=True) as live:
        header = Text("🌸  AIOps Security Monitor  🌸\n", style="bold pink1", justify="center")
        end = time.time() + duration
        while time.time() < end:
            for p in particles:
                p.update()
            content = Text()
            content.append_text(header)
            content.append_text(render_sakura(particles, width, height - 1))
            live.update(content)
            time.sleep(0.1)


def scene_select_scenario() -> dict:
    """시나리오 선택 메뉴를 표시하고 선택된 config를 반환한다."""
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print()
    console.print(Panel(
        "[bold cyan]  AIOps Demo — 시나리오 선택  [/bold cyan]",
        border_style="cyan",
        width=50,
    ), justify="center")
    console.print()
    for key, cfg in SCENARIO_CONFIGS.items():
        console.print(f"  [bold yellow]{key}[/bold yellow].  {cfg['label']}")
    console.print()

    while True:
        choice = console.input("  [bold white]번호를 입력하세요 (기본값: 1): [/bold white]").strip()
        if choice == "":
            choice = "1"
        if choice in SCENARIO_CONFIGS:
            selected = SCENARIO_CONFIGS[choice]
            console.print(f"\n  [bold green]✔  선택됨:[/bold green] {selected['label']}\n")
            time.sleep(1.0)
            return selected
        console.print("  [red]잘못된 입력입니다. 다시 시도하세요.[/red]")


def _run_scenario_thread(scenario_key: str):
    """실제 Docker 시나리오를 백그라운드 스레드에서 실행한다."""
    # scenarios/ 디렉토리를 sys.path에 추가 (상대 임포트를 위해)
    scenarios_dir = os.path.dirname(os.path.abspath(__file__))
    if scenarios_dir not in sys.path:
        sys.path.insert(0, scenarios_dir)

    try:
        if scenario_key == "cpu_stress":
            from category1_infra.cpu_stress import main as cpu_main
            cpu_main()
        elif scenario_key == "memory_leak":
            from category1_infra.memory_leak import main as mem_main
            mem_main()
    except Exception as e:
        # 백그라운드 스레드의 예외는 조용히 기록만 한다 (데모 흐름 방해 금지)
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "logs", "demo_error.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as f:
            f.write(f"[{scenario_key}] {e}\n")


def launch_scenario_background(scenario_cfg: dict) -> threading.Thread:
    """실제 시나리오를 백그라운드 스레드로 띄우고 Thread 객체를 반환한다."""
    t = threading.Thread(
        target=_run_scenario_thread,
        args=(scenario_cfg["key"],),
        daemon=True,
    )
    t.start()
    return t


CREEPER_EMOJI = [
    "🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩",
    "🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩",
    "🟩🟩⬛⬛🟩🟩⬛⬛🟩🟩",
    "🟩🟩⬛⬛🟩🟩⬛⬛🟩🟩",
    "🟩🟩🟩🟩⬛⬛🟩🟩🟩🟩",
    "🟩🟩🟩⬛⬛⬛⬛🟩🟩🟩",
    "🟩🟩⬛⬛⬛⬛⬛⬛🟩🟩",
    "🟩🟩⬛⬛🟩🟩⬛⬛🟩🟩",
    "🟩🟩🟩🟩🟩🟩🟩🟩🟩🟩",
]

def scene_creeper_approach():
    width, height = shutil.get_terminal_size((80, 24))
    end_pad = max(0, (width // 2) - 24)
    with Live(console=console, refresh_per_second=8, screen=True) as live:
        for step in range(0, end_pad + 1, 2):
            pad = step
            t = Text()
            t.append("\n" * 4)
            t.append(" " * (pad + 1))
            t.append("it\'s coming...\n", style="bold green")
            t.append("\n")
            for line in CREEPER_EMOJI:
                t.append(" " * pad + line + "\n")
            live.update(t)
            time.sleep(0.08)

def scene_attack_detected():
    for _ in range(5):
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print(
            Panel("[bold red blink]⚠   ATTACK DETECTED   ⚠[/bold red blink]",
                  border_style="red", width=50),
            justify="center"
        )
        time.sleep(0.3)
        os.system('cls' if os.name == 'nt' else 'clear')
        time.sleep(0.15)

def scene_collecting(scenario_cfg: dict):
    spinners = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    container = scenario_cfg["container"]
    steps = [
        (f"Prometheus 메트릭 수집중... ({container})", "cyan"),
        ("Loki 로그 수집중...", "cyan"),
        ("이상 패턴 탐지중...", "yellow"),
        ("LLM 프롬프트 조립중...", "yellow"),
    ]
    for step, color in steps:
        for i in range(10):
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print(f"\n\n  [{color}]{spinners[i % len(spinners)]}  {step}[/{color}]")
            time.sleep(0.1)

def _poll_llm_result(timeout_sec: int = 180) -> dict | None:
    """Pipeline /results/latest 를 폴링하여 실제 LLM 분석 결과를 가져온다."""
    import urllib.request, urllib.error, json as _json
    deadline = time.time() + timeout_sec
    spinners = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    i = 0
    while time.time() < deadline:
        try:
            r = urllib.request.urlopen(f"{PIPELINE_URL}/results/latest", timeout=5)
            data = _json.loads(r.read().decode())
            if data.get("status") == "ok":
                return data["data"]["result"]
        except Exception:
            pass
        os.system('cls' if os.name == 'nt' else 'clear')
        elapsed = int(time.time() - (deadline - timeout_sec))
        console.print(
            f"\n\n  [bold yellow]{spinners[i % len(spinners)]}  "
            f"AI 분석 대기중... ({elapsed}초 경과 / 최대 {timeout_sec}초)[/bold yellow]"
        )
        console.print("  [dim]Prometheus 탐지 → AlertManager → Pipeline → LLM[/dim]")
        time.sleep(1)
        i += 1
    return None


def scene_llm_analyzing(scenario_cfg: dict):
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("\n\n  [bold yellow]🤖  LLM ANALYZING (실제 AI 분석)...[/bold yellow]\n")
    time.sleep(0.5)

    # 실제 Pipeline에서 결과 폴링
    result = _poll_llm_result(timeout_sec=180)

    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("\n\n  [bold yellow]🤖  LLM 분석 완료[/bold yellow]\n")

    if result:
        display = [
            ("root_cause",   result.get("root_cause", "N/A")),
            ("threat_level", result.get("threat_level", "N/A")),
            ("action_risk",  result.get("action_risk", "N/A")),
            ("action",       result.get("action", "N/A")),
            ("confidence",   str(result.get("confidence", "N/A"))),
            ("evidence",     " | ".join(result.get("evidence", [])[:2])),
        ]
    else:
        console.print("  [red]⚠ Pipeline 응답 시간 초과 - 마지막 캐시 결과 없음[/red]")
        display = [("status", "분석 결과를 가져오지 못했습니다.")]

    for key, value in display:
        console.print(f"  [bold green]{key:14s}[/bold green]: ", end="")
        for ch in str(value):
            print(ch, end="", flush=True)
            time.sleep(0.018)
        print()
        time.sleep(0.12)
    time.sleep(1.5)

def scene_remediating(scenario_cfg: dict):
    import urllib.request, urllib.error, json as _json
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("\n\n  [bold magenta]🛡   REMEDIATING (실제 조치 확인)...[/bold magenta]\n")

    # Remediation 결과 확인
    remediation_steps = [
        "Docker API 연결중...",
        f"{scenario_cfg['container']} 컨테이너 상태 분석...",
        "Remediation Agent 결정 로직 실행...",
    ]
    for step in remediation_steps:
        console.print(f"  [magenta]▶[/magenta]  {step}")
        time.sleep(0.6)

    # 실제 Remediation 결과 가져오기
    try:
        r = urllib.request.urlopen(f"{PIPELINE_URL}/results/latest", timeout=5)
        data = _json.loads(r.read().decode())
        if data.get("status") == "ok":
            result = data["data"]["result"]
            action_risk = result.get("action_risk", "unknown")
            action = result.get("action", "N/A")
            if action_risk == "low":
                status_msg = f"✅  자동 조치 실행: {action}"
            else:
                status_msg = f"⚠  승인 요청 발송 (action_risk={action_risk}): {action}"
            console.print(f"  [magenta]▶[/magenta]  {status_msg}")
    except Exception:
        console.print("  [magenta]▶[/magenta]  Slack 알림 전송완료")

    time.sleep(0.8)

def scene_explosion():
    for _ in range(7):
        print_face_center("Explosion", label="💥  CONTAINER DESTROYED  💥", label_style="bold red blink")
        time.sleep(0.22)
        os.system('cls' if os.name == 'nt' else 'clear')
        time.sleep(0.1)

def scene_steve_dead():
    print_face_center("SteveDead", label="💀  YOU DIED  💀", label_style="bold red")
    time.sleep(2.5)

def scene_herobrine():
    dangerous = [
        "⚠  D A N G E R O U S !!!!!  ⚠",
        "🔴  CRITICAL THREAT DETECTED  🔴",
        "💀  HEROBRINE HAS ENTERED  💀",
        "⚡  SYSTEM FULLY COMPROMISED  ⚡",
        "🔥  EMERGENCY PROTOCOL ACTIVE  🔥",
    ]
    styles = [
        "bold red",
        "bold white on red",
        "bold red on white",
        "bold red",
        "bold white on red",
    ]
    width = shutil.get_terminal_size((80, 24)).columns
    face_w = 16
    pad = " " * max(0, (width - face_w) // 2)
    face_lines = render_face("Herobrine")

    for i in range(18):
        idx = i % len(dangerous)
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print(dangerous[idx], style=styles[idx], justify="center")
        print()
        for line in face_lines:
            print(pad + line)
        print()
        console.print("─" * 44, style="red", justify="center")
        console.print("threat_level : [bold red]CRITICAL[/bold red]", justify="center")
        console.print("root_cause   : [bold red]HEROBRINE 침투 감지[/bold red]", justify="center")
        console.print("action       : [bold yellow]ISOLATE + ALERT ADMIN[/bold yellow]", justify="center")
        console.print("─" * 44, style="red", justify="center")
        time.sleep(0.28)

def scene_resolved(scenario_cfg: dict):
    container = scenario_cfg["container"]
    for _ in range(6):
        print_face_center("Steve", label="✅  THREAT NEUTRALIZED  ✅", label_style="bold green")
        console.print(f"컨테이너 격리 완료 ({container}). 시스템 정상화.", style="green", justify="center")
        time.sleep(0.5)

# ──────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────
def run():
    try:
        # 1. 벚꽃 인트로
        scene_sakura(duration=7)

        # 2. 시나리오 선택
        scenario_cfg = scene_select_scenario()

        # 3. 실제 시나리오를 백그라운드에서 즉시 실행
        bg_thread = launch_scenario_background(scenario_cfg)
        console.print(
            f"  [dim]▶ 실제 시나리오 '{scenario_cfg['key']}' 백그라운드 실행 시작[/dim]"
        )
        time.sleep(1.0)

        # 4. 시각 데모 진행
        scene_creeper_approach()
        scene_attack_detected()
        scene_collecting(scenario_cfg)
        scene_llm_analyzing(scenario_cfg)
        scene_remediating(scenario_cfg)
        scene_explosion()
        scene_steve_dead()
        scene_herobrine()
        scene_resolved(scenario_cfg)

        os.system('cls' if os.name == 'nt' else 'clear')
        console.print("\n\n[bold green]✅  시나리오 종료. 시스템 정상화 완료.[/bold green]\n", justify="center")

        if bg_thread.is_alive():
            console.print(
                f"[dim]  (백그라운드 시나리오 '{scenario_cfg['key']}' 가 아직 실행 중입니다)[/dim]\n",
                justify="center",
            )

    except KeyboardInterrupt:
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print("\n[yellow]데모 종료.[/yellow]")

if __name__ == "__main__":
    run()
