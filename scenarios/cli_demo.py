"""
Minecraft 테마 AIOps 시나리오 데모 (통합본)
벚꽃 파티클 → 크리퍼 접근 → 공격 감지 → LLM 분석 → 히로빈 등장 → 격리 완료
"""
import time
import random
import shutil
import os
from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.panel import Panel

console = Console()

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
    # 왼쪽(0)에서 오른쪽(중앙)으로 이동
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

def scene_collecting():
    spinners = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    steps = [
        ("Prometheus 메트릭 수집중...", "cyan"),
        ("Loki 로그 수집중...", "cyan"),
        ("이상 패턴 탐지중...", "yellow"),
        ("LLM 프롬프트 조립중...", "yellow"),
    ]
    for step, color in steps:
        for i in range(10):
            os.system('cls' if os.name == 'nt' else 'clear')
            console.print(f"\n\n  [{color}]{spinners[i % len(spinners)]}  {step}[/{color}]")
            time.sleep(0.1)

def scene_llm_analyzing():
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("\n\n  [bold yellow]🤖  LLM ANALYZING...[/bold yellow]\n")
    time.sleep(0.5)
    analysis = [
        ("root_cause",   "컨테이너 내부 비정상 CPU 점유. 크립토마이닝 악성코드 의심."),
        ("evidence",     "CPU 91% 급등 / dd 프로세스 다수 실행 감지"),
        ("threat_level", "HIGH"),
        ("action_risk",  "HIGH"),
        ("action",       "isolate_container leafy-db"),
        ("confidence",   "0.93"),
    ]
    for key, value in analysis:
        console.print(f"  [bold green]{key:14s}[/bold green]: ", end="")
        for ch in value:
            print(ch, end="", flush=True)
            time.sleep(0.025)
        print()
        time.sleep(0.15)
    time.sleep(1.2)

def scene_remediating():
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("\n\n  [bold magenta]🛡   REMEDIATING...[/bold magenta]\n")
    actions = [
        "Docker API 연결중...",
        "leafy-net 네트워크 격리 실행",
        "docker network disconnect leafy-net leafy-db",
        "Slack 알림 전송중...",
        "✅  컨테이너 격리 완료",
    ]
    for action in actions:
        console.print(f"  [magenta]▶[/magenta]  {action}")
        time.sleep(0.55)
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

def scene_resolved():
    for _ in range(6):
        print_face_center("Steve", label="✅  THREAT NEUTRALIZED  ✅", label_style="bold green")
        console.print("컨테이너 격리 완료. 시스템 정상화.", style="green", justify="center")
        time.sleep(0.5)

# ──────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────
def run():
    try:
        scene_sakura(duration=7)
        scene_creeper_approach()
        scene_attack_detected()
        scene_collecting()
        scene_llm_analyzing()
        scene_remediating()
        scene_explosion()
        scene_steve_dead()
        scene_herobrine()
        scene_resolved()
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print("\n\n[bold green]✅  시나리오 종료. 시스템 정상화 완료.[/bold green]\n", justify="center")
    except KeyboardInterrupt:
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print("\n[yellow]데모 종료.[/yellow]")

if __name__ == "__main__":
    run()