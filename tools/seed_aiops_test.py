#!/usr/bin/env python3
"""시나리오 v2 검증용 테스트 DB(aiops_test) 시드 스크립트.

목적: 실제 앱 DB·실사용자 정보를 건드리지 않고, 시나리오(F2-c·S2-e·C-h·F3 백업)를
  검증할 수 있는 **별도 테스트 DB**를 만든다. 모든 데이터는 generate_series 로 생성한
  명백한 가짜 값이다(실 PII 없음).

접속: psql 만 사용한다(드라이버 의존성 없음). 비밀번호는 PGPASSFILE 로만 전달하며
  argv·로그·출력에 넣지 않는다. 관리자(슈퍼유저)로 접속해 테스트 DB·일반 역할을 만든다.

안전 가드:
  - 대상 DB 이름(SCEN_PGDATABASE)이 지정되지 않으면 거부한다.
  - 대상 DB 이름이 허용 접두사(기본 'aiops_test')로 시작하지 않으면 거부한다(운영 DB 오인 방지).
  - 확인값(--confirm 또는 SCEN_SEED_CONFIRM)이 대상 DB 이름과 정확히 일치해야 실행한다.
  - DROP/재생성은 **대상 테스트 DB 안에서만** 한다. 다른 DB 는 절대 건드리지 않는다.

사용 예:
  SCEN_PGHOST=127.0.0.1 SCEN_PGPORT=5433 SCEN_PGADMIN=scen_admin \
  SCEN_PGDATABASE=aiops_test SCEN_PGUSER=scen_app \
  python3 tools/seed_aiops_test.py --confirm aiops_test --rows 2000
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

ALLOWED_DB_PREFIX = os.getenv("SCEN_SEED_DB_PREFIX", "aiops_test")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# argv·로그에 값이 들어가지 않도록 libpq 비밀번호 환경은 PGPASSFILE 로만 전달.
_ROUTING = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD",
            "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS")


def ident(value: str, what: str) -> str:
    if not _IDENT.fullmatch(value):
        sys.exit(f"잘못된 {what}: {value!r} (영숫자·밑줄만)")
    return value


def env_for(passfile: str | None) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in _ROUTING}
    env["PGCONNECT_TIMEOUT"] = "5"
    if passfile:
        env["PGPASSFILE"] = passfile
    return env


def run_sql(host, port, admin, database, sql, passfile, label):
    """psql 로 한 덩어리 SQL 실행. 실패하면 중단(상세 오류는 stderr 로만)."""
    argv = ["psql", "-X", "-w", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", host, "-p", str(port),
            "-U", admin, "-d", database, "-c", sql]
    result = subprocess.run(argv, env=env_for(passfile), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stderr)
        sys.exit(f"[seed] 실패: {label}")
    return result.stdout.strip()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="시나리오 v2 검증용 테스트 DB 시드")
    parser.add_argument("--confirm", default=os.getenv("SCEN_SEED_CONFIRM"),
                        help="대상 DB 이름과 정확히 일치해야 실행(오작동 방지)")
    parser.add_argument("--rows", type=int, default=int(os.getenv("SCEN_SEED_ROWS", "2000")),
                        help="users 가짜 행 수(products·orders 는 이에 비례)")
    args = parser.parse_args(argv)

    host = os.getenv("SCEN_PGHOST", "host.docker.internal")
    port = os.getenv("SCEN_PGPORT", "5432")
    admin = ident(os.getenv("SCEN_PGADMIN", "postgres"), "SCEN_PGADMIN")
    database = os.getenv("SCEN_PGDATABASE")
    user = ident(os.getenv("SCEN_PGUSER", "scen_app"), "SCEN_PGUSER")
    passfile = os.getenv("SCEN_PGPASSFILE") or os.getenv("PGPASSFILE")

    if not database:
        sys.exit("SCEN_PGDATABASE(테스트 DB 이름)가 필요합니다 — 미지정이면 실행 거부")
    ident(database, "SCEN_PGDATABASE")
    if not database.startswith(ALLOWED_DB_PREFIX):
        sys.exit(f"안전 가드: 대상 DB 는 '{ALLOWED_DB_PREFIX}' 로 시작해야 합니다(운영 DB 오인 방지): {database}")
    if args.confirm != database:
        sys.exit(f"안전 가드: --confirm {database} (또는 SCEN_SEED_CONFIRM) 로 대상 DB 를 확인하세요")
    if admin == user:
        sys.exit("관리자(SCEN_PGADMIN)와 일반 역할(SCEN_PGUSER)은 달라야 합니다(F2-c 가드와 동일)")
    if args.rows < 1:
        sys.exit("--rows 는 1 이상")

    print(f"[seed] 대상 {host}:{port} db={database} admin={admin} user={user} rows={args.rows}", flush=True)

    # 1) 일반 로그인 역할(권한 제한 없음, 비슈퍼유저) — 없으면 생성.
    run_sql(host, port, admin, "postgres",
            f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{user}') "
            f"THEN CREATE ROLE {user} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$;",
            passfile, "일반 역할 생성")

    # 2) 테스트 DB — 대상 테스트 DB 만 DROP/CREATE(다른 DB 불변).
    run_sql(host, port, admin, "postgres", f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE);',
            passfile, "기존 테스트 DB 제거")
    run_sql(host, port, admin, "postgres", f'CREATE DATABASE "{database}" OWNER {admin};',
            passfile, "테스트 DB 생성")

    # 3) 스키마·가짜 데이터(모두 generate_series 로 생성 — 실 PII 없음).
    n = args.rows
    schema = f"""
CREATE TABLE app_users (
  id serial PRIMARY KEY, username text NOT NULL, email text NOT NULL,
  status text NOT NULL DEFAULT 'active', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE products (
  id serial PRIMARY KEY, name text NOT NULL, price_cents integer NOT NULL,
  in_stock boolean NOT NULL DEFAULT true);
CREATE TABLE orders (
  id serial PRIMARY KEY, user_id integer NOT NULL REFERENCES app_users(id),
  product_id integer NOT NULL REFERENCES products(id), quantity integer NOT NULL,
  ordered_at timestamptz NOT NULL DEFAULT now());

INSERT INTO app_users (username, email, status, created_at)
SELECT 'user_'||g, 'user'||g||'@example.test',
       (ARRAY['active','active','inactive'])[1+g%3],
       now() - (g || ' minutes')::interval
FROM generate_series(1, {n}) g;

INSERT INTO products (name, price_cents, in_stock)
SELECT 'product_'||g, 100 + (g*7)%90000, (g%5 <> 0)
FROM generate_series(1, {max(1, n // 20)}) g;

INSERT INTO orders (user_id, product_id, quantity, ordered_at)
SELECT 1 + (g % {n}), 1 + (g % {max(1, n // 20)}), 1 + g%5,
       now() - (g || ' seconds')::interval
FROM generate_series(1, {n * 3}) g;

GRANT CONNECT ON DATABASE "{database}" TO {user};
GRANT USAGE ON SCHEMA public TO {user};
GRANT SELECT ON ALL TABLES IN SCHEMA public TO {user};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {user};
ANALYZE;
"""
    run_sql(host, port, admin, database, schema, passfile, "스키마·데이터 적재")

    counts = run_sql(host, port, admin, database,
                     "SELECT format('app_users=%s products=%s orders=%s', "
                     "(SELECT count(*) FROM app_users), (SELECT count(*) FROM products), "
                     "(SELECT count(*) FROM orders))", passfile, "행 수 확인")
    sysid = run_sql(host, port, admin, database,
                    "SELECT (pg_control_system()).system_identifier", passfile, "system_id 확인")
    print(f"[seed] 완료: {counts}", flush=True)
    print(f"[seed] SCEN_EXPECTED_SYSTEM_ID={sysid}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
