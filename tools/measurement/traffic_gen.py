"""Leafy 정상 사용자 트래픽 생성기 (위양성 기준선 측정용).

실제 사용자처럼: 로그인 → 화면 이동(정적 페이지) → 목록·상세 조회 → 도감·이미지 조회,
가끔 사진 업로드, 드물게 신규 가입. 공격처럼 보이는 입력(이상한 쿼리, 스캐너 UA, 없는 경로)은 보내지 않는다.

    python -I traffic_gen.py --base http://<frontend> --dir <run dir> --setup 5     # 계정 준비만
    python -I traffic_gen.py --base http://<frontend> --dir <run dir> --duration 7200 [--seed N]

계정(비밀번호 포함)은 <run dir>/accounts.json 에만 저장하고 출력하지 않는다.
요청마다 <run dir>/requests.jsonl 에 (시각, 메서드, 경로 템플릿, 상태, 지연) 만 남긴다. 토큰·비밀번호는 남기지 않는다.

대조 모드 (위양성 대조 이벤트 C-c/C-e):
    python -I traffic_gen.py ... --control mixed --control-plan "0:15,2:10,20:5,40:5,60:5,0:10"
- 기준선 트래픽은 그대로 두고, 별도 스레드·별도 난수(--control-seed, 기본 seed+1)로 4xx 를 낸다.
  --control none(기본)이면 기준선과 같은 코드 경로·같은 난수 순서다
- 계획: "분당건수:분" 단계 목록. 단계 경계는 <run dir>/control_plan.jsonl 에 남긴다
- wrong-password: 기존 테스트 계정에 비밀번호 한 글자를 바꿔 로그인(401). 15% 는 login_id 오타. 70% 는 1~3초 뒤 올바르게 재시도
- not-found: 실사용자도 낼 수 있는 없는 경로(404). mixed 는 둘을 반반
- 대조 요청은 requests.jsonl 행에 "control" 필드가 붙는다. 보내기 전에 Loki 보안 룰 패턴에 걸리면 보내지 않고 종료한다
"""
import argparse
import json
import os
import random
import re
import secrets
import string
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import zlib
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
PAGES = ["/index.html", "/app/main/main.html", "/app/dictionary/dictionary.html",
         "/app/plant_detail/plant_detail.html", "/app/myplant/myplant_detail/myplant_detail.html",
         "/app/calendar/calendar.html", "/app/alarm/alarm.html", "/app/profile/profile.html",
         "/assets/js/core_api.js", "/assets/js/config.js", "/assets/js/auth_api.js"]
# 대조 모드 404 경로: 브라우저·오래된 북마크·지워진 사진처럼 실사용자도 내는 것만 쓴다
NOT_FOUND = ["/favicon.ico", "/robots.txt", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
             "/app/main/main_old.html", "/app/dictionary/list.html", "/app/profile/settings.html",
             "/files/journal/<uuid>.jpg"]
# Loki 보안 룰(PathTraversal·SQLInjection·SuspiciousProcessExecution) 패턴과 점(.)으로 시작하는 경로 세그먼트
GUARD = re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|\.env|/\.git/|(^|/)\.|union.{0,3}select|or.{0,3}1=1|"
                   r"drop.{0,3}table|sleep\(|extractvalue|information_schema|admin'--|and.{0,3}1=1|"
                   r"wget http|wget -|curl http[^s]|curl -o |nc -|netcat|/bin/bash -i|/bin/sh -i)")


class Client:
    def __init__(self, base, log, cache=None, tag=None):
        # cache: 계정(=브라우저)별 ETag. /files/ 재방문 때 브라우저처럼 If-None-Match 를 보내 304 를 받는다.
        # tag: 대조 요청 표시. 있으면 로그에 "control" 필드를 붙이고 보내기 전에 GUARD 를 검사한다
        self.base, self.log, self.token, self.cache = base, log, None, cache if cache is not None else {}
        self.tag = tag

    def req(self, method, path, route=None, body=None, ctype=None, raw=False):
        url = path if path.startswith("http") else self.base + path
        if self.tag and GUARD.search(urlparse(url).path + "?" + urlparse(url).query + UA):
            print(f"GUARD: 대조 요청이 보안 룰 패턴과 맞아 보내지 않고 종료: {route or urlparse(url).path}",
                  file=sys.stderr)
            os._exit(3)
        h = {"User-Agent": UA, "Accept": "*/*"}
        if self.token and "/api/" in url:
            h["Authorization"] = "Bearer " + self.token
        if method == "GET" and url in self.cache:
            h["If-None-Match"] = self.cache[url]
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            h["Content-Type"] = ctype or "application/json"
        t = time.time()
        status, payload, err = 0, None, None
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h, method=method),
                                        timeout=30) as r:
                status, payload = r.status, r.read()
                if method == "GET" and "/files/" in url and r.headers.get("ETag"):
                    self.cache[url] = r.headers["ETag"]
        except urllib.error.HTTPError as e:
            status, payload = e.code, e.read()
        except Exception as e:
            err = type(e).__name__
        row = {"ts": datetime.now(timezone.utc).isoformat(), "method": method,
               "route": route or urlparse(url).path, "status": status,
               "ms": round((time.time() - t) * 1000), "err": err}
        if self.tag:
            row["control"] = self.tag
        self.log(row)
        if raw or payload is None:
            return status, payload
        try:
            return status, json.loads(payload)
        except Exception:
            return status, payload.decode("utf-8", "replace")


def small_png():
    """64x64 단색 PNG (사진 업로드 대용). 매번 색이 달라 같은 파일이 반복되지 않는다."""
    w = h = 64
    px = bytes(random.randrange(256) for _ in range(3))
    raw = b"".join(b"\x00" + px * w for _ in range(h))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def multipart(field, filename, content, ctype):
    b = "----leafy" + secrets.token_hex(8)
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n").encode() + content + f"\r\n--{b}--\r\n".encode()
    return body, f"multipart/form-data; boundary={b}"


def new_account():
    login_id = "bl" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    pw = "".join(random.choices(string.ascii_letters, k=8)) + str(random.randrange(10, 99)) + "x"
    return {"login_id": login_id, "password": pw, "email": f"{login_id}@example.test",
            "nickname": "식집사" + login_id[-4:]}


class Sim:
    def __init__(self, base, run_dir):
        self.base, self.dir = base, run_dir
        self.acc_path = os.path.join(run_dir, "accounts.json")
        self.accounts = json.load(open(self.acc_path)) if os.path.exists(self.acc_path) else []
        self.logf = open(os.path.join(run_dir, "requests.jsonl"), "a", encoding="utf-8")
        self.dict_images, self.caches = [], {}
        self.lock = threading.Lock()  # 대조 스레드와 로그 파일을 같이 쓴다

    def log(self, row):
        with self.lock:
            self.logf.write(json.dumps(row) + "\n")
            self.logf.flush()

    def signup(self):
        c, a = Client(self.base, self.log), new_account()
        c.req("GET", "/auth/signup.html")
        pause()
        c.req("GET", f"/api/v1/auth/check-login-id?loginId={a['login_id']}", route="/api/v1/auth/check-login-id")
        pause()
        st, _ = c.req("POST", "/api/v1/auth/signup", body=a)
        if 200 <= st < 300:
            self.accounts.append(a)
            with open(self.acc_path, "w") as f:
                json.dump(self.accounts, f)
        return st

    def session(self):
        a = random.choice(self.accounts)
        c = Client(self.base, self.log, self.caches.setdefault(a["login_id"], {}))
        c.req("GET", "/index.html")
        pause()
        st, data = c.req("POST", "/api/v1/auth/login", body={"login_id": a["login_id"], "password": a["password"]})
        tok = find_token(data) if 200 <= st < 300 else None
        if not tok:
            return
        c.token = tok
        actions = [(self.browse_main, 5), (self.plants, 4), (self.dictionary, 2), (self.page, 4),
                   (self.upload, 0.4)]
        for _ in range(random.randint(4, 12)):
            pause(0.8, 2.5)
            random.choices([f for f, _ in actions], weights=[w for _, w in actions])[0](c)

    def browse_main(self, c):
        c.req("GET", "/app/main/main.html")
        for p in ("/api/v1/users/me", "/api/v1/my-plants", "/api/v1/notifications/unread-count"):
            pause(0.05, 0.3)
            c.req("GET", p)

    def load_dictionary(self, c):
        """도감·식물 상세 화면이 하는 것과 같다: /api/dictionary/url → 받은 주소의 JSON."""
        st, url = c.req("GET", "/api/dictionary/url")
        if st == 200 and isinstance(url, str) and same_host(self.base, url.strip()):
            st, plants = c.req("GET", urljoin(self.base, url.strip()), route="/files/<dictionary json>")
            if st == 200:  # 304 면 브라우저 캐시를 쓴 것이므로 이전 목록을 그대로 쓴다
                imgs = [p.get("imageUrl") for p in as_list(plants) if isinstance(p, dict) and p.get("imageUrl")]
                self.dict_images = [u for u in imgs if same_host(self.base, u)]

    def plants(self, c):
        """식물 상세: 상세 페이지 → 도감 JSON → 그 식물 이미지 1장."""
        c.req("GET", "/app/plant_detail/plant_detail.html")
        pause(0.05, 0.3)
        self.load_dictionary(c)
        if self.dict_images:
            pause(0.05, 0.3)
            c.req("GET", urljoin(self.base, random.choice(self.dict_images)),
                  route="/files/<dictionary image>", raw=True)

    def dictionary(self, c):
        c.req("GET", "/app/dictionary/dictionary.html")
        pause(0.05, 0.3)
        self.load_dictionary(c)
        for u in random.sample(self.dict_images, min(len(self.dict_images), random.randint(3, 8))):
            pause(0.05, 0.25)
            c.req("GET", urljoin(self.base, u), route="/files/<dictionary image>", raw=True)

    def page(self, c):
        c.req("GET", random.choice(PAGES))

    def upload(self, c):
        body, ct = multipart("file", f"IMG_{random.randrange(1000, 9999)}.png", small_png(), "image/png")
        c.req("POST", "/api/images/upload", body=body, ctype=ct)


class Control:
    """계획한 분당 건수만큼 4xx 를 낸다. 기준선과 난수를 공유하지 않는다(self.rng)."""

    def __init__(self, sim, mode, plan, seed):
        self.sim, self.mode, self.plan, self.rng = sim, mode, plan, random.Random(seed)
        self.plan_path = os.path.join(sim.dir, "control_plan.jsonl")

    def mark(self, phase, rate, minutes, edge):
        with open(self.plan_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "phase": phase, "edge": edge,
                                "rate_per_min": rate, "minutes": minutes, "mode": self.mode}) + "\n")

    def run(self):
        for i, (rate, minutes) in enumerate(self.plan):
            self.mark(i, rate, minutes, "start")
            for _ in range(minutes):
                t0 = time.time()
                # 1분 안에 rate 건을 균등 간격 + 지터로 둔다
                slots = sorted((k + self.rng.uniform(-0.4, 0.4)) * 60 / rate for k in range(rate)) if rate else []
                for s in slots:
                    time.sleep(max(0.0, t0 + max(0.0, s) - time.time()))
                    self.event()
                time.sleep(max(0.0, t0 + 60 - time.time()))
            self.mark(i, rate, minutes, "end")

    def event(self):
        kind = self.mode if self.mode != "mixed" else self.rng.choice(["wrong-password", "not-found"])
        if kind == "wrong-password":
            self.wrong_password()
        else:
            self.not_found()

    def typo(self, s, pool):
        i = self.rng.randrange(len(s))
        return s[:i] + self.rng.choice([ch for ch in pool if ch != s[i]]) + s[i + 1:]

    def wrong_password(self):
        a = self.rng.choice(self.sim.accounts)
        if self.rng.random() < 0.15:
            ids = {x["login_id"] for x in self.sim.accounts}
            lid = a["login_id"]
            while lid in ids:
                lid = lid[:-1] + self.rng.choice(string.ascii_lowercase + string.digits)
            tag, body = "unknown_login_id", {"login_id": lid, "password": a["password"]}
        else:
            pw = self.typo(a["password"], string.ascii_letters + string.digits)
            tag, body = "wrong_password", {"login_id": a["login_id"], "password": pw}
        Client(self.sim.base, self.sim.log, tag=tag).req("POST", "/api/v1/auth/login", body=body)
        if self.rng.random() < 0.7:  # 실사용자처럼 다시 입력해 성공한다 (계획 시간을 막지 않게 타이머로)
            right = {"login_id": a["login_id"], "password": a["password"]}
            threading.Timer(self.rng.uniform(1.0, 3.0), Client(self.sim.base, self.sim.log, tag="retry_ok").req,
                            args=("POST", "/api/v1/auth/login"), kwargs={"body": right}).start()

    def not_found(self):
        route = self.rng.choice(NOT_FOUND)
        path = route.replace("<uuid>", str(uuid.UUID(int=self.rng.getrandbits(128), version=4)))
        Client(self.sim.base, self.sim.log, tag="not_found").req("GET", path, route=route, raw=True)


def parse_plan(s):
    return [(int(r), int(m)) for r, m in (p.split(":") for p in s.split(","))]


def find_token(d):
    if isinstance(d, dict):
        for k in ("accessToken", "access_token", "token"):
            if isinstance(d.get(k), str):
                return d[k]
        for v in d.values():
            t = find_token(v)
            if t:
                return t
    return None


def as_list(d):
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        for k in ("data", "content", "items", "plants"):
            if isinstance(d.get(k), list):
                return d[k]
            if isinstance(d.get(k), dict):
                return as_list(d[k])
    return []


def same_host(base, url):
    p = urlparse(url)
    return not p.netloc or p.netloc == urlparse(base).netloc


def pause(lo=0.3, hi=1.0):
    time.sleep(random.uniform(lo, hi))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--setup", type=int, default=0, help="계정 N개만 만들고 종료")
    ap.add_argument("--duration", type=float, default=7200)
    ap.add_argument("--signup-every", type=float, default=900, help="평균 신규 가입 간격(초)")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--control", choices=["none", "wrong-password", "not-found", "mixed"], default="none")
    ap.add_argument("--control-plan", default="", help='"분당건수:분,..." 예: "0:15,2:10,20:5,40:5,60:5,0:10"')
    ap.add_argument("--control-seed", type=int, help="기본: seed+1")
    a = ap.parse_args()
    if a.seed is not None:
        random.seed(a.seed)
    sim = Sim(a.base.rstrip("/"), a.dir)
    if a.setup:
        ok = sum(200 <= sim.signup() < 300 for _ in range(a.setup))
        print(f"setup: {ok}/{a.setup} accounts created (saved to accounts.json)")
        return
    with open(os.path.join(a.dir, "traffic_gen.pid"), "w") as f:
        f.write(str(os.getpid()))
    if a.control != "none":
        plan = parse_plan(a.control_plan)
        if sum(m for _, m in plan) * 60 > a.duration:
            print("warning: control plan is longer than --duration; 기준선 트래픽이 먼저 끝난다", file=sys.stderr)
        cseed = a.control_seed if a.control_seed is not None else (a.seed + 1 if a.seed is not None else None)
        threading.Thread(target=Control(sim, a.control, plan, cseed).run, daemon=True).start()
    end, next_signup = time.time() + a.duration, time.time() + random.expovariate(1 / a.signup_every)
    while time.time() < end:
        if time.time() >= next_signup:
            sim.signup()
            next_signup = time.time() + random.expovariate(1 / a.signup_every)
        sim.session()
        pause(1.0, 4.0)


if __name__ == "__main__":
    main()
