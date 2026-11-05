"""Alertmanager /api/v2/alerts 를 주기적으로 조회해 JSONL 로 남긴다.

한 줄 = 한 번의 조회. 조회 시각(poll_ts)과 그 시점의 활성 경보 목록을 그대로 기록한다.
집계(발화 횟수·지속 시간)는 나중에 이 파일만으로 한다.

    python -I alert_recorder.py --out <jsonl> [--interval 15] [--url http://127.0.0.1:9093]
중지: 프로세스 종료 (pid 파일 참고). 매 줄 flush 하므로 중간에 끊겨도 앞부분은 남는다.
"""
import argparse
import json
import os
import time
import urllib.request
from datetime import datetime, timezone


def poll(url):
    with urllib.request.urlopen(f"{url}/api/v2/alerts", timeout=10) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--interval", type=float, default=15)
    ap.add_argument("--url", default="http://127.0.0.1:9093")
    a = ap.parse_args()

    with open(a.out + ".pid", "w") as f:
        f.write(str(os.getpid()))

    with open(a.out, "a", encoding="utf-8") as out:
        while True:
            row = {"poll_ts": datetime.now(timezone.utc).isoformat()}
            try:
                alerts = poll(a.url)
                row["ok"] = True
                row["alerts"] = [
                    {
                        "alertname": x["labels"].get("alertname"),
                        "fingerprint": x.get("fingerprint"),
                        "state": x.get("status", {}).get("state"),
                        "startsAt": x.get("startsAt"),
                        "endsAt": x.get("endsAt"),
                        "updatedAt": x.get("updatedAt"),
                        "labels": x.get("labels", {}),
                    }
                    for x in alerts
                ]
            except Exception as e:  # 조회 실패도 공백 구간으로 남긴다
                row["ok"] = False
                row["error"] = repr(e)
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            out.flush()
            time.sleep(a.interval)


if __name__ == "__main__":
    main()
