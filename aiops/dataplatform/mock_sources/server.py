"""Mock Loki + Prometheus HTTP server over the fixture (Compose service `dp-mock-sources`).

Read-only GET endpoints only: `/loki/api/v1/{query_range,series}` and `/api/v1/{query_range,series}`.
It never forwards to a real Loki/Prometheus.

    python -m mock_sources.server --port 3100
"""
from __future__ import annotations

import argparse
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from mock_sources.fixture_backend import FixtureSources


def make_server(host: str, port: int, sources: FixtureSources | None = None) -> ThreadingHTTPServer:
    sources = sources or FixtureSources()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 (http.server API)
            url = urlsplit(self.path)
            status, body = sources.handle(url.path, url.query)
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if body[:1] in (b"{", b"[") else "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            logging.getLogger("mock_sources").info("%s %s", self.address_string(), fmt % args)

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3100)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    server = make_server(args.host, args.port)
    logging.getLogger("mock_sources").info("serving fixture Loki/Prometheus on %s:%s", args.host, args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
