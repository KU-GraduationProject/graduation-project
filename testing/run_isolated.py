"""Run one unittest suite without network, Docker, subprocesses or real secrets.

Usage: python testing/run_isolated.py remediation|pipeline|network|observer
Install the guard BEFORE importing application code or discovering tests.
This runner never launches Docker (including a test container).
"""
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUITES = {"remediation": "aiops/remediation", "pipeline": "aiops/pipeline",
          "network": "scenarios/network", "observer": "aiops/network-observer"}


def install_guard(allow_http_fixtures=False):
    import socket
    import threading
    internal = threading.local()
    listeners = set()
    if allow_http_fixtures:
        import socketserver
        original_bind = socketserver.TCPServer.server_bind
        original_close = socketserver.TCPServer.server_close
        def bind_fixture(server):
            if server.server_address != ("127.0.0.1", 0):
                raise PermissionError("Only ephemeral loopback test servers allowed")
            original_bind(server)
            listeners.add(server.socket.getsockname())
        def close_fixture(server):
            listeners.discard(server.server_address)
            original_close(server)
        socketserver.TCPServer.server_bind = bind_fixture
        socketserver.TCPServer.server_close = close_fixture
    if os.name == "nt":
        # Windows asyncio implements socketpair using a loopback TCP pair.
        # Permit only this exact socket and the fresh private listener address.
        def socketpair(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0):
            with socket.socket(family, type, proto) as listener:
                listener.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
                listener.listen(1)
                client = socket.socket(family, type, proto)
                internal.pair = (client, listener.getsockname())
                try:
                    client.connect(listener.getsockname())
                    server, _ = listener.accept()
                    return server, client
                except BaseException:
                    client.close()
                    raise
                finally:
                    internal.pair = None
        socket.socketpair = socketpair
    def deny(*args, **kwargs):
        raise PermissionError("ISOLATED_TEST: Docker access forbidden; inject FakeDocker")

    import docker
    docker.from_env = deny
    docker.DockerClient.__init__ = deny
    docker.APIClient.__init__ = deny

    def audit(event, args):
        if event == "socket.connect" and getattr(internal, "pair", None) == args:
            return
        if event == "socket.getaddrinfo" and tuple(args[:2]) in listeners:
            return
        if event == "socket.connect" and args[1] in listeners:
            return
        if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo",
                     "socket.sendto", "subprocess.Popen", "os.system", "os.posix_spawn"}:
            raise PermissionError("ISOLATED_TEST: external IO forbidden: " + event)
        if event == "open":
            path = str(args[0]).lower().replace("\\", "/")
            if "docker.sock" in path or "/pipe/" in path:
                raise PermissionError("ISOLATED_TEST: Docker socket/named pipe forbidden")
    sys.addaudithook(audit)


def main():
    suite = sys.argv[1]
    directory = ROOT / SUITES[suite]
    with tempfile.TemporaryDirectory(prefix="leafy-isolated-") as state:
        for key in list(os.environ):
            if any(word in key for word in ("SLACK", "REMEDIATION", "AGENT_", "DOCKER_")):
                os.environ.pop(key)
        os.environ.update(REMEDIATION_MODE="disabled", REMEDIATION_STATE_DIR=state,
                          REMEDIATION_TTL_SCAN_SEC="0", SLACK_WEBHOOK_URL="",
                          AGENT_MODE="disabled", PYTHONUTF8="1")
        install_guard(allow_http_fixtures=suite == "network")
        os.chdir(directory)
        sys.path.insert(0, str(directory))
        sys.path.insert(0, str(ROOT))
        # Assert the guard is active before collecting a single test.
        import docker
        import socket
        for call in (docker.from_env, lambda: socket.create_connection(("127.0.0.1", 2375))):
            try:
                call()
            except PermissionError:
                pass
            else:
                raise RuntimeError("Isolation self-check failed")
        tests = unittest.defaultTestLoader.discover(str(directory / "tests"))
        result = unittest.TextTestRunner(verbosity=1).run(tests)
        print("ISOLATION: Docker constructors, socket connections, DNS, subprocess, pipes blocked", flush=True)
        return not result.wasSuccessful()


if __name__ == "__main__":
    sys.exit(main())
