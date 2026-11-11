"""No live DB/Docker calls. Stateful fake DB, fake clients, and platform branches."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2 import f2c_db_pool_exhaustion as f2c
from v2 import f2c_runtime as rt
from v2 import run as runner
from v2 import supervisor, variants


def target(mode="host"):
    """Build a synthetic explicit Host or Docker target for isolated tests."""
    return rt.Target(mode, "leafy", "admin", "app", "123456",
                     "127.0.0.1" if mode == "host" else "/var/run/postgresql",
                     container="leafy-db" if mode == "docker" else "")


class Clock:
    """Advance a deterministic monotonic clock without real hold delays."""
    def __init__(self):
        """Start simulated time at zero."""
        self.now = 0

    def monotonic(self):
        """Return the current simulated monotonic time."""
        return self.now

    def sleep(self, seconds):
        """Advance simulated time by the requested sleep interval."""
        self.now += seconds


class FakeDB:
    """Model run-owned sessions, external clients, login outcomes, and recovery."""
    def __init__(self, clock):
        """Initialize ordinary capacity, client tracking, and failure controls."""
        self.clock = clock
        self.owned = 0
        self.other = 2
        self.limit = 7
        self.clients = []
        self.failure_at = None
        self.forced_probe = None
        self.restore_ok = True
        self.restored_marks = []

    def preflight(self, mark):
        """Expose synthetic server settings with both types of reserved slots."""
        return dict(max_conn=10, super_reserved=2, reserved=1)

    def snapshot(self, mark):
        """Return observed total and run-owned counts without a query backend."""
        return dict(total=self.other + self.owned, owned=self.owned)

    def start_holder(self, mark, lifetime):
        """Simulate a confirmed session startup or an injected partial failure."""
        if self.failure_at == self.owned:
            raise rt.RuntimeFailure("simulated partial failure")
        proc = Mock()
        proc.poll.return_value = None
        self.clients.append((proc, mark, lifetime))
        self.owned += 1
        self.clock.sleep(0.4)  # Session startup is not free; early holders start sooner.
        return proc

    def probe(self, mark):
        """Return the forced outcome or derive it from ordinary slot capacity."""
        return self.forced_probe or ("rejected" if self.other + self.owned >= self.limit else "accepted")

    def restore(self, mark):
        """Simulate run-only cleanup while preserving external sessions."""
        self.restored_marks.append(mark)
        if not self.restore_ok:
            raise rt.RuntimeFailure("simulated recovery failure")
        self.owned = 0  # Only run-owned sessions; external sessions stay untouched.
        return True


class LifecycleTests(unittest.TestCase):
    """Exercise F2-c injection, full hold, failure handling, and recovery."""
    def setUp(self):
        """Replace live I/O, worker creation, and wall time with isolated fakes."""
        self.clock = Clock()
        self.db = FakeDB(self.clock)
        self.t = target()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, F2C_CONFIRM_TARGET=self.t.confirmation))
        self.stack.enter_context(patch.object(f2c, "Psql", return_value=self.db))
        self.stack.enter_context(patch.object(f2c.time, "monotonic", self.clock.monotonic))
        self.stack.enter_context(patch.object(f2c.time, "sleep", self.clock.sleep))
        self.wd = self.stack.enter_context(patch.object(f2c, "spawn_watchdog", return_value={"tag": "test"}))
        self.cancel = self.stack.enter_context(patch.object(supervisor, "cancel_watchdog"))
        self.bgstop = self.stack.enter_context(patch.object(supervisor, "stop_background_traffic"))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def inject(self, **kwargs):
        """Inject against the fake target with a short deterministic hold budget."""
        return f2c.inject(target=self.t, hold_seconds=10, max_seconds=60, background=False, **kwargs)

    def test_verified_hold_starts_after_last_open_and_rejection(self):
        """Require the full verified hold and preserve external sessions during recovery."""
        meta = self.inject()
        self.assertEqual(meta["held"], 5)
        self.assertTrue(meta["rejection_confirmed"])
        self.assertGreater(meta["verified_at"], meta["last_open_at"])
        f2c.hold(meta)
        self.assertGreaterEqual(self.clock.now - meta["hold_started_at"], 10)
        # Every early session outlives the entire hold, rather than sleeping only 10s.
        self.assertTrue(all(lifetime == 60 for _, _, lifetime in self.db.clients))
        self.assertTrue(f2c.cleanup(meta))
        self.assertEqual(self.db.other, 2)
        self.cancel.assert_called_once()

    def test_same_lifecycle_for_docker(self):
        """Apply the same verified injection, hold, and cleanup to a fake Docker target."""
        self.t = target("docker")
        with patch.dict(os.environ, F2C_CONFIRM_TARGET=self.t.confirmation):
            meta = self.inject()
            f2c.hold(meta)
            self.assertTrue(f2c.cleanup(meta))

    def test_watchdog_is_ready_before_first_session(self):
        """Ensure recovery readiness precedes every holder startup."""
        original = self.db.start_holder
        def start(*args):
            """Require worker readiness before simulating the first holder startup."""
            self.wd.assert_called_once()
            return original(*args)
        self.db.start_holder = start
        self.inject()

    def test_no_capacity_rejection_is_not_injection_success(self):
        """Reject pre-existing exhaustion before any worker or holder is started."""
        self.db.other = 7
        with self.assertRaises(rt.RuntimeFailure):
            self.inject()
        self.wd.assert_not_called()
        self.assertFalse(self.db.clients)

    def test_unconfirmed_rejection_never_returns_success(self):
        """Clean up and fail when a fresh login is accepted or its outcome is unknown."""
        for outcome in ("accepted", "unknown"):
            with self.subTest(outcome=outcome):
                self.db.forced_probe = outcome
                with self.assertRaises(rt.RuntimeFailure):
                    self.inject()
                self.assertEqual(self.db.owned, 0)

    def test_role_or_database_limit_cannot_fake_cluster_exhaustion(self):
        """Reject a claimed login refusal when global ordinary slots remain free."""
        meta = self.inject()
        self.db.other = 1  # Claimed rejection, but global ordinary slots remain.
        self.db.forced_probe = "rejected"
        with self.assertRaises(rt.RuntimeFailure):
            f2c.hold(meta)
        self.assertFalse(meta.get("hold_completed"))

    def test_early_session_exit_fails_the_hold(self):
        """Fail the hold if a previously confirmed owned session disappears."""
        meta = self.inject()
        self.db.owned -= 1
        with self.assertRaises(rt.RuntimeFailure):
            f2c.hold(meta)

    def test_partial_open_exception_recovers(self):
        """Recover already opened sessions when a later holder startup raises."""
        self.db.failure_at = 2
        with self.assertRaises(rt.RuntimeFailure):
            self.inject()
        self.assertEqual(self.db.owned, 0)
        self.assertEqual(len(self.db.clients), 2)
        self.cancel.assert_called_once()
        for proc, _, _ in self.db.clients:
            proc.terminate.assert_called_once()

    def test_process_launch_without_db_session_is_not_counted(self):
        """Require an observed DB session rather than counting a launched process."""
        proc = Mock()
        proc.poll.return_value = 2
        self.db.start_holder = Mock(return_value=proc)
        with self.assertRaises(rt.RuntimeFailure):
            self.inject()
        self.assertEqual(self.db.owned, 0)
        proc.wait.assert_called_once()
        self.cancel.assert_called_once()

    def test_ctrl_c_during_open_recovers(self):
        """Recover the partial run when injection is interrupted during startup."""
        original = self.db.start_holder
        def interrupted(mark, lifetime):
            """Interrupt after one confirmed holder to exercise partial cleanup."""
            if self.db.owned:
                raise KeyboardInterrupt
            return original(mark, lifetime)
        self.db.start_holder = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.inject()
        self.assertEqual(self.db.owned, 0)
        self.cancel.assert_called_once()

    def test_cleanup_failure_keeps_watchdog_and_stops_own_clients(self):
        """Retain recovery on failed cleanup while stopping only tracked local clients."""
        meta = self.inject()
        self.db.restore_ok = False
        self.assertFalse(f2c.cleanup(meta))
        self.cancel.assert_not_called()
        self.assertEqual(len(self.db.restored_marks), 3)
        self.bgstop.assert_called_once()

    def test_missing_meta_does_not_terminate_anything(self):
        """Authorize no session termination when run metadata is absent."""
        self.assertFalse(f2c.cleanup(None))
        self.assertFalse(self.db.restored_marks)
        self.cancel.assert_not_called()

    def test_slow_fill_aborts_instead_of_shortening_hold(self):
        """Abort and recover when charging consumes the complete-hold time budget."""
        self.wd.side_effect = lambda *a: self.clock.sleep(35) or {"tag": "slow"}
        with self.assertRaises(rt.RuntimeFailure):
            self.inject()
        self.assertEqual(self.db.owned, 0)

    def test_partial_start_before_watchdog_readiness_is_forbidden(self):
        """Open no holders if the recovery worker cannot become ready."""
        self.wd.side_effect = rt.RuntimeFailure("not ready")
        with self.assertRaises(rt.RuntimeFailure):
            self.inject()
        self.assertFalse(self.db.clients)

    def test_explicit_environment_watchdog_budget_is_honored(self):
        """Use the configured watchdog budget for both recovery and holder lifetimes."""
        with patch.dict(os.environ, F2C_MAX_SECONDS="80"):
            meta = f2c.inject(target=self.t, hold_seconds=10, background=False)
        self.wd.assert_called_once_with(self.t, meta["mark"], 80, None)
        self.assertTrue(all(lifetime == 80 for _, _, lifetime in self.db.clients))

    def test_unknown_hold_probe_after_verification_fails(self):
        """Fail a verified run if a later ordinary login outcome becomes unknown."""
        meta = self.inject()
        self.db.forced_probe = "unknown"
        with self.assertRaises(rt.RuntimeFailure):
            f2c.hold(meta)

    def test_dead_watchdog_during_hold_causes_failure_and_cleanup(self):
        """Fail and recover when the tracked worker exits during the hold."""
        meta = self.inject()
        worker = Mock()
        worker.poll.return_value = 1
        meta["watchdog"]["process"] = worker
        with self.assertRaises(rt.RuntimeFailure):
            f2c.hold(meta)
        self.assertTrue(f2c.cleanup(meta))

    def test_main_returns_failure_without_printing_credentials(self):
        """Suppress raw exception secrets and return failure without printing PASS."""
        output = io.StringIO()
        with patch.object(f2c, "inject", side_effect=RuntimeError("password=SECRET")), contextlib.redirect_stdout(output):
            self.assertEqual(f2c.main(), 1)
        self.assertNotIn("SECRET", output.getvalue())
        self.assertNotIn("PASS", output.getvalue())

    def test_main_handles_both_completion_and_hold_failure(self):
        """Propagate success or hold failure while cleaning up in both cases."""
        original = f2c.inject
        def inject(**kwargs):
            """Invoke the real injector with the isolated target and fixed time budget."""
            return original(target=self.t, hold_seconds=10, max_seconds=60, background=False)
        with patch.object(f2c, "inject", side_effect=inject):
            self.assertEqual(f2c.main(), 0)
        self.assertEqual(self.db.owned, 0)
        with patch.object(f2c, "inject", side_effect=inject), patch.object(f2c, "hold", side_effect=rt.RuntimeFailure("early exit")):
            self.assertEqual(f2c.main(), 1)
        self.assertEqual(self.db.owned, 0)

    def test_weak_never_claims_exhaustion_pass(self):
        """Return the pressure-only code when no ordinary connection rejection is required."""
        meta = self.inject(strength="weak")
        self.assertFalse(meta["rejection_confirmed"])
        with patch.object(f2c, "inject", return_value=meta):
            self.assertEqual(f2c.main(), 3)

    def test_failed_recovery_cannot_produce_pass(self):
        """Return failure and retain the watchdog when recovery cannot be verified."""
        meta = self.inject()
        self.db.restore_ok = False
        output = io.StringIO()
        with patch.object(f2c, "inject", return_value=meta), contextlib.redirect_stdout(output):
            self.assertEqual(f2c.main(), 1)
        self.cancel.assert_not_called()
        self.assertNotIn("PASS", output.getvalue())


class TransportTests(unittest.TestCase):
    """Validate endpoint guards and psql behavior through mocked subprocess I/O."""
    def test_explicit_target_and_exact_confirmation_required(self):
        """Require explicit configuration and the exact target token before any DB call."""
        with patch.dict(os.environ, {}, clear=True), patch.object(subprocess, "run") as execute:
            with self.assertRaises(rt.RuntimeFailure):
                f2c.inject()
            execute.assert_not_called()
        with patch.dict(os.environ, F2C_CONFIRM_TARGET="host:other:production:1"):
            with self.assertRaises(rt.RuntimeFailure):
                f2c.inject(target=target())

    def test_no_connection_string_or_multi_host_target(self):
        """Reject ambiguous routing, unsafe names, and a shared admin/holder account."""
        for change in ({"database": "postgresql://secret@prod/db"}, {"host": "test,prod"},
                       {"database": "leafy; drop database leafy"}, {"user": "admin"}):
            with self.subTest(change=change), self.assertRaises(rt.RuntimeFailure):
                rt.Target(**{**rt.asdict(target()), **change})

    def test_windows_and_docker_commands_have_no_shell_or_password(self):
        """Build explicit noninteractive argv without a host shell or password value."""
        for mode in ("host", "docker"):
            with self.subTest(mode=mode):
                db = rt.Psql(target(mode))
                cmd = db.command("SELECT 1", "app", "connhold-a")
                self.assertNotIn("sh", cmd)
                self.assertNotIn("pkill", cmd)
                self.assertIn("-w", cmd)
                self.assertIn("-X", cmd)
                self.assertIn("app", cmd)
                if mode == "docker":
                    self.assertEqual(cmd[:3], ["docker", "exec", "leafy-db"])
                    self.assertIn("-u", cmd)
                    self.assertIn("PGHOSTADDR", cmd)
                else:
                    self.assertEqual(cmd[0], "psql")

    def test_ambient_routing_and_password_are_scrubbed(self):
        """Prevent inherited libpq routing, role options, and passwords from overriding the target."""
        with patch.dict(os.environ, PGHOSTADDR="production", PGSERVICE="prod", PGPASSWORD="SECRET", PGOPTIONS="-c role=admin"):
            env = rt.Psql(target()).environment("connhold-a")
        for key in ("PGHOSTADDR", "PGSERVICE", "PGPASSWORD", "PGOPTIONS"):
            self.assertNotIn(key, env)

    def test_snapshot_excludes_observer_and_scopes_owned_sessions(self):
        """Exclude the query backend and match owned sessions by mark, role, and DB."""
        db = rt.Psql(target())
        with patch.object(db, "query", return_value={"total": 7, "owned": 5}) as query:
            self.assertEqual(db.snapshot("connhold-a")["total"], 7)
        sql = query.call_args.args[0]
        for token in ("pid <> pg_backend_pid()", "client backend", "connhold-a", "usename='app'", "datname='leafy'"):
            self.assertIn(token, sql)

    def test_preflight_rejects_wrong_identity_or_privileged_holder(self):
        """Reject cluster, privilege, reservation, and connection-limit mismatches."""
        info = dict(system_id="123456", database="leafy", admin="admin", superuser=True,
                    version=170000, max_conn=100, reserved=5, super_reserved=3)
        role = dict(user="app", superuser=False, reserved_role=False, role_limit=-1, db_limit=-1)
        for delta_info, delta_role in (({"system_id": "wrong"}, {}), ({"superuser": False}, {}),
                                      ({"super_reserved": 0}, {}), ({}, {"superuser": True}),
                                      ({}, {"reserved_role": True}), ({}, {"role_limit": 5}),
                                      ({}, {"db_limit": 5})):
            db = rt.Psql(target())
            with self.subTest(info=delta_info, role=delta_role), patch.object(db, "query", side_effect=[{**info, **delta_info}, {**role, **delta_role}]):
                with self.assertRaises(rt.RuntimeFailure):
                    db.preflight("connhold-a")
        with patch.object(db, "query", side_effect=[info, role]):
            self.assertEqual(db.preflight("connhold-a")["reserved"], 5)

    def test_probe_fails_closed_on_auth_network_and_localized_errors(self):
        """Recognize known exhaustion messages and leave other login errors unknown."""
        db = rt.Psql(target())
        for message, expected in (("FATAL: remaining connection slots are reserved for roles with privileges", "rejected"),
                                  ("FATAL: sorry, too many clients already", "rejected"),
                                  ("FATAL: password authentication failed SECRET", "unknown"),
                                  ("connection refused", "unknown"),
                                  ("FATAL: too many connections for role app", "unknown"),
                                  ("53300: localized message", "unknown")):
            with self.subTest(message=message), patch.object(db, "execute", return_value=Mock(returncode=2, stderr=message)):
                self.assertEqual(db.probe("connhold-a"), expected)

    def test_ordinary_and_admin_connections_share_explicit_endpoint(self):
        """Pass the explicit endpoint, run name, and timeout to mocked psql execution."""
        for mode in ("host", "docker"):
            db = rt.Psql(target(mode))
            with patch.object(subprocess, "run", return_value=Mock(returncode=0, stdout='{"ok":true}')) as run:
                self.assertTrue(db.query("SELECT 1", user="app", app="connhold-a-probe")["ok"])
            cmd = run.call_args.args[0]
            self.assertEqual(cmd[cmd.index("-h") + 1], db.target.host)
            self.assertEqual(cmd[cmd.index("-d") + 1], "leafy")
            self.assertEqual(run.call_args.kwargs["env"]["PGAPPNAME"], "connhold-a-probe")
            self.assertEqual(run.call_args.kwargs["timeout"], 10)

    def test_failed_query_output_and_timeout_are_not_exposed(self):
        """Convert query failures and timeouts into errors that omit raw secret text."""
        db = rt.Psql(target())
        with patch.object(db, "execute", return_value=Mock(returncode=1, stderr="password=SECRET")):
            with self.assertRaises(rt.RuntimeFailure) as caught:
                db.query("SELECT 1")
        self.assertNotIn("SECRET", str(caught.exception))
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(["SECRET"], 10)):
            with self.assertRaises(rt.RuntimeFailure) as caught:
                db.execute("SELECT 1")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_restore_only_terminates_exact_mark_role_and_database(self):
        """Scope termination to the exact owned mark, ordinary role, and database."""
        db = rt.Psql(target())
        with patch.object(db, "query", side_effect=[{"system_id": "123456"}, {"terminated": True}, {"owned": 0}]) as query, patch.object(db, "probe", return_value="accepted"):
            self.assertTrue(db.restore("connhold-a"))
        sql = query.call_args_list[1].args[0]
        for token in ("application_name='connhold-a'", "usename='app'", "datname='leafy'", "pg_terminate_backend"):
            self.assertIn(token, sql)
        self.assertNotIn("connhold-b", sql)

    def test_restore_requires_zero_owned_and_new_ordinary_connection(self):
        """Reject recovery if owned sessions remain or a fresh ordinary login fails."""
        for owned, outcome in ((1, "accepted"), (0, "unknown"), (0, "rejected")):
            db = rt.Psql(target())
            with self.subTest(owned=owned, outcome=outcome), patch.object(db, "query", side_effect=[{"system_id": "123456"}, {}, {"owned": owned}]), patch.object(db, "probe", return_value=outcome):
                self.assertFalse(db.restore("connhold-a"))

    def test_recovery_does_not_touch_replaced_cluster(self):
        """Stop before termination when the recovery endpoint has a different cluster ID."""
        db = rt.Psql(target())
        with patch.object(db, "query", return_value={"system_id": "other"}) as query:
            with self.assertRaises(rt.RuntimeFailure):
                db.restore("connhold-a")
        self.assertEqual(query.call_count, 1)


class PlatformAndWorkerTests(unittest.TestCase):
    """Check platform branches and independent Python workers with fake DB access."""
    def test_platform_creation_flags(self):
        """Choose independent-process options for Windows and POSIX."""
        self.assertEqual(supervisor.detached_process_kwargs("posix"), {"start_new_session": True})
        self.assertEqual(supervisor.detached_process_kwargs("nt"), {"creationflags": 0x208})

    def test_traffic_interpreter_preserves_posix_and_supports_windows(self):
        """Preserve the POSIX traffic interpreter and use the active Python on Windows."""
        for platform, expected in (("nt", sys.executable), ("posix", "python3")):
            with self.subTest(platform=platform), patch.object(supervisor.os, "name", platform):
                cmd = supervisor.build_traffic_command("traffic.py", "http://test", "run")
                self.assertEqual(cmd[0], expected)

    def test_windows_background_stop_uses_taskkill_without_killpg(self):
        """Stop the Windows traffic tree through taskkill without calling Unix killpg."""
        proc = Mock()
        proc.poll.return_value = None
        with patch.object(supervisor.os, "name", "nt"), patch.object(subprocess, "run") as run, patch.object(os, "killpg", create=True) as killpg:
            supervisor.stop_background_traffic({"pid": 1234, "process": proc})
        self.assertEqual(run.call_args.args[0], ["taskkill", "/PID", "1234", "/T", "/F"])
        killpg.assert_not_called()

    def test_posix_background_stop_and_exited_pid_safety(self):
        """Stop a live POSIX group while avoiding a stale PID after the tracked process exits."""
        proc = Mock()
        proc.poll.return_value = None
        with patch.object(supervisor.os, "name", "posix"), patch.object(os, "getpgid", return_value=1234, create=True), patch.object(os, "killpg", create=True) as killpg:
            supervisor.stop_background_traffic({"pid": 1234, "process": proc})
            killpg.assert_called_once()
            proc.poll.return_value = 0
            supervisor.stop_background_traffic({"pid": 1234, "process": proc})
            self.assertEqual(killpg.call_count, 1)

    def test_client_termination_escalates_only_own_process(self):
        """Escalate a timed-out client termination only through its retained Popen handle."""
        proc = Mock()
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired("psql", 2), 0]
        rt.stop_clients([proc])
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()

    def test_worker_launch_uses_pipe_and_platform_flags(self):
        """Send worker metadata by pipe and pass platform-specific creation options."""
        proc = Mock(pid=1234)
        data = io.StringIO()
        proc.stdin = Mock()
        proc.stdin.write.side_effect = data.write
        with tempfile.TemporaryDirectory() as td, patch.object(subprocess, "Popen", return_value=proc) as popen, patch.object(supervisor, "detached_process_kwargs", return_value={"creationflags": 0x208}), patch.object(Path, "exists", side_effect=[False, False, False, True]):
            rt.spawn_watchdog(target(), "connhold-a", 60, td)
        self.assertEqual(popen.call_args.kwargs["creationflags"], 0x208)
        self.assertEqual(popen.call_args.args[0][0], sys.executable)
        payload = json.loads(data.getvalue())
        self.assertEqual(payload["target"]["system_id"], "123456")
        self.assertNotIn("password", data.getvalue().lower())
        proc.stdin.close.assert_called_once()

    def test_failed_watchdog_start_stops_worker_before_any_session(self):
        """Stop a worker that exits without readiness before any holder can start."""
        proc = Mock(pid=1234)
        proc.poll.return_value = 1
        with tempfile.TemporaryDirectory() as td, patch.object(subprocess, "Popen", return_value=proc), patch.object(rt, "stop_clients") as stop:
            with self.assertRaises(rt.RuntimeFailure):
                rt.spawn_watchdog(target(), "connhold-a", 60, td)
            stop.assert_called_once_with([proc])

    def test_watchdog_retries_failed_restore_and_stops_after_success(self):
        """Retry exceptions and unverified recovery, logging only safe status text."""
        clock = Clock()
        db = Mock()
        db.restore.side_effect = [rt.RuntimeFailure("failed"), False, True]
        with tempfile.TemporaryDirectory() as td:
            paths = {k: str(Path(td) / k) for k in ("cancel", "ready", "log")}
            with patch.object(rt, "Psql", return_value=db), patch.object(rt.time, "monotonic", clock.monotonic), patch.object(rt.time, "sleep", clock.sleep):
                rt.watchdog_worker(dict(target=rt.asdict(target()), mark="connhold-a", timeout=1, paths=paths))
            self.assertTrue(Path(paths["ready"]).exists())
            self.assertEqual(db.restore.call_count, 3)
            self.assertEqual(Path(paths["log"]).read_text().splitlines(), ["RESTORE FAILED; retrying", "RESTORE FAILED; retrying", "restored"])

    def test_cancelled_watchdog_does_not_restore(self):
        """Honor the normal-cleanup cancellation file without attempting restoration."""
        db = Mock()
        with tempfile.TemporaryDirectory() as td:
            paths = {k: str(Path(td) / k) for k in ("cancel", "ready", "log")}
            Path(paths["cancel"]).touch()
            with patch.object(rt, "Psql", return_value=db):
                rt.watchdog_worker(dict(target=rt.asdict(target()), mark="connhold-a", timeout=1, paths=paths))
            db.restore.assert_not_called()

    def test_real_independent_worker_survives_parent_exit_with_fake_db(self):
        # The only real subprocesses are Python workers; DB operations are a stub.
        """Verify independent recovery after normal parent exit using only a fake DB."""
        with tempfile.TemporaryDirectory() as td:
            paths = {k: str(Path(td) / k) for k in ("cancel", "ready", "log")}
            payload = dict(target=rt.asdict(target()), mark="connhold-a", timeout=0.3, paths=paths)
            worker = ("import sys; sys.path.insert(0, sys.argv[1]); from v2 import f2c_runtime as r; "
                      "from unittest.mock import Mock; r.Psql=lambda target: Mock(restore=Mock(return_value=True)); "
                      "import json; r.watchdog_worker(json.loads(sys.argv[2]))")
            parent = ("import subprocess,sys; from pathlib import Path; "
                      "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]], "
                      "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL, "
                      "**({'creationflags':0x208} if sys.platform=='win32' else {'start_new_session':True}))")
            result = subprocess.run([sys.executable, "-c", parent, worker,
                                     str(Path(__file__).resolve().parents[2]), json.dumps(payload)],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            until = time.monotonic() + 5
            while not Path(paths["log"]).exists() and time.monotonic() < until:
                time.sleep(0.05)
            self.assertEqual(Path(paths["log"]).read_text(), "restored\n")

    def test_real_worker_recovers_after_parent_is_killed_with_fake_db(self):
        """Verify fake-DB recovery after forcibly terminating the real parent process."""
        with tempfile.TemporaryDirectory() as td:
            paths = {k: str(Path(td) / k) for k in ("cancel", "ready", "log")}
            payload = dict(target=rt.asdict(target()), mark="connhold-a", timeout=0.5, paths=paths)
            worker = ("import sys,json; sys.path.insert(0,sys.argv[1]); from v2 import f2c_runtime as r; "
                      "from unittest.mock import Mock; r.Psql=lambda target: Mock(restore=Mock(return_value=True)); "
                      "r.watchdog_worker(json.loads(sys.argv[2]))")
            parent = ("import subprocess,sys,time; "
                      "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]], "
                      "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL, "
                      "**({'creationflags':0x208} if sys.platform=='win32' else {'start_new_session':True})); time.sleep(30)")
            proc = subprocess.Popen([sys.executable, "-c", parent, worker,
                                     str(Path(__file__).resolve().parents[2]), json.dumps(payload)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                until = time.monotonic() + 5
                while not Path(paths["ready"]).exists() and time.monotonic() < until:
                    time.sleep(0.02)
                self.assertTrue(Path(paths["ready"]).exists())
            finally:
                proc.kill()
                proc.wait(timeout=5)
            until = time.monotonic() + 5
            while not Path(paths["log"]).exists() and time.monotonic() < until:
                time.sleep(0.05)
            self.assertEqual(Path(paths["log"]).read_text(), "restored\n")


class EntryPointTests(unittest.TestCase):
    """Check F2-c lifecycle dispatch while preserving other scenario entry paths."""
    def test_default_and_variant_share_full_lifecycle_and_exit_code(self):
        """Route both F2-c entry paths through main and forward variant timing and exit status."""
        with patch.object(f2c, "main", return_value=1) as main:
            self.assertEqual(runner.run("f2_c_db_pool_exhaustion", False), 1)
            main.assert_called_once_with()
        inst = variants.Instance("f2_c_db_pool_exhaustion", "fill-burst", 1,
                                 {"strength": "strong", "hold_seconds": 73})
        with patch.object(variants, "generate", return_value=inst), patch.object(f2c, "main", return_value=0) as main:
            self.assertEqual(runner.run(inst.scenario_id, False, inst.variant_id, 1), 0)
            main.assert_called_once_with(strength="strong", hold_seconds=73)

    def test_other_scenario_variant_dispatch_unchanged(self):
        """Preserve the existing inject-only variant dispatch for unrelated scenarios."""
        from v2 import f2a_minio_outage as f2a
        inst = variants.Instance("f2_a_minio_outage", "full-stop", 1, {"down_seconds": 20})
        with patch.object(variants, "generate", return_value=inst), patch.object(f2a, "inject") as inject, patch.object(f2a, "main") as main:
            self.assertEqual(runner.run(inst.scenario_id, False, inst.variant_id, 1), 0)
            inject.assert_called_once_with()
            main.assert_not_called()


if __name__ == "__main__":
    unittest.main()
