"""SQLite durable claims, nonces, evidence and per-target leases.

Every mutation claim commits BEFORE touching Docker. An interrupted claim is
uncertain and must never be re-executed. SQLite serializes different workers too.
Keep this DB on a local Docker volume, never OneDrive/NFS or a shared Windows mount.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import time


class Conflict(ValueError):
    pass


def fingerprint(command):
    body = command.model_dump(exclude={"expires_at"})
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class Ledger:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS records (
                    rid TEXT NOT NULL, target TEXT NOT NULL, digest TEXT NOT NULL,
                    body TEXT NOT NULL, PRIMARY KEY(rid,target));
                CREATE TABLE IF NOT EXISTS leases (target TEXT PRIMARY KEY, rid TEXT NOT NULL);
            """)
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("Agent ledger integrity check failed")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def remember_nonce(self, nonce, expires, now):
        with self.connection() as db:
            db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
            try:
                db.execute("INSERT INTO nonces VALUES (?,?)", (nonce, expires))
                return True
            except sqlite3.IntegrityError:
                return False

    def get(self, rid, target):
        with self.connection() as db:
            row = db.execute("SELECT body FROM records WHERE rid=? AND target=?", (rid,target)).fetchone()
            return json.loads(row[0]) if row else None

    def all(self):
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT body FROM records")]

    def claim(self, command):
        rid, target = command.remediation_id, command.target
        digest = fingerprint(command)
        with self.connection() as db:
            row = db.execute("SELECT digest,body FROM records WHERE rid=? AND target=?", (rid,target)).fetchone()
            if row:
                if row[0] != digest:
                    raise Conflict("remediation_id_payload_conflict")
                return json.loads(row[1]), False
            # Busy target is not a new accepted operation. No Docker calls.
            if db.execute("SELECT 1 FROM leases WHERE target=?", (target,)).fetchone():
                raise Conflict("target_has_unresolved_remediation")
            record = {"remediation_id": rid, "target": target, "request": command.model_dump(),
                      "state": "EXECUTING", "execution": None, "evidence": {},
                      "started_at": time.time(), "verified_at": None,
                      "recovery_state": None, "recovery": None, "recovery_verified_at": None,
                      "deadline": None, "observation": "not_verified"}
            db.execute("INSERT INTO records VALUES (?,?,?,?)", (rid,target,digest,json.dumps(record)))
            db.execute("INSERT INTO leases VALUES (?,?)", (target,rid))
            return record, True

    def save(self, record, release=False):
        rid, target = record["remediation_id"], record["target"]
        with self.connection() as db:
            db.execute("UPDATE records SET body=? WHERE rid=? AND target=?", (json.dumps(record),rid,target))
            if release:
                db.execute("DELETE FROM leases WHERE target=? AND rid=?", (target,rid))

    def claim_recovery(self, command, automatic=False):
        with self.connection() as db:
            row = db.execute("SELECT body FROM records WHERE rid=? AND target=?",
                             (command.remediation_id,command.target)).fetchone()
            if not row:
                raise Conflict("unknown_remediation_id")
            record = json.loads(row[0])
            if record["recovery_state"]:
                return record, False
            lease = db.execute("SELECT rid FROM leases WHERE target=?", (command.target,)).fetchone()
            if lease is None or lease[0] != command.remediation_id:
                raise Conflict("recovery_does_not_own_target_lease")
            if record["state"] == "EXECUTING" or not record["evidence"]:
                raise Conflict("execution_unresolved_or_no_evidence")
            if automatic and (record["state"] != "SUCCESS" or record["deadline"] is None
                              or record["deadline"] > time.time()):
                raise Conflict("automatic_recovery_not_due")
            record["recovery_state"] = "EXECUTING"
            record["recovery_request"] = command.model_dump()
            record["recovery_started_at"] = time.time()
            db.execute("UPDATE records SET body=? WHERE rid=? AND target=?",
                       (json.dumps(record),command.remediation_id,command.target))
            return record, True
