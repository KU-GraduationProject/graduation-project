"""Agent-only HMAC domain: method, path, principal, nonce and exact raw body.

Reuse Phase 0 signing/constant-time verification. Do not share its secret.
Nonces are committed to the Agent ledger before dispatch (including GETs).
"""
import re
import time
import uuid

from security import signing

MAX_AGE = 60


def canonical(method, path, controller, nonce, body):
    return f"leafy-agent-v1\n{method}\n{path}\n{controller}\n{nonce}\n".encode() + body


def headers(secret, method, path, body, controller="pc1", now=None, nonce=None):
    ts = str(int(time.time() if now is None else now))
    nonce = nonce or uuid.uuid4().hex
    payload = canonical(method, path, controller, nonce, body)
    return {"x-agent-timestamp": ts, "x-agent-nonce": nonce,
            "x-agent-controller": controller,
            "x-agent-signature": signing.sign(secret, ts, payload),
            "content-type": "application/json"}


def authenticate(secret, method, path, body, request_headers, controller, ledger, now=None):
    now = time.time() if now is None else now
    ts = request_headers.get("x-agent-timestamp", "")
    nonce = request_headers.get("x-agent-nonce", "")
    principal = request_headers.get("x-agent-controller", "")
    if (not secret or len(secret) < 32 or principal != controller
            or not re.fullmatch(r"[0-9]{1,12}", ts)
            or not re.fullmatch(r"v0=[a-f0-9]{64}", request_headers.get("x-agent-signature", ""))
            or not re.fullmatch(r"[a-f0-9]{32}", nonce)):
        return False
    ok, _ = signing.verify(secret, ts, request_headers.get("x-agent-signature"),
                           canonical(method, path, principal, nonce, body),
                           now=now, max_age_sec=MAX_AGE)
    if not ok:
        return False
    return ledger.remember_nonce(nonce, int(ts) + MAX_AGE + 1, now)
