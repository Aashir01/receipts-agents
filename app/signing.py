"""
Signatures for receipts.

Two parties sign every sandbox job:
  1. the executor that ran it: the runner on the executor VM signs what it actually executed with
     an Ed25519 key it generated in memory at boot (never written to disk, gone with the machine);
  2. the app server countersigns the receipt's entry in the append-only ledger.

All signed structures are canonical JSON (sorted keys, no spaces, UTF-8) built only from strings,
integers, booleans and null, so a browser or a 30-line script can rebuild the exact bytes.
"""

import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _app_key() -> tuple[Ed25519PrivateKey, str]:
    """The app's countersigning key: COUNTERSIGN_SIGNING_KEY (base64 32-byte seed) if set, otherwise
    derived from the runner token so it is stable across restarts without a new secret."""
    seed_b64 = os.environ.get("COUNTERSIGN_SIGNING_KEY", "").strip()
    if seed_b64:
        seed, source = base64.b64decode(seed_b64)[:32], "configured"
    else:
        base = os.environ.get("RUNNER_TOKEN", "") or "countersign-local-development"
        seed = hmac.new(base.encode(), b"countersign-app-signing-key-v1", hashlib.sha256).digest()
        source = "derived"
    return Ed25519PrivateKey.from_private_bytes(seed), source


_KEY, KEY_SOURCE = _app_key()
_PUB_RAW = _KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
APP_PUBLIC_KEY = b64(_PUB_RAW)
APP_KEY_ID = "app-" + sha256_hex(_PUB_RAW)[:16]


def sign(data: bytes) -> str:
    return b64(_KEY.sign(data))


def verify(pub_b64: str, sig_b64: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def key_id(pub_b64: str) -> str:
    try:
        return "exec-" + sha256_hex(base64.b64decode(pub_b64))[:16]
    except (ValueError, TypeError):
        return "exec-unknown"


def check_attestation(result: dict, expected_pub: str | None) -> dict:
    """Is the executor's signature on this result genuine, and does it describe this exact result?"""
    att = result.get("attestation")
    if not att:
        return {"signed": False, "reason": "this executor does not sign yet"}
    payload, pub, sig = att.get("payload") or {}, att.get("pub", ""), att.get("sig", "")
    ok_sig = verify(pub, sig, canonical(payload))
    known = expected_pub is None or expected_pub == pub
    outputs = {o["name"]: sha256_hex(base64.b64decode(o["content_b64"])) for o in result.get("outputs") or []}
    consistent = (payload.get("job_id") == result.get("job_id")
                  and payload.get("stdout_sha256") == sha256_hex((result.get("stdout") or "").encode())
                  and payload.get("exit_code") == result.get("exit_code")
                  and {o["name"]: o["sha256"] for o in payload.get("outputs") or []} == outputs)
    return {"signed": True, "valid": ok_sig and consistent and known, "signature_ok": ok_sig,
            "matches_result": consistent, "known_key": known, "key_id": key_id(pub), "pub": pub, "sig": sig,
            "payload": payload}
