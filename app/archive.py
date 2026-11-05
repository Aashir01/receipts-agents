"""
Tamper-evident receipt archive on Vultr Object Storage (S3-compatible).

Every receipt is written twice: to the app database, and as an independent JSON record plus its
output files in a Vultr Object Storage bucket, with the key hashes copied into the object's
metadata. Checking a receipt compares the database row with the archived copy, so an edit to
either one shows up. Audit-trail exports are archived the same way.

Archiving never blocks or breaks a run: failures are logged and reported by the status call.
"""

import asyncio
import hashlib
import json
import os
import time
from datetime import datetime, timezone

ENDPOINT = os.environ.get("VULTR_S3_ENDPOINT", "").strip().removeprefix("https://").removeprefix("http://").rstrip("/")
ACCESS = os.environ.get("VULTR_S3_ACCESS_KEY", "")
SECRET = os.environ.get("VULTR_S3_SECRET_KEY", "")
BUCKET = os.environ.get("VULTR_S3_BUCKET", "countersign-receipts")
SCHEME = os.environ.get("VULTR_S3_SCHEME", "https")
ENABLED = bool(ENDPOINT and ACCESS and SECRET)

STATUS = {"archived": 0, "failed": 0, "last_archived_at": None, "last_error": ""}
_client = None
_bucket_ready = False


def _s3():
    global _client
    if _client is None:
        import boto3
        from botocore.config import Config
        _client = boto3.client("s3", endpoint_url=f"{SCHEME}://{ENDPOINT}", aws_access_key_id=ACCESS,
                               aws_secret_access_key=SECRET, region_name="us-east-1",
                               config=Config(signature_version="s3v4", retries={"max_attempts": 3},
                                             connect_timeout=5, read_timeout=20))
    return _client


def _ensure_bucket():
    global _bucket_ready
    if _bucket_ready:
        return
    s3 = _s3()
    try:
        s3.head_bucket(Bucket=BUCKET)
    except Exception:  # noqa: BLE001
        s3.create_bucket(Bucket=BUCKET)
    _bucket_ready = True


def receipt_key(rid: str) -> str:
    return f"receipts/{rid}/receipt.json"


def _put(key: str, data: bytes, content_type: str, meta: dict | None = None) -> None:
    _ensure_bucket()
    _s3().put_object(Bucket=BUCKET, Key=key, Body=data, ContentType=content_type,
                     Metadata={k: str(v)[:256] for k, v in (meta or {}).items()})


def _archive_receipt(record: dict, files: list[tuple[str, bytes, str]]) -> None:
    rid = record["receipt_id"]
    for name, raw, mime in files:
        _put(f"receipts/{rid}/outputs/{name}", raw, mime, {"sha256": hashlib.sha256(raw).hexdigest()})
    body = json.dumps(record, indent=1, default=str).encode()
    _put(receipt_key(rid), body, "application/json",
         {"code-sha256": record.get("code_sha256", ""), "stdout-sha256": record.get("stdout_sha256", ""),
          "record-sha256": hashlib.sha256(body).hexdigest(), "outputs": len(files)})


async def archive_receipt(record: dict, files: list[tuple[str, bytes, str]]) -> None:
    if not ENABLED:
        return
    try:
        await asyncio.to_thread(_archive_receipt, record, files)
        STATUS["archived"] += 1
        STATUS["last_archived_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:  # noqa: BLE001
        STATUS["failed"] += 1
        STATUS["last_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        print(f"[archive] {STATUS['last_error']}", flush=True)


async def archive_export(key: str, data: bytes, content_type: str) -> str | None:
    if not ENABLED:
        return None
    try:
        await asyncio.to_thread(_put, key, data, content_type, {"sha256": hashlib.sha256(data).hexdigest()})
        return key
    except Exception as e:  # noqa: BLE001
        STATUS["last_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        return None


def _fetch(rid: str) -> dict | None:
    try:
        obj = _s3().get_object(Bucket=BUCKET, Key=receipt_key(rid))
    except Exception:  # noqa: BLE001
        return None
    body = obj["Body"].read()
    return {"record": json.loads(body), "meta": obj.get("Metadata", {}),
            "body_sha256": hashlib.sha256(body).hexdigest(), "modified": str(obj.get("LastModified", ""))}


async def check(rid: str, row: dict) -> dict:
    """Compare the database receipt with its archived copy."""
    got = await asyncio.to_thread(_fetch, rid)
    if not got:
        return {"archived": False, "checks": [], "matches": False}
    rec, meta = got["record"], got["meta"]
    db_out = {o["name"]: o.get("sha256") for o in row.get("outputs") or []}
    ar_out = {o["name"]: o.get("sha256") for o in rec.get("outputs") or []}
    checks = [
        {"item": "code", "database": row.get("code_sha256"), "archive": rec.get("code_sha256")},
        {"item": "printed output", "database": row.get("stdout_sha256"), "archive": rec.get("stdout_sha256")},
        {"item": "exit code", "database": row.get("exit_code"), "archive": rec.get("exit_code")},
        {"item": "machine", "database": row.get("executed_on"), "archive": rec.get("executed_on")},
    ] + [{"item": f"file {n}", "database": db_out.get(n), "archive": ar_out.get(n)} for n in sorted(set(db_out) | set(ar_out))]
    for c in checks:
        c["match"] = c["database"] == c["archive"]
    record_ok = meta.get("record-sha256") in (None, "", got["body_sha256"])
    url = await asyncio.to_thread(_s3().generate_presigned_url, "get_object",
                                  {"Bucket": BUCKET, "Key": receipt_key(rid)}, ExpiresIn=900)
    return {"archived": True, "bucket": BUCKET, "key": receipt_key(rid), "archived_at": rec.get("archived_at"),
            "checks": checks, "record_intact": record_ok,
            "matches": record_ok and all(c["match"] for c in checks), "url": url}


def status() -> dict:
    return {"enabled": ENABLED, "bucket": BUCKET if ENABLED else None, "endpoint": ENDPOINT or None, **STATUS,
            "uptime_s": int(time.monotonic())}
