"""
The Countersign ledger: an append-only, hash-chained log of every receipt.

Each entry carries the receipt's digest, the executor's signature, the hash of the previous entry
and the app's countersignature over its own hash. Editing any old receipt changes its digest;
editing any entry breaks its hash and every link after it. Entries are written to Vultr Object
Storage (ledger/entries/<seq>.json) in order, by a single background writer.

Anyone can check an entry with the public keys from /api/keys: in the browser on /verify, or
offline with tools/countersign_verify.py.
"""

import asyncio
from datetime import datetime, timezone

import archive
import signing

GENESIS = "0" * 64
_lock = asyncio.Lock()
_queue: asyncio.Queue | None = None
STATE = {"seq": 0, "hash": GENESIS, "loaded": False, "written": 0, "pending": 0, "error": ""}
_recent: dict[int, dict] = {}          # seq -> entry (bounded)
_by_receipt: dict[str, int] = {}       # receipt id -> seq
KEEP = 5000


def entry_key(seq: int) -> str:
    return f"ledger/entries/{seq:09d}.json"


def receipt_core(row: dict, executor: dict | None) -> dict:
    """The parts of a receipt that the ledger commits to. Only strings, ints and null."""
    limits = row.get("limits") or {}

    def s(v):
        return None if v is None else str(v)

    return {
        "receipt_id": s(row.get("id")), "kind": s(row.get("kind")), "run_id": s(row.get("run_id")),
        "dataset_id": s(row.get("dataset_id")), "attempt": row.get("attempt") if isinstance(row.get("attempt"), int) else None,
        "job_id": s(row.get("job_id")), "model": s(row.get("model")), "code_sha256": s(row.get("code_sha256")),
        "input_sha256": s(row.get("input_sha256")), "stdout_sha256": s(row.get("stdout_sha256")),
        "status": s(row.get("status")), "exit_code": row.get("exit_code") if isinstance(row.get("exit_code"), int) else None,
        "executed_on": s(row.get("executed_on")), "image": s(limits.get("image")),
        "outputs": sorted([{"name": str(o["name"]), "sha256": str(o["sha256"])} for o in row.get("outputs") or []],
                          key=lambda o: o["name"]),
        "executor_payload_sha256": signing.sha256_hex(signing.canonical(executor["payload"]))
        if executor and executor.get("signed") else None,
    }


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k not in ("hash", "app_sig")}
    return signing.sha256_hex(signing.canonical(body))


async def load() -> None:
    """Pick up the chain head from Object Storage after a restart."""
    if STATE["loaded"]:
        return
    head = await archive.get_json("ledger/head.json") if archive.ENABLED else None
    if head and isinstance(head.get("seq"), int):
        STATE["seq"], STATE["hash"] = head["seq"], head["hash"]
    STATE["loaded"] = True


async def _writer() -> None:
    while True:
        entry = await _queue.get()
        try:
            ok = await archive.put_json(entry_key(entry["seq"]), entry)
            await archive.put_json(f"ledger/receipts/{entry['receipt_id']}.json", {"seq": entry["seq"]})
            await archive.put_json("ledger/head.json", {"seq": entry["seq"], "hash": entry["hash"],
                                                        "updated_at": entry["time"]})
            STATE["written"] += 1 if ok else 0
            if not ok:
                STATE["error"] = archive.STATUS.get("last_error", "write failed")
        except Exception as e:  # noqa: BLE001
            STATE["error"] = f"{type(e).__name__}: {str(e)[:150]}"
        finally:
            STATE["pending"] = _queue.qsize()


async def append(row: dict, executor: dict | None) -> dict:
    """Add a receipt to the chain. Returns the signed entry (written to storage in the background)."""
    global _queue
    if _queue is None:
        _queue = asyncio.Queue()
        asyncio.get_running_loop().create_task(_writer())
    async with _lock:
        await load()
        core = receipt_core(row, executor)
        entry = {
            "seq": STATE["seq"] + 1, "prev": STATE["hash"],
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "receipt_id": core["receipt_id"], "kind": core["kind"],
            "receipt_digest": signing.sha256_hex(signing.canonical(core)),
            "executor_key_id": executor.get("key_id") if executor and executor.get("signed") else None,
            "executor_sig": executor.get("sig") if executor and executor.get("signed") else None,
            "app_key_id": signing.APP_KEY_ID,
        }
        entry["hash"] = entry_hash(entry)
        entry["app_sig"] = signing.sign(entry["hash"].encode())
        STATE["seq"], STATE["hash"] = entry["seq"], entry["hash"]
        _recent[entry["seq"]] = entry
        _by_receipt[entry["receipt_id"]] = entry["seq"]
        if len(_recent) > KEEP:
            del _recent[min(_recent)]
        _queue.put_nowait(entry)
        STATE["pending"] = _queue.qsize()
        return entry


async def get(seq: int) -> dict | None:
    if seq in _recent:
        return _recent[seq]
    return await archive.get_json(entry_key(seq))


async def for_receipt(rid: str) -> dict | None:
    seq = _by_receipt.get(rid)
    if seq is None:
        idx = await archive.get_json(f"ledger/receipts/{rid}.json")
        seq = idx.get("seq") if isinstance(idx, dict) else None
    return await get(seq) if isinstance(seq, int) else None


def check_entry(entry: dict, prev: dict | None) -> list[dict]:
    """Checks anyone can redo with the public key: hash, countersignature and chain link."""
    h = entry_hash(entry)
    out = [{"check": "Entry hash", "ok": h == entry.get("hash"),
            "detail": "recomputed from the entry" if h == entry.get("hash") else "the entry was edited"},
           {"check": "App countersignature", "ok": signing.verify(signing.APP_PUBLIC_KEY, entry.get("app_sig", ""),
                                                                    entry.get("hash", "").encode()),
            "detail": f"Ed25519, key {entry.get('app_key_id')}"}]
    if entry.get("seq") == 1:
        out.append({"check": "Chain link", "ok": entry.get("prev") == GENESIS, "detail": "first entry"})
    elif prev:
        out.append({"check": "Chain link", "ok": prev.get("hash") == entry.get("prev"),
                    "detail": f"entry #{prev.get('seq')} hashes to this entry's 'prev'"})
    else:
        out.append({"check": "Chain link", "ok": None, "detail": "previous entry not found"})
    return out


async def recent(limit: int = 30) -> list[dict]:
    top = STATE["seq"]
    out = []
    for seq in range(top, max(0, top - limit), -1):
        e = await get(seq)
        if e:
            out.append(e)
    return out


async def audit_chain(limit: int = 200) -> dict:
    """Walk the newest entries and check every hash, signature and link."""
    entries = list(reversed(await recent(limit)))
    bad = []
    for i, e in enumerate(entries):
        prev = entries[i - 1] if i else (await get(e["seq"] - 1) if e["seq"] > 1 else None)
        for c in check_entry(e, prev):
            if c["ok"] is False:
                bad.append({"seq": e["seq"], **c})
    return {"checked": len(entries), "from": entries[0]["seq"] if entries else None,
            "to": entries[-1]["seq"] if entries else None, "broken": bad, "intact": not bad}


def status() -> dict:
    return {"entries": STATE["seq"], "head": STATE["hash"], "written": STATE["written"], "pending": STATE["pending"],
            "error": STATE["error"], "storage": archive.ENABLED, "app_key_id": signing.APP_KEY_ID,
            "key_source": signing.KEY_SOURCE}
