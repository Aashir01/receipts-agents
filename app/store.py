"""Persistence for datasets, runs, the live event log and receipts (Supabase)."""

import base64
import copy
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

import db


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def mime_for(name: str) -> str:
    low = name.lower()
    if low.endswith(".png"):
        return "image/png"
    if low.endswith(".csv"):
        return "text/csv"
    if low.endswith(".pdf"):
        return "application/pdf"
    if low.endswith(".json"):
        return "application/json"
    return "application/octet-stream"


async def save_dataset(ds: dict, owner: str | None) -> None:
    data = ds["path"].read_bytes()
    storage_path = f"{ds['id']}/{ds['filename']}"
    await db.upload("uploads", storage_path, data, mime_for(ds["filename"]))
    await db.insert("datasets", {
        "id": ds["id"], "owner": owner, "filename": ds["filename"], "size_bytes": ds["size"],
        "sha256": ds["sha256"], "storage_path": storage_path, "profile": ds["profile"],
        "data_flags": ds.get("suspicious", []),
    })


async def load_dataset(ds_id: str, data_dir: Path) -> dict | None:
    """Rebuild a dataset from Supabase after a restart (or for Replay)."""
    row = await db.one("datasets", {"id": f"eq.{ds_id}", "select": "*"})
    if not row:
        return None
    data = await db.download("uploads", row["storage_path"])
    if data is None:
        return None
    folder = data_dir / ds_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / row["filename"]
    path.write_bytes(data)
    return {"id": ds_id, "filename": row["filename"], "path": path, "size": row["size_bytes"],
            "sha256": row["sha256"], "profile": row["profile"], "suspicious": row.get("data_flags") or [],
            "owner": row.get("owner")}


async def save_receipt(*, kind: str, code: str, result: dict, model: str | None, run_id: str | None,
                       dataset: dict | None, attempt: int | None = None, preflight: dict | None = None,
                       executed_on: str = "executor-vm") -> tuple[str, list[dict]]:
    """Store a sandbox execution and its output files. Returns (receipt_id, outputs with sha/url)."""
    rid = str(uuid.uuid4())
    outputs = []
    for o in result.get("outputs", []):
        raw = base64.b64decode(o["content_b64"])
        path = f"{rid}/{o['name']}"
        await db.upload("outputs", path, raw, mime_for(o["name"]))
        outputs.append({"name": o["name"], "size": o["size"], "sha256": sha256(raw), "storage_path": path})
    await db.insert("receipts", {
        "id": rid, "run_id": run_id, "dataset_id": dataset["id"] if dataset else None, "kind": kind,
        "attempt": attempt, "job_id": result["job_id"], "model": model, "code": code,
        "code_sha256": sha256(code.encode()), "input_sha256": dataset["sha256"] if dataset else None,
        "status": result["status"], "exit_code": result["exit_code"], "duration_s": result["duration_s"],
        "limits": result.get("limits"), "events": result.get("events"), "outputs": outputs,
        "preflight": preflight, "stdout": result.get("stdout", "")[:20000],
        "stdout_sha256": sha256(result.get("stdout", "").encode()),
        "stderr": result.get("stderr", "")[:20000], "executed_on": executed_on,
    })
    return rid, outputs


class RunRecorder:
    """Writes one run and its ordered event log so it can be reopened or shared."""

    def __init__(self, owner: str | None, dataset: dict, question: str):
        self.id = str(uuid.uuid4())
        self.owner = owner
        self.dataset = dataset
        self.question = question
        self.seq = 0

    async def start(self) -> None:
        await db.insert("runs", {"id": self.id, "owner": self.owner, "dataset_id": self.dataset["id"],
                                 "question": self.question, "status": "running"})

    async def event(self, ev: dict) -> None:
        self.seq += 1
        clean = copy.deepcopy(ev)
        for o in clean.get("outputs", []) or []:
            o.pop("data_url", None)         # files live in Storage, not in the log
        await db.insert("run_events", {"run_id": self.id, "seq": self.seq, "type": ev.get("type", "?"),
                                       "payload": clean})

    async def finish(self, status: str, answer: str | None, total_s: float | None,
                     verified: str | None = None) -> None:
        patch = {"status": status, "answer": answer, "total_s": total_s, "finished_at": now_iso()}
        if verified:
            patch["verified"] = verified
        await db.update("runs", self.id, patch)
