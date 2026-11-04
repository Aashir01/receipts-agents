"""
Receipts - a data analyst agent whose every number comes with a receipt.

App server (VM 1): plans, writes code with Vultr Serverless Inference,
dispatches it to the sandbox runner on the executor VM over the Vultr VPC,
self-heals on errors, and explains only numbers that real execution printed.
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import db
import guard
import llm
import prompts
import store

RUNNER_URL = os.environ.get("RUNNER_URL", "http://10.6.96.6:8080").rstrip("/")
RUNNER_TOKEN = os.environ.get("RUNNER_TOKEN", "")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/tmp/receipts"))
MAX_ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", "3"))
RUN_TIMEOUT_S = int(os.environ.get("RUN_TIMEOUT_S", "30"))
RUN_MEMORY_MB = int(os.environ.get("RUN_MEMORY_MB", "512"))
RATE_LIMIT_PER_HOUR = int(os.environ.get("RATE_LIMIT_PER_HOUR", "40"))
APPROVAL_TIMEOUT_S = int(os.environ.get("APPROVAL_TIMEOUT_S", "600"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXT = (".csv", ".tsv", ".txt", ".xlsx", ".xls", ".json")

HERE = Path(__file__).parent
SAMPLES = HERE / "samples"

app = FastAPI(title="Receipts")
_runner = httpx.AsyncClient(timeout=httpx.Timeout(RUN_TIMEOUT_S + 30, connect=5))
_hits: dict[str, deque] = defaultdict(deque)
DATASETS: dict[str, dict] = {}
APPROVALS: dict[str, dict] = {}


# ---------- helpers ----------

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or (request.client.host if request.client else "?")


def rate_limit(request: Request) -> None:
    ip, now = client_ip(request), time.time()
    q = _hits[ip]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_HOUR:
        raise HTTPException(429, "Hourly limit reached for this demo. Try again later.")
    q.append(now)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_name(name: str) -> str:
    base = Path(name or "data.csv").name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80] or "data.csv"
    if base == "main.py":
        base = "data_main.py.txt"
    return base


async def run_in_sandbox(code: str, files: list[dict]) -> dict:
    r = await _runner.post(
        f"{RUNNER_URL}/run",
        headers={"X-Runner-Token": RUNNER_TOKEN},
        json={"code": code, "files": files, "timeout_s": RUN_TIMEOUT_S, "memory_mb": RUN_MEMORY_MB},
    )
    if r.status_code != 200:
        raise RuntimeError(f"Runner error {r.status_code}: {r.text[:200]}")
    return r.json()


async def get_user(request: Request) -> dict | None:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    return await db.user_from_token(token)


async def get_dataset(ds_id: str) -> dict | None:
    ds = DATASETS.get(ds_id)
    if ds and ds["path"].exists():
        return ds
    ds = await store.load_dataset(ds_id, DATA_DIR)   # survives app restarts
    if ds:
        DATASETS[ds_id] = ds
    return ds


def dataset_files(ds: dict) -> list[dict]:
    return [{"name": ds["filename"], "content_b64": base64.b64encode(ds["path"].read_bytes()).decode()}]


def receipt(code: str, result: dict, model: str | None, preflight: dict | None = None) -> dict:
    return {
        "preflight": preflight,
        "job_id": result["job_id"],
        "model": model,
        "code_sha256": sha256(code.encode()),
        "status": result["status"],
        "exit_code": result["exit_code"],
        "duration_s": result["duration_s"],
        "outputs": [{"name": o["name"], "size": o["size"],
                     "sha256": sha256(base64.b64decode(o["content_b64"]))} for o in result["outputs"]],
    }


def public_outputs(result: dict, receipt_id: str | None = None) -> list[dict]:
    out = []
    for o in result["outputs"]:
        mime = store.mime_for(o["name"])
        item = {"name": o["name"], "size": o["size"], "mime": mime,
                "data_url": f"data:{mime};base64,{o['content_b64']}"}
        if receipt_id:
            item["url"] = f"/api/files/{receipt_id}/{o['name']}"
        out.append(item)
    return out


# ---------- API ----------

@app.get("/api/health")
async def health():
    runner_ok = False
    try:
        r = await _runner.get(f"{RUNNER_URL}/health", timeout=5)
        runner_ok = r.status_code == 200
    except Exception:  # noqa: BLE001
        pass
    return {"app": "ok", "runner_reachable": runner_ok,
            "model_main": llm.MODEL_MAIN, "model_fallback": llm.MODEL_FALLBACK}


@app.get("/api/samples")
async def samples():
    return [{"id": p.name, "title": p.stem.replace("_", " ").title()}
            for p in sorted(SAMPLES.glob("*")) if p.suffix in ALLOWED_EXT]


async def _register(filename: str, data: bytes, owner: str | None = None) -> dict:
    ds_id = str(uuid.uuid4())
    folder = DATA_DIR / ds_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    path.write_bytes(data)
    ds = {"id": ds_id, "filename": filename, "path": path, "size": len(data), "sha256": sha256(data)}

    # Even parsing the upload happens in the sandbox, never on the app server.
    code = prompts.PROFILE_CODE.format(filename=filename)
    result = await run_in_sandbox(code, dataset_files(ds))
    if result["status"] != "ok":
        raise HTTPException(400, f"Could not read file: {result['stderr'].strip().splitlines()[-1:]}")
    try:
        ds["profile"] = json.loads(result["stdout"].strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Could not profile file")
    ds["suspicious"] = ds["profile"].pop("suspicious_cells", [])
    ds["owner"] = owner
    DATASETS[ds_id] = ds
    await store.save_dataset(ds, owner)
    await store.save_receipt(kind="profile", code=code, result=result, model=None, run_id=None, dataset=ds)
    return {"dataset_id": ds_id, "filename": filename, "size": len(data), "sha256": ds["sha256"],
            "profile": ds["profile"], "profiling_receipt": receipt(code, result, None),
            "profiling_events": result["events"], "limits": result["limits"],
            "data_scan": {"flagged": len(ds["suspicious"]), "cells": ds["suspicious"][:5]}}


@app.post("/api/datasets")
async def upload(file: UploadFile, request: Request):
    rate_limit(request)
    name = safe_name(file.filename)
    if not name.lower().endswith(ALLOWED_EXT):
        raise HTTPException(400, f"Supported files: {', '.join(ALLOWED_EXT)}")
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (10 MB max)")
    user = await get_user(request)
    return await _register(name, data, user["id"] if user else None)


@app.post("/api/samples/{sample_id}")
async def use_sample(sample_id: str, request: Request):
    rate_limit(request)
    path = SAMPLES / Path(sample_id).name
    if not path.is_file():
        raise HTTPException(404, "Unknown sample")
    user = await get_user(request)
    return await _register(path.name, path.read_bytes(), user["id"] if user else None)


class Ask(BaseModel):
    dataset_id: str
    question: str = Field(..., min_length=3, max_length=1000)


class Decision(BaseModel):
    decision: str = Field(..., pattern="^(approve|reject)$")


def sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


@app.post("/api/approvals/{approval_id}")
async def decide(approval_id: str, body: Decision):
    a = APPROVALS.get(approval_id)
    if not a or a["event"].is_set():
        raise HTTPException(404, "No pending approval with that id")
    a["decision"] = body.decision
    a["event"].set()
    return {"ok": True, "decision": body.decision}


async def _wait_for_decision(approval_id: str):
    """Hold the stream open (with keep-alives) until a human decides or time runs out."""
    a = APPROVALS[approval_id]
    waited = 0
    while not a["event"].is_set() and waited < APPROVAL_TIMEOUT_S:
        try:
            await asyncio.wait_for(a["event"].wait(), 15)
        except asyncio.TimeoutError:
            waited += 15
            yield ": keep-alive\n\n"


@app.post("/api/ask")
async def ask(body: Ask, request: Request):
    rate_limit(request)
    user = await get_user(request)
    ds = await get_dataset(body.dataset_id)
    if not ds:
        raise HTTPException(404, "Dataset not found. Upload it again.")
    rec = store.RunRecorder(user["id"] if user else None, ds, body.question)
    await rec.start()

    async def agent():
        """Yields event dicts (recorded + streamed) or raw keep-alive strings (streamed only)."""
        started = time.monotonic()
        data_flags = ds.get("suspicious", [])
        yield {"type": "run", "run_id": rec.id, "question": body.question, "dataset": ds["filename"]}

        # 0. Pre-flight: question and data, before any model writes code
        yield {"type": "step", "id": "guard-q", "status": "running", "title": "Pre-flight: checking your question"}
        q_flags = guard.question_heuristics(body.question)
        safety = await llm.safety_check(body.question)
        q_safety = {k: safety[k] for k in ("status", "categories", "model", "latency_s")}
        q_risky = bool(q_flags) or safety["status"] == "unsafe"
        yield {"type": "preflight", "stage": "question", "risky": q_risky, "flags": q_flags, "safety": q_safety}
        if data_flags:
            yield {"type": "preflight", "stage": "data", "risky": True, "cells": data_flags[:5]}

        # 1. Plan
        yield {"type": "step", "id": "plan", "status": "running", "title": "Planning"}
        plan = await llm.chat(prompts.plan_messages(body.question, ds["filename"], ds["profile"]), max_tokens=3000)
        yield {"type": "step", "id": "plan", "status": "done", "title": "Plan",
               "content": plan["text"], "model": plan["model"], "latency_s": plan["latency_s"]}

        # 2. Code -> pre-flight scan -> (approval) -> run -> self-heal
        messages = prompts.code_messages(body.question, ds["filename"], ds["profile"], plan["text"],
                                         RUN_TIMEOUT_S, RUN_MEMORY_MB)
        messages[0]["content"] += guard.summarise_data_flags(data_flags)
        result, code, model, last_decision, final_receipt = None, "", None, None, None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            yield {"type": "step", "id": f"code{attempt}", "status": "running",
                   "title": "Writing code" if attempt == 1 else f"Fixing code (attempt {attempt})"}
            reply = await llm.chat(messages, max_tokens=8000)
            code, model = llm.extract_code(reply["text"]), reply["model"]
            yield {"type": "code", "attempt": attempt, "code": code, "model": model, "latency_s": reply["latency_s"]}

            findings = guard.scan_code(code)
            blocking = [f for f in findings if f["severity"] == "block"]
            yield {"type": "preflight", "stage": "code", "attempt": attempt, "risky": bool(blocking),
                   "findings": findings}
            preflight = {"question": q_safety["status"], "question_flags": len(q_flags),
                         "data_flags": len(data_flags), "code_findings": len(blocking), "approval": "not needed"}

            if blocking:
                aid = uuid.uuid4().hex
                APPROVALS[aid] = {"event": asyncio.Event(), "decision": None}
                yield {"type": "approval", "id": aid, "attempt": attempt, "findings": blocking,
                       "timeout_s": APPROVAL_TIMEOUT_S}
                async for keep_alive in _wait_for_decision(aid):
                    yield keep_alive
                last_decision = APPROVALS.pop(aid, {}).get("decision") or "timeout"
                preflight["approval"] = {"approve": "approved by you"}.get(last_decision, last_decision)
                yield {"type": "approval_result", "id": aid, "attempt": attempt,
                       "decision": last_decision, "findings": len(blocking)}
                if last_decision != "approve":
                    if attempt < MAX_ATTEMPTS:
                        messages = messages + [
                            {"role": "assistant", "content": f"```python\n{code}\n```"},
                            {"role": "user", "content": prompts.REJECTED_NOTE.format(
                                findings="; ".join(f["detail"] for f in blocking))},
                        ]
                    continue

            yield {"type": "step", "id": f"run{attempt}", "status": "running", "title": "Running in sandbox"}
            result = await run_in_sandbox(code, dataset_files(ds))
            if result["status"] == "ok" and not result["stdout"].strip() and not result["outputs"]:
                result["status"] = "no_output"
                result["stderr"] = ("The script exited without printing anything or saving files. "
                                    "It probably defined functions without calling them. Run the "
                                    "analysis at top level and print every result.")
            rid, _ = await store.save_receipt(kind="analysis", code=code, result=result, model=model,
                                              run_id=rec.id, dataset=ds, attempt=attempt, preflight=preflight)
            final_receipt = rid if result["status"] == "ok" else final_receipt
            yield {"type": "exec", "attempt": attempt, "receipt_id": rid if db.ENABLED else None,
                   "result": {k: result[k] for k in ("job_id", "status", "exit_code", "duration_s",
                                                     "stdout", "stderr", "events", "limits")},
                   "outputs": public_outputs(result, rid if db.ENABLED else None),
                   "receipt": receipt(code, result, model, preflight)}
            if result["status"] == "ok":
                break
            if attempt < MAX_ATTEMPTS:
                tail = "\n".join(result["stderr"].strip().splitlines()[-25:]) or "(no error output)"
                fix = prompts.FIX_USER.format(status=result["status"], exit_code=result["exit_code"], stderr=tail)
                blocked = [e["detail"] for e in result["events"] if e["kind"] == "blocked"]
                if blocked:
                    fix += prompts.BLOCKED_NOTE.format(what="; ".join(blocked))
                    yield {"type": "security", "attempt": attempt, "blocked": blocked}
                messages = messages + [
                    {"role": "assistant", "content": f"```python\n{code}\n```"},
                    {"role": "user", "content": fix},
                ]

        # 3. Explain only what execution proved
        if result and result["status"] == "ok":
            yield {"type": "step", "id": "explain", "status": "running", "title": "Writing answer"}
            ans = await llm.chat(prompts.explain_messages(body.question, code, result["stdout"], result["outputs"]),
                                 max_tokens=3000)
            yield {"type": "answer", "markdown": ans["text"], "model": ans["model"],
                   "grounded_in_job": result["job_id"], "receipt_id": final_receipt}
            status = "done"
        elif result is None:
            yield {"type": "answer", "markdown":
                   "Nothing was run. Every version of the code needed access this task never needs "
                   "(network, secrets, processes or system files), and it was not approved.",
                   "model": None, "grounded_in_job": None}
            status = "rejected"
        else:
            yield {"type": "answer", "markdown":
                   f"The agent could not produce working code in {MAX_ATTEMPTS} attempts. "
                   "Every attempt is shown above with its real error.", "model": None,
                   "grounded_in_job": result["job_id"]}
            status = "failed"
        yield {"type": "done", "total_s": round(time.monotonic() - started, 2), "status": status,
               "run_id": rec.id, "saved": db.ENABLED}

    async def stream():
        answer, status, total = None, "failed", None
        try:
            async for item in agent():
                if isinstance(item, str):
                    yield item
                    continue
                if item["type"] == "answer":
                    answer = item["markdown"]
                if item["type"] == "done":
                    status, total = item["status"], item["total_s"]
                await rec.event(item)
                yield sse(item)
        except Exception as e:  # noqa: BLE001
            err = {"type": "error", "message": f"{type(e).__name__}: {str(e)[:300]}"}
            await rec.event(err)
            yield sse(err)
        finally:
            await rec.finish(status, answer, total)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------- accounts, history, sharing, files, stats ----------

@app.get("/api/config")
async def config():
    return {"auth": db.ENABLED and bool(db.ANON_KEY), "supabase_url": db.URL, "supabase_anon_key": db.ANON_KEY}


@app.get("/api/me")
async def me(request: Request):
    return {"user": await get_user(request)}


@app.get("/api/runs")
async def my_runs(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Sign in to see your history")
    return await db.select("runs", {"owner": f"eq.{user['id']}", "order": "created_at.desc", "limit": "40",
                                    "select": "id,question,status,verified,share_slug,is_public,created_at,total_s"})


async def _run_bundle(run: dict) -> dict:
    events = await db.select("run_events", {"run_id": f"eq.{run['id']}", "order": "seq.asc",
                                            "select": "seq,type,payload"})
    ds = await db.one("datasets", {"id": f"eq.{run['dataset_id']}", "select": "filename,sha256,profile,data_flags"}) \
        if run.get("dataset_id") else None
    return {"run": run, "dataset": ds, "events": [e["payload"] for e in events]}


@app.get("/api/runs/{run_id}")
async def run_detail(run_id: str, request: Request):
    run = await db.one("runs", {"id": f"eq.{run_id}", "select": "*"})
    if not run:
        raise HTTPException(404, "Run not found")
    user = await get_user(request)
    if not run["is_public"] and run.get("owner") and (not user or user["id"] != run["owner"]):
        raise HTTPException(403, "This run is private")
    return await _run_bundle(run)


@app.post("/api/runs/{run_id}/share")
async def share_run(run_id: str, request: Request):
    run = await db.one("runs", {"id": f"eq.{run_id}", "select": "id,owner,share_slug"})
    if not run:
        raise HTTPException(404, "Run not found")
    user = await get_user(request)
    if run.get("owner") and (not user or user["id"] != run["owner"]):
        raise HTTPException(403, "Only the owner can share this run")
    slug = run.get("share_slug") or secrets.token_urlsafe(6).replace("_", "x").replace("-", "y")
    await db.update("runs", run_id, {"is_public": True, "share_slug": slug})
    return {"slug": slug, "path": f"/r/{slug}"}


@app.get("/api/share/{slug}")
async def shared(slug: str):
    run = await db.one("runs", {"share_slug": f"eq.{slug}", "is_public": "eq.true", "select": "*"})
    if not run:
        raise HTTPException(404, "This shared run does not exist or was unshared")
    return await _run_bundle(run)


@app.get("/api/files/{receipt_id}/{name}")
async def file_out(receipt_id: str, name: str):
    """Receipt ids are random UUIDs shown only to people who can see the run."""
    rc = await db.one("receipts", {"id": f"eq.{receipt_id}", "select": "outputs"})
    item = next((o for o in (rc or {}).get("outputs") or [] if o["name"] == name), None)
    if not item:
        raise HTTPException(404, "File not found")
    data = await db.download("outputs", item["storage_path"])
    if data is None:
        raise HTTPException(404, "File not available")
    return Response(content=data, media_type=store.mime_for(name),
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/api/stats")
async def stats():
    row = await db.one("containment_stats", {"select": "*"})
    return row or {}


# ---------- Replay: re-run a stored receipt and compare hashes ----------

@app.post("/api/receipts/{receipt_id}/replay")
async def replay(receipt_id: str, request: Request):
    rate_limit(request)
    rc = await db.one("receipts", {"id": f"eq.{receipt_id}", "select": "*"})
    if not rc:
        raise HTTPException(404, "Receipt not found")
    if rc["status"] != "ok" or rc["kind"] not in ("analysis", "verification"):
        raise HTTPException(400, "Only successful analysis or verification receipts can be replayed")
    ds = await get_dataset(rc["dataset_id"]) if rc.get("dataset_id") else None
    if not ds:
        raise HTTPException(404, "The input file for this receipt is no longer available")
    if ds["sha256"] != rc.get("input_sha256"):
        raise HTTPException(409, "Input file hash no longer matches the receipt")

    result = await run_in_sandbox(rc["code"], dataset_files(ds))
    new_id, new_outputs = await store.save_receipt(kind="replay", code=rc["code"], result=result,
                                                   model=rc.get("model"), run_id=rc.get("run_id"), dataset=ds,
                                                   attempt=rc.get("attempt"))
    original = {o["name"]: o["sha256"] for o in rc.get("outputs") or []}
    fresh = {o["name"]: o["sha256"] for o in new_outputs}
    checks = [{"item": "code", "original": rc["code_sha256"], "replay": store.sha256(rc["code"].encode())},
              {"item": "input file", "original": rc["input_sha256"], "replay": ds["sha256"]},
              {"item": "printed output", "original": rc.get("stdout_sha256"),
               "replay": store.sha256(result.get("stdout", "").encode())}]
    for name in sorted(set(original) | set(fresh)):
        checks.append({"item": name, "original": original.get(name), "replay": fresh.get(name)})
    for c in checks:
        c["match"] = bool(c["original"]) and c["original"] == c["replay"]
    matched = result["status"] == "ok" and all(c["match"] for c in checks)
    user = await get_user(request)
    await db.insert("replays", {"receipt_id": receipt_id, "replay_receipt": new_id, "matched": matched,
                                "details": {"checks": checks, "job_id": result["job_id"]},
                                "requested_by": user["id"] if user else None})
    return {"matched": matched, "checks": checks, "replay_receipt_id": new_id,
            "receipt": receipt(rc["code"], result, rc.get("model")),
            "events": result["events"], "limits": result["limits"]}


# ---------- static UI ----------

app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


@app.get("/")
async def index():
    return FileResponse(HERE / "static" / "index.html")


@app.get("/r/{slug}")
async def shared_page(slug: str):
    return FileResponse(HERE / "static" / "index.html")
