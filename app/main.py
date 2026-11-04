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
import research
import store
import verify

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
ACTIVE: dict[str, dict] = {}     # run_id -> {stop, job}


class Stopped(Exception):
    pass


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


async def run_in_sandbox(code: str, files: list[dict], job_id: str | None = None) -> dict:
    payload = {"code": code, "files": files, "timeout_s": RUN_TIMEOUT_S, "memory_mb": RUN_MEMORY_MB}
    if job_id:
        payload["job_id"] = job_id
    r = await _runner.post(f"{RUNNER_URL}/run", headers={"X-Runner-Token": RUNNER_TOKEN}, json=payload)
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

@app.get("/api/ping")
async def ping():
    """Liveness only: no network calls, so deploys never fail because a dependency is slow."""
    return {"ok": True}


@app.get("/api/health")
async def health():
    runner_ok = False
    try:
        r = await _runner.get(f"{RUNNER_URL}/health", timeout=5)
        runner_ok = r.status_code == 200
    except Exception:  # noqa: BLE001
        pass
    return {"app": "ok", "runner_reachable": runner_ok,
            "model_main": llm.MODEL_MAIN, "model_fallback": llm.MODEL_FALLBACK,
            "database": await db.diagnose()}


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
    run = ACTIVE.get(a.get("run_id"), {})
    while not a["event"].is_set() and waited < APPROVAL_TIMEOUT_S and not run.get("stop"):
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

    ACTIVE[rec.id] = {"stop": False, "job": None}

    def check_stop():
        if ACTIVE.get(rec.id, {}).get("stop"):
            raise Stopped()

    async def sandbox(code: str) -> dict:
        check_stop()
        job = uuid.uuid4().hex[:12]
        ACTIVE[rec.id]["job"] = job
        try:
            res = await run_in_sandbox(code, dataset_files(ds), job_id=job)
        finally:
            ACTIVE[rec.id]["job"] = None
        if res["status"] == "stopped":
            raise Stopped()
        return res

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
        check_stop()

        # 2. Explore: a short sandboxed look at the data before the real analysis
        yield {"type": "stage", "stage": "explore", "title": "Stage 1 of 3: explore the data"}
        findings_text = ""
        exp = await llm.chat(prompts.explore_messages(body.question, ds["filename"], ds["profile"],
                                                      RUN_TIMEOUT_S, RUN_MEMORY_MB), max_tokens=4000)
        exp_code = llm.extract_code(exp["text"])
        exp_scan = [f for f in guard.scan_code(exp_code) if f["severity"] == "block"]
        if exp_scan:
            yield {"type": "explore", "status": "skipped", "code": exp_code, "model": exp["model"],
                   "reason": "Exploration code wanted risky access, so it was not run: " +
                             "; ".join(f["detail"] for f in exp_scan)}
        else:
            exp_res = await sandbox(exp_code)
            exp_pre = {"question": q_safety["status"], "data_flags": len(data_flags), "code_findings": 0,
                       "approval": "not needed"}
            exp_rid, _ = await store.save_receipt(kind="analysis", code=exp_code, result=exp_res, model=exp["model"],
                                                  run_id=rec.id, dataset=ds, attempt=0, preflight=exp_pre)
            if exp_res["status"] == "ok" and exp_res["stdout"].strip():
                findings_text = exp_res["stdout"][:3000]
            yield {"type": "explore", "status": exp_res["status"], "code": exp_code, "model": exp["model"],
                   "latency_s": exp["latency_s"],
                   "result": {k: exp_res[k] for k in ("job_id", "status", "exit_code", "duration_s",
                                                      "stdout", "stderr", "events", "limits")},
                   "receipt": receipt(exp_code, exp_res, exp["model"], exp_pre)}
        check_stop()

        # 3. Analyze: code -> pre-flight scan -> (approval) -> run -> self-heal
        yield {"type": "stage", "stage": "analyze", "title": "Stage 2 of 3: analyze"}
        messages = prompts.code_messages(body.question, ds["filename"], ds["profile"], plan["text"],
                                         RUN_TIMEOUT_S, RUN_MEMORY_MB)
        messages[0]["content"] += guard.summarise_data_flags(data_flags)
        if findings_text:
            messages[1]["content"] += ("\n\nExploration findings (printed by a sandboxed exploration run; "
                                       "use the exact values shown):\n" + findings_text)
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
                APPROVALS[aid] = {"event": asyncio.Event(), "decision": None, "run_id": rec.id}
                yield {"type": "approval", "id": aid, "attempt": attempt, "findings": blocking,
                       "timeout_s": APPROVAL_TIMEOUT_S}
                async for keep_alive in _wait_for_decision(aid):
                    yield keep_alive
                last_decision = APPROVALS.pop(aid, {}).get("decision") or "timeout"
                check_stop()
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
            result = await sandbox(code)
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

        # 4. Verify (two-key): separately written code recomputes the headline numbers
        verification = None
        if result and result["status"] == "ok":
            check_stop()
            yield {"type": "stage", "stage": "verify", "title": "Stage 3 of 3: independent verification"}
            yield {"type": "step", "id": "verify", "status": "running", "title": "Picking the headline numbers to verify"}
            ext = await llm.chat(prompts.extract_messages(body.question, result["stdout"]), max_tokens=2000)
            yield {"type": "step", "id": "verify", "status": "running",
                   "title": f"Picked the numbers to verify ({ext['model']}, {ext['latency_s']} s)"}
            quantities = verify.parse_quantities(ext["text"], result["stdout"])
            verification = {"status": "inconclusive", "checks": [], "reason": "No checkable numbers in the output"}
            if quantities:
                yield {"type": "step", "id": "verify", "status": "running",
                       "title": f"A second auditor is recomputing {len(quantities)} number{'s' if len(quantities) > 1 else ''} from scratch"}
                vmsgs = prompts.verify_messages(body.question, ds["filename"], ds["profile"], quantities,
                                                RUN_TIMEOUT_S, RUN_MEMORY_MB)
                for vtry in (1, 2):
                    vrep = await llm.chat(vmsgs, max_tokens=6000)
                    vcode = llm.extract_code(vrep["text"])
                    if any(f["severity"] == "block" for f in guard.scan_code(vcode)):
                        verification = {"status": "inconclusive", "checks": [],
                                        "reason": "Verification code wanted risky access and was not run"}
                        break
                    vres = await sandbox(vcode)
                    vpre = {"question": q_safety["status"], "data_flags": len(data_flags),
                            "code_findings": 0, "approval": "not needed"}
                    v_rid, _ = await store.save_receipt(kind="verification", code=vcode, result=vres,
                                                        model=vrep["model"], run_id=rec.id, dataset=ds,
                                                        attempt=vtry, preflight=vpre)
                    verification = verify.compare(quantities, verify.parse_recomputed(vres["stdout"]))
                    verification.update({"code": vcode, "model": vrep["model"], "receipt_id": v_rid if db.ENABLED else None,
                                         "result": {k: vres[k] for k in ("job_id", "status", "exit_code", "duration_s",
                                                                         "stdout", "stderr", "events", "limits")},
                                         "receipt": receipt(vcode, vres, vrep["model"], vpre)})
                    if vres["status"] == "ok" and verification["status"] != "inconclusive":
                        break
                    vmsgs = vmsgs + [{"role": "assistant", "content": f"```python\n{vcode}\n```"},
                                     {"role": "user", "content": prompts.FIX_USER.format(
                                         status=vres["status"], exit_code=vres["exit_code"],
                                         stderr=(vres["stderr"].strip()[-2000:] or "No JSON line with the requested names was printed."))}]
            yield {"type": "verify", **verification}

        # 5. Explain only what execution proved (and what verification confirmed)
        if result and result["status"] == "ok":
            yield {"type": "step", "id": "explain", "status": "running", "title": "Writing answer"}
            ans = await llm.chat(prompts.explain_messages_verified(body.question, code, result["stdout"],
                                                                   result["outputs"], verification), max_tokens=3000)
            yield {"type": "answer", "markdown": ans["text"], "model": ans["model"],
                   "grounded_in_job": result["job_id"], "receipt_id": final_receipt,
                   "verified": verification["status"] if verification else None}
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
               "run_id": rec.id, "saved": db.ENABLED,
               "verified": verification["status"] if verification else None}

    async def stream():
        answer, status, total, verified = None, "failed", None, None
        t0 = time.monotonic()
        try:
            async for item in agent():
                if isinstance(item, str):
                    yield item
                    continue
                if item["type"] == "answer":
                    answer = item["markdown"]
                if item["type"] == "done":
                    status, total, verified = item["status"], item["total_s"], item.get("verified")
                await rec.event(item)
                yield sse(item)
        except Stopped:
            status, total = "stopped", round(time.monotonic() - t0, 2)
            for item in ({"type": "stopped", "message": "Stopped by you. Any running sandbox container was killed."},
                         {"type": "done", "total_s": total, "status": "stopped", "run_id": rec.id, "saved": db.ENABLED}):
                await rec.event(item)
                yield sse(item)
        except Exception as e:  # noqa: BLE001
            err = {"type": "error", "message": f"{type(e).__name__}: {str(e)[:300]}"}
            await rec.event(err)
            yield sse(err)
        finally:
            ACTIVE.pop(rec.id, None)
            v = verified if verified in ("verified", "mismatch") else ("skipped" if status == "done" else None)
            await rec.finish(status, answer, total, v)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------- web research agent (Pattern B) ----------

BROWSE_TIMEOUT_S = int(os.environ.get("BROWSE_TIMEOUT_S", "90"))


class Research(BaseModel):
    goal: str = Field(..., min_length=5, max_length=1500)
    domains: list[str] = Field(default_factory=list, max_length=5)


async def browse_in_sandbox(actions: list, domains: list[str], job_id: str) -> dict:
    r = await _runner.post(f"{RUNNER_URL}/browse", headers={"X-Runner-Token": RUNNER_TOKEN},
                           json={"actions": actions, "allow_domains": domains,
                                 "timeout_s": BROWSE_TIMEOUT_S, "job_id": job_id},
                           timeout=BROWSE_TIMEOUT_S + 60)
    if r.status_code != 200:
        raise RuntimeError(f"Browser sandbox error {r.status_code}: {r.text[:200]}")
    return r.json()


async def _approval_flow(run_id: str, payload: dict, holder: dict):
    """Ask a human, keep the stream alive while waiting, and report the decision."""
    aid = uuid.uuid4().hex
    APPROVALS[aid] = {"event": asyncio.Event(), "decision": None, "run_id": run_id}
    yield {"type": "approval", "id": aid, "timeout_s": APPROVAL_TIMEOUT_S, **payload}
    async for keep_alive in _wait_for_decision(aid):
        yield keep_alive
    holder["decision"] = APPROVALS.pop(aid, {}).get("decision") or "timeout"
    yield {"type": "approval_result", "id": aid, "attempt": payload.get("attempt", 0),
           "decision": holder["decision"], "findings": len(payload.get("findings", []))}


async def _recorded_stream(rec, agen):
    answer, status, total, verified = None, "failed", None, None
    t0 = time.monotonic()
    try:
        async for item in agen:
            if isinstance(item, str):
                yield item
                continue
            if item["type"] == "answer":
                answer = item["markdown"]
            if item["type"] == "done":
                status, total, verified = item["status"], item["total_s"], item.get("verified")
            await rec.event(item)
            yield sse(item)
    except Stopped:
        status, total = "stopped", round(time.monotonic() - t0, 2)
        for item in ({"type": "stopped", "message": "Stopped by you. Any running sandbox container was killed."},
                     {"type": "done", "total_s": total, "status": "stopped", "run_id": rec.id, "saved": db.ENABLED}):
            await rec.event(item)
            yield sse(item)
    except Exception as e:  # noqa: BLE001
        err = {"type": "error", "message": f"{type(e).__name__}: {str(e)[:300]}"}
        await rec.event(err)
        yield sse(err)
    finally:
        ACTIVE.pop(rec.id, None)
        v = verified if verified in ("verified", "mismatch") else ("skipped" if status == "done" else None)
        await rec.finish(status, answer, total, v)


@app.post("/api/research")
async def research_run(body: Research, request: Request):
    rate_limit(request)
    user = await get_user(request)
    owner = user["id"] if user else None
    rec = store.RunRecorder(owner, None, body.goal)
    await rec.start()
    ACTIVE[rec.id] = {"stop": False, "job": None}

    def check_stop():
        if ACTIVE.get(rec.id, {}).get("stop"):
            raise Stopped()

    async def agent():
        started = time.monotonic()
        yield {"type": "run", "run_id": rec.id, "question": body.goal, "mode": "research"}

        # 0. Pre-flight on the goal
        yield {"type": "step", "id": "guard-q", "status": "running", "title": "Pre-flight: checking your goal"}
        q_flags = guard.question_heuristics(body.goal)
        safety = await llm.safety_check(body.goal)
        q_safety = {k: safety[k] for k in ("status", "categories", "model", "latency_s")}
        yield {"type": "preflight", "stage": "question", "risky": bool(q_flags) or safety["status"] == "unsafe",
               "flags": q_flags, "safety": q_safety}

        # 1. Scope: which sites may the browser reach at all?
        yield {"type": "step", "id": "scope", "status": "running", "title": "Choosing which sites to visit"}
        domains = research.clean_domains(body.domains)
        source = "you" if domains else "agent"
        hint = f"\nThe user allows only these domains: {', '.join(domains)}" if domains else ""
        sc = await llm.chat([{"role": "system", "content": research.SCOPE_SYSTEM},
                             {"role": "user", "content": f"Goal: {body.goal}{hint}"}], max_tokens=1500)
        sj = research.parse_json(sc["text"]) or {}
        if not domains:
            domains = research.clean_domains(sj.get("domains"))
        if not domains:
            yield {"type": "answer", "markdown": "I could not tell which website this goal needs. "
                   "Name the site in the goal or in the Sites box.", "model": None, "grounded_in_job": None}
            yield {"type": "done", "total_s": round(time.monotonic() - started, 2), "status": "failed",
                   "run_id": rec.id, "saved": db.ENABLED}
            return
        start_url = str(sj.get("start_url") or "")
        if not research.on_allowlist(start_url, domains):
            start_url = f"https://{domains[0]}/"
        yield {"type": "scope", "domains": domains, "start_url": start_url, "source": source,
               "model": sc["model"], "latency_s": sc["latency_s"]}
        scope_state = "chosen by you"
        if source == "agent":
            holder: dict = {}
            async for item in _approval_flow(rec.id, {"kind": "scope", "attempt": 0, "findings": [
                    {"detail": f"Allow the browser to reach only: {', '.join(domains)}"}]}, holder):
                yield item
            check_stop()
            if holder["decision"] != "approve":
                yield {"type": "answer", "markdown": "Nothing was browsed: the proposed sites were not approved.",
                       "model": None, "grounded_in_job": None}
                yield {"type": "done", "total_s": round(time.monotonic() - started, 2), "status": "rejected",
                       "run_id": rec.id, "saved": db.ENABLED}
                return
            scope_state = "approved by you"

        # 2. Browse in turns
        yield {"type": "stage", "stage": "browse", "title": "Browsing in a sealed sandbox"}
        messages = [{"role": "system", "content": research.BROWSE_SYSTEM.format(
                        domains=", ".join(domains), max_actions=research.MAX_ACTIONS)},
                    {"role": "user", "content": f"Goal: {body.goal}\nStart at: {start_url}"}]
        seen_texts: list[str] = []
        last_shot, final, last_job, model = None, None, None, sc["model"]
        for turn in range(1, research.MAX_TURNS + 1):
            check_stop()
            yield {"type": "step", "id": f"plan{turn}", "status": "running", "title": f"Planning browser turn {turn}"}
            reply = await llm.chat(messages, max_tokens=6000)
            model = reply["model"]
            plan = research.parse_json(reply["text"])
            if not plan:
                messages += [{"role": "assistant", "content": reply["text"][:2000]},
                             {"role": "user", "content": "Reply with ONLY the JSON object described."}]
                yield {"type": "step", "id": f"plan{turn}", "status": "done", "title": "Reply was not valid JSON; asking again",
                       "model": model, "latency_s": reply["latency_s"]}
                continue
            if plan.get("done"):
                final = plan
                yield {"type": "step", "id": f"plan{turn}", "status": "done", "title": "Finished browsing",
                       "model": model, "latency_s": reply["latency_s"]}
                break
            chk = research.check_actions(plan.get("actions") or [], domains)
            yield {"type": "step", "id": f"plan{turn}", "status": "done", "title": f"Browser turn {turn}",
                   "content": plan.get("thought", ""), "model": model, "latency_s": reply["latency_s"]}
            yield {"type": "browse_plan", "turn": turn, "actions": chk["actions"], "refused": chk["refused"],
                   "risky": chk["risky"]}
            if chk["refused"] or not chk["actions"]:
                messages += [{"role": "assistant", "content": reply["text"][:3000]},
                             {"role": "user", "content": "These actions were refused before running: "
                              + "; ".join(chk["refused"] or ["no valid actions"]) + ". Fix them and reply again."}]
                continue
            approval_state = "not needed"
            if chk["risky"]:
                holder = {}
                async for item in _approval_flow(rec.id, {"kind": "browser", "attempt": turn, "actions": chk["actions"],
                                                          "findings": [{"detail": r} for r in chk["risky"]]}, holder):
                    yield item
                check_stop()
                approval_state = {"approve": "approved by you"}.get(holder["decision"], holder["decision"])
                if holder["decision"] != "approve":
                    messages += [{"role": "assistant", "content": reply["text"][:3000]},
                                 {"role": "user", "content": "The human REJECTED these actions: "
                                  + "; ".join(chk["risky"]) + ". Do not perform them. Finish with what you have, "
                                  "or continue read-only."}]
                    continue

            job = uuid.uuid4().hex[:12]
            ACTIVE[rec.id]["job"] = job
            yield {"type": "step", "id": f"browse{turn}", "status": "running", "title": "Browsing in the sandbox"}
            try:
                res = await browse_in_sandbox(chk["actions"], domains, job)
            finally:
                ACTIVE[rec.id]["job"] = None
            if res["status"] == "stopped":
                raise Stopped()
            last_job = res["job_id"]
            if res.get("infra_error"):
                yield {"type": "browse", "turn": turn, "receipt_id": None,
                       "result": {k: res[k] for k in ("job_id", "status", "exit_code", "duration_s", "events", "limits")},
                       "final_url": None, "title": None, "steps": [], "outputs": [],
                       "receipt": receipt(json.dumps(chk["actions"], indent=1), res, model)}
                yield {"type": "error", "message": res["infra_error"] + " Nothing was browsed; please try again later."}
                yield {"type": "done", "total_s": round(time.monotonic() - started, 2), "status": "failed",
                       "run_id": rec.id, "saved": db.ENABLED}
                return
            actions_text = json.dumps(chk["actions"], indent=1)
            pre = {"question": q_safety["status"], "data_flags": 0, "code_findings": 0, "approval": approval_state,
                   "sites": f"{', '.join(domains)} ({scope_state})"}
            rid, _ = await store.save_receipt(kind="browser", code=actions_text, result=res, model=model,
                                              run_id=rec.id, dataset=None, attempt=turn, preflight=pre)
            r = res.get("result") or {}
            for s in r.get("steps", []):
                seen_texts += s.get("texts") or []
            seen_texts.append(r.get("page_text") or "")
            if res["outputs"]:
                last_shot = res["outputs"][-1]
            yield {"type": "browse", "turn": turn, "receipt_id": rid if db.ENABLED else None,
                   "result": {k: res[k] for k in ("job_id", "status", "exit_code", "duration_s", "events", "limits")},
                   "final_url": r.get("final_url"), "title": r.get("title"),
                   "steps": [{**{k: s.get(k) for k in ("i", "type", "ok", "url", "status", "screenshot")},
                              "error": research.friendly_error(s.get("error")),
                              "texts": (s.get("texts") or [])[:15]} for s in r.get("steps", [])],
                   "outputs": public_outputs(res, rid if db.ENABLED else None),
                   "receipt": receipt(actions_text, res, model, pre)}
            messages += [{"role": "assistant", "content": reply["text"][:3000]},
                         {"role": "user", "content": "Observation:\n" + research.observation(r, res["events"])}]

        if not final:
            reply = await llm.chat(messages + [{"role": "user", "content":
                                   "Stop browsing. Finish now with done:true using only what you already extracted."}],
                                   max_tokens=6000)
            final = research.parse_json(reply["text"]) or {}
            final.setdefault("answer", "The agent could not finish within the step limit.")

        # 3. Verify: quotes must exist in what the browser returned; a vision model checks the screenshot
        yield {"type": "stage", "stage": "verify", "title": "Checking the evidence"}
        ev = research.evidence_check(final.get("evidence"), seen_texts)
        claims = (final.get("answer") or "") + "\nEvidence quotes: " + json.dumps(final.get("evidence") or [])[:1500]
        vis = await llm.vision_check(last_shot["content_b64"] if last_shot else "", claims)
        if (ev["total"] and ev["matched"] < ev["total"]) or vis["status"] == "inconsistent":
            vstatus = "mismatch"
        elif ev["total"] and ev["matched"] == ev["total"]:
            vstatus = "verified"
        else:
            vstatus = "inconclusive"
        yield {"type": "web_verify", "status": vstatus, "evidence": ev, "vision": vis,
               "screenshot": last_shot["name"] if last_shot else None}

        # 4. Hand structured data to the analyst
        records = [x for x in (final.get("records") or []) if isinstance(x, dict)]
        csv_bytes = research.records_to_csv(records)
        if csv_bytes:
            info = await _register(f"web_research_{rec.id[:8]}.csv", csv_bytes, owner)
            yield {"type": "records", "count": len(records), "preview": records[:8], "dataset": info}

        yield {"type": "answer", "markdown": final.get("answer") or "", "model": model,
               "grounded_in_job": last_job, "receipt_id": None, "verified": vstatus}
        yield {"type": "done", "total_s": round(time.monotonic() - started, 2), "status": "done",
               "run_id": rec.id, "saved": db.ENABLED, "verified": vstatus}

    return StreamingResponse(_recorded_stream(rec, agent()), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/runs/{run_id}/stop")
async def stop_run(run_id: str):
    """Stop button: halt the agent and kill its running sandbox container right away."""
    run = ACTIVE.get(run_id)
    if not run:
        raise HTTPException(404, "That run is not active")
    run["stop"] = True
    for a in APPROVALS.values():
        if a.get("run_id") == run_id and not a["event"].is_set():
            a["decision"] = "stopped"
            a["event"].set()
    killed = False
    if run.get("job"):
        try:
            r = await _runner.post(f"{RUNNER_URL}/kill/{run['job']}", headers={"X-Runner-Token": RUNNER_TOKEN}, timeout=10)
            killed = r.status_code == 200 and r.json().get("killed", False)
        except Exception:  # noqa: BLE001
            pass
    return {"stopping": True, "container_killed": killed}


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
    row = await db.one("containment_stats", {"select": "*"}) or {}
    try:
        r = await _runner.get(f"{RUNNER_URL}/alive", headers={"X-Runner-Token": RUNNER_TOKEN}, timeout=5)
        row["containers_alive"] = r.json().get("containers") if r.status_code == 200 else None
    except Exception:  # noqa: BLE001
        row["containers_alive"] = None
    return row


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
