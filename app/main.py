"""
Countersign - an AI analyst and web agent whose every answer is checked twice and comes with a receipt.

App server (VM 1): plans, writes code with Vultr Serverless Inference,
dispatches it to the sandbox runner on the executor VM over the Vultr VPC,
self-heals on errors, and explains only numbers that real execution printed.
"""

import asyncio
import csv
import io
import base64
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import archive
import db
import disposable
import guard
import missions
import llm
import prompts
import report
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

app = FastAPI(title="Countersign")
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


def _target(vm: dict | None) -> tuple[str, str]:
    """Runner URL and token: the run's fresh VM if it has one, otherwise the shared executor VM."""
    if vm and vm.get("url") and not vm.get("destroyed"):
        return vm["url"], vm["token"]
    return RUNNER_URL, RUNNER_TOKEN


def _mark_machine(res: dict, vm: dict | None) -> dict:
    if vm and vm.get("url") and not vm.get("destroyed"):
        res["executed_on"] = f"disposable-vm:{vm['id']}"
        res.setdefault("limits", {})["machine"] = f"fresh VM {vm['label']} (destroyed)"
        res.setdefault("events", []).insert(0, {"t": round(time.time(), 3), "kind": "created",
                                                "detail": f"Fresh Vultr VM {vm['label']} ({vm['id'][:8]}) created for this run only"})
    return res


async def run_in_sandbox(code: str, files: list[dict], job_id: str | None = None, vm: dict | None = None) -> dict:
    payload = {"code": code, "files": files, "timeout_s": RUN_TIMEOUT_S, "memory_mb": RUN_MEMORY_MB}
    if job_id:
        payload["job_id"] = job_id
    url, token = _target(vm)
    r = await _runner.post(f"{url}/run", headers={"X-Runner-Token": token}, json=payload)
    if r.status_code != 200:
        raise RuntimeError(f"Runner error {r.status_code}: {r.text[:200]}")
    return _mark_machine(r.json(), vm)


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
    """The run's input files: the dataset, plus any extra files of a multi-file analysis."""
    out = []
    for d in [ds] + list(ds.get("extra") or []):
        out.append({"name": d["filename"], "content_b64": base64.b64encode(d["path"].read_bytes()).decode()})
    return out


def combine_datasets(primary: dict, extras: list[dict]) -> dict:
    """One analysis over several files: same id and hash as the primary file, every file in the sandbox."""
    if not extras:
        return primary
    names = [primary["filename"]] + [e["filename"] for e in extras]
    if len(set(names)) != len(names):
        raise HTTPException(400, "Two files have the same name; rename one and upload it again.")
    work = dict(primary)
    work["extra"] = extras
    work["profile"] = {"files": {d["filename"]: d["profile"] for d in [primary] + extras},
                       "note": "Several files are in the working directory. Load each one by its file name."}
    work["suspicious"] = list(primary.get("suspicious", [])) + [c for e in extras for c in e.get("suspicious", [])]
    work["display_name"] = " + ".join(names)
    work["files_label"] = ", ".join(names)
    return work


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
        path = SAMPLES / "missions" / Path(sample_id).name
    if not path.is_file():
        raise HTTPException(404, "Unknown sample")
    user = await get_user(request)
    return await _register(path.name, path.read_bytes(), user["id"] if user else None)


class Ask(BaseModel):
    dataset_id: str
    question: str = Field(..., min_length=3, max_length=3000)
    extra_dataset_ids: list[str] = Field(default_factory=list, max_length=3)
    isolation: str = Field("container", pattern="^(container|vm)$")


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


# ---------- fresh-VM isolation tier ----------

async def _teardown(vm: dict):
    yield {"type": "step", "id": "vm-end", "status": "running", "title": "Destroying the fresh VM"}
    res = await disposable.destroy(vm["id"])
    vm["destroyed"] = True
    yield {"type": "step", "id": "vm-end", "status": "done" if res["requested"] else "failed",
           "title": "Fresh VM destroyed" if res["requested"] else "Could not delete the VM; the watchdog will remove it"}
    yield {"type": "vm", "status": "destroyed", "instance_id": vm["id"], "label": vm["label"],
           "lifetime_s": round(time.time() - vm["created"], 1), "requested": res["requested"],
           "confirmed": res["confirmed"], "max_age_min": disposable.MAX_AGE_MIN}


async def _provision(run_id: str):
    """Give this run a fresh Vultr VM from the warm pool: booted from the executor snapshot ahead
    of time, never used, destroyed after this run. Falls back to the shared sandbox (and says so)."""
    run = ACTIVE[run_id]
    why = disposable.can_use()
    if why:
        yield {"type": "vm", "status": "unavailable", "message": f"{why}. This run uses the shared sandbox."}
        return
    yield {"type": "step", "id": "vm", "status": "running", "title": "Taking a fresh Vultr VM for this run"}
    vm, reason = await disposable.claim(run_id)
    if not vm:
        yield {"type": "step", "id": "vm", "status": "failed", "title": "No fresh VM ready yet"}
        yield {"type": "vm", "status": "unavailable",
               "message": f"No fresh VM is ready yet: {reason}. Restoring the executor snapshot on Vultr "
                          "takes 10 to 60 minutes and happens in the background. This run uses the shared sandbox."}
        return
    vm["owner"] = run_id
    run["vm"] = vm
    yield {"type": "step", "id": "vm", "status": "done", "title": f"Fresh VM {vm['label']} assigned to this run only"}
    yield {"type": "vm", "status": "ready", "instance_id": vm["id"], "label": vm["label"], "ip": vm["ip"],
           "booted_min": vm["booted_min"], "region": vm["region"], "plan": vm["plan"]}
    if run.get("stop"):
        raise Stopped()


async def _with_teardown(run_id: str, agen):
    """Destroy the run's fresh VM before the final event, on Stop, and on any error."""
    run = ACTIVE.get(run_id, {})

    def live():
        vm = run.get("vm")
        return vm if vm and not vm.get("destroyed") and vm.get("owner") == run_id else None

    try:
        async for item in agen:
            if isinstance(item, dict) and item.get("type") == "done" and live():
                async for x in _teardown(live()):
                    yield x
            yield item
    except Stopped:
        if live():
            async for x in _teardown(live()):
                yield x
        raise
    finally:
        if live():
            await disposable.destroy(live()["id"])
            run["vm"]["destroyed"] = True


@app.on_event("startup")
async def _start_watchdog():
    if disposable.ENABLED:
        asyncio.create_task(disposable.watchdog())   # also boots the first standby VM


@app.post("/api/ask")
async def ask(body: Ask, request: Request):
    rate_limit(request)
    user = await get_user(request)
    if body.isolation == "vm" and not user:
        raise HTTPException(401, "Sign in to run on a fresh VM (each one is a real, billed Vultr server).")
    ds = await get_dataset(body.dataset_id)
    if not ds:
        raise HTTPException(404, "Dataset not found. Upload it again.")
    extras = []
    for xid in body.extra_dataset_ids:
        x = await get_dataset(xid)
        if not x:
            raise HTTPException(404, "One of the extra files was not found. Upload it again.")
        extras.append(x)
    ds = combine_datasets(ds, extras)
    rec = store.RunRecorder(user["id"] if user else None, ds, body.question)
    await rec.start()

    ACTIVE[rec.id] = {"stop": False, "job": None, "vm": None}

    def check_stop():
        if ACTIVE.get(rec.id, {}).get("stop"):
            raise Stopped()

    async def sandbox(code: str) -> dict:
        check_stop()
        job = uuid.uuid4().hex[:12]
        ACTIVE[rec.id]["job"] = job
        try:
            res = await run_in_sandbox(code, dataset_files(ds), job_id=job, vm=ACTIVE[rec.id]["vm"])
        finally:
            ACTIVE[rec.id]["job"] = None
        if res["status"] == "stopped":
            raise Stopped()
        return res

    async def agent():
        """Yields event dicts (recorded + streamed) or raw keep-alive strings (streamed only)."""
        started = time.monotonic()
        data_flags = ds.get("suspicious", [])
        yield {"type": "run", "run_id": rec.id, "question": body.question, "dataset": ds.get("display_name", ds["filename"])}

        # 0. Pre-flight: question and data, before any model writes code
        yield {"type": "step", "id": "guard-q", "status": "running", "title": "Pre-flight: checking your question"}
        q_flags = guard.question_heuristics(body.question)
        safety = await llm.safety_check(body.question)
        q_safety = {k: safety[k] for k in ("status", "categories", "model", "latency_s")}
        q_risky = bool(q_flags) or safety["status"] == "unsafe"
        yield {"type": "preflight", "stage": "question", "risky": q_risky, "flags": q_flags, "safety": q_safety}
        if body.isolation == "vm":
            async for item in _provision(rec.id):
                yield item
        if data_flags:
            yield {"type": "preflight", "stage": "data", "risky": True, "cells": data_flags[:5]}

        # 1. Plan
        yield {"type": "step", "id": "plan", "status": "running", "title": "Planning"}
        plan = await llm.chat(prompts.plan_messages(body.question, ds.get("files_label", ds["filename"]), ds["profile"]), max_tokens=6000)
        yield {"type": "step", "id": "plan", "status": "done", "title": "Plan",
               "content": plan["text"], "model": plan["model"], "latency_s": plan["latency_s"]}
        check_stop()

        # 2. Explore: a short sandboxed look at the data before the real analysis
        yield {"type": "stage", "stage": "explore", "title": "Stage 1 of 3: explore the data"}
        findings_text = ""
        exp = await llm.chat(prompts.explore_messages(body.question, ds.get("files_label", ds["filename"]), ds["profile"],
                                                      RUN_TIMEOUT_S, RUN_MEMORY_MB), max_tokens=8000)
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
        messages = prompts.code_messages(body.question, ds.get("files_label", ds["filename"]), ds["profile"], plan["text"],
                                         RUN_TIMEOUT_S, RUN_MEMORY_MB)
        messages[0]["content"] += guard.summarise_data_flags(data_flags)
        if findings_text:
            messages[1]["content"] += ("\n\nExploration findings (printed by a sandboxed exploration run; "
                                       "use the exact values shown):\n" + findings_text)
        result, code, model, last_decision, final_receipt = None, "", None, None, None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            yield {"type": "step", "id": f"code{attempt}", "status": "running",
                   "title": "Writing code" if attempt == 1 else f"Fixing code (attempt {attempt})"}
            reply = await llm.chat(messages, max_tokens=16000, code=True)
            code, model = llm.extract_code(reply["text"]), reply["model"]
            for _ in range(2):                            # a sketch with "..." gaps never reaches the sandbox
                if not llm.has_placeholders(code):
                    break
                yield {"type": "step", "id": f"code{attempt}", "status": "running",
                       "title": "The draft had '...' gaps; asking for the complete script"}
                reply = await llm.chat(messages + [
                    {"role": "assistant", "content": f"```python\n{code}\n```"},
                    {"role": "user", "content": "That script has '...' placeholders, so it cannot run. Write the "
                     "complete script with every line filled in, and keep it under 120 lines."}], max_tokens=16000, code=True)
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
            try:
                ext = await llm.chat(prompts.extract_messages(body.question, result["stdout"]), max_tokens=4000)
                yield {"type": "step", "id": "verify", "status": "running",
                       "title": f"Picked the numbers to verify ({ext['model']}, {ext['latency_s']} s)"}
                quantities = verify.parse_quantities(ext["text"], result["stdout"])
                verification = {"status": "inconclusive", "checks": [], "reason": "No checkable numbers in the output"}
                if quantities:
                    yield {"type": "step", "id": "verify", "status": "running",
                           "title": f"A second auditor is recomputing {len(quantities)} number{'s' if len(quantities) > 1 else ''} from scratch"}
                    vmsgs = prompts.verify_messages(body.question, ds.get("files_label", ds["filename"]), ds["profile"], quantities,
                                                    RUN_TIMEOUT_S, RUN_MEMORY_MB)
                    for vtry in (1, 2):
                        vrep = await llm.chat(vmsgs, max_tokens=12000, code=True)
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
            except llm.LLMError as e:
                # The analysis already ran and is kept; only the second key is missing.
                print("[verify]", str(e)[:300], flush=True)
                verification = {"status": "inconclusive", "checks": [],
                                "reason": "The auditor model could not write its check this time, so the numbers are unverified"}
            yield {"type": "verify", **verification}

        # 5. Explain only what execution proved (and what verification confirmed)
        if result and result["status"] == "ok":
            yield {"type": "step", "id": "explain", "status": "running", "title": "Writing answer"}
            try:
                ans = await llm.chat(prompts.explain_messages_verified(body.question, code, result["stdout"],
                                                                       result["outputs"], verification), max_tokens=6000)
            except llm.LLMError as e:
                print("[explain]", str(e)[:300], flush=True)
                ans = {"model": None, "text": "The model could not write a summary this time, so here is the sandbox's "
                       "printed output exactly as it ran:\n\n```\n" + result["stdout"][-6000:] + "\n```"}
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
                   "grounded_in_job": None}
            status = "failed"
        yield {"type": "done", "total_s": round(time.monotonic() - started, 2), "status": status,
               "run_id": rec.id, "saved": db.ENABLED,
               "verified": verification["status"] if verification else None}

    async def stream():
        answer, status, total, verified = None, "failed", None, None
        t0 = time.monotonic()
        try:
            async for item in _with_teardown(rec.id, agent()):
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
    isolation: str = Field("container", pattern="^(container|vm)$")


async def browse_in_sandbox(actions: list, domains: list[str], job_id: str, vm: dict | None = None) -> dict:
    url, token = _target(vm)
    r = await _runner.post(f"{url}/browse", headers={"X-Runner-Token": token},
                           json={"actions": actions, "allow_domains": domains,
                                 "timeout_s": BROWSE_TIMEOUT_S, "job_id": job_id},
                           timeout=BROWSE_TIMEOUT_S + 60)
    if r.status_code != 200:
        raise RuntimeError(f"Browser sandbox error {r.status_code}: {r.text[:200]}")
    return _mark_machine(r.json(), vm)


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
    if body.isolation == "vm" and not user:
        raise HTTPException(401, "Sign in to run on a fresh VM (each one is a real, billed Vultr server).")
    owner = user["id"] if user else None
    rec = store.RunRecorder(owner, None, body.goal)
    await rec.start()
    ACTIVE[rec.id] = {"stop": False, "job": None, "vm": None}

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
        if body.isolation == "vm":
            async for item in _provision(rec.id):
                yield item

        # 1. Scope: which sites may the browser reach at all?
        yield {"type": "step", "id": "scope", "status": "running", "title": "Choosing which sites to visit"}
        domains = research.clean_domains(body.domains)
        source = "you" if domains else "agent"
        hint = f"\nThe user allows only these domains: {', '.join(domains)}" if domains else ""
        sc = await llm.chat([{"role": "system", "content": research.SCOPE_SYSTEM},
                             {"role": "user", "content": f"Goal: {body.goal}{hint}"}], max_tokens=3000)
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
            reply = await llm.chat(messages, max_tokens=8000)
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
                res = await browse_in_sandbox(chk["actions"], domains, job, vm=ACTIVE[rec.id]["vm"])
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
                                   max_tokens=8000)
            final = research.parse_json(reply["text"]) or {}
            final.setdefault("answer", "The agent could not finish within the step limit.")

        # 3. Verify: quotes must exist in what the browser returned; a vision model checks the screenshot
        yield {"type": "stage", "stage": "verify", "title": "Checking the evidence"}
        ev = research.evidence_check(final.get("evidence"), seen_texts)
        claims = (final.get("answer") or "") + "\nEvidence quotes: " + json.dumps(final.get("evidence") or [])[:1500]
        vis = await llm.vision_check(last_shot["content_b64"] if last_shot else "", claims)
        # Quotes decide: each must appear word for word in a page the browser loaded. The vision model
        # sees only the final screenshot, so it can confirm a claim but not overrule the evidence.
        if ev["total"] and ev["matched"] < ev["total"]:
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

    return StreamingResponse(_recorded_stream(rec, _with_teardown(rec.id, agent())), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------- Missions: a lead agent runs a team of specialists ----------

class MissionReq(BaseModel):
    mission: str = Field(..., pattern="^[a-z_]{3,30}$")
    goal: str | None = Field(None, max_length=1500)
    dataset_ids: list[str] = Field(default_factory=list, max_length=3)
    domains: list[str] = Field(default_factory=list, max_length=5)
    isolation: str = Field("container", pattern="^(container|vm)$")


@app.get("/api/missions")
async def mission_list():
    return missions.public_templates()


async def _forward(mission_id: str, step: int, agent: str, resp, sink: dict):
    """Relay a specialist's live stream into the mission stream, and note what it produced."""
    buf = ""
    async for chunk in resp.body_iterator:
        if isinstance(chunk, bytes):
            chunk = chunk.decode()
        if chunk.startswith(":"):
            yield chunk
            continue
        buf += chunk
        while "\n\n" in buf:
            part, buf = buf.split("\n\n", 1)
            if not part.startswith("data: "):
                continue
            ev = json.loads(part[6:])
            t = ev.get("type")
            if t == "run":
                sink["run_id"] = ev["run_id"]
                ACTIVE[mission_id]["child"] = ev["run_id"]
                vm = ACTIVE[mission_id].get("vm")
                if vm and ev["run_id"] in ACTIVE:          # specialists share the mission's fresh VM
                    ACTIVE[ev["run_id"]]["vm"] = vm
            elif t == "answer":
                sink["answer"] = ev.get("markdown") or ""
            elif t == "verify":
                sink["verified"] = ev.get("status")
            elif t == "web_verify":
                sink["verified"] = ev.get("status")
            elif t == "records" and ev.get("dataset"):
                sink["dataset"] = ev["dataset"]
            elif t == "done":
                sink["status"] = ev.get("status") or "failed"
                sink["verified"] = ev.get("verified") or sink.get("verified")
            elif t == "error":
                sink["error"] = ev.get("message")
            yield {"type": "agent_event", "step": step, "agent": agent, "event": ev}
    ACTIVE[mission_id]["child"] = None


@app.post("/api/missions/run")
async def mission_run(body: MissionReq, request: Request):
    rate_limit(request)
    custom = body.mission == "custom"
    if custom:
        if not body.goal or len(body.goal.strip()) < 10:
            raise HTTPException(400, "Describe the goal of the mission in a sentence or two.")
        t = missions.custom_template(len(body.dataset_ids), research.clean_domains(body.domains))
    else:
        t = missions.TEMPLATES.get(body.mission)
    if not t:
        raise HTTPException(404, "Unknown mission")
    user = await get_user(request)
    if body.isolation == "vm" and not user:
        raise HTTPException(401, "Sign in to run on a fresh VM (each one is a real, billed Vultr server).")
    if not custom and len(body.dataset_ids) != len(t["files"]):
        raise HTTPException(400, f"This mission needs {len(t['files'])} file(s): " + ", ".join(f["label"] for f in t["files"]))
    files = []
    for fid in body.dataset_ids:
        d = await get_dataset(fid)
        if not d:
            raise HTTPException(404, "A mission file was not found. Load it again.")
        files.append(d)
    domains = research.clean_domains(body.domains or t["sites"])
    if custom and not files and not domains:
        raise HTTPException(400, "Attach at least one file or allow at least one website for the team to work with.")
    if not custom and any(a == "researcher" for a, _ in t["steps"]) and not domains:
        raise HTTPException(400, "Name the website(s) the researcher may visit.")
    goal = (body.goal or t["goal"]).strip()
    owner = user["id"] if user else None
    rec = store.RunRecorder(owner, files[0] if files else None, f"Mission: {t['title']}. {goal}")
    await rec.start()
    ACTIVE[rec.id] = {"stop": False, "job": None, "vm": None, "child": None}

    def check_stop():
        if ACTIVE.get(rec.id, {}).get("stop"):
            raise Stopped()

    async def agent():
        started = time.monotonic()
        yield {"type": "run", "run_id": rec.id, "question": goal, "mode": "mission", "mission": body.mission,
               "title": t["title"]}
        yield {"type": "step", "id": "guard-q", "status": "running", "title": "Pre-flight: checking the mission goal"}
        q_flags = guard.question_heuristics(goal)
        safety = await llm.safety_check(goal)
        q_safety = {k: safety[k] for k in ("status", "categories", "model", "latency_s")}
        yield {"type": "preflight", "stage": "question", "risky": bool(q_flags) or safety["status"] == "unsafe",
               "flags": q_flags, "safety": q_safety}
        if body.isolation == "vm":
            async for item in _provision(rec.id):
                yield item

        # 1. the lead agent plans
        inputs = {f["role"]: d["filename"] for f, d in zip(t["files"], files)}
        inputs.update({"sites": ", ".join(domains), "web": "the file the researcher produces"})
        yield {"type": "step", "id": "lead", "status": "running", "title": "Lead agent is planning the mission"}
        if custom:
            msgs = missions.custom_lead_messages(goal, inputs)
            lead = await llm.chat(msgs, max_tokens=8000)
            reply = research.parse_json(lead["text"]) or {}
            plan, why = missions.accept_custom_plan(reply, bool(files), bool(domains))
            if not plan:                                   # one chance to fix it, with the reason
                yield {"type": "step", "id": "lead", "status": "running",
                       "title": f"Lead agent's plan was rejected ({why}); asking it to fix the plan"}
                lead = await llm.chat(msgs + [{"role": "assistant", "content": lead["text"][:3000]},
                                              {"role": "user", "content": f"That plan breaks a rule: {why}. Return a corrected plan."}],
                                      max_tokens=8000)
                reply = research.parse_json(lead["text"]) or {}
                plan, why = missions.accept_custom_plan(reply, bool(files), bool(domains))
            from_model = plan is not None
            brief = str(reply.get("brief") or "")[:300]
            if not plan:
                plan = ([{"agent": "researcher", "task": f"Collect the facts needed for this goal from {inputs['sites']}: {goal}"}]
                        if domains else []) + \
                       [{"agent": "analyst", "task": f"Using the available files, compute and print the numbers that answer: {goal}"},
                        {"agent": "reporter", "task": "Write the brief for the goal."}]
                brief = brief or "The team will collect what it needs, compute the answer and brief you."
        else:
            lead = await llm.chat(missions.lead_messages(body.mission, goal, inputs), max_tokens=8000)
            plan, brief, from_model = missions.accept_plan(body.mission, research.parse_json(lead["text"]), inputs)
        yield {"type": "step", "id": "lead", "status": "done", "title": f"Lead agent planned {len(plan)} steps",
               "model": lead["model"], "latency_s": lead["latency_s"]}
        yield {"type": "mission_plan", "title": t["title"], "for": t["for"], "brief": brief, "from_model": from_model,
               "steps": [{"step": i, "agent": st["agent"], "task": st["task"]} for i, st in enumerate(plan, 1)]}

        # 2. specialists, one sealed run each
        reports, web_ds = [], None
        for i, st in enumerate(plan, 1):
            if st["agent"] == "reporter":
                continue
            check_stop()
            task = st["task"]
            sink = {"status": "failed", "answer": "", "verified": None}
            if st["agent"] == "analyst" and web_ds:
                task += f"\nThe researcher's records are in the file {web_ds['filename']}."
            yield {"type": "agent_start", "step": i, "agent": st["agent"], "task": task}
            try:
                if st["agent"] == "researcher":
                    resp = await research_run(Research(goal=task[:1500], domains=domains), request)
                else:
                    ids = [d["id"] for d in files] + ([web_ds["dataset_id"]] if web_ds else [])
                    if not ids:
                        raise HTTPException(400, "There is no file for the analyst to work on.")
                    resp = await ask(Ask(dataset_id=ids[0], question=task[:3000], extra_dataset_ids=ids[1:]), request)
                async for item in _forward(rec.id, i, st["agent"], resp, sink):
                    yield item
            except HTTPException as e:
                sink["error"] = str(e.detail)
            check_stop()
            if sink["status"] == "stopped":
                raise Stopped()
            if st["agent"] == "researcher":
                web_ds = sink.get("dataset")
            reports.append({"step": i, "agent": st["agent"], "task": task, "status": sink["status"],
                            "answer": sink.get("answer") or sink.get("error") or "", "verified": sink.get("verified")})
            yield {"type": "agent_done", "step": i, "agent": st["agent"], "status": sink["status"],
                   "verified": sink.get("verified"), "child_run": sink.get("run_id"), "error": sink.get("error")}
            if st["agent"] == "researcher" and not web_ds:
                reports.append({"step": i, "agent": "lead", "task": "check hand-off", "status": "failed",
                                "answer": "The researcher returned no records, so the analysis could not compare prices.",
                                "verified": None})
                break

        # 3. the reporter writes the brief from what the specialists actually reported
        check_stop()
        rstep = len(plan)
        yield {"type": "agent_start", "step": rstep, "agent": "reporter", "task": plan[-1]["task"]}
        rep = await llm.chat(missions.reporter_messages(body.mission, goal, reports), max_tokens=8000)
        statuses = [r["verified"] for r in reports if r.get("verified")]
        overall = ("mismatch" if "mismatch" in statuses else "verified" if "verified" in statuses
                   else "inconclusive" if statuses else None)
        yield {"type": "agent_done", "step": rstep, "agent": "reporter", "status": "done", "verified": None,
               "model": rep["model"], "latency_s": rep["latency_s"]}
        ok = all(r["status"] == "done" for r in reports)
        yield {"type": "answer", "markdown": rep["text"], "model": rep["model"], "grounded_in_job": None,
               "receipt_id": None, "verified": overall, "mission": True,
               "specialists": [{k: r[k] for k in ("step", "agent", "status", "verified")} for r in reports]}
        yield {"type": "done", "total_s": round(time.monotonic() - started, 2), "status": "done" if ok else "failed",
               "run_id": rec.id, "saved": db.ENABLED, "verified": overall}

    return StreamingResponse(_recorded_stream(rec, _with_teardown(rec.id, agent())), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/runs/{run_id}/stop")
async def stop_run(run_id: str):
    """Stop button: halt the agent and kill its running sandbox container right away."""
    run = ACTIVE.get(run_id)
    if not run:
        raise HTTPException(404, "That run is not active")
    run["stop"] = True
    if run.get("child") and run["child"] in ACTIVE:          # a mission stops the agent that is working
        await stop_run(run["child"])
    for a in APPROVALS.values():
        if a.get("run_id") == run_id and not a["event"].is_set():
            a["decision"] = "stopped"
            a["event"].set()
    killed = False
    if run.get("job"):
        try:
            url, token = _target(run.get("vm"))
            r = await _runner.post(f"{url}/kill/{run['job']}", headers={"X-Runner-Token": token}, timeout=10)
            killed = r.status_code == 200 and r.json().get("killed", False)
        except Exception:  # noqa: BLE001
            pass
    return {"stopping": True, "container_killed": killed}


# ---------- accounts, history, sharing, files, stats ----------

@app.get("/api/config")
async def config():
    return {"auth": db.ENABLED and bool(db.ANON_KEY), "supabase_url": db.URL, "supabase_anon_key": db.ANON_KEY,
            "archive": archive.ENABLED,
            "fresh_vm": disposable.ENABLED, "fresh_vm_max_age_min": disposable.MAX_AGE_MIN,
            "fresh_vm_pool": {k: disposable.STATUS[k] for k in ("ready", "booting", "claimed")}}


@app.get("/api/vm-pool")
async def vm_pool():
    """Warm-pool status for the UI and for debugging the fresh-VM tier."""
    return {"enabled": disposable.ENABLED, "pool_size": disposable.POOL_SIZE, **disposable.STATUS}


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


async def _audit(user: dict) -> dict:
    """Every run on the account with its sealed jobs, blocked actions, human decisions and machines."""
    runs = await db.select("runs", {"owner": f"eq.{user['id']}", "order": "created_at.desc", "limit": "150",
                                    "select": "id,question,status,verified,created_at,total_s"})
    ids = [r["id"] for r in runs]
    receipts, approvals, links = [], [], []
    for i in range(0, len(ids), 50):                     # keep URLs short
        chunk = "in.(" + ",".join(ids[i:i + 50]) + ")"
        receipts += await db.select("receipts", {"run_id": chunk, "limit": "5000",
                                                 "select": "run_id,kind,status,executed_on,events,job_id,created_at"})
        approvals += await db.select("run_events", {"run_id": chunk, "type": "eq.approval_result", "limit": "2000",
                                                    "select": "run_id,payload,created_at"})
        links += await db.select("run_events", {"run_id": chunk, "type": "eq.agent_done", "limit": "2000",
                                                "select": "run_id,payload"})
    parent = {l["payload"].get("child_run"): l["run_id"] for l in links if l["payload"].get("child_run")}
    by_run: dict[str, dict] = {r["id"]: {"jobs": 0, "blocked": 0, "approvals": {}, "machines": set(), "kinds": set()} for r in runs}
    events = []
    for rc in receipts:
        a = by_run.get(rc["run_id"])
        if not a:
            continue
        if rc["kind"] not in ("profile", "report"):
            a["jobs"] += 1
        a["kinds"].add(rc["kind"])
        a["machines"].add("fresh VM" if (rc.get("executed_on") or "").startswith("disposable-vm") else "shared executor")
        for ev in rc.get("events") or []:
            if ev.get("kind") in ("blocked", "killed"):
                a["blocked"] += 1
                events.append({"time": ev.get("t"), "run_id": rc["run_id"], "kind": ev["kind"], "detail": ev.get("detail", "")[:200]})
    for ap in approvals:
        a = by_run.get(ap["run_id"])
        d = ap["payload"].get("decision", "timeout")
        if a:
            a["approvals"][d] = a["approvals"].get(d, 0) + 1
        events.append({"time": ap.get("created_at"), "run_id": ap["run_id"], "kind": f"approval {d}",
                       "detail": f"A human decision was needed ({ap['payload'].get('findings', 0)} finding(s)); decision: {d}"})
    rows = []
    for r in runs:
        a = by_run[r["id"]]
        kind = ("mission" if r["question"].startswith("Mission:") else "web research" if "browser" in a["kinds"]
                else "analysis")
        rows.append({"run_id": r["id"], "created_at": r["created_at"], "kind": kind, "question": r["question"][:200],
                     "status": r["status"], "verified": r.get("verified") or "", "sandbox_jobs": a["jobs"],
                     "blocked_actions": a["blocked"], "approvals": a["approvals"], "machines": sorted(a["machines"]),
                     "part_of_mission": parent.get(r["id"]), "total_s": r.get("total_s")})
    fresh = {rc["executed_on"] for rc in receipts if (rc.get("executed_on") or "").startswith("disposable-vm")}
    appr = {}
    for row in rows:
        for k, v in row["approvals"].items():
            appr[k] = appr.get(k, 0) + v
    summary = {"runs": len(rows), "missions": sum(r["kind"] == "mission" for r in rows),
               "sandbox_jobs": sum(r["sandbox_jobs"] for r in rows), "blocked_actions": sum(r["blocked_actions"] for r in rows),
               "approvals": appr, "fresh_vms": len(fresh), "verified": sum(r["verified"] == "verified" for r in rows),
               "mismatch": sum(r["verified"] == "mismatch" for r in rows)}
    events.sort(key=lambda e: str(e.get("time") or ""), reverse=True)
    return {"summary": summary, "runs": rows, "events": events[:60]}


@app.get("/api/audit")
async def audit(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Sign in to see your audit trail")
    return await _audit(user)


@app.get("/api/audit.csv")
async def audit_csv(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Sign in to export your audit trail")
    data = await _audit(user)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["run_id", "created_at", "kind", "question", "status", "verified", "sandbox_jobs", "blocked_actions",
                "approvals_approved", "approvals_rejected", "approvals_timeout", "machines", "part_of_mission", "total_s"])
    for r in data["runs"]:
        ap = r["approvals"]
        w.writerow([r["run_id"], r["created_at"], r["kind"], r["question"], r["status"], r["verified"], r["sandbox_jobs"],
                    r["blocked_actions"], ap.get("approve", 0), ap.get("reject", 0), ap.get("timeout", 0),
                    "; ".join(r["machines"]), r["part_of_mission"] or "", r["total_s"]])
    data_bytes = buf.getvalue().encode()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = await archive.archive_export(f"audit-exports/{user['id']}/{stamp}.csv", data_bytes, "text/csv")
    headers = {"Content-Disposition": 'attachment; filename="countersign-audit-trail.csv"'}
    if key:
        headers["X-Archived-Key"] = key
    return Response(content=data_bytes, media_type="text/csv", headers=headers)


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


@app.post("/api/runs/{run_id}/report")
async def make_report(run_id: str, request: Request):
    """F10: build a PDF of a run inside the sandbox with a fixed script; the PDF gets its own receipt."""
    rate_limit(request)
    run = await db.one("runs", {"id": f"eq.{run_id}", "select": "*"})
    if not run:
        raise HTTPException(404, "Run not found")
    user = await get_user(request)
    if not run["is_public"] and run.get("owner") and (not user or user["id"] != run["owner"]):
        raise HTTPException(403, "This run is private")
    payload, images = report.build(await _run_bundle(run))
    files, kept = [], []
    for img in images:
        data = await db.download("outputs", f"{img['receipt_id']}/{img['name']}")
        if data:
            files.append({"name": img["file"], "content_b64": base64.b64encode(data).decode()})
            kept.append(img["file"])
    payload["images"] = [i for i in payload["images"] if i["file"] in kept]
    files.insert(0, {"name": "report.json", "content_b64": base64.b64encode(report.payload_bytes(payload)).decode()})
    res = await run_in_sandbox(report.REPORT_CODE, files)
    pdf = next((o for o in res["outputs"] if o["name"] == "report.pdf"), None)
    if res["status"] != "ok" or not pdf:
        tail = "\n".join((res.get("stderr") or "").strip().splitlines()[-3:])
        raise HTTPException(500, f"The report builder failed in the sandbox: {tail[:300]}")
    pre = {"question": "n/a", "data_flags": 0, "code_findings": 0, "approval": "not needed (fixed script)"}
    rid, _ = await store.save_receipt(kind="report", code=report.REPORT_CODE, result=res, model=None,
                                      run_id=run_id, dataset=None, preflight=pre)
    saved = bool(await db.one("receipts", {"id": f"eq.{rid}", "select": "id"}))
    return {"filename": f"countersign-report-{run_id[:8]}.pdf",
            "data_url": f"data:application/pdf;base64,{pdf['content_b64']}",
            "url": f"/api/files/{rid}/report.pdf" if saved else None,
            "receipt": receipt(report.REPORT_CODE, res, None, pre),
            "result": {k: res[k] for k in ("job_id", "status", "exit_code", "duration_s", "events", "limits")}}


@app.delete("/api/runs/{run_id}")
async def delete_run(run_id: str, request: Request):
    """Owner removes a run from history (its events and receipts go with it)."""
    run = await db.one("runs", {"id": f"eq.{run_id}", "select": "id,owner"})
    if not run:
        raise HTTPException(404, "Run not found")
    user = await get_user(request)
    if not user or run.get("owner") != user["id"]:
        raise HTTPException(403, "Only the owner can delete this run")
    if run_id in ACTIVE:
        raise HTTPException(409, "Stop the run before deleting it")
    return {"deleted": await db.delete("runs", run_id)}


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
    vms = await db.select("receipts", {"executed_on": "like.disposable-vm*", "select": "executed_on", "limit": "5000"})
    row["fresh_vms"] = len({r["executed_on"] for r in vms}) if db.ENABLED else None
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
    if (rc.get("limits") or {}).get("image"):          # which exact sandbox image ran
        checks.append({"item": "sandbox image", "original": rc["limits"]["image"],
                       "replay": (result.get("limits") or {}).get("image")})
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


@app.get("/api/receipts/{receipt_id}/archive")
async def receipt_archive(receipt_id: str):
    """Tamper check: compare the database receipt with its copy on Vultr Object Storage."""
    if not archive.ENABLED:
        raise HTTPException(404, "The Object Storage archive is not configured on this server")
    row = await db.one("receipts", {"id": f"eq.{receipt_id}",
                                    "select": "id,code_sha256,stdout_sha256,exit_code,executed_on,outputs"})
    if not row:
        raise HTTPException(404, "Receipt not found")
    return await archive.check(receipt_id, row)


@app.get("/api/platform")
async def platform():
    """Platform safeguards, read live: backups, firewalls, fresh-VM pool, pinned images, archive."""
    out: dict = {"archive": archive.status(), "pool": {"enabled": disposable.ENABLED, **disposable.STATUS}}
    try:
        r = await _runner.get(f"{RUNNER_URL}/health", timeout=5)
        out["images"] = r.json().get("images") if r.status_code == 200 else None
    except Exception:  # noqa: BLE001
        out["images"] = None
    out["vms"] = []
    if disposable.ENABLED:
        try:
            for label in (os.environ.get("APP_VM_LABEL", "agentrush-app"), disposable.TEMPLATE_LABEL):
                rv = await disposable._req("GET", "/instances", params={"label": label, "per_page": 10})
                inst = next((i for i in (rv.json().get("instances", []) if rv.status_code == 200 else [])
                             if i.get("label") == label), None)
                if not inst:
                    out["vms"].append({"label": label, "found": False})
                    continue
                vm = {"label": label, "found": True, "region": inst.get("region"), "plan": inst.get("plan"),
                      "firewall": bool(inst.get("firewall_group_id")), "backups": None, "next_backup": None}
                rb = await disposable._req("GET", f"/instances/{inst['id']}/backup-schedule")
                if rb.status_code == 200:
                    bs = rb.json().get("backup_schedule", {})
                    vm["backups"] = bool(bs.get("enabled"))
                    vm["backup_type"] = bs.get("type")
                    vm["next_backup"] = bs.get("next_scheduled_time_utc")
                out["vms"].append(vm)
        except Exception as e:  # noqa: BLE001
            out["vms_error"] = type(e).__name__
    return out


# ---------- static UI ----------

app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")


NO_CACHE = {"Cache-Control": "no-cache"}      # always revalidate, so a redeploy is picked up at once


@app.get("/")
async def landing(request: Request):
    # If a proxy rule strips a /app or /workspace prefix, the request arrives here; serve the workspace.
    prefix = request.headers.get("x-forwarded-prefix", "")
    page = "index.html" if prefix.rstrip("/") in ("/app", "/workspace") else "landing.html"
    return FileResponse(HERE / "static" / page, headers=NO_CACHE)


@app.get("/workspace")
@app.get("/app")
async def workspace():
    return FileResponse(HERE / "static" / "index.html", headers=NO_CACHE)


@app.get("/r/{slug}")
async def shared_page(slug: str):
    return FileResponse(HERE / "static" / "index.html", headers=NO_CACHE)
