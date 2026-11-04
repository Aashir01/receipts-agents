"""
Agent Rush - Sandbox Runner (runs on the executor VM).

Receives code + input files from the app server over the Vultr VPC,
runs them inside a throwaway gVisor container with no network and hard
limits, and returns real output plus a containment report.

The executor holds no API keys. Only the shared RUNNER_TOKEN, which
authenticates the app server.
"""

import asyncio
import base64
import json
import os
import re
import secrets
import shutil
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

RUNNER_TOKEN = os.environ.get("RUNNER_TOKEN", "")
SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "agentrush-sandbox:latest")
BROWSER_IMAGE = os.environ.get("BROWSER_IMAGE", "agentrush-browser:latest")
EGRESS_IMAGE = os.environ.get("EGRESS_IMAGE", "agentrush-egress:latest")
DOCKER_RUNTIME = os.environ.get("DOCKER_RUNTIME", "runsc")
JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/var/lib/agentrush/jobs"))
SANDBOX_UID = os.environ.get("SANDBOX_UID", "1000")
DOCKER_BIN = os.environ.get("DOCKER_BIN", "docker")

MAX_TIMEOUT_S = 60
MAX_MEMORY_MB = 1024
MAX_INPUT_BYTES = 20 * 1024 * 1024
MAX_OUTPUT_FILE_BYTES = 5 * 1024 * 1024
MAX_OUTPUT_FILES = 10
MAX_LOG_CHARS = 20_000
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT", "2"))

SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

app = FastAPI(title="Agent Rush Sandbox Runner")
_slots = asyncio.Semaphore(MAX_CONCURRENT)
_browser_slot = asyncio.Semaphore(1)        # one browser at a time: Chromium is heavy
DOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_stopped: set[str] = set()   # job ids a human stopped


class BrowseRequest(BaseModel):
    actions: list[dict] = Field(..., min_length=1, max_length=25)
    allow_domains: list[str] = Field(..., min_length=1, max_length=10)
    timeout_s: int = Field(90, ge=10, le=180)
    job_id: str | None = Field(None, pattern=r"^[a-f0-9]{12}$")


class InputFile(BaseModel):
    name: str
    content_b64: str


class RunRequest(BaseModel):
    code: str = Field(..., max_length=200_000)
    files: list[InputFile] = []
    timeout_s: int = Field(20, ge=1, le=MAX_TIMEOUT_S)
    memory_mb: int = Field(512, ge=64, le=MAX_MEMORY_MB)
    job_id: str | None = Field(None, pattern=r"^[a-f0-9]{12}$")   # chosen by the app so it can stop the job


def _check_token(token: str | None) -> None:
    if not RUNNER_TOKEN:
        raise HTTPException(500, "Runner token not configured")
    if not token or not secrets.compare_digest(token, RUNNER_TOKEN):
        raise HTTPException(401, "Invalid runner token")


def _truncate(text: str) -> str:
    if len(text) <= MAX_LOG_CHARS:
        return text
    return text[:MAX_LOG_CHARS] + f"\n...[truncated {len(text) - MAX_LOG_CHARS} chars]"


async def _docker(*args: str, timeout: float = 15) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        DOCKER_BIN, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", "docker command timed out"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def _detect_blocked_actions(stderr: str) -> list[str]:
    """Spot attempts the sandbox stopped, so the UI can show them."""
    findings = []
    checks = [
        (r"Temporary failure in name resolution|Network is unreachable|"
         r"Name or service not known|ConnectionRefusedError|urlopen error",
         "Outbound network attempt blocked (no network in sandbox)"),
        (r"Read-only file system", "Write outside work folder blocked (read-only filesystem)"),
        (r"Permission denied|Operation not permitted", "Privileged action denied (non-root, no capabilities)"),
        (r"BlockingIOError|Resource temporarily unavailable|can't start new thread",
         "Process/thread limit reached (pids limit)"),
    ]
    for pattern, label in checks:
        if re.search(pattern, stderr):
            findings.append(label)
    return findings


@app.get("/health")
async def health():
    return {"ok": True, "runtime": DOCKER_RUNTIME, "image": SANDBOX_IMAGE}


@app.post("/kill/{job_id}")
async def kill(job_id: str, x_runner_token: str | None = Header(default=None)):
    """Stop button: kill a running sandbox container immediately."""
    _check_token(x_runner_token)
    if not re.fullmatch(r"[a-f0-9]{12}", job_id):
        raise HTTPException(400, "Bad job id")
    _stopped.add(job_id)
    rc, _, _ = await _docker("kill", f"sbx-{job_id}")
    return {"killed": rc == 0, "job_id": job_id}


@app.get("/alive")
async def alive(x_runner_token: str | None = Header(default=None)):
    """How many sandbox containers exist right now (should be 0 when idle)."""
    _check_token(x_runner_token)
    rc, out, _ = await _docker("ps", "-q", "--filter", "name=sbx-")
    return {"containers": len([x for x in out.split() if x]) if rc == 0 else None}


@app.post("/run")
async def run(req: RunRequest, x_runner_token: str | None = Header(default=None)):
    _check_token(x_runner_token)

    total_in = sum(len(f.content_b64) * 3 // 4 for f in req.files)
    if total_in > MAX_INPUT_BYTES:
        raise HTTPException(413, "Input files too large")

    job_id = req.job_id or uuid.uuid4().hex[:12]
    name = f"sbx-{job_id}"
    job_dir = JOBS_DIR / job_id
    events: list[dict] = []

    def event(kind: str, detail: str) -> None:
        events.append({"t": round(time.time(), 3), "kind": kind, "detail": detail})

    async with _slots:
        try:
            job_dir.mkdir(parents=True, exist_ok=False)
            input_names = set()
            for f in req.files:
                if not SAFE_NAME.match(f.name) or f.name == "main.py":
                    raise HTTPException(400, f"Bad file name: {f.name}")
                (job_dir / f.name).write_bytes(base64.b64decode(f.content_b64))
                input_names.add(f.name)
            (job_dir / "main.py").write_text(req.code, encoding="utf-8")
            os.system(f"chown -R {SANDBOX_UID}:{SANDBOX_UID} {job_dir} 2>/dev/null")
            before = {p.name: p.stat().st_mtime for p in job_dir.iterdir()}

            limits = {
                "runtime": DOCKER_RUNTIME,
                "network": "none",
                "memory_mb": req.memory_mb,
                "cpus": 1,
                "pids_limit": 64,
                "timeout_s": req.timeout_s,
                "root_fs": "read-only",
                "user": f"uid {SANDBOX_UID} (non-root)",
                "capabilities": "all dropped",
                "secrets_in_sandbox": 0,
            }

            cmd = [
                "run", "--name", name, "--rm",
                f"--runtime={DOCKER_RUNTIME}",
                "--network", "none",
                "--memory", f"{req.memory_mb}m", "--memory-swap", f"{req.memory_mb}m",
                "--cpus", "1", "--pids-limit", "64",
                "--read-only", "--tmpfs", "/tmp:rw,size=64m",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{SANDBOX_UID}:{SANDBOX_UID}",
                "-e", "HOME=/tmp", "-e", "MPLCONFIGDIR=/tmp", "-e", "MPLBACKEND=Agg",
                "-v", f"{job_dir}:/work:rw", "-w", "/work",
                SANDBOX_IMAGE, "python", "-u", "/work/main.py",
            ]

            event("created", f"Container {name} created on gVisor ({DOCKER_RUNTIME}), network disabled")
            start = time.monotonic()
            proc = await asyncio.create_subprocess_exec(
                DOCKER_BIN, *cmd,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            status = "ok"
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), req.timeout_s)
                exit_code = proc.returncode
            except asyncio.TimeoutError:
                status = "timeout"
                event("killed", f"Time limit {req.timeout_s}s reached - container killed")
                await _docker("kill", name)
                try:
                    out_b, err_b = await asyncio.wait_for(proc.communicate(), 3)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    out_b, err_b = b"", b""
                exit_code = 124
            duration = round(time.monotonic() - start, 2)

            stdout = out_b.decode(errors="replace")
            stderr = err_b.decode(errors="replace")

            if job_id in _stopped:
                _stopped.discard(job_id)
                status = "stopped"
                event("killed", "Stopped by a human - container killed immediately")
            elif status == "ok" and exit_code == 137:
                status = "oom_killed"
                event("killed", f"Memory limit {req.memory_mb} MB exceeded - process killed")
            elif status == "ok" and exit_code != 0:
                status = "error"

            for label in _detect_blocked_actions(stderr):
                event("blocked", label)

            outputs = []
            for p in sorted(job_dir.iterdir()):
                if not p.is_file() or p.name == "main.py":
                    continue
                changed = p.name not in before or p.stat().st_mtime != before[p.name]
                if p.name in input_names and not changed:
                    continue
                if len(outputs) >= MAX_OUTPUT_FILES:
                    break
                size = p.stat().st_size
                if size > MAX_OUTPUT_FILE_BYTES:
                    event("skipped", f"Output {p.name} too large ({size} bytes)")
                    continue
                outputs.append({
                    "name": p.name,
                    "size": size,
                    "content_b64": base64.b64encode(p.read_bytes()).decode(),
                })

            # Prove the environment is gone.
            rc, _, _ = await _docker("inspect", name)
            if rc != 0:
                event("destroyed", f"Container {name} removed - nothing persists")
            else:
                await _docker("rm", "-f", name)
                event("destroyed", f"Container {name} force-removed")

            return {
                "job_id": job_id,
                "status": status,
                "exit_code": exit_code,
                "duration_s": duration,
                "stdout": _truncate(stdout),
                "stderr": _truncate(stderr),
                "outputs": outputs,
                "limits": limits,
                "events": events,
            }
        finally:
            shutil.rmtree(job_dir, ignore_errors=True)
            await _docker("rm", "-f", name)


@app.post("/browse")
async def browse(req: BrowseRequest, x_runner_token: str | None = Header(default=None)):
    """Pattern B: run browser actions in a gVisor container whose only exit is a per-task
    egress proxy that allows just this task's domains. All three parts are destroyed after."""
    _check_token(x_runner_token)
    domains = sorted({d.strip().lower().strip(".") for d in req.allow_domains})
    for d in domains:
        if not DOMAIN.match(d):
            raise HTTPException(400, f"Bad domain: {d}")
    allowed_kinds = {"goto", "click", "fill", "select", "check", "press", "wait", "extract", "screenshot"}
    for a in req.actions:
        if a.get("type") not in allowed_kinds:
            raise HTTPException(400, f"Action type not allowed: {a.get('type')}")

    job_id = req.job_id or uuid.uuid4().hex[:12]
    name, proxy_name, net = f"sbx-{job_id}", f"egress-{job_id}", f"net-{job_id}"
    job_dir = JOBS_DIR / job_id
    events: list[dict] = []

    def event(kind: str, detail: str) -> None:
        events.append({"t": round(time.time(), 3), "kind": kind, "detail": detail})

    async with _browser_slot:
        try:
            job_dir.mkdir(parents=True, exist_ok=False)
            (job_dir / "task.json").write_text(json.dumps({"actions": req.actions, "proxy": "http://proxy:8888"}))
            os.system(f"chown -R {SANDBOX_UID}:{SANDBOX_UID} {job_dir} 2>/dev/null")

            # 1. private network with no route to anywhere
            rc, _, err = await _docker("network", "create", "--internal", net)
            if rc != 0:
                raise HTTPException(500, f"network create failed: {err[:200]}")
            event("created", f"Private network {net} created with no internet route")
            # 2. egress proxy: the only bridge between that network and the internet
            rc, _, err = await _docker(
                "run", "-d", "--name", proxy_name, f"--runtime={DOCKER_RUNTIME}",
                "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "-e", f"ALLOW={','.join(domains)}", EGRESS_IMAGE)
            if rc != 0:
                raise HTTPException(500, f"proxy start failed: {err[:200]}")
            await _docker("network", "connect", "--alias", "proxy", net, proxy_name)
            event("created", f"Egress proxy {proxy_name} allows only: {', '.join(domains)}")
            # 3. the browser itself, on the private network only
            cmd = [
                "run", "--name", name, "--rm", f"--runtime={DOCKER_RUNTIME}", "--network", net,
                "--memory", "1024m", "--memory-swap", "1024m", "--cpus", "1", "--pids-limit", "256",
                "--shm-size", "256m", "--read-only", "--tmpfs", "/tmp:rw,size=256m",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{SANDBOX_UID}:{SANDBOX_UID}", "-e", "HOME=/tmp",
                "-v", f"{job_dir}:/work:rw", "-w", "/work", BROWSER_IMAGE, "python", "-u", "/opt/driver.py",
            ]
            event("created", f"Browser {name} started on gVisor ({DOCKER_RUNTIME}), reachable network: proxy only")
            start = time.monotonic()
            proc = await asyncio.create_subprocess_exec(DOCKER_BIN, *cmd, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            status = "ok"
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), req.timeout_s)
                exit_code = proc.returncode
            except asyncio.TimeoutError:
                status, exit_code = "timeout", 124
                event("killed", f"Time limit {req.timeout_s}s reached - browser killed")
                await _docker("kill", name)
                try:
                    out_b, err_b = await asyncio.wait_for(proc.communicate(), 3)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    out_b, err_b = b"", b""
            duration = round(time.monotonic() - start, 2)
            if job_id in _stopped:
                _stopped.discard(job_id)
                status = "stopped"
                event("killed", "Stopped by a human - browser killed immediately")
            elif status == "ok" and exit_code != 0:
                status = "error"

            # proxy decisions become receipt events
            _, plog, _ = await _docker("logs", proxy_name)
            allowed_hosts: dict[str, int] = {}
            for line in plog.splitlines():
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d.get("action") == "allowed":
                    allowed_hosts[d.get("host", "?")] = allowed_hosts.get(d.get("host", "?"), 0) + 1
                elif d.get("action") == "blocked":
                    event("blocked", f"Egress to {d.get('host', '?')} blocked: {d.get('reason', '')}")
            for host, n in sorted(allowed_hosts.items()):
                event("egress", f"{n} connection{'s' if n > 1 else ''} to {host} (allowlisted)")

            result = {}
            rf = job_dir / "result.json"
            if rf.exists():
                try:
                    result = json.loads(rf.read_text())
                except json.JSONDecodeError:
                    result = {}
            shots = []
            for f in sorted(job_dir.glob("shot_*.png"), key=lambda x: int(x.stem.split("_")[1]))[:20]:
                if f.stat().st_size <= MAX_OUTPUT_FILE_BYTES:
                    shots.append({"name": f.name, "size": f.stat().st_size,
                                  "content_b64": base64.b64encode(f.read_bytes()).decode()})
            return {
                "job_id": job_id, "status": status, "exit_code": exit_code, "duration_s": duration,
                "stdout": _truncate(out_b.decode(errors="replace")), "stderr": _truncate(err_b.decode(errors="replace")),
                "result": result, "outputs": shots, "events": events,
                "limits": {"runtime": DOCKER_RUNTIME, "network": f"private, egress via allowlist proxy ({', '.join(domains)})",
                           "memory_mb": 1024, "cpus": 1, "pids_limit": 256, "timeout_s": req.timeout_s,
                           "root_fs": "read-only", "user": f"uid {SANDBOX_UID} (non-root)",
                           "capabilities": "all dropped", "secrets_in_sandbox": 0, "allow_domains": domains},
            }
        finally:
            await _docker("rm", "-f", name)
            await _docker("rm", "-f", proxy_name)
            await _docker("network", "rm", net)
            shutil.rmtree(job_dir, ignore_errors=True)
            rc, _, _ = await _docker("inspect", name)
            rc2, _, _ = await _docker("inspect", proxy_name)
            if rc != 0 and rc2 != 0:
                event("destroyed", f"Browser, proxy and network for job {job_id} removed - nothing persists")
