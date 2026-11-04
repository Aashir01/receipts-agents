#!/usr/bin/env bash
# Agent Rush - sandbox runner installer for the executor VM (VM 2).
# Run as root. Safe to re-run: keeps the existing token.
set -euo pipefail

echo "==> Installing Python venv support"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq python3-venv python3-pip openssl >/dev/null

echo "==> Writing runner files"
mkdir -p /opt/agentrush-runner /etc/agentrush /var/lib/agentrush/jobs
chmod 711 /var/lib/agentrush /var/lib/agentrush/jobs

cat > /opt/agentrush-runner/app.py <<'AGENTRUSH_EOF'
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
_stopped: set[str] = set()   # job ids a human stopped


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
AGENTRUSH_EOF

cat > /opt/agentrush-runner/sandbox.Dockerfile <<'AGENTRUSH_EOF'
# Image every sandboxed job runs in. The sandbox has no network,
# so all libraries the agent may use are baked in here.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
        pandas numpy matplotlib seaborn scipy openpyxl tabulate \
    && useradd -m -u 1000 sandbox \
    && python -c "import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot"

USER sandbox
WORKDIR /work
AGENTRUSH_EOF

cat > /etc/systemd/system/agentrush-runner.service <<'AGENTRUSH_EOF'
[Unit]
Description=Agent Rush sandbox runner
After=docker.service network-online.target
Requires=docker.service

[Service]
EnvironmentFile=/etc/agentrush/runner.env
WorkingDirectory=/opt/agentrush-runner
ExecStart=/opt/agentrush-runner/venv/bin/uvicorn app:app --host ${RUNNER_BIND} --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
AGENTRUSH_EOF

echo "==> Creating Python environment"
python3 -m venv /opt/agentrush-runner/venv
/opt/agentrush-runner/venv/bin/pip install -q --upgrade pip
/opt/agentrush-runner/venv/bin/pip install -q fastapi "uvicorn[standard]" pydantic

echo "==> Building sandbox image (pandas, matplotlib, ...) - takes 1-3 minutes"
docker build -q -t agentrush-sandbox:latest -f /opt/agentrush-runner/sandbox.Dockerfile /opt/agentrush-runner >/dev/null

echo "==> Detecting private (VPC) IP"
PRIV_IP=$(ip -4 -o addr show | awk '$2 !~ /^(docker|br-|lo|veth)/ {print $4}' | cut -d/ -f1 | grep -E '^10\.' | head -1 || true)
if [ -z "$PRIV_IP" ]; then
  echo "ERROR: no 10.x private IP found. Is VPC attached?" >&2
  exit 1
fi

if [ -f /etc/agentrush/runner.env ] && grep -q '^RUNNER_TOKEN=' /etc/agentrush/runner.env; then
  TOKEN=$(grep '^RUNNER_TOKEN=' /etc/agentrush/runner.env | cut -d= -f2-)
else
  TOKEN=$(openssl rand -hex 32)
fi

cat > /etc/agentrush/runner.env <<AGENTRUSH_EOF
RUNNER_TOKEN=$TOKEN
RUNNER_BIND=$PRIV_IP
SANDBOX_IMAGE=agentrush-sandbox:latest
DOCKER_RUNTIME=runsc
JOBS_DIR=/var/lib/agentrush/jobs
MAX_CONCURRENT=2
AGENTRUSH_EOF
chmod 600 /etc/agentrush/runner.env

echo "==> Starting service"
systemctl daemon-reload
systemctl enable -q agentrush-runner
systemctl restart agentrush-runner
sleep 3

echo "==> Health check"
curl -s "http://$PRIV_IP:8080/health" && echo

echo
echo "=================================================================="
echo " Runner is listening ONLY on the private network: http://$PRIV_IP:8080"
echo " RUNNER_TOKEN (copy into your notes; never commit it):"
echo "   $TOKEN"
echo "=================================================================="
