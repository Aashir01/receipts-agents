"""
Disposable executor VMs (maximum isolation tier).

For a run marked "fresh VM", the app creates a brand-new Vultr Cloud Compute instance from a
snapshot of the executor VM, in the same VPC and firewall group, with its own one-time runner
token. The run's sandbox jobs go only to that VM; afterwards the VM is destroyed and the
deletion is confirmed through the Vultr API. A watchdog deletes any disposable VM older than
DISPOSABLE_MAX_AGE_MIN minutes, so nothing outlives a crash.

The Vultr API key lives only on the app server. Restrict it in the Vultr console to the app
server's IP address.
"""

import asyncio
import base64
import os
import secrets
import time
from datetime import datetime, timezone

import httpx

API = os.environ.get("VULTR_API_BASE", "https://api.vultr.com/v2").rstrip("/")
KEY = os.environ.get("VULTR_API_KEY", "")
TEMPLATE_LABEL = os.environ.get("DISPOSABLE_TEMPLATE_LABEL", "agentrush-exec")
SNAPSHOT_DESC = os.environ.get("DISPOSABLE_SNAPSHOT_DESC", "agentrush-exec-template")
SNAPSHOT_ID = os.environ.get("DISPOSABLE_SNAPSHOT_ID", "")
VPC_ID = os.environ.get("DISPOSABLE_VPC_ID", "")
PLAN = os.environ.get("DISPOSABLE_PLAN", "")
RUNNER_PORT = int(os.environ.get("DISPOSABLE_RUNNER_PORT", "8080"))
TAG = "receipts-disposable"
MAX_AGE_MIN = int(os.environ.get("DISPOSABLE_MAX_AGE_MIN", "15"))
MAX_CONCURRENT = int(os.environ.get("DISPOSABLE_MAX_CONCURRENT", "2"))
PER_HOUR = int(os.environ.get("DISPOSABLE_PER_HOUR", "10"))
BOOT_TIMEOUT_S = int(os.environ.get("DISPOSABLE_BOOT_TIMEOUT_S", "480"))
ENABLED = bool(KEY)

_c = httpx.AsyncClient(timeout=httpx.Timeout(25, connect=8))
_template: dict | None = None
_created_at: list[float] = []          # for the hourly cap
LIVE: dict[str, dict] = {}             # instance id -> {run_id, created}


class VMError(Exception):
    pass


def _h() -> dict:
    return {"Authorization": f"Bearer {KEY}"}


async def _req(method: str, path: str, **kw) -> httpx.Response:
    for attempt in range(3):
        r = await _c.request(method, f"{API}{path}", headers=_h(), **kw)
        if r.status_code not in (429, 503):
            return r
        await asyncio.sleep(1.5 * (attempt + 1))
    return r


async def template() -> dict:
    """Region, plan, VPC, firewall group and snapshot, copied from the executor VM."""
    global _template
    if _template:
        return _template
    r = await _req("GET", "/instances", params={"label": TEMPLATE_LABEL, "per_page": 50})
    if r.status_code != 200:
        raise VMError(f"Vultr API returned {r.status_code} listing instances (check the key's IP access control)")
    insts = [i for i in r.json().get("instances", []) if i.get("label") == TEMPLATE_LABEL]
    if not insts:
        raise VMError(f"No instance labelled {TEMPLATE_LABEL} to copy settings from")
    base = insts[0]
    vpcs = [VPC_ID] if VPC_ID else []
    if not vpcs:
        rv = await _req("GET", f"/instances/{base['id']}/vpcs")
        if rv.status_code == 200:
            vpcs = [v["id"] for v in rv.json().get("vpcs", []) if v.get("id")]
    if not vpcs:
        raise VMError("Could not find the executor VM's VPC; set DISPOSABLE_VPC_ID")
    snap = SNAPSHOT_ID
    if not snap:
        rs = await _req("GET", "/snapshots", params={"per_page": 100})
        if rs.status_code != 200:
            raise VMError(f"Vultr API returned {rs.status_code} listing snapshots")
        snaps = [s for s in rs.json().get("snapshots", [])
                 if s.get("description") == SNAPSHOT_DESC and s.get("status") == "complete"]
        if not snaps:
            raise VMError(f"No completed snapshot described '{SNAPSHOT_DESC}'")
        snap = sorted(snaps, key=lambda s: s.get("date_created", ""))[-1]["id"]
    _template = {"region": base["region"], "plan": PLAN or base["plan"], "vpcs": vpcs, "snapshot_id": snap,
                 "firewall_group_id": base.get("firewall_group_id") or "", "template_ip": base.get("internal_ip", "")}
    return _template


def user_data(token: str, template_ip: str) -> str:
    """Boot script: give this VM its own private address check and its own runner token."""
    return f"""#!/bin/bash
# Receipts disposable executor: one-time runner token, bind to this VM's own private IP.
TOKEN='{token}'
TEMPLATE_IP='{template_ip}'
META=$(curl -s --max-time 5 http://169.254.169.254/v1.json || true)
read -r MAC ADDR MASK <<< "$(printf '%s' "$META" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit()
for i in d.get("interfaces", []):
    v4 = i.get("ipv4") or {{}}
    if i.get("network-type") == "private" or str(v4.get("address", "")).startswith("10."):
        print(i.get("mac", ""), v4.get("address", ""), v4.get("netmask", ""))
        break
')"
if [ -n "${{ADDR:-}}" ] && [ -n "${{MAC:-}}" ]; then
  IFACE=$(ip -o link | awk -v m="$MAC" 'tolower($0) ~ tolower(m) {{sub(":", "", $2); print $2; exit}}')
  if [ -n "$IFACE" ]; then
    PREFIX=$(python3 -c "import ipaddress,sys; print(ipaddress.IPv4Network('0.0.0.0/'+sys.argv[1]).prefixlen)" "${{MASK:-255.255.240.0}}" 2>/dev/null || echo 20)
    [ -n "$TEMPLATE_IP" ] && ip addr del "$TEMPLATE_IP/$PREFIX" dev "$IFACE" 2>/dev/null
    ip addr show dev "$IFACE" | grep -q "inet $ADDR/" || ip addr add "$ADDR/$PREFIX" dev "$IFACE"
    ip link set "$IFACE" up
  fi
fi
for i in $(seq 1 30); do
  PRIV_IP=$(ip -4 -o addr show | awk '$2 !~ /^(docker|br-|lo|veth)/ {{print $4}}' | cut -d/ -f1 | grep -E '^10\\.' | grep -v "^$TEMPLATE_IP$" | head -1)
  [ -n "$PRIV_IP" ] && break
  sleep 2
done
sed -i "s/^RUNNER_TOKEN=.*/RUNNER_TOKEN=$TOKEN/; s/^RUNNER_BIND=.*/RUNNER_BIND=$PRIV_IP/" /etc/agentrush/runner.env
systemctl restart agentrush-runner
"""


def can_create() -> str | None:
    now = time.time()
    _created_at[:] = [t for t in _created_at if now - t < 3600]
    if not ENABLED:
        return "Fresh-VM mode is not configured on this server"
    if len(LIVE) >= MAX_CONCURRENT:
        return f"{len(LIVE)} fresh VMs are already running; try again in a few minutes"
    if len(_created_at) >= PER_HOUR:
        return "The hourly limit for fresh VMs is reached; try again later"
    return None


async def create(run_id: str) -> dict:
    t = await template()
    token = secrets.token_hex(32)
    label = f"rcpt-{run_id[:8]}"
    body = {"region": t["region"], "plan": t["plan"], "snapshot_id": t["snapshot_id"], "label": label,
            "hostname": label, "tags": [TAG, f"run-{run_id[:8]}"], "attach_vpc": t["vpcs"],
            "backups": "disabled", "enable_ipv6": False,
            "user_data": base64.b64encode(user_data(token, t["template_ip"]).encode()).decode()}
    if t["firewall_group_id"]:
        body["firewall_group_id"] = t["firewall_group_id"]
    r = await _req("POST", "/instances", json=body)
    if r.status_code not in (200, 201, 202):
        raise VMError(f"Vultr API refused to create the VM ({r.status_code}): {r.text[:200]}")
    inst = r.json()["instance"]
    _created_at.append(time.time())
    LIVE[inst["id"]] = {"run_id": run_id, "created": time.time()}
    return {"id": inst["id"], "label": label, "token": token, "region": t["region"], "plan": t["plan"],
            "created": time.time(), "ip": None, "url": None}


async def get(instance_id: str) -> dict | None:
    r = await _req("GET", f"/instances/{instance_id}")
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise VMError(f"Vultr API returned {r.status_code}")
    return r.json().get("instance")


async def wait_ready(vm: dict, should_stop) -> bool:
    """Wait until Vultr reports the VM running with a private IP and its runner accepts our token."""
    deadline = vm["created"] + BOOT_TIMEOUT_S
    while time.time() < deadline:
        if should_stop():
            return False
        inst = await get(vm["id"])
        if inst is None:
            raise VMError("The VM disappeared while booting")
        ip = inst.get("internal_ip") or ""
        if inst.get("status") == "active" and inst.get("power_status") == "running" and ip.startswith(("10.", "127.")):
            vm["ip"] = ip
            vm["url"] = f"http://{ip}:{RUNNER_PORT}"
            try:
                h = await _c.get(f"{vm['url']}/alive", headers={"X-Runner-Token": vm["token"]}, timeout=4)
                if h.status_code == 200:
                    vm["ready_s"] = round(time.time() - vm["created"], 1)
                    return True
            except httpx.HTTPError:
                pass
        await asyncio.sleep(5)
    raise VMError(f"The VM was not ready within {BOOT_TIMEOUT_S} s")


async def destroy(instance_id: str) -> dict:
    """Delete the VM and confirm through the API that it is gone (or being destroyed)."""
    out = {"requested": False, "confirmed": False}
    for _ in range(3):
        r = await _req("DELETE", f"/instances/{instance_id}")
        if r.status_code in (200, 202, 204, 404):
            out["requested"] = True
            break
        await asyncio.sleep(2)
    for _ in range(12):
        inst = await get(instance_id)
        if inst is None or inst.get("status") in ("destroying", "destroyed", "closed"):
            out["confirmed"] = True
            break
        await asyncio.sleep(2.5)
    if out["requested"]:
        LIVE.pop(instance_id, None)
    return out


def _age_min(inst: dict) -> float:
    try:
        created = datetime.fromisoformat(inst["date_created"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return 0
    return (datetime.now(timezone.utc) - created).total_seconds() / 60


async def reap() -> list[str]:
    """Delete disposable VMs older than the maximum age (the safety net behind every run)."""
    if not ENABLED:
        return []
    r = await _req("GET", "/instances", params={"tag": TAG, "per_page": 100})
    if r.status_code != 200:
        return []
    deleted = []
    for inst in r.json().get("instances", []):
        if TAG in (inst.get("tags") or []) and _age_min(inst) > MAX_AGE_MIN:
            res = await destroy(inst["id"])
            if res["requested"]:
                deleted.append(inst["id"])
    return deleted


async def watchdog() -> None:
    while True:
        try:
            gone = await reap()
            if gone:
                print(f"[watchdog] deleted stale disposable VMs: {gone}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[watchdog] {type(e).__name__}: {e}", flush=True)
        await asyncio.sleep(60)
