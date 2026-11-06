"""
Disposable executor VMs (maximum isolation tier), served from a warm pool.

Restoring a Vultr snapshot takes 10 to 60 minutes, so VMs are booted ahead of time: the app
keeps DISPOSABLE_POOL_SIZE standby instances, each a brand-new Cloud Compute instance restored
from a snapshot of the executor VM, in the same VPC and firewall group, with its own runner
token. A standby VM never runs anything. A run that asks for a fresh VM claims one, uses it
for that run only, and destroys it (deletion confirmed through the Vultr API); a replacement
starts booting in the background. A watchdog deletes claimed VMs older than
DISPOSABLE_MAX_AGE_MIN minutes, stale standbys, and standbys whose runner never came up.

The Vultr API key lives only on the app server. Restrict it in the Vultr console to the app
server's IP address.
"""

import asyncio
import base64
import hashlib
import hmac
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
TAG = "receipts-disposable"          # claimed: serving (or served) exactly one run
STANDBY_TAG = "receipts-standby"     # booted ahead of time, never used
POOL_SIZE = int(os.environ.get("DISPOSABLE_POOL_SIZE", "1"))
STANDBY_MAX_H = float(os.environ.get("DISPOSABLE_STANDBY_MAX_H", "24"))
BROKEN_AFTER_MIN = float(os.environ.get("DISPOSABLE_BROKEN_AFTER_MIN", "15"))
_SECRET = (os.environ.get("RUNNER_TOKEN", "") or secrets.token_hex(16)).encode()
MAX_AGE_MIN = int(os.environ.get("DISPOSABLE_MAX_AGE_MIN", "15"))
MAX_CONCURRENT = int(os.environ.get("DISPOSABLE_MAX_CONCURRENT", "2"))
PER_HOUR = int(os.environ.get("DISPOSABLE_PER_HOUR", "10"))
ENABLED = bool(KEY)

_c = httpx.AsyncClient(timeout=httpx.Timeout(25, connect=8))
_template: dict | None = None
_template_at = 0.0
_created_at: list[float] = []          # for the hourly cap
LIVE: dict[str, dict] = {}             # claimed instance id -> {run_id, claimed}
STATUS: dict = {"ready": 0, "booting": 0, "claimed": 0, "last_error": "", "checked": 0, "fails": 0}
_active_since: dict[str, float] = {}   # standby id -> first time seen active (broken-boot detection)
_claim_lock = asyncio.Lock()
_maint_lock = asyncio.Lock()


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
    global _template, _template_at
    if _template and time.time() - _template_at < 600:      # look again every 10 minutes: a newer snapshot is picked up
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
    _template_at = time.time()
    _template = {"region": base["region"], "plan": PLAN or base["plan"], "vpcs": vpcs, "snapshot_id": snap,
                 "firewall_group_id": base.get("firewall_group_id") or "", "template_ip": base.get("internal_ip", "")}
    return _template


def user_data(token: str, template_ip: str) -> str:
    """Boot script: give this VM its own private address check and its own runner token."""
    return f"""#!/bin/bash
# Countersign disposable executor: one-time runner token, bind to this VM's own private IP.
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



def token_for(label: str) -> str:
    """Per-VM runner token, derived so it survives app restarts and never equals the main token."""
    return hmac.new(_SECRET, f"disposable:{label}".encode(), hashlib.sha256).hexdigest()


def can_use() -> str | None:
    if not ENABLED:
        return "Fresh-VM mode is not configured on this server"
    if len(LIVE) >= MAX_CONCURRENT:
        return f"{len(LIVE)} fresh VMs are already in use; try again in a few minutes"
    return None


def _hourly_ok() -> bool:
    now = time.time()
    _created_at[:] = [t for t in _created_at if now - t < 3600]
    return len(_created_at) < PER_HOUR


def _snap_tag(snapshot_id: str) -> str:
    return f"snap-{snapshot_id}"


async def _current_snap_tag() -> str | None:
    """Tag of the snapshot new standbys boot from, or None if it can't be read right now."""
    try:
        return _snap_tag((await template())["snapshot_id"])
    except Exception:  # noqa: BLE001
        return None


def _is_current(inst: dict, cur: str | None) -> bool:
    return cur is None or cur in (inst.get("tags") or [])


async def create_standby() -> dict:
    t = await template()
    label = f"rcpt-{secrets.token_hex(4)}"
    body = {"region": t["region"], "plan": t["plan"], "snapshot_id": t["snapshot_id"], "label": label,
            "hostname": label, "tags": [STANDBY_TAG, _snap_tag(t["snapshot_id"])], "attach_vpc": t["vpcs"],
            "backups": "disabled", "enable_ipv6": False,
            "user_data": base64.b64encode(user_data(token_for(label), t["template_ip"]).encode()).decode()}
    if t["firewall_group_id"]:
        body["firewall_group_id"] = t["firewall_group_id"]
    r = await _req("POST", "/instances", json=body)
    if r.status_code not in (200, 201, 202):
        raise VMError(f"Vultr API refused to create the VM ({r.status_code}): {r.text[:200]}")
    _created_at.append(time.time())
    return r.json()["instance"]


async def _list(tag: str) -> list[dict]:
    r = await _req("GET", "/instances", params={"tag": tag, "per_page": 100})
    if r.status_code != 200:
        raise VMError(f"Vultr API returned {r.status_code} listing instances")
    return [i for i in r.json().get("instances", []) if tag in (i.get("tags") or [])]


async def _runner_ok(inst: dict) -> bool:
    ip = inst.get("internal_ip") or ""
    if not (inst.get("status") == "active" and inst.get("power_status") == "running" and ip.startswith(("10.", "127."))):
        return False
    try:
        h = await _c.get(f"http://{ip}:{RUNNER_PORT}/alive", headers={"X-Runner-Token": token_for(inst["label"])}, timeout=4)
        return h.status_code == 200
    except httpx.HTTPError:
        return False


async def claim(run_id: str) -> tuple[dict | None, str]:
    """Take a ready standby VM for this run. Returns (vm, "") or (None, reason)."""
    async with _claim_lock:
        try:
            standby = await _list(STANDBY_TAG)
        except VMError as e:
            return None, str(e)
        booting = 0
        cur = await _current_snap_tag()
        # VMs from the newest snapshot first; an older one is still used rather than none
        for inst in sorted(standby, key=lambda i: (not _is_current(i, cur), i.get("date_created", ""))):
            if not await _runner_ok(inst):
                booting += 1
                continue
            tags = [TAG, f"run-{run_id[:8]}", f"claimed-{int(time.time())}"]
            r = await _req("PATCH", f"/instances/{inst['id']}", json={"tags": tags})
            if r.status_code not in (200, 202, 204):
                continue
            LIVE[inst["id"]] = {"run_id": run_id, "claimed": time.time()}
            asyncio.create_task(maintain())          # start booting the replacement now
            return {"id": inst["id"], "label": inst["label"], "token": token_for(inst["label"]),
                    "region": inst.get("region"), "plan": inst.get("plan"), "ip": inst["internal_ip"],
                    "url": f"http://{inst['internal_ip']}:{RUNNER_PORT}", "created": time.time(),
                    "booted_min": round(_age_min(inst), 1)}, ""
        if booting:
            return None, "the pre-booted VM is still restoring from the snapshot"
        return None, STATUS.get("last_error") or "no pre-booted VM exists yet"


async def get(instance_id: str) -> dict | None:
    r = await _req("GET", f"/instances/{instance_id}")
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise VMError(f"Vultr API returned {r.status_code}")
    return r.json().get("instance")


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


def _age_min(inst: dict, since: str | None = None) -> float:
    try:
        created = datetime.fromisoformat((since or inst["date_created"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return 0
    return (datetime.now(timezone.utc) - created).total_seconds() / 60


def _claimed_age_min(inst: dict) -> float:
    for t in inst.get("tags") or []:
        if t.startswith("claimed-") and t[8:].isdigit():
            return (time.time() - int(t[8:])) / 60
    return _age_min(inst)


async def maintain() -> dict:
    """Watchdog pass: delete expired or broken VMs, then refill the standby pool."""
    if not ENABLED:
        return STATUS
    async with _maint_lock:
        return await _maintain()


async def _maintain() -> dict:
    try:
        for inst in await _list(TAG):                              # claimed VMs
            if _claimed_age_min(inst) > MAX_AGE_MIN:
                await destroy(inst["id"])
                print(f"[watchdog] deleted claimed VM {inst['label']} (older than {MAX_AGE_MIN} min)", flush=True)
        standby = await _list(STANDBY_TAG)
        cur = await _current_snap_tag()
        old = [i for i in standby if not _is_current(i, cur)]       # booted from an older snapshot
        standby = [i for i in standby if _is_current(i, cur)]
        ready, booting, old_ready = 0, 0, 0
        for inst in sorted(standby, key=lambda i: i.get("date_created", "")):
            if _age_min(inst) > STANDBY_MAX_H * 60 or ready + booting >= POOL_SIZE:
                await destroy(inst["id"])
                continue
            if await _runner_ok(inst):
                ready += 1
                STATUS["fails"] = 0
                continue
            if inst.get("status") == "active" and inst.get("server_status") == "ok":
                first = _active_since.setdefault(inst["id"], time.time())
                if time.time() - first > BROKEN_AFTER_MIN * 60:
                    await destroy(inst["id"])
                    STATUS["fails"] += 1
                    STATUS["last_error"] = ("a standby VM finished booting but its runner never answered; "
                                            "check the executor snapshot")
                    print(f"[watchdog] {STATUS['last_error']} ({inst['label']})", flush=True)
                    continue
            booting += 1
        for inst in old:
            # Keep an old-snapshot VM only until a VM from the newest snapshot is ready to replace it.
            if ready >= POOL_SIZE or _age_min(inst) > STANDBY_MAX_H * 60 or not await _runner_ok(inst):
                await destroy(inst["id"])
                print(f"[watchdog] deleted standby VM {inst['label']}: replaced by one from the newest snapshot", flush=True)
            else:
                old_ready += 1
        if ready + booting < POOL_SIZE and STATUS["fails"] < 2 and _hourly_ok():
            inst = await create_standby()
            booting += 1
            print(f"[watchdog] booting standby VM {inst['label']} from the executor snapshot", flush=True)
        STATUS.update(ready=ready + old_ready, booting=booting, claimed=len(LIVE), checked=int(time.time()),
                      old_snapshot=old_ready)
    except Exception as e:  # noqa: BLE001
        STATUS["last_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        print(f"[watchdog] {STATUS['last_error']}", flush=True)
    return STATUS


async def watchdog() -> None:
    while True:
        await maintain()
        await asyncio.sleep(60)
