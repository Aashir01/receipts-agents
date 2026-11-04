"""
Supabase client for the app server: Postgres via PostgREST, Storage, and Auth.

The service-role key never leaves this server. Every write is best-effort: if
Supabase is down, the agent still runs; it just doesn't save.
"""

import os
import time
from urllib.parse import quote

import httpx

URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
ENABLED = bool(URL and SERVICE_KEY)

_c = httpx.AsyncClient(timeout=httpx.Timeout(float(os.environ.get("DB_TIMEOUT_S", "12")), connect=4))
_user_cache: dict[str, tuple[float, dict | None]] = {}


def _headers(extra: dict | None = None) -> dict:
    h = {"apikey": SERVICE_KEY, "Authorization": f"Bearer {SERVICE_KEY}", "Content-Type": "application/json"}
    if extra:
        h.update(extra)
    return h


def _log(msg: str) -> None:
    print(f"[db] {msg}", flush=True)


async def insert(table: str, row: dict) -> dict | None:
    if not ENABLED:
        return None
    try:
        r = await _c.post(f"{URL}/rest/v1/{table}", headers=_headers({"Prefer": "return=representation"}), json=row)
        if r.status_code >= 300:
            _log(f"insert {table} -> {r.status_code} {r.text[:200]}")
            return None
        data = r.json()
        return data[0] if isinstance(data, list) and data else data
    except Exception as e:  # noqa: BLE001
        _log(f"insert {table} failed: {e}")
        return None


async def update(table: str, row_id: str, patch: dict) -> bool:
    if not ENABLED:
        return False
    try:
        r = await _c.patch(f"{URL}/rest/v1/{table}?id=eq.{quote(row_id)}", headers=_headers(), json=patch)
        if r.status_code >= 300:
            _log(f"update {table} -> {r.status_code} {r.text[:200]}")
        return r.status_code < 300
    except Exception as e:  # noqa: BLE001
        _log(f"update {table} failed: {e}")
        return False


async def select(table: str, params: dict) -> list[dict]:
    """params use PostgREST syntax, e.g. {"id": "eq.<uuid>", "select": "*", "order": "created_at.desc"}."""
    if not ENABLED:
        return []
    try:
        r = await _c.get(f"{URL}/rest/v1/{table}", headers=_headers(), params=params)
        if r.status_code >= 300:
            _log(f"select {table} -> {r.status_code} {r.text[:200]}")
            return []
        return r.json()
    except Exception as e:  # noqa: BLE001
        _log(f"select {table} failed: {e}")
        return []


async def one(table: str, params: dict) -> dict | None:
    rows = await select(table, {**params, "limit": "1"})
    return rows[0] if rows else None


async def upload(bucket: str, path: str, data: bytes, content_type: str = "application/octet-stream") -> bool:
    if not ENABLED:
        return False
    try:
        r = await _c.post(f"{URL}/storage/v1/object/{bucket}/{quote(path)}",
                          headers={"apikey": SERVICE_KEY, "Authorization": f"Bearer {SERVICE_KEY}",
                                   "Content-Type": content_type, "x-upsert": "true"},
                          content=data)
        if r.status_code >= 300:
            _log(f"upload {bucket}/{path} -> {r.status_code} {r.text[:200]}")
        return r.status_code < 300
    except Exception as e:  # noqa: BLE001
        _log(f"upload failed: {e}")
        return False


async def download(bucket: str, path: str) -> bytes | None:
    if not ENABLED:
        return None
    try:
        r = await _c.get(f"{URL}/storage/v1/object/{bucket}/{quote(path)}",
                         headers={"apikey": SERVICE_KEY, "Authorization": f"Bearer {SERVICE_KEY}"})
        if r.status_code >= 300:
            _log(f"download {bucket}/{path} -> {r.status_code}")
            return None
        return r.content
    except Exception as e:  # noqa: BLE001
        _log(f"download failed: {e}")
        return None


async def user_from_token(token: str | None) -> dict | None:
    """Verify a Supabase access token with the Auth server. Cached for 60 s."""
    if not (ENABLED and token):
        return None
    now = time.time()
    hit = _user_cache.get(token)
    if hit and now - hit[0] < 60:
        return hit[1]
    user = None
    try:
        r = await _c.get(f"{URL}/auth/v1/user",
                         headers={"apikey": ANON_KEY or SERVICE_KEY, "Authorization": f"Bearer {token}"})
        if r.status_code == 200:
            d = r.json()
            user = {"id": d.get("id"), "email": d.get("email")}
    except Exception as e:  # noqa: BLE001
        _log(f"auth check failed: {e}")
    _user_cache[token] = (now, user)
    if len(_user_cache) > 2000:
        _user_cache.clear()
    return user


def _jwt_role(token: str) -> str | None:
    """Read the role claim of a Supabase key (no verification, nothing secret is returned)."""
    import base64, json
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part)).get("role")
    except Exception:  # noqa: BLE001
        return None


async def diagnose() -> dict:
    """Health details for the database connection, safe to show publicly."""
    out = {"configured": ENABLED, "service_key_role": _jwt_role(SERVICE_KEY) if SERVICE_KEY else None,
           "anon_key_role": _jwt_role(ANON_KEY) if ANON_KEY else None}
    if not ENABLED:
        return out
    try:
        r = await _c.get(f"{URL}/rest/v1/runs", headers=_headers(), params={"select": "id", "limit": "1"}, timeout=4)
        out["read_status"] = r.status_code
        if r.status_code >= 300:
            out["read_error"] = r.text[:160]
        s = await _c.get(f"{URL}/storage/v1/bucket/outputs", headers=_headers(), timeout=4)
        out["storage_status"] = s.status_code
    except Exception as e:  # noqa: BLE001
        out["error"] = type(e).__name__
    return out
