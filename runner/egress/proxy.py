"""
Egress proxy for one browsing task. It is the browser sandbox's ONLY way out.

- Allows only hosts on this task's allowlist (exact domain or its subdomains).
- Resolves DNS itself and connects to the resolved IP, refusing private, loopback,
  link-local (incl. cloud metadata 169.254.169.254), reserved and multicast addresses,
  so allowlisted names cannot be pointed at the internal network (DNS rebinding).
- Plain-HTTP requests are forced to `Connection: close` so one connection cannot be
  reused for a second, unchecked host.
- Caps total bytes transferred. Logs every decision as one JSON line on stdout.
"""

import asyncio
import ipaddress
import json
import os
import socket
import time
from urllib.parse import urlsplit

ALLOW = [d.strip().lower().strip(".") for d in os.environ.get("ALLOW", "").split(",") if d.strip()]
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE") == "1"          # local testing only, never set on the server
MAX_BYTES = int(os.environ.get("MAX_BYTES", str(60 * 1024 * 1024)))
PORT = int(os.environ.get("PORT", "8888"))
_total = 0


def log(**kw):
    print(json.dumps({"t": round(time.time(), 3), **kw}), flush=True)


def host_allowed(host: str) -> bool:
    h = host.lower().strip(".")
    return any(h == d or h.endswith("." + d) for d in ALLOW)


def ip_is_internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
            or a.is_multicast or a.is_unspecified)


async def resolve(host: str, port: int):
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for _fam, _t, _p, _c, sa in infos:
        ip = sa[0]
        if ALLOW_PRIVATE or not ip_is_internal(ip):
            return ip, None
        return None, ip
    return None, None


async def pipe(reader, writer):
    global _total
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            _total += len(data)
            if _total > MAX_BYTES:
                log(action="blocked", reason=f"byte limit of {MAX_BYTES} reached")
                break
            writer.write(data)
            await writer.drain()
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def deny(cw, code: int, text: str):
    cw.write(f"HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
    try:
        await cw.drain()
    finally:
        cw.close()


async def handle(cr, cw):
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 20)
    except Exception:  # noqa: BLE001
        cw.close()
        return
    first = head.split(b"\r\n", 1)[0].decode("latin-1")
    try:
        method, target, _ver = first.split(" ", 2)
    except ValueError:
        return await deny(cw, 400, "Bad Request")

    if method.upper() == "CONNECT":
        host, _, port_s = target.rpartition(":")
        host, port = host.strip("[]"), int(port_s or 443)
        url = None
    else:
        url = urlsplit(target)
        host, port = (url.hostname or ""), (url.port or 80)
    if url is None and port not in (443, 8443):
        log(action="blocked", host=host, port=port, reason="only HTTPS ports may be tunnelled")
        return await deny(cw, 403, "Forbidden")
    if not host_allowed(host):
        log(action="blocked", host=host, port=port, reason="not on this task's allowlist")
        return await deny(cw, 403, "Forbidden")
    try:
        ip, internal = await asyncio.wait_for(resolve(host, port), 10)
    except Exception:  # noqa: BLE001
        log(action="blocked", host=host, reason="DNS lookup failed")
        return await deny(cw, 502, "Bad Gateway")
    if not ip:
        log(action="blocked", host=host, reason=f"resolves to internal address {internal}")
        return await deny(cw, 403, "Forbidden")
    try:
        ur, uw = await asyncio.wait_for(asyncio.open_connection(ip, port), 10)
    except Exception:  # noqa: BLE001
        log(action="error", host=host, reason="could not connect")
        return await deny(cw, 502, "Bad Gateway")

    log(action="allowed", host=host, port=port, method=method.upper())
    if url is None:
        cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await cw.drain()
    else:
        path = (url.path or "/") + (f"?{url.query}" if url.query else "")
        lines = head.decode("latin-1").split("\r\n")
        lines[0] = f"{method} {path} HTTP/1.1"
        kept = [ln for ln in lines[1:] if ln and not ln.lower().startswith(("proxy-", "connection:", "keep-alive:"))]
        req = "\r\n".join([lines[0], *kept, "Connection: close", "", ""])
        uw.write(req.encode("latin-1"))
        await uw.drain()
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", PORT)
    log(action="ready", allow=ALLOW, port=PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
