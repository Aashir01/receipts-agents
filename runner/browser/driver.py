"""
Browser driver that runs INSIDE the gVisor browser sandbox.

It executes a fixed vocabulary of actions chosen by the agent - never arbitrary code -
through headless Chromium whose only network route is the per-task egress proxy.
Writes screenshots and result.json into the work folder.
"""

import json
import os

from playwright.sync_api import sync_playwright

WORK = os.environ.get("WORK", "/work")
MAX_TEXT = 6000
NAV_ACTIONS = {"goto", "click", "press", "screenshot"}

task = json.load(open(os.path.join(WORK, "task.json")))
actions = task.get("actions", [])[:25]
proxy = task.get("proxy")
out = {"steps": [], "final_url": None, "title": None, "page_text": "", "links": [], "fields": []}

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=True,
        proxy={"server": proxy} if proxy else None,
        # gVisor is the sandbox; Chromium's own setuid sandbox cannot run unprivileged inside it.
        args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--no-first-run",
              "--proxy-bypass-list=<-loopback>",   # no implicit localhost bypass: everything goes via the proxy
              "--disable-background-networking", "--disable-component-update", "--disable-sync"],
    )
    ctx = browser.new_context(viewport={"width": 1280, "height": 860}, accept_downloads=False,
                              user_agent="ReceiptsResearchAgent/1.0 (sandboxed browser; human-approved actions)")
    page = ctx.new_page()
    page.set_default_timeout(15000)
    shots = 0
    for i, a in enumerate(actions):
        kind = a.get("type")
        rec = {"i": i, "type": kind}
        try:
            if kind == "goto":
                resp = page.goto(a["url"], wait_until="domcontentloaded")
                rec["status"] = resp.status if resp else None
                if resp is not None and resp.status == 403 and not page.inner_text("body").strip():
                    raise PermissionError("blocked by the egress proxy (site not on this task's allowlist)")
            elif kind == "click":
                if a.get("selector"):
                    page.click(a["selector"])
                else:
                    page.get_by_text(a["text"], exact=False).first.click()
                page.wait_for_load_state("domcontentloaded")
            elif kind == "fill":
                page.fill(a["selector"], str(a.get("value", "")))
            elif kind == "select":
                page.select_option(a["selector"], str(a.get("value", "")))
            elif kind == "check":
                page.check(a["selector"])
            elif kind == "press":
                page.press(a.get("selector") or "body", a.get("key", "Enter"))
                page.wait_for_load_state("domcontentloaded")
            elif kind == "wait":
                page.wait_for_timeout(min(int(a.get("ms", 1000)), 5000))
            elif kind == "extract":
                els = page.query_selector_all(a.get("selector") or "body")[:200]
                rec["texts"] = [e.inner_text()[:400] for e in els]
            elif kind == "screenshot":
                pass
            else:
                raise ValueError(f"unknown action type {kind!r}")
            rec["ok"] = True
        except Exception as e:  # noqa: BLE001
            rec["ok"] = False
            rec["error"] = f"{type(e).__name__}: {str(e)[:300]}"
        rec["url"] = page.url
        if kind in NAV_ACTIONS or not rec["ok"]:
            shots += 1
            name = f"shot_{shots}.png"
            try:
                page.screenshot(path=os.path.join(WORK, name))
                rec["screenshot"] = name
            except Exception:  # noqa: BLE001
                pass
        out["steps"].append(rec)
        if not rec["ok"]:
            break

    out["final_url"] = page.url
    try:
        out["title"] = page.title()
        out["page_text"] = page.inner_text("body")[:MAX_TEXT]
        out["links"] = page.eval_on_selector_all(
            "a[href]", "els => els.slice(0, 60).map(e => ({text: (e.innerText || '').trim().slice(0, 80), href: e.href}))")
        out["fields"] = page.eval_on_selector_all(
            "input, select, textarea, button",
            "els => els.slice(0, 50).map(e => ({tag: e.tagName.toLowerCase(), type: e.type || '', name: e.name || '', "
            "id: e.id || '', label: ((e.labels && e.labels[0] && e.labels[0].innerText) || e.placeholder || "
            "(e.tagName === 'BUTTON' ? e.innerText : '') || '').trim().slice(0, 60)}))")
    except Exception:  # noqa: BLE001
        pass
    browser.close()

json.dump(out, open(os.path.join(WORK, "result.json"), "w"))
print(json.dumps({"steps": len(out["steps"]), "final_url": out["final_url"], "shots": shots}))
