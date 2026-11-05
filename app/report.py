"""
PDF report for a finished run (F10).

The report is built INSIDE the sandbox by a fixed, human-written script (never model-written),
from the run's recorded events and its stored charts or screenshots. The PDF gets its own
receipt like any other sandbox job, so its hash is on record.
"""

import json
import re

MAX_IMAGES = 4

REPORT_CODE = r'''
# Fixed report builder: reads report.json and images from /work, writes report.pdf.
import json, textwrap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
from matplotlib.backends.backend_pdf import PdfPages

R = json.load(open("report.json"))
W, H = 8.27, 11.69                      # A4 portrait, inches
INK, MUTED, BLUE, RED, GREEN = "#16202E", "#5B6676", "#007BFC", "#C2122B", "#18794E"
STAMP = {"verified": ("VERIFIED", GREEN), "mismatch": ("MISMATCH", RED), "inconclusive": ("INCONCLUSIVE", MUTED)}


class Page:
    def __init__(self, pdf):
        self.pdf, self.fig, self.y = pdf, None, 0
        self.new()

    def new(self):
        if self.fig is not None:
            self.finish()
        self.fig = plt.figure(figsize=(W, H))
        self.fig.text(0.07, 0.965, "Receipts", fontsize=13, weight="bold", color=INK)
        self.fig.text(0.93, 0.965, f"Run {R['run_id'][:8]}", fontsize=8, color=MUTED, ha="right", family="monospace")
        self.fig.add_artist(plt.Line2D([0.07, 0.93], [0.955, 0.955], color="#D5DBE3", lw=0.8))
        self.y = 0.93

    def finish(self):
        self.fig.text(0.5, 0.025, "Built inside a sealed gVisor sandbox on Vultr by a fixed script. "
                      "Every number comes from sandbox output on record.", fontsize=7, color=MUTED, ha="center")
        self.pdf.savefig(self.fig)
        plt.close(self.fig)

    def need(self, h):
        if self.y - h < 0.06:
            self.new()

    def text(self, s, size=9.5, color=INK, weight="normal", width=95, mono=False, gap=0.004):
        lines = []
        for para in str(s).split("\n"):
            lines += textwrap.wrap(para, width) or [""]
        step = size / 72 / H * 1.45
        for ln in lines:
            self.need(step)
            self.fig.text(0.07, self.y, ln, fontsize=size, color=color, weight=weight, va="top",
                          family="monospace" if mono else "DejaVu Sans")
            self.y -= step
        self.y -= gap

    def heading(self, s):
        self.need(0.06)
        self.y -= 0.012
        self.text(s, size=12, weight="bold", gap=0.006)

    def kv(self, rows):
        step = 9 / 72 / H * 1.5
        for k, v in rows:
            self.need(step)
            self.fig.text(0.07, self.y, str(k), fontsize=8.5, color=MUTED, va="top")
            self.fig.text(0.32, self.y, str(v)[:90], fontsize=8.5, color=INK, va="top", family="monospace")
            self.y -= step
        self.y -= 0.006

    def image(self, path, title, caption):
        img = mpimg.imread(path)
        h_in = min(4.2, 6.9 * img.shape[0] / img.shape[1])
        h = h_in / H
        self.need(h + 0.08)                       # keep the heading with its image
        self.heading(title)
        ax = self.fig.add_axes([0.07, self.y - h, 0.86, h])
        ax.imshow(img)
        ax.axis("off")
        self.y -= h + 0.008
        self.text(caption, size=7.5, color=MUTED)


with PdfPages("report.pdf") as pdf:
    d = pdf.infodict()
    d["Title"] = f"Receipts report {R['run_id'][:8]}"
    d["Creator"] = "Receipts (sandboxed report builder)"
    p = Page(pdf)
    if R.get("verified") in STAMP:
        label, color = STAMP[R["verified"]]
        p.fig.text(0.93, 0.933, label, fontsize=11, weight="bold", color=color, ha="right", va="top",
                   rotation=4, bbox=dict(boxstyle="round,pad=0.3", fc="none", ec=color, lw=1.6))
    p.text(R["mode_label"], size=9, color=BLUE, weight="bold", gap=0.012)
    p.text(R["question"], size=15, weight="bold", width=58, gap=0.01)
    p.kv(R["meta"])

    p.heading("Answer")
    p.text(R["answer"] or "No answer was produced.", size=10.5, width=88)
    if R.get("grounded"):
        p.text(R["grounded"], size=8, color=GREEN)

    if R.get("checks"):
        p.heading("Independent verification")
        p.text(R["check_note"], size=8.5, color=MUTED)
        for c in R["checks"]:
            p.text(f"{'MATCH   ' if c['match'] else 'NO MATCH'}  {c['name']}: printed {c['original']}, "
                   f"recomputed {c['recomputed']}", size=8.5, mono=True, color=GREEN if c["match"] else RED)

    if R.get("evidence"):
        p.heading("Evidence from the pages the browser loaded")
        for q in R["evidence"]:
            p.text(f"{'FOUND  ' if q['found'] else 'MISSING'}  \"{q['quote']}\"", size=8.5, mono=True,
                   color=GREEN if q["found"] else RED)

    for img in R["images"]:
        p.image(img["file"], img["title"], img["caption"])

    p.heading("Containment")
    p.kv(R["containment"])
    for e in R["events"]:
        p.text(f"- {e}", size=8, color=MUTED, width=110)

    p.heading("Sandbox receipts")
    for rc in R["receipts"]:
        p.kv(rc)

    if R.get("code"):
        p.heading("Final code that produced the answer")
        p.text(R["code"], size=7.2, mono=True, width=118, color=INK)
    p.finish()

import os
print(json.dumps({"pages": "ok", "bytes": os.path.getsize("report.pdf")}))
'''


def _plain(md: str) -> str:
    s = re.sub(r"\*\*([^*]+)\*\*", r"\1", md or "")
    s = re.sub(r"`([^`]+)`", r"\1", s)
    s = re.sub(r"^#+\s*", "", s, flags=re.M)
    return re.sub(r"^\s*[-*]\s+", "- ", s, flags=re.M)


def build(bundle: dict) -> tuple[dict, list[dict]]:
    """Turn a stored run into report.json content plus the images to fetch from Storage.
    Returns (payload, [{"receipt_id", "name", "file"}])."""
    run, ds, events = bundle["run"], bundle.get("dataset"), bundle["events"]
    research = any(e.get("type") == "run" and e.get("mode") == "research" for e in events)
    answer = next((e for e in reversed(events) if e.get("type") == "answer"), {})
    verify_ev = next((e for e in reversed(events) if e.get("type") == "verify"), None)
    web = next((e for e in reversed(events) if e.get("type") == "web_verify"), None)
    vm_ready = next((e for e in events if e.get("type") == "vm" and e.get("status") == "ready"), None)
    vm_gone = next((e for e in events if e.get("type") == "vm" and e.get("status") == "destroyed"), None)

    jobs = [e for e in events if e.get("type") in ("explore", "exec", "browse", "verify") and e.get("result")]
    receipts, contained = [], []
    for e in jobs:
        r = e["result"]
        rc = e.get("receipt") or {}
        label = {"explore": "Explore", "exec": f"Analysis attempt {e.get('attempt')}",
                 "browse": f"Browser turn {e.get('turn')}", "verify": "Auditor (verification)"}[e["type"]]
        rows = [(label, f"job {r.get('job_id')}"), ("status", f"{r.get('status')} (exit {r.get('exit_code')})"),
                ("time", f"{r.get('duration_s')} s")]
        if rc.get("code_sha256"):
            rows.append(("code sha256", rc["code_sha256"][:32] + "..."))
        lim = r.get("limits") or {}
        rows.append(("machine", lim.get("machine") or "shared executor VM (gVisor)"))
        for o in rc.get("outputs") or []:
            rows.append((o["name"], f"sha256 {o['sha256'][:24]}..."))
        receipts.append(rows)
        for ev in r.get("events") or []:
            if ev.get("kind") in ("blocked", "killed", "error"):
                contained.append(ev.get("detail", ""))

    images: list[dict] = []
    final_exec = next((e for e in reversed(events) if e.get("type") == "exec" and e["result"]["status"] == "ok"), None)
    if final_exec and final_exec.get("receipt_id"):
        for o in final_exec.get("outputs") or []:
            if o["name"].lower().endswith(".png") and len(images) < MAX_IMAGES:
                images.append({"receipt_id": final_exec["receipt_id"], "name": o["name"], "title": o["name"],
                               "caption": f"Saved by sandbox job {final_exec['result']['job_id']}"})
    for b in reversed([e for e in events if e.get("type") == "browse" and e.get("receipt_id")]):
        pngs = [o for o in b.get("outputs") or [] if o["name"].endswith(".png")]
        if pngs and len(images) < 2:
            o = pngs[-1]
            images.append({"receipt_id": b["receipt_id"], "name": o["name"], "title": f"Browser turn {b['turn']}: final page",
                           "caption": f"Screenshot from sandboxed browser job {b['result']['job_id']}, {b.get('final_url') or ''}"})
    for i, img in enumerate(images):
        img["file"] = f"img_{i + 1}.png"

    code_ev = next((e for e in reversed(events) if e.get("type") == "code"), None)
    meta = [("Status", f"{run.get('status')}" + (f", {run.get('verified')}" if run.get("verified") else "")),
            ("Started", (run.get("created_at") or "")[:19].replace("T", " ") + " UTC"),
            ("Total time", f"{run.get('total_s')} s" if run.get("total_s") is not None else "?"),
            ("Answer model", answer.get("model") or "?")]
    if ds:
        meta.insert(0, ("Dataset", f"{ds['filename']}  sha256 {ds['sha256'][:16]}..."))
    if research:
        scope = next((e for e in events if e.get("type") == "scope"), {})
        meta.insert(0, ("Sites allowed", ", ".join(scope.get("domains") or [])))

    containment = [("Sandbox", "gVisor (runsc), non-root, read-only root, all capabilities dropped"),
                   ("Network", "allowlist proxy only" if research else "none"),
                   ("Secrets inside", "0"),
                   ("Sandbox jobs", str(len(jobs))),
                   ("Actions contained", str(len(contained)))]
    if vm_ready:
        containment.insert(0, ("Machine", f"fresh Vultr VM {vm_ready['label']}, used for this run only"))
    if vm_gone:
        containment.insert(1, ("VM destroyed", "yes, confirmed by the Vultr API" if vm_gone.get("confirmed")
                               else "requested"))

    payload = {
        "run_id": run["id"], "question": run.get("question") or "",
        "mode_label": "Web research report" if research else "Data analysis report",
        "verified": (verify_ev or {}).get("status") or (web or {}).get("status") or run.get("verified"),
        "meta": meta, "answer": _plain(answer.get("markdown", "")),
        "grounded": (f"Every number above was printed by sandbox job {answer['grounded_in_job']}."
                     if answer.get("grounded_in_job") and not research else
                     f"Based on pages loaded by sandboxed browser job {answer['grounded_in_job']}."
                     if answer.get("grounded_in_job") else ""),
        "checks": (verify_ev or {}).get("checks") or [],
        "check_note": "A second script, written without seeing the analysis, recomputed the headline numbers "
                      "in a fresh sandbox. Match tolerance 0.5%.",
        "evidence": ((web or {}).get("evidence") or {}).get("checks") or [],
        "images": [{k: i[k] for k in ("file", "title", "caption")} for i in images],
        "containment": containment, "events": contained[:12], "receipts": receipts[:10],
        "code": (code_ev or {}).get("code", "")[:6000] if not research else "",
    }
    return payload, images


def payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, default=str).encode()
