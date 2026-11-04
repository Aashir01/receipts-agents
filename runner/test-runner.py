#!/usr/bin/env python3
"""
Run on the APP server (VM 1) to prove the runner works across the VPC.
Usage:  RUNNER_URL=http://10.6.96.6:8080 RUNNER_TOKEN=xxxx python3 test-runner.py
Uses only the Python standard library.
"""
import base64
import json
import os
import urllib.request

URL = os.environ["RUNNER_URL"].rstrip("/")
TOKEN = os.environ["RUNNER_TOKEN"]

CSV = b"date,region,sales\n2026-01-01,North,10\n2026-01-02,South,20\n2026-01-03,North,5\n"
FILES = [{"name": "data.csv", "content_b64": base64.b64encode(CSV).decode()}]


def run(code, files=None, **kw):
    body = json.dumps({"code": code, "files": files or [], **kw}).encode()
    req = urllib.request.Request(
        f"{URL}/run", data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Runner-Token": TOKEN},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def show(title, r, expect):
    ok = expect(r)
    print(f"\n{'PASS' if ok else 'FAIL'}  {title}")
    print(f"  status={r['status']} exit={r['exit_code']} time={r['duration_s']}s")
    if r["stdout"].strip():
        print("  stdout:", r["stdout"].strip().replace("\n", " | ")[:200])
    if r["stderr"].strip():
        print("  stderr:", r["stderr"].strip().splitlines()[-1][:200])
    for e in r["events"]:
        print(f"  [{e['kind']}] {e['detail']}")
    if r["outputs"]:
        print("  outputs:", [(o["name"], o["size"]) for o in r["outputs"]])
    return ok


results = [
    show("1. Real analysis: CSV in, numbers + chart out", run(
        "import pandas as pd, matplotlib.pyplot as plt\n"
        "df = pd.read_csv('data.csv')\n"
        "t = df.groupby('region')['sales'].sum()\n"
        "print(t.to_string())\n"
        "t.plot(kind='bar'); plt.tight_layout(); plt.savefig('chart.png')\n",
        FILES), lambda r: r["status"] == "ok" and any(o["name"] == "chart.png" for o in r["outputs"])),

    show("2. Bad code returns a real traceback (for self-healing)", run(
        "import pandas as pd\nprint(pd.read_csv('data.csv')['Region'])\n", FILES),
        lambda r: r["status"] == "error" and "KeyError" in r["stderr"]),

    show("3. Data exfiltration attempt is blocked", run(
        "import urllib.request\nurllib.request.urlopen('https://example.com')\n"),
        lambda r: r["status"] == "error" and any(e["kind"] == "blocked" for e in r["events"])),

    show("4. Secrets are not inside the sandbox", run(
        "import os\nprint('env vars:', sorted(os.environ))\n"
        "print('secrets found:', [k for k in os.environ if k in "
        "('RUNNER_TOKEN', 'VULTR_INFERENCE_API_KEY', 'VULTR_API_KEY')])\n"),
        lambda r: r["status"] == "ok" and "secrets found: []" in r["stdout"]),

    show("5. Infinite loop is killed at the time limit", run(
        "while True: pass\n", timeout_s=5),
        lambda r: r["status"] == "timeout"),

    show("6. Memory bomb is killed at the memory limit", run(
        "x = b'a' * (1024**3)\nprint('allocated')\n", memory_mb=256),
        lambda r: r["status"] == "oom_killed"),

    show("7. Host filesystem is read-only", run(
        "open('/etc/pwned', 'w').write('x')\n"),
        lambda r: r["status"] == "error" and any(e["kind"] == "blocked" for e in r["events"])),
]

print(f"\n{sum(results)}/{len(results)} passed")
