#!/usr/bin/env python3
"""
Verify a Countersign receipt without trusting Countersign.

    pip install cryptography
    python verify.py <bundle folder or .zip>                 # offline, from a downloaded bundle
    python verify.py <bundle> --site https://agentrush.aashirnoman.dev   # also pin the app key from the site
    python verify.py --receipt <id> --site https://agentrush.aashirnoman.dev  # fetch the proof online

Checks: the receipt hashes to the digest in its ledger entry; the entry hashes correctly and carries
the app's Ed25519 countersignature; it links to the previous entry; the executor's Ed25519 signature
covers exactly the printed output and files in the receipt; and every file in the bundle matches.
"""

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    sys.exit("Please run: pip install cryptography")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ed_ok(pub_b64: str, sig_b64: str, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), data)
        return True
    except Exception:
        return False


def entry_hash(e: dict) -> str:
    return sha(canonical({k: v for k, v in e.items() if k not in ("hash", "app_sig")}))


def load(src: str):
    p = Path(src)
    if p.suffix == ".zip":
        z = zipfile.ZipFile(p)
        return json.loads(z.read("proof.json")), {n: z.read(n) for n in z.namelist()}
    files = {str(f.relative_to(p)).replace("\\", "/"): f.read_bytes() for f in p.rglob("*") if f.is_file()}
    return json.loads(files["proof.json"]), files


def get(url: str):
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("bundle", nargs="?")
    ap.add_argument("--site", help="pin the app's public key from this site's /api/keys")
    ap.add_argument("--receipt", help="fetch the proof for this receipt id from --site")
    a = ap.parse_args()
    files = {}
    if a.receipt:
        if not a.site:
            sys.exit("--receipt needs --site")
        proof = get(f"{a.site.rstrip('/')}/api/receipts/{a.receipt}/proof")
    elif a.bundle:
        proof, files = load(a.bundle)
    else:
        ap.print_help()
        return 2
    app_pub = proof["app_key"]["public_key"]
    if a.site:
        site_pub = get(f"{a.site.rstrip('/')}/api/keys")["app"]["public_key"]
        if site_pub != app_pub:
            print("FAIL  the bundle's app key differs from the key the site publishes")
            return 1
        app_pub = site_pub

    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        mark = {True: "PASS", False: "FAIL", None: "SKIP"}[ok]
        print(f"{mark}  {name}" + (f"  ({detail})" if detail else ""))

    core, entry, prev, ex = proof["core"], proof["entry"], proof.get("prev_entry"), proof.get("executor") or {}
    check("receipt hashes to the digest in its ledger entry", sha(canonical(core)) == entry["receipt_digest"])
    check("ledger entry hash", entry_hash(entry) == entry["hash"], f"entry #{entry['seq']}")
    check("app countersignature (Ed25519)", ed_ok(app_pub, entry["app_sig"], entry["hash"].encode()), entry["app_key_id"])
    if entry["seq"] == 1:
        check("chain link", entry["prev"] == "0" * 64, "first entry")
    elif prev:
        check("chain link", entry_hash(prev) == prev["hash"] and prev["hash"] == entry["prev"], f"entry #{prev['seq']} -> #{entry['seq']}")
    else:
        check("chain link", None, "previous entry not included")
    if ex.get("signed"):
        pl = ex["payload"]
        check("executor signature (Ed25519)", ed_ok(ex["pub"], ex["sig"], canonical(pl)) and entry.get("executor_sig") == ex["sig"],
              f"{ex['key_id']} on {pl.get('host')}")
        check("executor signature is bound into the receipt", core.get("executor_payload_sha256") == sha(canonical(pl)))
        if pl.get("kind") == "run":
            check("signed printed output = receipt", pl.get("stdout_sha256") == core["stdout_sha256"])
            check("signed output files = receipt", sorted(pl.get("outputs") or [], key=lambda o: o["name"]) == core["outputs"])
    else:
        check("executor signature", None, "this receipt was made before the executor signed")
    if files:
        if "code.py" in files:
            check("code.py matches the receipt", sha(files["code.py"]) == core["code_sha256"])
        if "executed/main.py" in files and ex.get("signed"):
            check("executed script matches the executor's signature", sha(files["executed/main.py"]) == ex["payload"].get("script_sha256"))
        if "stdout.txt" in files and len(files["stdout.txt"]) < 19000:      # long output is stored truncated
            check("stdout.txt matches the receipt", sha(files["stdout.txt"]) == core["stdout_sha256"])
        for o in core["outputs"]:
            f = files.get(f"outputs/{o['name']}")
            if f is not None:
                check(f"file {o['name']}", sha(f) == o["sha256"])
    bad = results.count(False)
    print("\nVERIFIED: every check passed." if not bad else f"\nNOT VERIFIED: {bad} check(s) failed.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
