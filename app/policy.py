"""
Policy as code: a compliance team writes the rules once; every run on the account obeys them.

The policy is a short YAML document stored per account in Vultr Object Storage. Each run loads it,
states which rules apply, enforces them, and records the policy's SHA-256 on its receipts, so an
auditor can see exactly which rules a run was held to.
"""

import fnmatch
import hashlib

import yaml

import archive

DEFAULT_TEXT = """# Countersign policy. Every run on this account is checked against these rules.
name: Default policy

privacy:
  mask_personal_data: true        # the model never sees emails, phones, card numbers or names

web:
  allowed_sites: ["*"]            # e.g. ["books.toscrape.com", "*.gov"]; anything else is refused

exports:
  max_rows_per_file: 10000        # result files with more rows are withheld

machines:
  fresh_vm_for_files_matching: [] # e.g. ["payroll", "confidential"]: those files never share a machine

approvals:
  risky_code: ask                 # ask: a human decides; never: refuse without asking
  browser_submit: ask             # ask or never

agent:
  max_fix_attempts: 3             # 1 to 5
"""

_MEM: dict[str, str] = {}


def _key(uid: str) -> str:
    return f"policies/{uid}.yaml"


def parse(text: str) -> tuple[dict | None, list[str]]:
    """Validate a policy. Returns (normalised policy, errors)."""
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        return None, [f"Not valid YAML: {str(e).splitlines()[0][:160]}"]
    if not isinstance(raw, dict):
        return None, ["The policy must be a YAML mapping (key: value lines)."]
    errs = []

    def section(name):
        v = raw.get(name) or {}
        if not isinstance(v, dict):
            errs.append(f"'{name}' must be a section with indented settings.")
            return {}
        return v

    pv, web, ex, mc, ap, ag = (section(n) for n in ("privacy", "web", "exports", "machines", "approvals", "agent"))
    sites = web.get("allowed_sites", ["*"])
    if isinstance(sites, str):
        sites = [sites]
    if not isinstance(sites, list) or not all(isinstance(s, str) and s.strip() for s in sites):
        errs.append("web.allowed_sites must be a list of domains, for example [\"*.gov\"].")
        sites = ["*"]
    rows = ex.get("max_rows_per_file", 10000)
    if not isinstance(rows, int) or rows < 1:
        errs.append("exports.max_rows_per_file must be a whole number above 0.")
        rows = 10000
    pats = mc.get("fresh_vm_for_files_matching", []) or []
    if isinstance(pats, str):
        pats = [pats]
    if not isinstance(pats, list):
        errs.append("machines.fresh_vm_for_files_matching must be a list of words.")
        pats = []
    for k in ("risky_code", "browser_submit"):
        if ap.get(k, "ask") not in ("ask", "never"):
            errs.append(f"approvals.{k} must be 'ask' or 'never'.")
    att = ag.get("max_fix_attempts", 3)
    if not isinstance(att, int) or not 1 <= att <= 5:
        errs.append("agent.max_fix_attempts must be between 1 and 5.")
        att = 3
    pol = {
        "name": str(raw.get("name") or "Unnamed policy")[:80],
        "mask_pii": bool(pv.get("mask_personal_data", True)),
        "allowed_sites": [s.strip().lower() for s in sites][:50],
        "max_rows": rows,
        "fresh_vm_patterns": [str(p).lower() for p in pats][:20],
        "risky_code": ap.get("risky_code", "ask") if ap.get("risky_code", "ask") in ("ask", "never") else "ask",
        "browser_submit": ap.get("browser_submit", "ask") if ap.get("browser_submit", "ask") in ("ask", "never") else "ask",
        "max_attempts": att,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }
    return (None if errs else pol), errs


DEFAULT, _ = parse(DEFAULT_TEXT)


async def text_for(uid: str | None) -> tuple[str, bool]:
    """(policy text, is_custom)."""
    if not uid:
        return DEFAULT_TEXT, False
    if uid in _MEM:
        return _MEM[uid], True
    t = await archive.get_text(_key(uid))
    if t:
        _MEM[uid] = t
        return t, True
    return DEFAULT_TEXT, False


async def for_user(user: dict | None) -> dict:
    text, custom = await text_for(user["id"] if user else None)
    pol, _ = parse(text)
    pol = pol or dict(DEFAULT)
    pol["custom"] = custom
    return pol


async def save(uid: str, text: str) -> tuple[dict | None, list[str]]:
    pol, errs = parse(text)
    if pol:
        _MEM[uid] = text
        await archive.put_text(_key(uid), text, "text/yaml")
    return pol, errs


def site_allowed(pol: dict, domain: str) -> bool:
    d = domain.lower().strip(".")
    for p in pol["allowed_sites"]:
        if p == "*" or fnmatch.fnmatch(d, p) or (p.startswith("*.") and d == p[2:]) or d == p:
            return True
    return False


def needs_fresh_vm(pol: dict, filenames: list[str]) -> str | None:
    for f in filenames:
        for p in pol["fresh_vm_patterns"]:
            if p and p in f.lower():
                return p
    return None


def summary(pol: dict) -> list[str]:
    """The rules, in plain words, for the timeline."""
    out = ["Personal data is masked before any model sees it" if pol["mask_pii"]
           else "Personal data masking is OFF for this account"]
    if pol["allowed_sites"] != ["*"]:
        out.append("Browsing only on: " + ", ".join(pol["allowed_sites"]))
    out.append(f"Result files over {pol['max_rows']:,} rows are withheld")
    if pol["fresh_vm_patterns"]:
        out.append("Files matching " + ", ".join(f"'{p}'" for p in pol["fresh_vm_patterns"]) + " run only on a fresh VM")
    out.append("Risky code is refused without asking" if pol["risky_code"] == "never" else "Risky code waits for a human")
    out.append("Browser submits are refused without asking" if pol["browser_submit"] == "never"
               else "Browser submits wait for a human")
    out.append(f"Up to {pol['max_attempts']} fix attempts")
    return out


def public(pol: dict) -> dict:
    return {"name": pol["name"], "sha256": pol["sha256"], "custom": pol.get("custom", False), "rules": summary(pol)}
