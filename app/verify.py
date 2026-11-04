"""Two-key verification: compare headline numbers from the analysis with an
independent recomputation done by separately written code in a fresh sandbox."""

import json
import math
import re

_NUM = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")


def numbers_in(text: str) -> list[float]:
    clean = re.sub(r"(?<=\d),(?=\d{3}\b)", "", text)        # 1,234,567.8 -> 1234567.8
    out = []
    for m in _NUM.findall(clean):
        try:
            out.append(float(m))
        except ValueError:
            pass
    return out


def close(a: float, b: float, rel: float = 0.005, abs_tol: float = 0.01) -> bool:
    """Equal within 0.5% (printed values are often rounded) or within 0.01."""
    if any(isinstance(x, bool) or x is None or (isinstance(x, float) and math.isnan(x)) for x in (a, b)):
        return False
    return abs(a - b) <= max(abs_tol, rel * max(abs(a), abs(b)))


def parse_quantities(reply: str, stdout: str, limit: int = 4) -> list[dict]:
    """Parse the extractor's JSON and keep only numbers that really appear in the output."""
    m = re.search(r"\[.*\]", reply, re.DOTALL)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    printed = numbers_in(stdout)
    good, seen = [], set()
    for it in items if isinstance(items, list) else []:
        try:
            name = re.sub(r"[^A-Za-z0-9_]", "_", str(it["name"]))[:60].strip("_")
            value = float(str(it["value"]).replace(",", "").rstrip("%"))
            definition = str(it.get("definition", ""))[:300]
        except (KeyError, TypeError, ValueError):
            continue
        if not name or name in seen:
            continue
        # The number must literally exist in what the sandbox printed (no invented values).
        if not any(close(value, p, rel=1e-6, abs_tol=1e-9) for p in printed):
            continue
        seen.add(name)
        good.append({"name": name, "value": value, "definition": definition})
        if len(good) >= limit:
            break
    return good


def parse_recomputed(stdout: str) -> dict:
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                return {str(k): v for k, v in data.items()} if isinstance(data, dict) else {}
            except json.JSONDecodeError:
                return {}
    return {}


def compare(quantities: list[dict], recomputed: dict) -> dict:
    checks = []
    for q in quantities:
        raw = recomputed.get(q["name"])
        try:
            val = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            val = None
        checks.append({"name": q["name"], "definition": q["definition"], "original": q["value"],
                       "recomputed": val, "match": val is not None and close(q["value"], val)})
    if not checks:
        status = "inconclusive"
    elif all(c["match"] for c in checks):
        status = "verified"
    elif any(c["recomputed"] is None for c in checks) and not any(
            (not c["match"]) and c["recomputed"] is not None for c in checks):
        status = "inconclusive"
    else:
        status = "mismatch"
    return {"status": status, "checks": checks}
