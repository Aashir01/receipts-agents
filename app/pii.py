"""
Privacy firewall: the model never sees personal data.

Everything the app sends to a language model passes through a per-run Masker. Emails, phone
numbers, card numbers, IBANs, social security numbers, IP addresses and people's names (taken
from name-like columns by the sandboxed profiler) are replaced with stable tokens such as
[EMAIL_3]. The model reasons over tokens; its replies (code, plans, answers) are un-masked on the
app server before they run or reach you, so the analysis still works on the real values.
"""

import re

_PATTERNS = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("PHONE", re.compile(r"(?:\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4})|(?:\(\d{3}\)\s?\d{3}[-.\s]\d{4})|"
                         r"(?:\b\d{3}[-.]\d{3}[-.]\d{4}\b)|(?:\b0\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b)")),
    ("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]
_TOKEN = re.compile(r"\[(EMAIL|CARD|IBAN|SSN|PHONE|IP|NAME)_(\d+)\]")


def _luhn(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            n -= 9 if n > 9 else 0
        total += n
    return total % 10 == 0


class Masker:
    def __init__(self, enabled: bool = True, names: list[str] | None = None):
        self.enabled = enabled
        self.fwd: dict[str, str] = {}      # value -> token
        self.back: dict[str, str] = {}     # token -> value
        self.count: dict[str, int] = {}
        self.replacements = 0
        names = sorted({n.strip() for n in names or [] if n and len(n.strip()) >= 3}, key=len, reverse=True)[:5000]
        self._names = re.compile(r"(?<![\w\[])(" + "|".join(re.escape(n) for n in names) + r")(?![\w\]])") if names else None

    def _tok(self, kind: str, value: str) -> str:
        if value in self.fwd:
            self.replacements += 1
            return self.fwd[value]
        self.count[kind] = self.count.get(kind, 0) + 1
        tok = f"[{kind}_{self.count[kind]}]"
        self.fwd[value], self.back[tok] = tok, value
        self.replacements += 1
        return tok

    def mask(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        if self._names:
            text = self._names.sub(lambda m: self._tok("NAME", m.group(1)), text)
        for kind, rx in _PATTERNS:
            def rep(m, kind=kind):
                v = m.group(0)
                if kind == "CARD" and not _luhn(v):
                    return v
                if kind == "PHONE" and sum(c.isdigit() for c in v) < 9:
                    return v
                return self._tok(kind, v)
            text = rx.sub(rep, text)
        return text

    def unmask(self, text: str) -> str:
        if not self.back or not text:
            return text
        return _TOKEN.sub(lambda m: self.back.get(m.group(0), m.group(0)), text)

    def mask_messages(self, messages: list[dict]) -> list[dict]:
        if not self.enabled:
            return messages
        return [{**m, "content": self.mask(m["content"])} if isinstance(m.get("content"), str) else m for m in messages]

    def stats(self) -> dict:
        return {"enabled": self.enabled, "values": len(self.fwd), "replacements": self.replacements,
                "kinds": {k.lower(): v for k, v in sorted(self.count.items())}}


def names_from(ds: dict) -> list[str]:
    out = []
    for d in [ds] + list(ds.get("extra") or []):
        for vals in (d.get("pii_values") or {}).values():
            out += [str(v) for v in vals]
    return out
