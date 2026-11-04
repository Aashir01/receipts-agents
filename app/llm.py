"""Vultr Serverless Inference client (OpenAI-compatible) with model fallback.

Handles reasoning models that spend part of the token budget thinking:
- generous budgets, and one automatic retry with a bigger budget when a reply
  is cut off (finish_reason == "length") before any answer text appears;
- <think> blocks are stripped; answers returned in a separate reasoning field
  are recovered when the main content is empty;
- failures report finish_reason and token usage so they can be diagnosed.
"""

import json
import os
import re
import time

import httpx

BASE_URL = os.environ.get("INFERENCE_BASE_URL", "https://api.vultrinference.com/v1").rstrip("/")
API_KEY = os.environ.get("VULTR_INFERENCE_API_KEY", "")
MODEL_MAIN = os.environ.get("MODEL_MAIN", "minimax-m3.1-flash")
MODEL_FALLBACK = os.environ.get("MODEL_FALLBACK", "deepseek-v4.1-flash-1017")
MAX_TOKENS_CAP = int(os.environ.get("LLM_MAX_TOKENS_CAP", "16000"))
# Optional extra request fields, e.g. LLM_EXTRA_JSON={"reasoning_effort":"low"}
try:
    EXTRA_BODY = json.loads(os.environ.get("LLM_EXTRA_JSON", "") or "{}")
except json.JSONDecodeError:
    EXTRA_BODY = {}

_client = httpx.AsyncClient(timeout=httpx.Timeout(float(os.environ.get("LLM_TIMEOUT_S", "60")), connect=10))


class LLMError(RuntimeError):
    pass


async def _call(model: str, messages: list[dict], max_tokens: int, temperature: float) -> dict:
    body = {"model": model, "messages": messages, "max_tokens": max_tokens,
            "temperature": temperature, **EXTRA_BODY}
    r = await _client.post(f"{BASE_URL}/chat/completions",
                           headers={"Authorization": f"Bearer {API_KEY}"}, json=body)
    if r.status_code != 200:
        raise LLMError(f"HTTP {r.status_code}: {r.text[:200]}")
    return r.json()


def _answer_text(data: dict) -> tuple[str, str, dict]:
    choice = data["choices"][0]
    msg = choice.get("message") or {}
    finish = choice.get("finish_reason") or "?"
    text = strip_thinking(msg.get("content") or "")
    if not text:
        # Some servers put everything in a separate reasoning field.
        for key in ("reasoning_content", "reasoning"):
            alt = msg.get(key)
            if isinstance(alt, str) and "```" in alt:
                text = alt.strip()
                break
    info = {"finish_reason": finish, "usage": data.get("usage", {}),
            "fields": sorted(k for k, v in msg.items() if v)}
    return text, finish, info


async def chat(messages: list[dict], max_tokens: int = 4000, temperature: float = 0.2) -> dict:
    """Call the main model (retrying once with a bigger budget if cut off), then the fallback."""
    if not API_KEY:
        raise LLMError("VULTR_INFERENCE_API_KEY is not set")
    errors = []
    for model in (MODEL_MAIN, MODEL_FALLBACK):
        budget = min(max_tokens, MAX_TOKENS_CAP)
        for _ in range(2):
            start = time.monotonic()
            try:
                data = await _call(model, messages, budget, temperature)
                text, finish, info = _answer_text(data)
                if text:
                    return {"text": text, "model": model,
                            "latency_s": round(time.monotonic() - start, 2),
                            "usage": info["usage"], "finish_reason": finish}
                msg = f"{model}: empty answer (finish={finish}, usage={info['usage']}, fields={info['fields']})"
                print("[llm]", msg, flush=True)
                errors.append(msg)
                if finish == "length" and budget < MAX_TOKENS_CAP:
                    budget = min(budget * 2, MAX_TOKENS_CAP)
                    continue
                break
            except Exception as e:  # noqa: BLE001 - any failure moves on
                msg = f"{model}: {type(e).__name__}: {str(e)[:200]}"
                print("[llm]", msg, flush=True)
                errors.append(msg)
                break
    raise LLMError("All models failed. " + " | ".join(errors[-3:]))


def strip_thinking(text: str) -> str:
    """Remove <think>...</think> blocks; an unclosed block means the answer never started."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    if "<think>" in text:
        text = text.split("<think>")[0]
    return text.strip()


def extract_code(text: str) -> str:
    """Pull Python code out of a reply, tolerating missing closing fences."""
    blocks = re.findall(r"```(?:python|py)?\s*\n(.*?)```", text, flags=re.DOTALL)
    if blocks:
        return max(blocks, key=len).strip()
    m = re.search(r"```(?:python|py)?\s*\n(.*)", text, flags=re.DOTALL)
    if m:
        return m.group(1).strip()
    return text.strip()


SAFETY_MODEL = os.environ.get("SAFETY_MODEL", "nemotron-3.5-content-safety")


async def safety_check(text: str) -> dict:
    """Classify text with the Nemotron content-safety model.

    Returns {status: safe|unsafe|unavailable, categories, model, latency_s, raw}.
    Never raises: the guard must degrade to heuristics, not block the app.
    """
    start = time.monotonic()
    out = {"status": "unavailable", "categories": [], "model": SAFETY_MODEL, "latency_s": 0, "raw": ""}
    if not API_KEY:
        return out
    try:
        r = await _client.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={"model": SAFETY_MODEL, "max_tokens": 300, "temperature": 0,
                  "messages": [{"role": "user", "content": text[:6000]}]},
            timeout=25,
        )
        out["latency_s"] = round(time.monotonic() - start, 2)
        if r.status_code != 200:
            out["raw"] = f"HTTP {r.status_code}"
            return out
        msg = r.json()["choices"][0]["message"]
        raw = strip_thinking(msg.get("content") or "") or (msg.get("reasoning_content") or "")
        out["raw"] = raw[:400]
        low = raw.lower()
        verdict = None
        try:  # NemoGuard-style JSON: {"User Safety": "unsafe", "Safety Categories": "..."}
            data = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
            for k, v in data.items():
                if "safety" in k.lower() and "categor" not in k.lower() and isinstance(v, str):
                    verdict = v.strip().lower()
                if "categor" in k.lower() and v:
                    out["categories"] = [c.strip() for c in str(v).split(",") if c.strip()]
        except (ValueError, AttributeError):
            pass
        if verdict is None:
            verdict = "unsafe" if re.search(r"\bunsafe\b", low) else ("safe" if re.search(r"\bsafe\b", low) else None)
        if verdict in ("safe", "unsafe"):
            out["status"] = verdict
        return out
    except Exception as e:  # noqa: BLE001
        out["raw"] = f"{type(e).__name__}"
        out["latency_s"] = round(time.monotonic() - start, 2)
        return out


VISION_MODEL = os.environ.get("VISION_MODEL", "nemotron-3-nano-omni-30b-a3b-reasoning")


async def vision_check(image_b64: str, claims: str) -> dict:
    """Ask a vision model whether a screenshot supports the agent's claims.
    Returns {status: consistent|inconsistent|unavailable, notes, model, latency_s}. Never raises."""
    start = time.monotonic()
    out = {"status": "unavailable", "notes": "", "model": VISION_MODEL, "latency_s": 0}
    if not API_KEY or not image_b64:
        return out
    prompt = ("You are checking a browser agent's work. Look at the screenshot and decide whether it is "
              "consistent with the claims below (the claims may cover more than one page; judge what is "
              "visible). Reply with ONLY JSON: {\"consistent\": true|false, \"notes\": \"one sentence\"}.\n\n"
              f"Claims:\n{claims[:2500]}")
    try:
        r = await _client.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={"model": VISION_MODEL, "max_tokens": 1500, "temperature": 0,
                  "messages": [{"role": "user", "content": [
                      {"type": "text", "text": prompt},
                      {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_b64}"}}]}]},
            timeout=60,
        )
        out["latency_s"] = round(time.monotonic() - start, 2)
        if r.status_code != 200:
            out["notes"] = f"vision model returned HTTP {r.status_code}"
            return out
        msg = r.json()["choices"][0]["message"]
        raw = strip_thinking(msg.get("content") or "")
        try:
            data = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
            verdict = data.get("consistent", data.get("status"))
            if isinstance(verdict, str):
                verdict = verdict.strip().lower() in ("true", "yes", "consistent")
            out["status"] = "consistent" if verdict is True else "inconsistent"
            out["notes"] = str(data.get("notes", ""))[:300]
        except (ValueError, AttributeError):
            low = raw.lower()
            if "inconsistent" in low or "not consistent" in low:
                out["status"] = "inconsistent"
            elif "consistent" in low or low.startswith("yes"):
                out["status"] = "consistent"
            out["notes"] = raw[:300]
        return out
    except Exception as e:  # noqa: BLE001
        out["notes"] = type(e).__name__
        out["latency_s"] = round(time.monotonic() - start, 2)
        return out
