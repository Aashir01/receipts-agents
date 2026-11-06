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
# Code writing goes to the model that answers code tasks fastest without exhausting its budget on
# hidden reasoning; the other model is the fallback.
MODEL_CODE = os.environ.get("MODEL_CODE", MODEL_FALLBACK)
MAX_TOKENS_CAP = int(os.environ.get("LLM_MAX_TOKENS_CAP", "32768"))
# Optional extra request fields, e.g. LLM_EXTRA_JSON={"reasoning_effort":"low"}
try:
    EXTRA_BODY = json.loads(os.environ.get("LLM_EXTRA_JSON", "") or "{}")
except json.JSONDecodeError:
    EXTRA_BODY = {}

_client = httpx.AsyncClient(timeout=httpx.Timeout(float(os.environ.get("LLM_TIMEOUT_S", "240")), connect=10))


_limit: dict[str, int] = {}  # per-model output limit learned from HTTP 400 replies


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
    from_reasoning = False
    if not text and finish != "length":
        # Some servers put a finished answer in a separate reasoning field. Never use it when the
        # model was cut off: then the reasoning holds only drafts and sketches with "..." gaps.
        for key in ("reasoning_content", "reasoning"):
            alt = msg.get(key)
            if isinstance(alt, str) and "```" in alt:
                text, from_reasoning = alt.strip(), True
                break
    info = {"finish_reason": finish, "usage": data.get("usage", {}), "from_reasoning": from_reasoning,
            "fields": sorted(k for k, v in msg.items() if v)}
    return text, finish, info


async def chat(messages: list[dict], max_tokens: int = 4000, temperature: float = 0.2,
               code: bool = False) -> dict:
    """Call the main model (retrying once with a bigger budget if cut off), then the fallback.

    code=True puts MODEL_CODE first. A fallback starts at the biggest budget already tried."""
    if not API_KEY:
        raise LLMError("VULTR_INFERENCE_API_KEY is not set")
    errors = []
    order = (MODEL_MAIN, MODEL_FALLBACK)
    if code:
        order = (MODEL_CODE,) + tuple(m for m in order if m != MODEL_CODE)
    budget = min(max_tokens, MAX_TOKENS_CAP)
    for model in order:
        for _ in range(2):
            start = time.monotonic()
            try:
                budget = min(budget, _limit.get(model, budget))
                try:
                    data = await _call(model, messages, budget, temperature)
                except LLMError as e:
                    # A budget above what this model allows comes back as HTTP 400: halve it and retry.
                    if "HTTP 400" in str(e) and "token" in str(e).lower() and budget > 4000:
                        budget //= 2
                        _limit[model] = budget
                        data = await _call(model, messages, budget, temperature)
                    else:
                        raise
                text, finish, info = _answer_text(data)
                if text and finish == "length" and budget < min(MAX_TOKENS_CAP, _limit.get(model, MAX_TOKENS_CAP)):
                    # cut off mid-answer: a partial script or JSON is worse than a slower full one
                    print(f"[llm] {model}: answer cut off at {budget} tokens; retrying with more", flush=True)
                    errors.append(f"{model}: cut off at {budget} tokens")
                    budget = min(budget * 2, MAX_TOKENS_CAP)
                    continue
                if text:
                    return {"text": text, "model": model,
                            "latency_s": round(time.monotonic() - start, 2),
                            "usage": info["usage"], "finish_reason": finish}
                msg = f"{model}: empty answer (finish={finish}, usage={info['usage']}, fields={info['fields']})"
                print("[llm]", msg, flush=True)
                errors.append(msg)
                if finish == "length" and budget < min(MAX_TOKENS_CAP, _limit.get(model, MAX_TOKENS_CAP)):
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


_PLACEHOLDER = re.compile(r"^\s*\.\.\.\s*(#.*)?$|=\s*\.\.\.\s*(#.*)?$|[\[(,]\s*\.\.\.\s*[\])]|^\s*#\s*\.\.\.", re.M)


def incomplete(code: str) -> bool:
    """True when the script does not even parse, e.g. a reply cut off mid-line."""
    try:
        compile(code, "main.py", "exec", dont_inherit=True)      # parse only; nothing runs here
        return False
    except SyntaxError:
        return True
    except Exception:  # noqa: BLE001
        return False


def has_placeholders(code: str) -> bool:
    """True when a script is a sketch: lines like `x = ...`, `[...]`, or a bare `...`."""
    return bool(_PLACEHOLDER.search(code))


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
