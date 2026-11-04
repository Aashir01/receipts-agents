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

_client = httpx.AsyncClient(timeout=httpx.Timeout(180, connect=10))


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
