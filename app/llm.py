"""Vultr Serverless Inference client (OpenAI-compatible) with model fallback."""

import os
import re
import time

import httpx

BASE_URL = os.environ.get("INFERENCE_BASE_URL", "https://api.vultrinference.com/v1").rstrip("/")
API_KEY = os.environ.get("VULTR_INFERENCE_API_KEY", "")
MODEL_MAIN = os.environ.get("MODEL_MAIN", "minimax-m3.1-flash")
MODEL_FALLBACK = os.environ.get("MODEL_FALLBACK", "deepseek-v4.1-flash-1017")

_client = httpx.AsyncClient(timeout=httpx.Timeout(90, connect=10))


class LLMError(RuntimeError):
    pass


async def chat(messages: list[dict], max_tokens: int = 1500, temperature: float = 0.2) -> dict:
    """Call the main model; on failure fall back once. Returns text, model, latency."""
    if not API_KEY:
        raise LLMError("VULTR_INFERENCE_API_KEY is not set")
    last_err = None
    for model in (MODEL_MAIN, MODEL_FALLBACK):
        start = time.monotonic()
        try:
            r = await _client.post(
                f"{BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {API_KEY}"},
                json={"model": model, "messages": messages,
                      "max_tokens": max_tokens, "temperature": temperature},
            )
            r.raise_for_status()
            data = r.json()
            text = data["choices"][0]["message"].get("content") or ""
            text = strip_thinking(text)
            if not text.strip():
                raise LLMError("empty response")
            return {"text": text, "model": model,
                    "latency_s": round(time.monotonic() - start, 2),
                    "usage": data.get("usage", {})}
        except Exception as e:  # noqa: BLE001 - any failure triggers fallback
            last_err = f"{model}: {type(e).__name__}: {str(e)[:200]}"
    raise LLMError(f"All models failed. Last error: {last_err}")


def strip_thinking(text: str) -> str:
    """Remove <think>...</think> blocks some reasoning models emit."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    if "<think>" in text and "</think>" not in text:
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
