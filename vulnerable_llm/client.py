from typing import Any, Dict, List, Tuple
import time

import httpx

Message = Dict[str, str]


class OllamaClient:
    """Small asynchronous wrapper around Ollama's /api/chat endpoint."""

    def __init__(self, base_url: str, timeout_sec: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_sec

    async def chat(
        self,
        model: str,
        messages: List[Message],
        temperature: float,
        max_tokens: int,
    ) -> Tuple[str, Dict[str, Any]]:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        t0 = time.time()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        latency_ms = int((time.time() - t0) * 1000)

        text = (data.get("message") or {}).get("content", "") or ""

        meta: Dict[str, Any] = {
            "backend": "ollama",
            "model": model,
            "latency_ms": latency_ms,
            "prompt_eval_count": data.get("prompt_eval_count"),
            "eval_count": data.get("eval_count"),
            "done": data.get("done"),
            "done_reason": data.get("done_reason"),
            "total_duration_ns": data.get("total_duration"),
            "load_duration_ns": data.get("load_duration"),
            "prompt_eval_duration_ns": data.get("prompt_eval_duration"),
            "eval_duration_ns": data.get("eval_duration"),
        }
        return text, meta
