from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple
import time

import httpx

Message = Dict[str, str]


@dataclass(frozen=True)
class ProviderResult:
    """Lossless provider result used by the canonical execution path."""

    text: str
    provider: str
    model: str
    raw_request: Dict[str, Any]
    raw_response: Dict[str, Any]
    model_identity: Optional[str] = None
    model_version: Optional[str] = None
    model_digest: Optional[str] = None
    generation_metrics: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None


class ProviderExecutionError(RuntimeError):
    """Provider failure carrying request/response material when available."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str,
        raw_request: Optional[Dict[str, Any]] = None,
        raw_response: Any = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.raw_request = raw_request
        self.raw_response = raw_response


class ProviderClient(Protocol):
    async def generate(
        self,
        *,
        model: str,
        messages: List[Message],
        generation_config: Dict[str, Any],
    ) -> ProviderResult: ...


class OllamaClient:
    """Small asynchronous wrapper around Ollama's /api/chat endpoint."""

    def __init__(self, base_url: str, timeout_sec: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_sec

    @staticmethod
    def build_request(
        *,
        model: str,
        messages: List[Message],
        generation_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        options: Dict[str, Any] = {
            "temperature": generation_config["temperature"],
            "num_predict": generation_config["max_tokens"],
        }
        random_seed = generation_config.get("random_seed")
        if random_seed is not None:
            options["seed"] = random_seed
        options.update(generation_config.get("provider_options") or {})
        return {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": options,
        }

    async def generate(
        self,
        *,
        model: str,
        messages: List[Message],
        generation_config: Dict[str, Any],
    ) -> ProviderResult:
        """Canonical Ollama adapter. Tests inject a mock instead of calling it."""
        url = f"{self.base_url}/api/chat"
        payload = self.build_request(
            model=model,
            messages=messages,
            generation_config=generation_config,
        )
        t0 = time.time()
        response: Optional[httpx.Response] = None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ProviderExecutionError(
                        "Ollama response must be a JSON object",
                        error_type="malformed_provider_response",
                        raw_request=payload,
                        raw_response=data,
                    )
        except httpx.TimeoutException as exc:
            raise ProviderExecutionError(
                str(exc),
                error_type="timeout",
                raw_request=payload,
            ) from exc
        except httpx.HTTPStatusError as exc:
            try:
                raw_response: Any = exc.response.json()
            except ValueError:
                raw_response = {"text": exc.response.text}
            raise ProviderExecutionError(
                str(exc),
                error_type="http_error",
                raw_request=payload,
                raw_response=raw_response,
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raw_response = None
            if response is not None:
                raw_response = {"text": response.text}
            raise ProviderExecutionError(
                str(exc),
                error_type="provider_response_error",
                raw_request=payload,
                raw_response=raw_response,
            ) from exc
        latency_ms = int((time.time() - t0) * 1000)
        message = data.get("message") or {}
        if not isinstance(message, dict) or not isinstance(
            message.get("content", ""), str
        ):
            raise ProviderExecutionError(
                "Ollama response message content must be a string",
                error_type="malformed_provider_response",
                raw_request=payload,
                raw_response=data,
            )
        text = message.get("content", "") or ""
        metrics = {
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
        return ProviderResult(
            text=text,
            provider="ollama",
            model=model,
            raw_request=payload,
            raw_response=data,
            model_identity=data.get("model") or model,
            model_version=data.get("model_version"),
            model_digest=data.get("model_digest") or data.get("digest"),
            generation_metrics=metrics,
        )

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
