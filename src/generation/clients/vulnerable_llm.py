from __future__ import annotations

import time
from typing import Any

import requests

from src.generation.clients.base import (
    ClientGenerationResult,
    GenerationHTTPError,
    GenerationResponseError,
)
from src.generation.models import GenerationInput


class VulnerableLLMClient:
    def __init__(
        self,
        *,
        base_url: str = "http://localhost:8000",
        timeout_sec: float = 180.0,
        max_retries: int = 3,
        retry_delay_sec: float = 2.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_sec = timeout_sec
        self.max_retries = max(1, max_retries)
        self.retry_delay_sec = max(0.0, retry_delay_sec)

    def health(self) -> dict[str, Any]:
        response = requests.get(
            f"{self.base_url}/health",
            timeout=self.timeout_sec,
        )
        response.raise_for_status()

        body = response.json()

        if not isinstance(body, dict):
            raise GenerationResponseError(
                "Health endpoint did not return a JSON object"
            )

        return body

    def generate(
        self,
        generation_input: GenerationInput,
        *,
        experiment_id: str,
        generation_profile: str,
        generation_id: str,
        run_id: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> ClientGenerationResult:
        payload = self._build_payload(
            generation_input=generation_input,
            experiment_id=experiment_id,
            generation_profile=generation_profile,
            generation_id=generation_id,
            run_id=run_id,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        response_body = self._post_with_retry(
            path="/chat-generate",
            payload=payload,
        )

        return self._parse_generation_response(response_body)

    def _build_payload(
        self,
        *,
        generation_input: GenerationInput,
        experiment_id: str,
        generation_profile: str,
        generation_id: str,
        run_id: str | None,
        temperature: float | None,
        max_tokens: int | None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}

        if temperature is not None:
            params["temperature"] = temperature

        if max_tokens is not None:
            params["max_tokens"] = max_tokens

        return {
            "messages": [
                message.to_dict()
                for message in generation_input.messages
            ],
            "generation_profile": generation_profile,
            "dataset_id": generation_input.dataset_id,
            "experiment_id": experiment_id,
            "generation_id": generation_id,
            "run_id": run_id,
            "input_view": generation_input.input_view,
            "dataset_subset": generation_input.dataset_subset,
            "attack_type": generation_input.attack_type,
            "is_malicious": generation_input.is_malicious,
            "metadata": {
                **generation_input.metadata,
                "prompt_text": generation_input.prompt_text,
                "context_text": generation_input.context_text,
                "context_type": generation_input.context_type,
            },
            "params": params,
        }

    def _post_with_retry(
        self,
        *,
        path: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(
                    url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                    },
                    timeout=self.timeout_sec,
                )

                if 400 <= response.status_code < 500:
                    raise GenerationHTTPError(
                        status_code=response.status_code,
                        message=(
                            "Generation request was rejected "
                            f"with HTTP {response.status_code}"
                        ),
                        response_body=response.text,
                    )

                response.raise_for_status()

                try:
                    body = response.json()
                except ValueError as exc:
                    raise GenerationResponseError(
                        "Generation server returned non-JSON response"
                    ) from exc

                if not isinstance(body, dict):
                    raise GenerationResponseError(
                        "Generation server response must be a JSON object"
                    )

                return body

            except GenerationHTTPError:
                raise

            except (
                requests.ConnectionError,
                requests.Timeout,
                requests.HTTPError,
                GenerationResponseError,
            ) as exc:
                last_error = exc

                if attempt >= self.max_retries:
                    break

                time.sleep(self.retry_delay_sec)

        raise GenerationResponseError(
            "Generation request failed after "
            f"{self.max_retries} attempts: {last_error}"
        )

    @staticmethod
    def _parse_generation_response(
        body: dict[str, Any],
    ) -> ClientGenerationResult:
        response_text = body.get("response")
        execution_status = body.get("execution_status")

        if not isinstance(response_text, str):
            raise GenerationResponseError(
                "Generation response is missing string field 'response'"
            )

        if not isinstance(execution_status, str):
            raise GenerationResponseError(
                "Generation response is missing string field "
                "'execution_status'"
            )

        meta = body.get("meta") or {}

        if not isinstance(meta, dict):
            raise GenerationResponseError(
                "Generation response field 'meta' must be an object"
            )

        return ClientGenerationResult(
            execution_status=execution_status,
            response_text=response_text,
            request_id=body.get("request_id"),
            generation_id=body.get("generation_id"),
            meta=meta,
            raw_response=body,
        )