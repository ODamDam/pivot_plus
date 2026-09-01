from datetime import datetime, timezone
from typing import Any, Dict, Optional
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

from fastapi import FastAPI, HTTPException
import httpx

try:
    from .canonical import (
        CanonicalGenerationRequest,
        build_canonical_messages,
        provider_messages,
    )
    from .schemas import (
        CanonicalGenerateResponse,
        ChatGenerateRequest,
        ChatGenerateResponse,
        GenerateRequest,
        GenerateResponse,
        DirectGenerateRequest,
        DirectGenerateResponse,
    )
    from .vuln import (
        apply_generation_profile,
        build_vulnerable_messages,
        is_high_risk,
    )
    from .config import settings
    from .client import OllamaClient, ProviderClient, ProviderExecutionError
    from .logging_utils import append_jsonl
except ImportError:  # Docker runs this module with /app as the import root.
    from canonical import (
        CanonicalGenerationRequest,
        build_canonical_messages,
        provider_messages,
    )
    from schemas import (
        CanonicalGenerateResponse,
        ChatGenerateRequest,
        ChatGenerateResponse,
        GenerateRequest,
        GenerateResponse,
        DirectGenerateRequest,
        DirectGenerateResponse,
    )
    from vuln import apply_generation_profile, build_vulnerable_messages, is_high_risk
    from config import settings
    from client import OllamaClient, ProviderClient, ProviderExecutionError
    from logging_utils import append_jsonl


app = FastAPI(title="Vulnerable LLM API", version="0.2.0")

ollama = OllamaClient(
    base_url=settings.OLLAMA_BASE_URL,
    timeout_sec=settings.OLLAMA_TIMEOUT_SEC,
)
canonical_provider: ProviderClient = ollama


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _sha256_text(encoded)


def _git_commit() -> Optional[str]:
    project_root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _context_to_text(context: Any) -> Optional[str]:
    if context is None:
        return None
    if isinstance(context, str):
        return context
    return json.dumps(context, ensure_ascii=False, sort_keys=True)


def _base_record(
    req: GenerateRequest,
    *,
    request_id: str,
    case_id: str,
    generation_id: str,
    prompt: str,
) -> Dict[str, Any]:
    return {
        "schema_version": "vulnerable_llm_log.v0.2",
        "request_id": request_id,
        "case_id": case_id,
        "generation_id": generation_id,
        "testcase_id": req.testcase_id,
        "run_id": req.run_id,
        "seed_id": req.seed_id,
        "mutation_id": req.mutation_id,
        "benchmark_category": req.benchmark_category,
        "attack": {
            "delivery_channel": req.delivery_channel,
            "attack_type": req.attack_type,
            "primary_objective_id": req.primary_objective_id,
            "objective_text": req.objective_text,
            "expected_markers": req.triggers,
        },
        "prompt_p": prompt,
        "prompt_sha256": _sha256_text(prompt),
        "context": req.context,
        "source_metadata": req.metadata,
        "requested_params": {
            "temperature": req.params.temperature,
            "max_tokens": req.params.max_tokens,
        },
        "received_at": _utc_now(),
    }

def _chat_base_record(
    req: ChatGenerateRequest,
    *,
    request_id: str,
    generation_id: str,
    source_messages: list[dict[str, str]],
) -> Dict[str, Any]:
    return {
        "schema_version": "vulnerable_llm_chat_log.v1",
        "request_id": request_id,
        "dataset_id": req.dataset_id,
        "experiment_id": req.experiment_id,
        "generation_id": generation_id,
        "run_id": req.run_id,
        "input_view": req.input_view,
        "dataset_subset": req.dataset_subset,
        "attack_type": req.attack_type,
        "is_malicious": req.is_malicious,
        "generation_profile": req.generation_profile,
        "source_messages": source_messages,
        "source_messages_sha256": _json_hash(source_messages),
        "source_metadata": req.metadata,
        "requested_params": {
            "temperature": req.params.temperature,
            "max_tokens": req.params.max_tokens,
        },
        "received_at": _utc_now(),
    }

def _log_failure(record: Dict[str, Any], status: str, error: Dict[str, Any]) -> None:
    failure_record = {
        **record,
        "execution_status": status,
        "final_messages": None,
        "response_r": None,
        "response_sha256": None,
        "meta": None,
        "error": error,
        "completed_at": _utc_now(),
    }
    append_jsonl(settings.LOG_DIR, "vulnerable_llm.jsonl", failure_record)

def _log_chat_failure(
    record: Dict[str, Any],
    status: str,
    error: Dict[str, Any],
    *,
    final_messages: Optional[list[dict[str, str]]] = None,
) -> None:
    failure_record = {
        **record,
        "execution_status": status,
        "final_messages": final_messages,
        "final_messages_sha256": (
            _json_hash(final_messages)
            if final_messages is not None
            else None
        ),
        "response_r": None,
        "response_sha256": None,
        "meta": None,
        "error": error,
        "completed_at": _utc_now(),
    }

    append_jsonl(
        settings.LOG_DIR,
        "vulnerable_llm_chat.jsonl",
        failure_record,
    )

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "time": int(time.time()),
        "api_version": "0.2.0",
        "ollama_base_url": settings.OLLAMA_BASE_URL,
        "ollama_model": settings.OLLAMA_MODEL,
        "default_temperature": settings.DEFAULT_TEMPERATURE,
        "default_max_tokens": settings.DEFAULT_MAX_TOKENS,
        "log_dir": settings.LOG_DIR,
        "canonical_provider": settings.CANONICAL_PROVIDER,
    }


@app.post(
    "/canonical-generate",
    response_model=CanonicalGenerateResponse,
)
async def canonical_generate(
    req: CanonicalGenerationRequest,
) -> CanonicalGenerateResponse:
    """Execute the neutral canonical path without legacy prompt profiles."""
    request_id = f"req-{uuid.uuid4()}"
    received_at = _utc_now()
    canonical_request = req.model_dump(mode="json")
    rendered = build_canonical_messages(req)
    rendered_record = rendered.model_dump(mode="json")["messages"]
    messages = provider_messages(rendered)

    generation_config = req.generation_config.model_dump(mode="json")
    if generation_config["random_seed"] is None:
        generation_config["random_seed"] = req.random_seed

    base_record = {
        "schema_version": "vulnerable_llm_canonical_log.v1",
        "request_id": request_id,
        "run_id": req.run_id,
        "generation_id": req.generation_id,
        "case_id": req.case_id,
        "scenario_id": req.scenario_id,
        "condition": req.condition,
        "repetition_index": req.repetition_index,
        "provider": req.provider,
        "model": req.model,
        "generation_config": generation_config,
        "dataset_sha256": req.dataset_sha256,
        "random_seed": generation_config["random_seed"],
        "git_commit": _git_commit(),
        "canonical_request": canonical_request,
        "rendered_messages": rendered_record,
        "rendered_messages_sha256": _json_hash(rendered_record),
        "received_at": received_at,
    }

    if req.provider != settings.CANONICAL_PROVIDER:
        error = {
            "type": "ProviderConfigurationError",
            "message": (
                f"requested provider {req.provider!r} does not match configured "
                f"canonical provider {settings.CANONICAL_PROVIDER!r}"
            ),
        }
        append_jsonl(
            settings.LOG_DIR,
            "vulnerable_llm_canonical.jsonl",
            {
                **base_record,
                "execution_status": "configuration_error",
                "provider_request": None,
                "raw_provider_response": None,
                "normalized_response": None,
                "error": error,
                "completed_at": _utc_now(),
            },
        )
        raise HTTPException(status_code=400, detail=error["message"])

    try:
        provider_result = await canonical_provider.generate(
            model=req.model,
            messages=messages,
            generation_config=generation_config,
        )
        if (
            not isinstance(provider_result.raw_request, dict)
            or not isinstance(provider_result.raw_response, dict)
            or not isinstance(provider_result.text, str)
        ):
            raise ProviderExecutionError(
                "provider returned a malformed canonical result",
                error_type="malformed_provider_response",
                raw_request=(
                    provider_result.raw_request
                    if isinstance(provider_result.raw_request, dict)
                    else None
                ),
                raw_response=provider_result.raw_response,
            )
        if not provider_result.text.strip():
            raise ProviderExecutionError(
                "provider returned empty response text",
                error_type="empty_provider_text",
                raw_request=provider_result.raw_request,
                raw_response=provider_result.raw_response,
            )
        if provider_result.provider != req.provider:
            raise ValueError(
                "provider result identity does not match canonical request"
            )
        if provider_result.model != req.model:
            raise ValueError("provider model identity does not match canonical request")
    except Exception as exc:
        provider_error = exc if isinstance(exc, ProviderExecutionError) else None
        error = {
            "type": type(exc).__name__,
            "message": str(exc),
            "provider_error_type": (
                provider_error.error_type if provider_error is not None else None
            ),
        }
        failure_status = (
            "invalid_provider_response"
            if provider_error is not None
            and provider_error.error_type
            in {"malformed_provider_response", "empty_provider_text"}
            else "runtime_error"
        )
        append_jsonl(
            settings.LOG_DIR,
            "vulnerable_llm_canonical.jsonl",
            {
                **base_record,
                "execution_status": failure_status,
                "provider_request": (
                    provider_error.raw_request if provider_error is not None else None
                ),
                "raw_provider_response": (
                    provider_error.raw_response if provider_error is not None else None
                ),
                "normalized_response": None,
                "error": error,
                "completed_at": _utc_now(),
            },
        )
        raise HTTPException(
            status_code=502,
            detail=f"Canonical provider request failed: {type(exc).__name__}: {exc}",
        ) from exc

    completed_at = _utc_now()
    normalized_response = {
        "text": provider_result.text,
        "text_sha256": _sha256_text(provider_result.text),
        "model_identity": provider_result.model_identity,
        "model_version": provider_result.model_version,
        "model_digest": provider_result.model_digest,
        "generation_metrics": provider_result.generation_metrics,
    }
    record = {
        **base_record,
        "execution_status": "completed",
        "provider_request": provider_result.raw_request,
        "provider_request_sha256": _json_hash(provider_result.raw_request),
        "raw_provider_response": provider_result.raw_response,
        "raw_provider_response_sha256": _json_hash(provider_result.raw_response),
        "normalized_response": normalized_response,
        "error": provider_result.error,
        "completed_at": completed_at,
    }
    append_jsonl(
        settings.LOG_DIR,
        "vulnerable_llm_canonical.jsonl",
        record,
    )

    return CanonicalGenerateResponse(
        request_id=request_id,
        run_id=req.run_id,
        generation_id=req.generation_id,
        case_id=req.case_id,
        scenario_id=req.scenario_id,
        condition=req.condition,
        repetition_index=req.repetition_index,
        provider=provider_result.provider,
        model=provider_result.model,
        response=provider_result.text,
        meta={
            "generated_at": completed_at,
            "model_identity": provider_result.model_identity,
            "model_version": provider_result.model_version,
            "model_digest": provider_result.model_digest,
            "generation_metrics": provider_result.generation_metrics,
            "rendered_messages_sha256": record["rendered_messages_sha256"],
            "provider_request_sha256": record["provider_request_sha256"],
            "raw_provider_response_sha256": record[
                "raw_provider_response_sha256"
            ],
            "response_sha256": normalized_response["text_sha256"],
        },
    )


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest) -> GenerateResponse:
    request_id = f"req-{uuid.uuid4()}"
    case_id = req.case_id or f"case-{uuid.uuid4()}"
    generation_id = req.generation_id or f"gen-{uuid.uuid4()}"
    prompt = (req.prompt or "").strip()

    base_record = _base_record(
        req,
        request_id=request_id,
        case_id=case_id,
        generation_id=generation_id,
        prompt=prompt,
    )

    if not prompt:
        _log_failure(
            base_record,
            "invalid_input",
            {"type": "ValidationError", "message": "prompt is required"},
        )
        raise HTTPException(status_code=400, detail="prompt is required")

    if settings.ENABLE_HIGH_RISK_BLOCK and is_high_risk(prompt):
        _log_failure(
            base_record,
            "blocked",
            {
                "type": "HighRiskPolicyBlock",
                "message": "High-risk request blocked by server policy.",
            },
        )
        raise HTTPException(
            status_code=400,
            detail="High-risk request blocked by server policy. Use safe evaluation prompts.",
        )

    # The server intentionally fixes temperature for reproducibility.
    requested_temperature = req.params.temperature
    temperature = settings.DEFAULT_TEMPERATURE

    requested_max_tokens = req.params.max_tokens
    max_tokens = settings.DEFAULT_MAX_TOKENS
    if requested_max_tokens is not None:
        try:
            requested = max(1, int(requested_max_tokens))
            max_tokens = min(requested, settings.MAX_MAX_TOKENS)
        except (TypeError, ValueError):
            max_tokens = settings.DEFAULT_MAX_TOKENS

    context_text = _context_to_text(req.context)
    messages = build_vulnerable_messages(prompt=prompt, context=context_text)

    try:
        text, client_meta = await ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except httpx.HTTPStatusError as exc:
        _log_failure(
            base_record,
            "runtime_error",
            {
                "type": "OllamaHTTPError",
                "message": str(exc),
                "status_code": exc.response.status_code,
            },
        )
        raise HTTPException(
            status_code=502,
            detail=f"Ollama HTTP error: {exc.response.status_code}",
        ) from exc
    except Exception as exc:
        _log_failure(
            base_record,
            "runtime_error",
            {"type": type(exc).__name__, "message": str(exc)},
        )
        raise HTTPException(
            status_code=502,
            detail=f"Ollama request failed: {type(exc).__name__}: {exc}",
        ) from exc

    effective_config = {
        "backend": "ollama",
        "model": settings.OLLAMA_MODEL,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    generation_meta = {
        **client_meta,
        "requested_temperature": requested_temperature,
        "effective_temperature": temperature,
        "requested_max_tokens": requested_max_tokens,
        "effective_max_tokens": max_tokens,
        "config_hash": _json_hash(effective_config),
    }

    completed_at = _utc_now()
    record = {
        **base_record,
        "execution_status": "completed",
        "final_messages": messages,
        "response_r": text,
        "response_sha256": _sha256_text(text),
        "meta": generation_meta,
        "error": None,
        "completed_at": completed_at,
    }
    append_jsonl(settings.LOG_DIR, "vulnerable_llm.jsonl", record)

    return GenerateResponse(
        request_id=request_id,
        case_id=case_id,
        generation_id=generation_id,
        response=text,
        meta={
            **generation_meta,
            "generated_at": completed_at,
            "prompt_sha256": record["prompt_sha256"],
            "response_sha256": record["response_sha256"],
        },
    )

@app.post(
    "/chat-generate",
    response_model=ChatGenerateResponse,
)
async def chat_generate(
    req: ChatGenerateRequest,
) -> ChatGenerateResponse:
    request_id = f"req-{uuid.uuid4()}"
    generation_id = (
        req.generation_id
        or f"gen-{uuid.uuid4()}"
    )

    source_messages = [
        message.model_dump()
        for message in req.messages
    ]

    base_record = _chat_base_record(
        req,
        request_id=request_id,
        generation_id=generation_id,
        source_messages=source_messages,
    )

    try:
        final_messages = apply_generation_profile(
            source_messages,
            req.generation_profile,
        )
    except ValueError as exc:
        _log_chat_failure(
            base_record,
            "invalid_input",
            {
                "type": type(exc).__name__,
                "message": str(exc),
            },
        )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # ?ы쁽?깆쓣 ?꾪빐 temperature???쒕쾭 ?ㅼ젙媛믪쑝濡?怨좎젙?쒕떎.
    requested_temperature = req.params.temperature
    temperature = settings.DEFAULT_TEMPERATURE

    requested_max_tokens = req.params.max_tokens
    max_tokens = settings.DEFAULT_MAX_TOKENS

    if requested_max_tokens is not None:
        try:
            requested = max(
                1,
                int(requested_max_tokens),
            )
            max_tokens = min(
                requested,
                settings.MAX_MAX_TOKENS,
            )
        except (TypeError, ValueError):
            max_tokens = settings.DEFAULT_MAX_TOKENS

    try:
        text, client_meta = await ollama.chat(
            model=settings.OLLAMA_MODEL,
            messages=final_messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except httpx.HTTPStatusError as exc:
        _log_chat_failure(
            base_record,
            "runtime_error",
            {
                "type": "OllamaHTTPError",
                "message": str(exc),
                "status_code": exc.response.status_code,
            },
            final_messages=final_messages,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Ollama HTTP error: "
                f"{exc.response.status_code}"
            ),
        ) from exc

    except Exception as exc:
        _log_chat_failure(
            base_record,
            "runtime_error",
            {
                "type": type(exc).__name__,
                "message": str(exc),
            },
            final_messages=final_messages,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Ollama request failed: "
                f"{type(exc).__name__}: {exc}"
            ),
        ) from exc

    effective_config = {
        "backend": "ollama",
        "model": settings.OLLAMA_MODEL,
        "generation_profile": req.generation_profile,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    generation_meta = {
        **client_meta,
        "requested_temperature": requested_temperature,
        "effective_temperature": temperature,
        "requested_max_tokens": requested_max_tokens,
        "effective_max_tokens": max_tokens,
        "config_hash": _json_hash(effective_config),
        "source_message_count": len(source_messages),
        "final_message_count": len(final_messages),
    }

    completed_at = _utc_now()

    record = {
        **base_record,
        "execution_status": "completed",
        "final_messages": final_messages,
        "final_messages_sha256": _json_hash(final_messages),
        "response_r": text,
        "response_sha256": _sha256_text(text),
        "meta": generation_meta,
        "error": None,
        "completed_at": completed_at,
    }

    append_jsonl(
        settings.LOG_DIR,
        "vulnerable_llm_chat.jsonl",
        record,
    )

    return ChatGenerateResponse(
        request_id=request_id,
        dataset_id=req.dataset_id,
        experiment_id=req.experiment_id,
        generation_id=generation_id,
        generation_profile=req.generation_profile,
        response=text,
        meta={
            **generation_meta,
            "generated_at": completed_at,
            "source_messages_sha256": (
                record["source_messages_sha256"]
            ),
            "final_messages_sha256": (
                record["final_messages_sha256"]
            ),
            "response_sha256": (
                record["response_sha256"]
            ),
        },
    )


@app.post(
    "/direct-generate",
    response_model=DirectGenerateResponse,
)
async def direct_generate(
    req: DirectGenerateRequest,
) -> DirectGenerateResponse:
    """Neutral direct generation using the canonical provider adapter."""
    request_id = f"req-{uuid.uuid4()}"
    received_at = _utc_now()

    messages = [
        {
            "role": message.role,
            "content": message.content,
        }
        for message in req.messages
    ]

    generation_config = req.generation_config.model_dump(mode="json")

    base_record = {
        "schema_version": "vulnerable_llm_direct_log.v1",
        "request_id": request_id,
        "run_id": req.run_id,
        "generation_id": req.generation_id,
        "case_id": req.case_id,
        "repetition_index": req.repetition_index,
        "provider": req.provider,
        "model": req.model,
        "generation_config": generation_config,
        "dataset_sha256": req.dataset_sha256,
        "model_visible_messages": messages,
        "model_visible_messages_sha256": _json_hash(messages),
        "received_at": received_at,
    }

    if req.provider != settings.CANONICAL_PROVIDER:
        error = {
            "type": "ProviderConfigurationError",
            "message": (
                f"requested provider {req.provider!r} does not match configured "
                f"provider {settings.CANONICAL_PROVIDER!r}"
            ),
        }

        append_jsonl(
            settings.LOG_DIR,
            "vulnerable_llm_direct.jsonl",
            {
                **base_record,
                "execution_status": "configuration_error",
                "provider_request": None,
                "raw_provider_response": None,
                "normalized_response": None,
                "error": error,
                "completed_at": _utc_now(),
            },
        )

        raise HTTPException(status_code=400, detail=error["message"])

    try:
        provider_result = await canonical_provider.generate(
            model=req.model,
            messages=messages,
            generation_config=generation_config,
        )

        if (
            not isinstance(provider_result.raw_request, dict)
            or not isinstance(provider_result.raw_response, dict)
            or not isinstance(provider_result.text, str)
        ):
            raise ProviderExecutionError(
                "provider returned a malformed direct result",
                error_type="malformed_provider_response",
                raw_request=(
                    provider_result.raw_request
                    if isinstance(provider_result.raw_request, dict)
                    else None
                ),
                raw_response=provider_result.raw_response,
            )

        if not provider_result.text.strip():
            raise ProviderExecutionError(
                "provider returned empty response text",
                error_type="empty_provider_text",
                raw_request=provider_result.raw_request,
                raw_response=provider_result.raw_response,
            )

        if provider_result.provider != req.provider:
            raise ValueError(
                "provider result identity does not match direct request"
            )

        if provider_result.model != req.model:
            raise ValueError(
                "provider model identity does not match direct request"
            )

    except Exception as exc:
        provider_error = (
            exc if isinstance(exc, ProviderExecutionError) else None
        )

        error = {
            "type": type(exc).__name__,
            "message": str(exc),
            "provider_error_type": (
                provider_error.error_type
                if provider_error is not None
                else None
            ),
        }

        append_jsonl(
            settings.LOG_DIR,
            "vulnerable_llm_direct.jsonl",
            {
                **base_record,
                "execution_status": "runtime_error",
                "provider_request": (
                    provider_error.raw_request
                    if provider_error is not None
                    else None
                ),
                "raw_provider_response": (
                    provider_error.raw_response
                    if provider_error is not None
                    else None
                ),
                "normalized_response": None,
                "error": error,
                "completed_at": _utc_now(),
            },
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Direct provider request failed: "
                f"{type(exc).__name__}: {exc}"
            ),
        ) from exc

    meta = {
        "generated_at": _utc_now(),
        "model_identity": provider_result.model_identity,
        "model_version": provider_result.model_version,
        "model_digest": provider_result.model_digest,
        "generation_metrics": provider_result.generation_metrics,
        "provider_request_sha256": _json_hash(
            provider_result.raw_request
        ),
        "raw_provider_response_sha256": _json_hash(
            provider_result.raw_response
        ),
        "model_visible_messages_sha256": _json_hash(messages),
        "response_sha256": _sha256_text(provider_result.text),
    }

    append_jsonl(
        settings.LOG_DIR,
        "vulnerable_llm_direct.jsonl",
        {
            **base_record,
            "execution_status": "completed",
            "provider_request": provider_result.raw_request,
            "raw_provider_response": provider_result.raw_response,
            "normalized_response": provider_result.text,
            "provider_result": {
                "provider": provider_result.provider,
                "model": provider_result.model,
                "model_identity": provider_result.model_identity,
                "model_version": provider_result.model_version,
                "model_digest": provider_result.model_digest,
                "generation_metrics": provider_result.generation_metrics,
            },
            "error": None,
            "completed_at": _utc_now(),
        },
    )

    return DirectGenerateResponse(
        request_id=request_id,
        run_id=req.run_id,
        generation_id=req.generation_id,
        case_id=req.case_id,
        repetition_index=req.repetition_index,
        provider=req.provider,
        model=req.model,
        response=provider_result.text,
        meta=meta,
    )

