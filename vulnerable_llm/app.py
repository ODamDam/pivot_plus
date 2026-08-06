from datetime import datetime, timezone
from typing import Any, Dict, Optional
import hashlib
import json
import time
import uuid

from fastapi import FastAPI, HTTPException
import httpx

from schemas import (
    ChatGenerateRequest,
    ChatGenerateResponse,
    GenerateRequest,
    GenerateResponse,
)
from vuln import (
    apply_generation_profile,
    build_vulnerable_messages,
    is_high_risk,
)

from config import settings
from client import OllamaClient
from logging_utils import append_jsonl


app = FastAPI(title="Vulnerable LLM API", version="0.2.0")

ollama = OllamaClient(
    base_url=settings.OLLAMA_BASE_URL,
    timeout_sec=settings.OLLAMA_TIMEOUT_SEC,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_hash(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return _sha256_text(encoded)


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
    }


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

    # 재현성을 위해 temperature는 서버 설정값으로 고정한다.
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