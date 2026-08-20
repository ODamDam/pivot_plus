import pytest
from pydantic import ValidationError

from vulnerable_llm.canonical import CanonicalGenerationConfig
from vulnerable_llm.client import OllamaClient, ProviderResult


def test_ollama_request_fixture_is_complete_and_network_free():
    client = OllamaClient("http://invalid.local")
    request = client.build_request(
        model="neutral-model",
        messages=[{"role": "system", "content": "task"}, {"role": "user", "content": "data"}],
        generation_config={"temperature": 0.0, "max_tokens": 64, "random_seed": 9},
    )
    assert request == {
        "model": "neutral-model",
        "messages": [{"role": "system", "content": "task"}, {"role": "user", "content": "data"}],
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 64, "seed": 9},
    }


def test_provider_result_preserves_raw_request_and_response():
    result = ProviderResult(
        text="normalized", provider="mock", model="neutral-model",
        raw_request={"messages": []},
        raw_response={"message": {"content": "normalized"}, "model_digest": "sha256:x"},
        model_identity="neutral-model", model_version=None, model_digest="sha256:x",
        generation_metrics={"eval_count": 3},
    )
    assert result.raw_request == {"messages": []}
    assert result.raw_response["model_digest"] == "sha256:x"
    assert result.error is None


def test_provider_options_cannot_override_canonical_generation_fields():
    with pytest.raises(ValidationError, match="cannot override"):
        CanonicalGenerationConfig(
            temperature=0.0,
            max_tokens=64,
            random_seed=9,
            provider_options={"seed": 999},
        )


def test_non_reserved_provider_options_are_preserved_losslessly():
    client = OllamaClient("http://invalid.local")
    request = client.build_request(
        model="neutral-model", messages=[],
        generation_config={
            "temperature": 0.2, "max_tokens": 33, "random_seed": 4,
            "provider_options": {"top_k": 10, "stop": ["END"]},
        },
    )
    assert request["options"] == {
        "temperature": 0.2, "num_predict": 33, "seed": 4,
        "top_k": 10, "stop": ["END"],
    }
