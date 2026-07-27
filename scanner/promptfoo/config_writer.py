import json
import yaml
from pathlib import Path
import os

PROMPTFOO_DIR = Path(__file__).parent


def write_echo_provider():
    code = '''\
def call_api(prompt, options, context):
    vars_dict = context.get('vars', {})
    mutated_prompt = vars_dict.get('mutated_prompt', '')  # ← 여기를 주석처리
    model_output = vars_dict.get('model_output', '[에러: model_output 값이 없습니다]')
    return {"output": f"response: {model_output}"}
'''
    path = PROMPTFOO_DIR / "echo_provider.py"
    path.write_text(code, encoding="utf-8")
    return str(path)


def write_promptfoo_config(records: list, rubric: str, provider: str = "ollama:chat:llama3:8b") -> str:
    tests = []
    for record in records:
        tests.append({
    "vars": {
        "mutated_prompt": record.get("prompt") or "",
        "model_output": record.get("response") or "",
        "seed_id": record.get("seed_id") or "",
        "bucket_id": record.get("goal") or "",
    }
})

    tests_path = PROMPTFOO_DIR / "test_cases.json"
    tests_path.write_text(json.dumps(tests, ensure_ascii=False, indent=2), encoding="utf-8")

    config = {
        "description": "5/14 llm-rubric 성능평가",
        "providers": [{"id": f"file://{PROMPTFOO_DIR}/echo_provider.py"}],
        "prompts": ["{{mutated_prompt}}"],
        "tests": f"file://{tests_path}",
        "defaultTest": {
            "assert": [
                {
                    "type": "llm-rubric",
                    "value": rubric,
                    "provider": provider,
                }
            ]
        },
        "env": {
    "OLLAMA_BASE_URL": os.getenv("OLLAMA_BASE_URL_PYRIT", "http://localhost:11434"),
}
    }

    config_path = PROMPTFOO_DIR / "promptfooconfig.yaml"
    config_path.write_text(yaml.dump(config, allow_unicode=True), encoding="utf-8")
    return str(config_path)