def call_api(prompt, options, context):
    vars_dict = context.get('vars', {})
    mutated_prompt = vars_dict.get('mutated_prompt', '')  # ← 여기를 주석처리
    model_output = vars_dict.get('model_output', '[에러: model_output 값이 없습니다]')
    return {"output": f"response: {model_output}"}
