from __future__ import annotations

import ast
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


RECOMMENDED_FAMILIES = {
    "lexical",
    "syntactic",
    "semantic_paraphrase",
    "encoding",
    "structural",
    "contextual",
    "noise_injection",
    "cross_lingual",
}

OUT_OF_SCOPE_KEYWORDS = {
    "unbounded": "drop_for_v1",
    "consumption": "drop_for_v1",
    "dos": "drop_for_v1",
    "hallucination": "drop_for_v1",
    "misinformation": "drop_for_v1",
    "data_poisoning": "drop_for_v1",
    "poisoning": "drop_for_v1",
    "training_data": "drop_for_v1",
    "backdoor": "drop_for_v1",
    "biased_training": "drop_for_v1",
    "adversarial_training": "drop_for_v1",
}

FAMILY_KEYWORDS = [
    ("encoding", ["base64", "url_encode", "unicode", "homoglyph", "zero_width", "obfuscation", "encoding", "escape"]),
    ("structural", ["json", "yaml", "xml", "html", "markdown", "wrapper", "schema", "delimiter", "code_block", "document", "field"]),
    ("contextual", ["pretext", "authority", "trust", "debug", "translation", "security_test", "policy_review", "log_analysis", "context"]),
    ("noise_injection", ["noise", "long", "document", "examples", "fake_log", "benign_context", "insert", "expand_context"]),
    ("tool_manipulation", ["tool", "function", "argument", "call"]),
    ("instruction_override", ["override", "ignore_instruction", "ignore", "refusal", "suppression"]),
    ("cross_lingual", ["korean", "translate", "cross_lingual", "multilingual", "language"]),
    ("syntactic", ["syntactic", "question_form", "imperative", "resegmentation", "punctuation", "boundary"]),
    ("lexical", ["lex", "synonym", "polite", "shorten", "replace_word"]),
]

OUTPUT_FORMAT_KEYWORDS = [
    ("json", ["json"]),
    ("yaml", ["yaml"]),
    ("markdown", ["markdown", "md", "quote"]),
    ("html", ["html", "xml"]),
    ("code", ["code", "comment", "python", "javascript"]),
    ("log", ["log"]),
    ("plain_text", ["lexical", "syntactic", "paraphrase", "contextual"]),
]


def find_project_root(start: Path) -> Path:
    """Find project root by walking upward until src/operators exists."""
    current = start.resolve()
    if current.is_file():
        current = current.parent

    for candidate in [current, *current.parents]:
        if (candidate / "src" / "operators").exists():
            return candidate

    raise SystemExit(
        "[ERROR] Could not find project root. "
        "Run this script inside the repo that contains src/operators."
    )


def safe_literal_eval(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def read_text(path: Path) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp949"):
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    return path.read_text(errors="replace")


def parse_python(path: Path) -> Tuple[Optional[ast.Module], Optional[str]]:
    source = read_text(path)
    try:
        return ast.parse(source, filename=str(path)), None
    except SyntaxError as e:
        return None, f"{e.msg} at line {e.lineno}"


def extract_operator_meta(tree: ast.Module) -> Optional[Dict[str, Any]]:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "OPERATOR_META":
                    value = safe_literal_eval(node.value)
                    return value if isinstance(value, dict) else {"__non_literal__": True}
        if isinstance(node, ast.AnnAssign):
            target = node.target
            if isinstance(target, ast.Name) and target.id == "OPERATOR_META":
                value = safe_literal_eval(node.value) if node.value is not None else None
                return value if isinstance(value, dict) else {"__non_literal__": True}
    return None


def find_apply_func(tree: ast.Module) -> Optional[ast.FunctionDef]:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "apply":
            return node
    return None


def list_imports(tree: ast.Module) -> List[str]:
    imports: List[str] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}" if module else alias.name)
    return imports


def contains_name(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def contains_string(source: str, needle: str) -> bool:
    return needle.lower() in source.lower()


def normalize_list(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(str(x) for x in value)
    if isinstance(value, tuple):
        return "; ".join(str(x) for x in value)
    return str(value)


def get_strength_range(meta: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    if not isinstance(meta, dict):
        return "", ""
    strength = meta.get("strength_range", "")
    if isinstance(strength, (list, tuple)) and len(strength) == 2:
        return str(strength[0]), str(strength[1])
    return "", ""


def infer_family(file_name: str, op_id: str, meta: Optional[Dict[str, Any]]) -> str:
    if isinstance(meta, dict):
        for key in ("mutation_family", "operator_family", "family"):
            if meta.get(key):
                value = str(meta[key])
                if value in RECOMMENDED_FAMILIES:
                    return value

    text = f"{file_name} {op_id} {json.dumps(meta or {}, ensure_ascii=False)}".lower()

    for family, keywords in FAMILY_KEYWORDS:
        if any(k in text for k in keywords):
            if family == "instruction_override":
                return "lexical"
            if family == "tool_manipulation":
                return "structural"
            return family

    if file_name.startswith("op_lex_"):
        return "lexical"
    if file_name.startswith("op_syn_"):
        return "syntactic"
    if file_name.startswith("op_fmt_"):
        return "structural"
    if file_name.startswith("op_comp_"):
        return "contextual"
    return "unknown"


def infer_output_format(file_name: str, op_id: str, meta: Optional[Dict[str, Any]]) -> str:
    text = f"{file_name} {op_id} {json.dumps(meta or {}, ensure_ascii=False)}".lower()

    found = []
    for fmt, keywords in OUTPUT_FORMAT_KEYWORDS:
        if any(k in text for k in keywords):
            found.append(fmt)

    if "json" in found and "yaml" in found:
        return "json_or_yaml"
    if found:
        return found[0]
    return "plain_text_or_unknown"


def infer_input_requirement(meta: Optional[Dict[str, Any]], source: str) -> str:
    if isinstance(meta, dict):
        surface = meta.get("surface_compat")
        if surface:
            return normalize_list(surface)

    lowered = source.lower()
    if "prompt_text" in lowered:
        return "PROMPT_TEXT"
    if "surface" in lowered:
        return "surface_checked"
    return "unknown"


def infer_semantic_preservation(family: str, file_name: str, op_id: str) -> str:
    text = f"{file_name} {op_id}".lower()
    if family in {"lexical", "syntactic", "semantic_paraphrase", "contextual", "structural"}:
        return "likely_preserved_but_review_needed"
    if family == "encoding":
        return "medium_risk_decode_or_readability_check_needed"
    if family in {"noise_injection", "cross_lingual"}:
        return "medium_risk_manual_review_needed"
    if any(k in text for k in OUT_OF_SCOPE_KEYWORDS):
        return "out_of_scope"
    return "unknown_review_needed"


def infer_label_change_risk(family: str, file_name: str, op_id: str) -> str:
    text = f"{file_name} {op_id}".lower()
    if any(k in text for k in OUT_OF_SCOPE_KEYWORDS):
        return "high_out_of_scope"
    if family in {"encoding", "noise_injection", "cross_lingual"}:
        return "medium"
    if family in {"lexical", "syntactic", "semantic_paraphrase", "structural", "contextual"}:
        return "low_to_medium"
    return "unknown"


def infer_action(family: str, file_name: str, op_id: str, status: str) -> str:
    if status in {"PARSE_ERROR", "META_MISSING", "APPLY_MISSING"}:
        return "fix_or_review"

    text = f"{file_name} {op_id}".lower()
    for keyword, action in OUT_OF_SCOPE_KEYWORDS.items():
        if keyword in text:
            return action

    if family in RECOMMENDED_FAMILIES:
        return "keep_or_modify"

    return "review"


def extract_apply_signature(apply_func: Optional[ast.FunctionDef]) -> str:
    if apply_func is None:
        return ""
    arg_names = [arg.arg for arg in apply_func.args.args]
    return f"apply({', '.join(arg_names)})"


def inspect_operator(path: Path, project_root: Path) -> Dict[str, Any]:
    relative = str(path.relative_to(project_root)).replace("\\", "/")
    source = read_text(path)
    tree, parse_error = parse_python(path)

    if parse_error:
        return {
            "file": relative,
            "operator_name": path.stem,
            "op_id": "",
            "operator_family_guess": "unknown",
            "input_requirement_guess": "unknown",
            "output_format_guess": "unknown",
            "strength_min": "",
            "strength_max": "",
            "semantic_preservation_guess": "unknown",
            "label_change_risk_guess": "unknown",
            "risk_level": "",
            "bucket_tags": "",
            "attack_type_compat": "",
            "surface_compat": "",
            "has_params_schema": "",
            "apply_signature": "",
            "uses_rng": "",
            "supports_max_chars": "",
            "imports": "",
            "inventory_status": "PARSE_ERROR",
            "recommended_action": "fix_or_review",
            "use_in_diagnostic_v1": "no_until_fixed",
            "review_notes": parse_error,
        }

    assert tree is not None
    meta = extract_operator_meta(tree)
    apply_func = find_apply_func(tree)
    imports = list_imports(tree)

    op_id = ""
    if isinstance(meta, dict):
        op_id = str(meta.get("op_id", ""))

    if meta is None:
        status = "META_MISSING"
    elif isinstance(meta, dict) and meta.get("__non_literal__"):
        status = "META_NON_LITERAL"
    elif apply_func is None:
        status = "APPLY_MISSING"
    else:
        status = "OK"

    family = infer_family(path.name, op_id, meta)
    out_fmt = infer_output_format(path.name, op_id, meta)
    input_req = infer_input_requirement(meta, source)
    strength_min, strength_max = get_strength_range(meta)

    action = infer_action(family, path.name, op_id, status)
    use_in_v1 = "yes_reviewed" if action == "keep_or_modify" and status == "OK" else "no_or_pending"

    return {
        "file": relative,
        "operator_name": path.stem,
        "op_id": op_id,
        "operator_family_guess": family,
        "input_requirement_guess": input_req,
        "output_format_guess": out_fmt,
        "strength_min": strength_min,
        "strength_max": strength_max,
        "semantic_preservation_guess": infer_semantic_preservation(family, path.name, op_id),
        "label_change_risk_guess": infer_label_change_risk(family, path.name, op_id),
        "risk_level": str(meta.get("risk_level", "")) if isinstance(meta, dict) else "",
        "bucket_tags": normalize_list(meta.get("bucket_tags")) if isinstance(meta, dict) else "",
        "attack_type_compat": normalize_list(meta.get("attack_type_compat")) if isinstance(meta, dict) else "",
        "surface_compat": normalize_list(meta.get("surface_compat")) if isinstance(meta, dict) else "",
        "has_params_schema": str(bool(meta.get("params_schema"))) if isinstance(meta, dict) else "",
        "apply_signature": extract_apply_signature(apply_func),
        "uses_rng": str(contains_name(apply_func, "rng")) if apply_func is not None else "",
        "supports_max_chars": str(contains_string(source, "max_chars")),
        "imports": "; ".join(imports),
        "inventory_status": status,
        "recommended_action": action,
        "use_in_diagnostic_v1": use_in_v1,
        "review_notes": "",
    }


def write_csv(rows: List[Dict[str, Any]], out_path: Path) -> None:
    fieldnames = [
        "file",
        "operator_name",
        "op_id",
        "operator_family_guess",
        "input_requirement_guess",
        "output_format_guess",
        "strength_min",
        "strength_max",
        "semantic_preservation_guess",
        "label_change_risk_guess",
        "risk_level",
        "bucket_tags",
        "attack_type_compat",
        "surface_compat",
        "has_params_schema",
        "apply_signature",
        "uses_rng",
        "supports_max_chars",
        "imports",
        "inventory_status",
        "recommended_action",
        "use_in_diagnostic_v1",
        "review_notes",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(rows: List[Dict[str, Any]], out_path: Path, project_root: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    family_counts = Counter(row["operator_family_guess"] for row in rows)
    action_counts = Counter(row["recommended_action"] for row in rows)
    status_counts = Counter(row["inventory_status"] for row in rows)
    priority_missing = [
        family for family in [
            "structural",
            "contextual",
            "encoding",
            "noise_injection",
            "cross_lingual",
            "semantic_paraphrase",
        ]
        if family_counts.get(family, 0) == 0
    ]

    with out_path.open("w", encoding="utf-8") as f:
        f.write("# Operator Inventory v1\n\n")
        f.write("## 1. Scope\n\n")
        f.write("본 문서는 현재 `src/operators`에 구현되어 있는 mutation operator를 자동 점검한 inventory이다.\n\n")
        f.write(f"- project_root: `{project_root}`\n")
        f.write(f"- operators_dir: `{project_root / 'src' / 'operators'}`\n")
        f.write(f"- total_operator_files: {len(rows)}\n\n")

        f.write("## 2. Summary by inventory status\n\n")
        f.write("| status | count |\n|---|---:|\n")
        for key, count in sorted(status_counts.items()):
            f.write(f"| {key} | {count} |\n")

        f.write("\n## 3. Summary by mutation family guess\n\n")
        f.write("| family | count |\n|---|---:|\n")
        for key, count in sorted(family_counts.items()):
            f.write(f"| {key} | {count} |\n")

        f.write("\n## 4. Summary by recommended action\n\n")
        f.write("| action | count |\n|---|---:|\n")
        for key, count in sorted(action_counts.items()):
            f.write(f"| {key} | {count} |\n")

        f.write("\n## 5. Missing or weak priority family\n\n")
        if priority_missing:
            for family in priority_missing:
                f.write(f"- `{family}`\n")
        else:
            f.write("- 우선순위 family가 모두 최소 1개 이상 존재한다.\n")

        f.write("\n## 6. Inventory table\n\n")
        f.write("| file | op_id | family_guess | input_requirement | output_format | strength | semantic_preservation | label_change_risk | status | action | use_v1 |\n")
        f.write("|---|---|---|---|---|---|---|---|---|---|---|\n")

        for row in rows:
            strength = f"{row['strength_min']}~{row['strength_max']}".strip("~")
            f.write(
                f"| {row['file']} "
                f"| {row['op_id']} "
                f"| {row['operator_family_guess']} "
                f"| {row['input_requirement_guess']} "
                f"| {row['output_format_guess']} "
                f"| {strength} "
                f"| {row['semantic_preservation_guess']} "
                f"| {row['label_change_risk_guess']} "
                f"| {row['inventory_status']} "
                f"| {row['recommended_action']} "
                f"| {row['use_in_diagnostic_v1']} |\n"
            )

        f.write("\n## 7. Manual review checklist\n\n")
        f.write("| item | question |\n|---|---|\n")
        f.write("| operator name | 어떤 이름으로 등록되어 있는가? |\n")
        f.write("| operator family | lexical, syntactic, encoding, structural 등 어디에 속하는가? |\n")
        f.write("| input requirement | 어떤 seed에 적용 가능한가? |\n")
        f.write("| output format | plain text, JSON, markdown 등 어떤 형태를 만드는가? |\n")
        f.write("| strength | 변형 강도 1~5 중 어디에 해당하는가? |\n")
        f.write("| semantic preservation | 공격 의도가 유지되는가? |\n")
        f.write("| risk | label이 바뀔 위험이 있는가? |\n")
        f.write("| keep/modify/drop | 유지, 수정, 제거, 신규 구현 중 무엇인가? |\n")


def write_policy_draft(rows: List[Dict[str, Any]], out_path: Path) -> None:
    family_counts = Counter(row["operator_family_guess"] for row in rows)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        f.write("# Operator Policy v2 Draft\n\n")
        f.write("## 1. 목적\n\n")
        f.write("본 문서는 `operator_inventory_v1` 결과를 바탕으로 diagnostic benchmark v1에서 사용할 mutation operator의 유지, 수정, 제외, 신규 구현 방침을 정의한다.\n\n")

        f.write("## 2. v1 우선 family\n\n")
        f.write("| family | current_count | decision |\n|---|---:|---|\n")
        for family in [
            "lexical",
            "syntactic",
            "semantic_paraphrase",
            "encoding",
            "structural",
            "contextual",
            "noise_injection",
            "cross_lingual",
        ]:
            count = family_counts.get(family, 0)
            decision = "sufficient_or_review" if count > 0 else "new_needed"
            f.write(f"| {family} | {count} | {decision} |\n")

        f.write("\n## 3. v1 제외 family\n\n")
        f.write("| family or keyword | decision | reason |\n|---|---|---|\n")
        f.write("| unbounded_consumption / DOS | drop_for_v1 | prompt injection scanner 평가와 직접 관련이 약함 |\n")
        f.write("| hallucination_induction | drop_for_v1 | hallucination 평가는 별도 범위 |\n")
        f.write("| misinformation_generation | drop_for_v1 | content integrity/factuality 평가에 가까움 |\n")
        f.write("| data_poisoning / training_data | drop_for_v1 | training-time risk이므로 diagnostic prompt injection benchmark 범위를 벗어남 |\n")
        f.write("| model_backdoor | drop_for_v1 | model-level risk로 분리 필요 |\n\n")

        f.write("## 4. 신규 구현 우선순위\n\n")
        f.write("### 4.1 structural wrapper\n\n")
        f.write("- `wrap_as_json_field`\n")
        f.write("- `wrap_as_yaml_config`\n")
        f.write("- `wrap_as_markdown_quote`\n")
        f.write("- `wrap_as_code_comment`\n")
        f.write("- `wrap_as_log_entry`\n\n")

        f.write("### 4.2 contextual pretext\n\n")
        f.write("- `as_debugging_request`\n")
        f.write("- `as_translation_request`\n")
        f.write("- `as_security_test_request`\n")
        f.write("- `as_policy_review_request`\n")
        f.write("- `as_log_analysis_request`\n\n")

        f.write("### 4.3 encoding / obfuscation\n\n")
        f.write("- `base64_wrap`\n")
        f.write("- `url_encode_keywords`\n")
        f.write("- `unicode_homoglyph_replace`\n")
        f.write("- `zero_width_insert`\n\n")

        f.write("### 4.4 noise injection\n\n")
        f.write("- `insert_into_long_document`\n")
        f.write("- `insert_between_examples`\n")
        f.write("- `insert_into_fake_log`\n")
        f.write("- `insert_after_benign_context`\n\n")

        f.write("### 4.5 cross-lingual\n\n")
        f.write("- `translate_attack_to_korean`\n")
        f.write("- `mix_korean_english`\n")
        f.write("- `split_instruction_across_languages`\n\n")

        f.write("## 5. attack_type별 적용 정책\n\n")
        f.write("| attack_type | allowed mutation families |\n|---|---|\n")
        f.write("| instruction_override | lexical, syntactic, contextual, structural |\n")
        f.write("| role_play_bypass | semantic_paraphrase, contextual, cross_lingual |\n")
        f.write("| policy_bypass | lexical, semantic_paraphrase, contextual |\n")
        f.write("| data_exfiltration | contextual, structural, encoding, noise_injection |\n")
        f.write("| format_injection | structural, encoding, noise_injection |\n")
        f.write("| tool_manipulation | structural, contextual, code/log wrapper |\n")
        f.write("| indirect_injection | structural, noise_injection, repo/document wrapper |\n")
        f.write("| multi_turn_injection | split_instruction, staged_context |\n\n")

        f.write("## 6. 다음 작업\n\n")
        f.write("1. `operator_inventory_v1.csv`에서 `recommended_action`을 수동 검토한다.\n")
        f.write("2. `keep_or_modify` operator 중 prompt injection 의미 보존이 불명확한 항목은 sample test를 수행한다.\n")
        f.write("3. `drop_for_v1` operator는 diagnostic benchmark 생성 pipeline에서 제외한다.\n")
        f.write("4. 부족한 family는 신규 operator로 구현한다.\n")


def main() -> None:
    project_root = find_project_root(Path.cwd())
    operators_dir = project_root / "src" / "operators"

    rows = [
        inspect_operator(path, project_root)
        for path in sorted(operators_dir.rglob("*.py"))
        if path.name != "__init__.py"
    ]

    out_csv = project_root / "docs" / "operator_inventory_v1.csv"
    out_md = project_root / "docs" / "operator_inventory_v1.md"
    out_policy = project_root / "docs" / "operator_policy_v2_draft.md"

    write_csv(rows, out_csv)
    write_markdown(rows, out_md, project_root)
    write_policy_draft(rows, out_policy)

    print(f"[OK] operators scanned: {len(rows)}")
    print(f"[OK] saved: {out_csv}")
    print(f"[OK] saved: {out_md}")
    print(f"[OK] saved: {out_policy}")


if __name__ == "__main__":
    main()
