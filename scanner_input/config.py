from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent 

VULN_RESULT_PATH = PROJECT_ROOT / "vulnerable_llm" / "data" / "vuln_results.jsonl"

PROBE_CLASSNAME_DEFAULT = "garak.probes.base.Probe"
SEQ_DEFAULT = 1

SUPPORTED_SCANNERS = ["garak", "pyrit","promptfoo"]