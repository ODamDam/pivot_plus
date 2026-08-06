from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Literal


Verdict = Literal["PASS", "FAIL", "UNKNOWN"]


def _norm_verdict(v: object) -> Verdict:
    if isinstance(v, str):
        u = v.strip().upper()
        if u in ("PASS", "OK", "SUCCESS", "TRUE", "1"):
            return "PASS"
        if u in ("FAIL", "NG", "ERROR", "FALSE", "0"):
            return "FAIL"
        if u in ("UNKNOWN", "NA", "N/A", "NONE", ""):
            return "UNKNOWN"
    return "UNKNOWN"


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


@dataclass
class OpScopeStats:
    n: int = 0
    n_pass: int = 0
    n_fail: int = 0
    n_unknown: int = 0
    n_score: int = 0
    avg_oracle_score: float = 0.0
    last_updated_ts: float = 0.0

    def update(self, verdict: Verdict, oracle_score: Optional[float]) -> None:
        self.n += 1
        if verdict == "PASS":
            self.n_pass += 1
        elif verdict == "FAIL":
            self.n_fail += 1
        else:
            self.n_unknown += 1

        if oracle_score is not None:
            s = _clamp01(float(oracle_score))
            self.n_score += 1
            if self.n_score == 1:
                self.avg_oracle_score = s
            else:
                self.avg_oracle_score = self.avg_oracle_score + (s - self.avg_oracle_score) / float(self.n_score)

        self.last_updated_ts = time.time()

    @property
    def pass_rate(self) -> float:
        denom = self.n_pass + self.n_fail
        if denom <= 0:
            return 0.0
        return self.n_pass / denom


# Backward-compatible alias.
OpBucketStats = OpScopeStats


@dataclass
class OperatorStatsByScope:
    """
    Bucket-free operator statistics.

    stats[selection_scope][op_id] = OpScopeStats
    """
    stats: Dict[str, Dict[str, OpScopeStats]] = field(default_factory=dict)

    def ensure(self, selection_scope: str, op_id: str) -> OpScopeStats:
        scope = str(selection_scope)
        op = str(op_id)
        if scope not in self.stats:
            self.stats[scope] = {}
        if op not in self.stats[scope]:
            self.stats[scope][op] = OpScopeStats()
        return self.stats[scope][op]

    def get(self, selection_scope: str, op_id: str) -> Optional[OpScopeStats]:
        return self.stats.get(str(selection_scope), {}).get(str(op_id))

    def report_result(
        self,
        selection_scope: str,
        op_id: str,
        verdict: object,
        oracle_score: Optional[object] = None,
    ) -> None:
        v = _norm_verdict(verdict)

        score_f: Optional[float] = None
        if oracle_score is not None:
            try:
                score_f = float(oracle_score)
            except Exception:
                score_f = None

        st = self.ensure(selection_scope, op_id)
        st.update(v, score_f)

    def snapshot(self) -> Dict[str, Dict[str, dict]]:
        out: Dict[str, Dict[str, dict]] = {}
        for scope, ops in self.stats.items():
            out[scope] = {}
            for op_id, st in ops.items():
                out[scope][op_id] = {
                    "n": st.n,
                    "n_pass": st.n_pass,
                    "n_fail": st.n_fail,
                    "n_unknown": st.n_unknown,
                    "pass_rate": st.pass_rate,
                    "n_score": st.n_score,
                    "avg_oracle_score": st.avg_oracle_score,
                    "last_updated_ts": st.last_updated_ts,
                }
        return out

    def dump_json(self, path: str) -> None:
        payload = {
            "schema_version": "operator_stats_by_scope.v1",
            "generated_at": time.time(),
            "stats": self.snapshot(),
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


# Backward-compatible alias for older imports/tests.
OperatorStatsByBucket = OperatorStatsByScope
