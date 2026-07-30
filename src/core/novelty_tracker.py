# src/core/novelty_tracker.py
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, Set


def _hash_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class ScopeNoveltyStats:
    total: int = 0
    unique: int = 0
    seen_hits: int = 0
    hashes: Set[str] = field(default_factory=set)

    def mark(self, text: str) -> bool:
        """
        Returns:
          True  => duplicate
          False => unique
        """
        self.total += 1
        h = _hash_text(text)
        if h in self.hashes:
            self.seen_hits += 1
            return True
        self.hashes.add(h)
        self.unique += 1
        return False

    @property
    def unique_ratio(self) -> float:
        if self.total <= 0:
            return 0.0
        return float(self.unique) / float(self.total)


# Backward-compatible alias for older imports/tests.
BucketNoveltyStats = ScopeNoveltyStats


class NoveltyTracker:
    """
    Track novelty per selection_scope rather than per OWASP bucket.
    """

    def __init__(self) -> None:
        self._by_scope: Dict[str, ScopeNoveltyStats] = {}

    def _get(self, selection_scope: str) -> ScopeNoveltyStats:
        key = str(selection_scope)
        if key not in self._by_scope:
            self._by_scope[key] = ScopeNoveltyStats()
        return self._by_scope[key]

    def mark_seen(self, selection_scope: str, child_text: str) -> bool:
        return self._get(selection_scope).mark(child_text)

    def snapshot(self) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        for scope, st in self._by_scope.items():
            out[scope] = {
                "total": st.total,
                "unique": st.unique,
                "seen_hits": st.seen_hits,
                "unique_ratio": st.unique_ratio,
            }
        return out

    def snapshot_one(self, selection_scope: str) -> dict:
        st = self._get(selection_scope)
        return {
            "total": st.total,
            "unique": st.unique,
            "seen_hits": st.seen_hits,
            "unique_ratio": st.unique_ratio,
        }
