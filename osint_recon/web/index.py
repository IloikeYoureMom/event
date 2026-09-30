from __future__ import annotations

import json
import math
import re
import threading
import time
from pathlib import Path

STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "http", "https",
    "www", "com", "net", "org",
}


def _tokenize(text: str) -> list[str]:
    return [t for t in re.split(r"[^0-9a-z_@.\-:/]+", text.lower()) if len(t) >= 2]


class SearchIndex:
    def __init__(self, runs_dir: Path):
        self.runs_dir = Path(runs_dir)
        self._lock = threading.Lock()
        self._items: dict[str, dict] = {}
        self._order: list[str] = []
        self._postings: dict[str, set[str]] = {}
        self._norm: float = 1.0
        self._signature: tuple = ()
        self._last_check = 0.0

    def _disk_signature(self) -> tuple:
        sig = []
        if not self.runs_dir.exists():
            return ()
        for d in sorted(self.runs_dir.iterdir()):
            jl = d / "items.jsonl"
            if jl.exists():
                st = jl.stat()
                sig.append((jl.name, int(st.st_mtime), st.st_size))
        return tuple(sig)

    def maybe_refresh(self, interval: float = 1.5) -> bool:
        now = time.time()
        if now - self._last_check < interval:
            return False
        self._last_check = now
        sig = self._disk_signature()
        with self._lock:
            if sig == self._signature:
                return False
        self.rebuild(sig)
        return True

    def snapshot(self) -> tuple[list[dict], dict]:
        with self._lock:
            items = [self._items[i] for i in reversed(self._order)]
            meta = {"count": len(items), "signature": self._signature}
        return items, meta

    def query(self, terms: list[str], limit: int = 500) -> list[dict]:
        with self._lock:
            postings = self._postings
            norm = self._norm
            items = self._items
            total_terms = len(self._order)
            if not terms:
                ranked = None
            else:
                scores: dict[str, float] | None = None
                for raw in terms:
                    tok = raw.lower()
                    exact = postings.get(tok)
                    if exact is not None and len(exact) >= 200:
                        matched = exact
                    else:
                        cand = [v for k, v in postings.items()
                                if tok in k or (len(tok) >= 4 and k in tok)]
                        if exact is not None:
                            cand.append(exact)
                        if not cand:
                            return []
                        matched = set()
                        for s in cand:
                            matched |= s
                    idf = math.log(1 + total_terms / (1 + len(matched)))
                    w = max(norm * idf, 1e-6)
                    if scores is None:
                        scores = {i: w for i in matched}
                    else:
                        scores = {i: s + w for i, s in scores.items() if i in matched}
                        for i in matched:
                            scores.setdefault(i, w)
                ranked = sorted(scores.items(), key=lambda kv: -kv[1])[:limit]
            out = []
            if ranked is None:
                for i in reversed(self._order[-limit:]):
                    out.append(items[i])
            else:
                for i, _score in ranked:
                    it = items.get(i)
                    if it:
                        out.append(it)
            return out

    def rebuild(self, signature: tuple | None = None) -> None:
        items: dict[str, dict] = {}
        order: list[str] = []
        fields: dict[str, str] = {}
        if self.runs_dir.exists():
            for d in sorted(self.runs_dir.iterdir()):
                jl = d / "items.jsonl"
                if not jl.exists():
                    continue
                try:
                    with jl.open() as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                it = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            iid = it.get("id") or it.get("raw_hash")
                            if not iid or iid in items:
                                continue
                            it["_run"] = d.name
                            it["_ts"] = (it.get("collected_at") or "")[:19]
                            items[iid] = it
                            order.append(iid)
                            hay = " ".join([
                                str(it.get("value", "")),
                                str(it.get("category", "")),
                                str(it.get("source", "")),
                                " ".join(str(t) for t in (it.get("tags") or [])),
                                json.dumps(it.get("attributes") or {}, default=str),
                            ])
                            fields[iid] = hay.lower()
                except OSError:
                    continue
        df: dict[str, int] = {}
        postings: dict[str, set[str]] = {}
        for iid, hay in fields.items():
            toks = set(_tokenize(hay))
            for sub in re.findall(r"[0-9a-z]{3,}", hay):
                toks.add(sub)
            for tok in toks:
                postings.setdefault(tok, set()).add(iid)
                df[tok] = df.get(tok, 0) + 1
        n = max(len(order), 1)
        norm = max((math.log(1 + n / (1 + c)) for c in df.values()), default=1.0)
        with self._lock:
            self._items = items
            self._order = order
            self._postings = postings
            self._norm = norm
            self._signature = signature if signature is not None else self._disk_signature()


_index: SearchIndex | None = None
_build_lock = threading.Lock()


def get_index(runs_dir: Path) -> SearchIndex:
    global _index
    with _build_lock:
        if _index is None or str(_index.runs_dir) != str(runs_dir):
            _index = SearchIndex(runs_dir)
    return _index


def warm_async(runs_dir: Path) -> None:
    idx = get_index(runs_dir)
    if not idx.snapshot()[1]["count"]:
        threading.Thread(target=idx.rebuild, daemon=True).start()
