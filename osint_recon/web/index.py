from __future__ import annotations

import json
import math
import re
import threading
import time
from pathlib import Path

from osint_recon.models import entity_type, normalise_value

STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "http", "https",
    "www", "com", "net", "org",
}


def _tokenize(text: str) -> list[str]:
    return [t for t in re.split(r"[^0-9a-z_@.\-:/]+", text.lower()) if len(t) >= 2]


_TRIGRAM_MIN = 4


def _trigrams(tok: str) -> set[str]:
    if len(tok) < _TRIGRAM_MIN:
        return set()
    return {tok[i:i + 3] for i in range(len(tok) - 2)}


class SearchIndex:
    def __init__(self, runs_dir: Path):
        self.runs_dir = Path(runs_dir)
        self._lock = threading.Lock()
        self._items: dict[str, dict] = {}
        self._order: list[str] = []
        self._postings: dict[str, set[str]] = {}
        self._tri_postings: dict[str, set[str]] = {}
        self._tri_tokens: dict[str, set[str]] = {}
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

    def query(self, terms: list[str], limit: int = 500) -> tuple[list[dict], dict]:
        with self._lock:
            norm = self._norm
            postings = self._postings
            tri_postings = self._tri_postings
            tri_tokens = self._tri_tokens
            items = self._items
            norm_map = getattr(self, "_norm_map", {})
            total_terms = len(self._order)
            suggestions: set[str] = set()
            if not terms:
                ranked = None
            else:
                scores: dict[str, float] | None = None
                for raw in terms:
                    tok = raw.lower().strip()
                    if not tok:
                        continue
                    matched: set[str] = set()
                    exact = postings.get(tok)
                    if exact is not None:
                        matched |= exact
                    ent = entity_type(raw)
                    if ent:
                        host_m = re.match(r"^(?:https?://)?([\w.-]+)", raw.strip())
                        if ent == "domain" and host_m:
                            body_key = f"ioc_domain:{host_m.group(1).lower().removeprefix('www.')}"
                        else:
                            body_key = f"ioc_{ent}:{raw.strip().lower()}"
                        short_key = body_key.replace("ioc_", "", 1)
                        bare = short_key.split(":", 1)[1]
                        for alias in (body_key, short_key, bare):
                            for iid in norm_map.get(alias, ()):
                                matched.add(iid)
                    subtokens = [t for t in _tokenize(raw) if len(t) >= 2 and t != tok]
                    for st in subtokens:
                        s = postings.get(st)
                        if s is not None and len(s) < max(total_terms * 0.05, 50):
                            matched |= s
                    fuzzy: set[str] = set()
                    if not matched and len(tok) >= _TRIGRAM_MIN:
                        tset = _trigrams(tok)
                        hits: dict[str, int] = {}
                        for tg in tset:
                            for iid in tri_postings.get(tg, ()):
                                hits[iid] = hits.get(iid, 0) + 1
                        thr = max(2, int(len(tset) * 0.6))
                        for iid, h in hits.items():
                            if h >= thr:
                                fuzzy.add(iid)
                        if not fuzzy and len(tset) >= 2:
                            thr2 = max(2, int(len(tset) * 0.4))
                            for iid, h in hits.items():
                                if h >= thr2:
                                    fuzzy.add(iid)
                                    for cand in tri_tokens.get(iid, ()):
                                        if cand != tok:
                                            suggestions.add(cand)
                        matched = fuzzy
                    if not matched:
                        continue
                    idf = math.log(1 + total_terms / (1 + len(matched)))
                    w = max(norm * idf, 1e-6)
                    if scores is None:
                        scores = {i: w for i in matched}
                    else:
                        for i in matched:
                            scores[i] = scores.get(i, 0.0) + w
                if scores is None:
                    return [], {"suggestions": sorted(suggestions)[:10]}
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
            return out, {"suggestions": sorted(suggestions)[:10]}

    def rebuild(self, signature: tuple | None = None) -> None:
        items: dict[str, dict] = {}
        order: list[str] = []
        fields: dict[str, str] = {}
        canon_groups: dict[str, list[str]] = {}
        norm_map: dict[str, set[str]] = {}
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
                            cat = it.get("category", "")
                            val = str(it.get("value", ""))
                            if cat.startswith("ioc_"):
                                nv = normalise_value(cat, val)
                                ent = entity_type(nv)
                                host_m = re.match(r"^(?:https?://)?([\w.-]+)", nv)
                                if ent == "domain" and host_m:
                                    ck = f"ioc_domain:{host_m.group(1).lower().removeprefix('www.')}"
                                elif ent:
                                    ck = f"ioc_{ent}:{nv.lower()}"
                                else:
                                    ck = f"ioc_url:{nv}"
                                it["_canon"] = ck
                                it["_entity"] = ent or "url"
                                canon_groups.setdefault(ck, []).append(iid)
                                head, _, body = ck.partition(":")
                                short = head.replace("ioc_", "")
                                for alias in (ck, f"{short}:{body}", body):
                                    norm_map.setdefault(alias, set()).add(iid)
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
        tri_postings: dict[str, set[str]] = {}
        tri_tokens: dict[str, set[str]] = {}
        for iid, hay in fields.items():
            toks = set(_tokenize(hay))
            for sub in re.findall(r"[0-9a-z]{3,}", hay):
                toks.add(sub)
            for tok in toks:
                postings.setdefault(tok, set()).add(iid)
                df[tok] = df.get(tok, 0) + 1
                for tg in _trigrams(tok):
                    tri_postings.setdefault(tg, set()).add(iid)
                    tri_tokens.setdefault(iid, set()).add(tok)
        n = max(len(order), 1)
        norm = max((math.log(1 + n / (1 + c)) for c in df.values()), default=1.0)
        with self._lock:
            self._items = items
            self._order = order
            self._postings = postings
            self._tri_postings = tri_postings
            self._tri_tokens = tri_tokens
            self._norm_map = norm_map
            self._canon = canon_groups
            self._norm = norm
            self._signature = signature if signature is not None else self._disk_signature()

    def canon_group(self, canon_key: str) -> list[dict]:
        with self._lock:
            ids = self._canon.get(canon_key, [])
            return [self._items[i] for i in ids if i in self._items]

    def lookup_item(self, item_id: str) -> dict | None:
        with self._lock:
            it = self._items.get(item_id)
            if it is None:
                for v in self._items.values():
                    if v.get("raw_hash") == item_id:
                        return v
                return None
            return it


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
