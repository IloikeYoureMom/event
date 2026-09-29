from __future__ import annotations

import json
import re
import urllib.parse
from typing import Iterable

from ..models import IntelItem
from .base import Collector


class RansomLeakCollector(Collector):
    name = "ransom_leaks"

    DEFAULT_SOURCES = {
        "ransomware_live": "https://api.ransomware.live/v1/recentvictims?limit=200",
    }

    def collect(self) -> Iterable[IntelItem]:
        watch = [w.lower() for w in self.cfg.get("watchlist", [])]
        if not watch:
            self.log.info("ransom_leaks: empty watchlist -> collecting all recent leaks")
        srcs = dict(self.DEFAULT_SOURCES)
        srcs.update(self.cfg.get("extra_sources", {}))
        for provider, url in srcs.items():
            resp = self.http.get(url)
            if not resp.ok:
                self.log.warning("%s failed (%s)", provider, resp.error or resp.status)
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            yield from self._rows(provider, data, watch)

    def _rows(self, provider: str, data, watch: list[str]) -> Iterable[IntelItem]:
        rows = data if isinstance(data, list) else data.get("items", [data])
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict):
                continue
            victim = str(r.get("victim") or r.get("post_title")
                         or r.get("company") or r.get("site") or "?")
            actor = str(r.get("group_name") or r.get("blog") or r.get("group")
                        or r.get("actor") or "?")
            posted = r.get("discovered") or r.get("published") or r.get("date") or r.get("added")
            link = r.get("url") or r.get("link") or r.get("post_url")
            desc = str(r.get("description") or "")[:600]
            haystack = f"{victim} {desc}".lower()
            matched = [w for w in watch if w in haystack]
            if watch and not matched:
                continue
            tags = ["ransom-leak", provider] + ([f"watch-hit:{m}" for m in matched] or ["unfiltered"])
            yield IntelItem(
                category="ransom_leak", value=f"{victim} :: {actor}", source=self.name,
                source_ref=link, first_seen=str(posted)[:20] if posted else None,
                confidence=0.9 if matched else 0.6, tlp="AMBER" if matched else "CLEAR",
                tags=tags,
                attributes={"victim": victim, "actor": actor, "provider": provider,
                            "sector": r.get("activity"), "country": r.get("country"),
                            "data_size": r.get("data_size"),
                            "description": desc, "watch_hits": matched},
            )
