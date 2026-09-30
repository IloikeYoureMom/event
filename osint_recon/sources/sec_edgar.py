from __future__ import annotations

import json
import re
import time
from typing import Iterable
from urllib.parse import urlencode

from ..models import IntelItem
from .base import Collector, iocs_from_text

FTS_URL = "https://efts.sec.gov/LATEST/search-index?"
RE_105_BLOCK = re.compile(
    r"Item\s*\.?\s*1\.05[\s\S]{0,60}?(Material Cybersecurity Incidents)?\s*"
    r"([\s\S]{20,4000}?)(?=Item\s*\.?\s*[1-9]\.[0-9]|$)", re.I)


class EdgarItem105Collector(Collector):
    name = "sec_8k_item105"
    enabled_by_default = False

    def collect(self) -> Iterable[IntelItem]:
        days = int(self.cfg.get("lookback_days", 7))
        forms = self.cfg.get("forms", ["8-K"])
        q = self.cfg.get("query", '"Item 1.05"')
        end = time.strftime("%Y-%m-%d")
        start = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
        max_items = int(self.cfg.get("max_items", 100))
        page_size = int(self.cfg.get("page_size", 50))
        urls: list[str] = []
        offset = 0
        while offset < max(200, max_items):
            params = {"q": q, "forms": ",".join(forms), "dateRange": "custom",
                      "startdt": start, "enddt": end}
            urls.append(FTS_URL + urlencode(params) + f"&start={offset}")
            if offset + page_size >= max_items or offset + 100 >= 200:
                break
            offset += 100
        resps = self.http.get_many(urls, headers={"Accept": "application/json"},
                                   skip_rate_limit=True)
        emitted = 0
        for resp in resps:
            if not resp.ok:
                self.log.warning("EDGAR FTS failed: %s", resp.error or resp.status)
                continue
            try:
                data = resp.json()
            except Exception as exc:
                self.log.warning("EDGAR FTS bad json: %s", exc)
                continue
            hits = data.get("hits", {}).get("hits", [])
            for h in hits:
                src = h.get("_source", {})
                items = [str(i) for i in (src.get("items") or [])]
                if self.cfg.get("require_item_tag", True) and \
                        not any(i.strip().lstrip(".") == "1.05" for i in items):
                    continue
                yield from self._emit(src)
                emitted += 1
                if emitted >= max_items:
                    return

    def _emit(self, src: dict) -> Iterable[IntelItem]:
        names = src.get("display_names") or ["?"]
        company = names[0].split("(")[0].strip() or "?"
        cik = (src.get("ciks") or [""])[0]
        adsh = src.get("adsh", "")
        filed = src.get("file_date")
        accession_url = ""
        if cik and adsh:
            accession_url = (f"https://www.sec.gov/Archives/edgar/data/"
                             f"{cik.lstrip('0') or '0'}/{adsh.replace('-', '')}/")
        yield IntelItem(
            category="sec_8k_item105", value=f"{company}: 8-K Item 1.05 disclosure",
            source=self.name, source_ref=accession_url or None, first_seen=filed,
            confidence=0.95, tlp="CLEAR", tags=["sec-8k", "item-1.05", "cyber-disclosure"],
            attributes={"company": company, "cik": cik, "accession_no": adsh,
                        "form": src.get("form"),
                        "file_num": (src.get("file_num") or [""])[0],
                        "period_ending": src.get("period_ending"),
                        "sics": src.get("sics"),
                        "state_of_incorp": src.get("inc_states")},
        )
        if self.cfg.get("fetch_item_text") and accession_url:
            yield from self._grab_narrative(company, accession_url)

    def _grab_narrative(self, company: str, base_url: str) -> Iterable[IntelItem]:
        try:
            idx = self.http.get(base_url.rstrip("/") + "/index.json")
            if not idx.ok:
                return
            files = idx.json().get("directory", [])
            primary = next((f["name"] for f in files
                            if f.get("name", "").lower().endswith(".htm")
                            and "-index" not in f["name"]), None)
            if not primary:
                return
            doc = self.http.get(base_url + primary)
            if not doc.ok:
                return
            text = re.sub(r"<[^>]+>", " ", doc.body)
            text = re.sub(r"\s+", " ", text)
            m = RE_105_BLOCK.search(text)
            block = (m.group(3) if m and m.lastindex and m.group(3)
                     else (m.group(0) if m else ""))[:3000]
            if not block.strip():
                return
            yield IntelItem(
                category="sec_8k_item105", value=f"{company} :: {block}",
                source=f"{self.name}:narrative", source_ref=base_url + primary,
                confidence=0.95, tlp="CLEAR", tags=["sec-8k", "narrative"],
                attributes={"company": company})
            for it in iocs_from_text(block, source=f"{self.name}:ioc",
                                     source_ref=base_url + primary,
                                     tags=["from-8k"]):
                yield it
        except Exception as exc:
            self.log.warning("narrative fetch failed for %s: %s", company, exc)
