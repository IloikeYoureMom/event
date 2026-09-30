from __future__ import annotations

import json
import urllib.parse
from typing import Iterable

from ..models import IntelItem
from .base import Collector


class MalwareBazaarBrandCollector(Collector):

    name = "malwarebazaar_brand"
    enabled_by_default = True

    API = "https://mb-api.abuse.ch/api/v1/"

    def collect(self) -> Iterable[IntelItem]:
        needles = self.cfg.get("search_terms", []) or ["stealer", "redline", "vidar"]
        if not needles:
            self.log.info("set sources.malwarebazaar_brand.search_terms to skip-noop")
            return
        for term in needles:
            payload = urllib.parse.urlencode({"query": "search_term", "search_term": term})
            resp = self.http.post_form(self.API, payload,
                                       headers={"User-Agent": "curl/8.5.0"})
            if not resp or not resp.ok:
                self.log.warning("MalwareBazaar lookup failed for %s", term)
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            for s in data.get("data", []).get("samples", []) if isinstance(data.get("data"), dict) else data.get("data", []):
                sha256 = s.get("sha256", "")
                if not sha256:
                    continue
                yield IntelItem(
                    category="stealer_log",           # "sample references our brand"
                    value=sha256, source=self.name,
                    source_ref=f"https://bazaar.abuse.ch/sample/{sha256}/",
                    first_seen=s.get("first_seen"), confidence=0.75, tlp="CLEAR",
                    tags=["malware-sample", "brand-mention"],
                    attributes={
                        "signature": s.get("signature"),
                        "file_name": s.get("file_name"),
                        "file_type": s.get("file_type"),
                        "tags": s.get("tags", []),
                        "matched_term": term,
                    },
                )



class CrtshRogueCertCollector(Collector):

    name = "crtsh_certs"

    DEFAULT_DOMAINS = ["abuse.ch", "urlhaus.abuse.ch"]

    def collect(self) -> Iterable[IntelItem]:
        domains = self.cfg.get("domains", []) or self.DEFAULT_DOMAINS
        since = self.cfg.get("since_id", 0)     # crt.sh ids grow ~monotonically
        for d in domains:
            url = (f"https://crt.sh/?q=%25.{urllib.parse.quote(d, safe='')}"
                   f"&output=json&mincertid={since}")
            resp = self.http.get(url, allow_robots_override=True)
            if not resp.ok:
                self.log.warning("crt.sh failed for %s (%s)", d, resp.error or resp.status)
                continue
            try:
                rows = resp.json()
            except Exception:
                continue
            for r in rows if isinstance(rows, list) else []:
                cn = r.get("common_name", "")
                if d.lower().split(".")[0] not in cn.lower():
                    pass  # wildcard matches from %25. prefix; keep all, tag them
                yield IntelItem(
                    category="infected_device",       # proxy signal: spoof infra
                    value=cn, source=self.name,
                    source_ref=f"https://crt.sh/?id={r.get('id')}",
                    first_seen=r.get("not_before"), confidence=0.85,
                    tags=["certificate", "possible-spoof"],
                    attributes={
                        "issuer_ca": r.get("issuer_name"),
                        "serial": r.get("serial_number"),
                        "san": (r.get("name_value") or "")[:400],
                        "log_id": r.get("id"),
                        "watched_domain": d,
                    },
                )
