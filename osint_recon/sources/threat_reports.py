from __future__ import annotations

import email.utils
import re
import xml.etree.ElementTree as ET
from typing import Iterable
from urllib.parse import urlparse

from ..models import IntelItem
from ..registry import Registry
from .base import Collector, iocs_from_text

ATOM_NS = "{http://www.w3.org/2005/Atom}"

DEFAULT_REPORT_FEEDS: dict[str, str] = {
    "microsoft_msec": "https://www.microsoft.com/en-us/security/blog/feed/",
    "google_mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
    "crowdstrike_blog": "https://www.crowdstrike.com/blog/feed/",
    "unit42_paloaltonetworks": "https://unit42.paloaltonetworks.com/feed/",
    "kaspersky_securelist": "https://securelist.com/feed/",
    "sentinelone_labs": "https://www.sentinelone.com/labs/feed/",
    "elastic_security_labs": "https://www.elastic.co/security-labs/rss.xml",
    "redcanary_covalence": "https://www.redcanary.com/blog-category/covalence/feed/",
    "malwarebytes_labs": "https://malwarebytes.com/blog/feed/",
}

RE_ACTORISH = [
    re.compile(r"\bUNC\d{4}(?:-\d)?\b"),
    re.compile(r"'([A-Z][A-Za-z0-9 -]{2,30})'"),
    re.compile(r"\(([A-Z][a-zA-Z]+(?:[ -][A-Z][a-zA-Z]+){0,2})\)"),
]


class RssReportCollector(Collector):
    name = "rss_reports"

    def __init__(self, cfg, http=None, registry: Registry | None = None):
        super().__init__(cfg, http)
        self.registry = registry

    def collect(self) -> Iterable[IntelItem]:
        feeds = dict(DEFAULT_REPORT_FEEDS)
        feeds.update(self.cfg.get("feeds", {}))
        keywords = [k.lower() for k in self.cfg.get("filter_keywords", [])]
        for org, url in feeds.items():
            resp = self.http.get(url)
            if not resp.ok:
                self.log.warning("feed %s (%s) failed: %s", org, url, resp.error or resp.status)
                continue
            try:
                yield from self._parse(org, url, resp.body, keywords)
            except ET.ParseError as exc:
                self.log.warning("feed %s XML parse error: %s", org, exc)

    def _parse(self, org: str, feed_url: str, body: str,
               keywords: list[str]) -> Iterable[IntelItem]:
        root = ET.fromstring(body.strip())
        entries = []
        if root.tag == "rss":
            for item in root.iter("item"):
                entries.append({
                    "title": (item.findtext("title") or "").strip(),
                    "link": (item.findtext("link") or "").strip(),
                    "date": item.findtext("pubDate") or "",
                    "summary": re.sub(r"<[^>]+>", " ", item.findtext("description") or ""),
                })
        else:  # Atom
            for e in root.findall(f"{ATOM_NS}entry"):
                link_el = e.find(f"{ATOM_NS}link")
                entries.append({
                    "title": (e.findtext(f"{ATOM_NS}title") or "").strip(),
                    "link": link_el.get("href") if link_el is not None else "",
                    "date": e.findtext(f"{ATOM_NS}published") or e.findtext(f"{ATOM_NS}updated") or "",
                    "summary": re.sub(r"<[^>]+>", " ",
                                      e.findtext(f"{ATOM_NS}summary") or
                                      e.findtext(f"{ATOM_NS}content") or ""),
                })

        for ent in entries:
            text = f"{ent['title']} {ent['summary']}"
            if keywords and not any(k in text.lower() for k in keywords):
                continue
            date = ent["date"]
            try:
                date = email.utils.parsedate_to_datetime(date).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass
            yield IntelItem(
                category="threat_report", value=text[:1500], source=f"{self.name}:{org}",
                source_ref=ent["link"] or feed_url, first_seen=date,
                attributes={"title": ent["title"], "publisher": org},
                tags=["report", org.replace("_", "-")],
            )
            for pat in RE_ACTORISH:
                for m in pat.finditer(ent["title"]):
                    name = m.group(1) if m.groups() else m.group(0)
                    name = re.sub(r"\s+", " ", name).strip()
                    if len(name) < 3 or name.lower() in {"new", "update"}:
                        continue
                    canon = self.registry.resolve(name) if self.registry else name
                    yield IntelItem(
                        category="actor", value=canon, source=f"{self.name}:actors",
                        source_ref=ent["link"],
                        attributes={"as_reported": name, "publisher": org,
                                    "report_title": ent["title"]},
                        tags=["actor-mention"], confidence=0.6,
                    )
            for it in iocs_from_text(ent["summary"], source=f"{self.name}:ioc",
                                     source_ref=ent["link"], tags=["from-report", org]):
                yield it
