from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from typing import Iterable

from ..models import IntelItem
from ..redact import redact_secrets
from .base import Collector, iocs_from_text


class ForumRssCollector(Collector):

    name = "forums"
    enabled_by_default = True

    def collect(self) -> Iterable[IntelItem]:
        sites = self.cfg.get("sites", [])   # [{name,url,keywords[],auth_env}]
        if not sites:
            self.log.info("forums: add sources.forums.sites entries (opt-in per ToS)")
            return
        for site in sites:
            url = site.get("url")
            if not url:
                continue
            headers = {}
            auth_env = site.get("auth_env")
            if auth_env:
                tok = os.getenv(auth_env, "")
                if not tok:
                    self.log.warning("forum %s needs $%s - skipping", site.get("name"), auth_env)
                    continue
                headers["Authorization"] = f"Bearer {tok}"
            resp = self.http.get(url, headers=headers)
            if not resp.ok:
                self.log.warning("forum %s fetch failed (%s)",
                                 site.get("name"), resp.error or resp.status)
                continue
            yield from self._parse(site, resp.body)

    def _parse(self, site: dict, body: str) -> Iterable[IntelItem]:
        sname = str(site.get("name", "forum"))
        keywords = [k.lower() for k in site.get("keywords", [])]
        try:
            root = ET.fromstring(body.strip())
        except ET.ParseError:
            self.log.warning("forum %s: not XML", sname)
            return
        items = []
        for node in list(root.iter("item")) + list(
                root.iter("{http://www.w3.org/2005/Atom}entry")):
            def txt(*names: str) -> str:
                for n in names:
                    el = node.find(n) if node.tag != "{http://www.w3.org/2005/Atom}entry" \
                        else node.find(f"{{http://www.w3.org/2005/Atom}}{n}")
                    if el is not None and el.text:
                        return el.text.strip()
                link = node.find("link") if node.find("link") is not None \
                    else node.find("{http://www.w3.org/2005/Atom}link")
                if link is not None and link.get("href"):
                    return str(link.get("href"))
                return ""
            title = txt("title", "{http://www.w3.org/2005/Atom}title")
            link = txt("link", "{http://www.w3.org/2005/Atom}link")
            desc = re.sub(r"<[^>]+>", " ", txt("description",
                                               "{http://www.w3.org/2005/Atom}summary",
                                               "{http://www.w3.org/2005/Atom}content"))
            author = txt("author", "{http://www.w3.org/2005/Atom}author")
            items.append((title, link, desc, author))

        for title, link, desc, author in items:
            blob = f"{title} {desc}".lower()
            if keywords and not any(k in blob for k in keywords):
                continue
            safe_title = redact_secrets(title)
            safe_body = redact_secrets(desc[:4000])
            yield IntelItem(
                category="forum_post", value=f"{safe_title.text} :: {safe_body.text}"[:4500],
                source=f"{self.name}:{sname}", source_ref=link,
                confidence=0.5, tlp="CLEAR",
                tags=["forum", sname] + [k for k in keywords if k in blob],
                attributes={"author_handle": author,
                            "redaction_hits": {**safe_title.hits, **safe_body.hits}},
                redacted=safe_title.changed or safe_body.changed,
            )
            if author:
                yield IntelItem(category="forum_profile", value=author,
                                source=f"{self.name}:{sname}:profiles",
                                source_ref=link, confidence=0.4,
                                tags=["handle", sname])
            for it in iocs_from_text(safe_body.text, source=f"{self.name}:{sname}:ioc",
                                     source_ref=link, tags=["from-forum", sname]):
                yield it
