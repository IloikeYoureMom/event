from __future__ import annotations

import hashlib
import io
import re
import tarfile
from typing import Iterable

from ..models import IntelItem
from ..redact import redact_secrets
from .base import Collector


class PublicPasteDumpCollector(Collector):
    name = "paste_dumps"
    enabled_by_default = False   # point at a mirror you're allowed to use

    def collect(self) -> Iterable[IntelItem]:
        urls = self.cfg.get("dump_urls", [])   # daily tarball mirrors
        watch = [w.lower() for w in self.cfg.get("watch_terms", [])]
        if not urls:
            self.log.info("paste_dumps: configure sources.paste_dumps.dump_urls")
            return
        max_bytes = int(self.cfg.get("max_dump_mb", 200)) * 1024 * 1024
        for url in urls:
            resp = self.http.get(url)
            if not resp.ok:
                self.log.warning("dump %s failed", url)
                continue
            blob = resp.body.encode(errors="replace")[:max_bytes]
            try:
                tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
            except tarfile.TarError:
                self.log.warning("dump %s not a tarball", url)
                continue
            for member in tf:
                if not member.isfile() or member.size > 2_000_000:
                    continue
                fobj = tf.extractfile(member)
                if not fobj:
                    continue
                text = fobj.read().decode(errors="replace")
                low = text.lower()
                hits = [w for w in watch if w in low]
                if watch and not hits:
                    continue
                safe = redact_secrets(text[:3000])
                yield IntelItem(
                    category="paste", value=safe.text, source=self.name,
                    source_ref=url, confidence=0.6 if hits else 0.3, tlp="CLEAR",
                    tags=["paste"] + ([f"watch:{h}" for h in hits] or ["untargeted"]),
                    attributes={"member": member.name,
                                "raw_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                "watch_hits": hits, "redaction_hits": safe.hits},
                    redacted=safe.changed,
                )


class RentrySearchCollector(Collector):

    name = "rentry_search"
    enabled_by_default = False

    RE_LINK = re.compile(r'href="(/([A-Za-z0-9]{6,8}))"')

    def collect(self) -> Iterable[IntelItem]:
        terms = self.cfg.get("watch_terms", [])
        for t in terms:
            url = f"https://rentry.co/search/?q={t.replace(' ', '+')}"
            resp = self.http.get(url)
            if not resp.ok:
                continue
            for m in self.RE_LINK.finditer(resp.body):
                slug = m.group(2)
                raw_url = f"https://rentry.co/{slug}/raw"
                pr = self.http.get(raw_url)
                if not pr.ok:
                    continue
                safe = redact_secrets(pr.body[:3000])
                yield IntelItem(
                    category="paste", value=safe.text, source=self.name,
                    source_ref=raw_url, confidence=0.5, tlp="CLEAR",
                    tags=["rentry", f"search:{t}"],
                    attributes={"redaction_hits": safe.hits}, redacted=safe.changed)
