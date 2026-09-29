from __future__ import annotations

import io
import json
import os
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterable

from ..models import IntelItem
from ..registry import IOC_CATEGORY_BY_STIX
from .base import Collector


class TextFeedCollector(Collector):

    name = "text_feeds"

    DEFAULT_FEEDS: dict[str, dict[str, str]] = {
        "urlhaus_urls": {
            "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "kind": "csv", "column_hint": "url", "tags": "phishing,malware-url",
        },
        "feodo_ips": {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
            "kind": "csv", "column_hint": "ip", "tags": "c2,botnet",
        },
        "threatfox_c2": {
            "url": "https://threatfox.abuse.ch/export/text/recent/",
            "kind": "text", "column_hint": "auto", "tags": "c2",
        },
    }

    def collect(self) -> Iterable[IntelItem]:
        feeds = dict(self.DEFAULT_FEEDS)
        feeds.update(self.cfg.get("feeds", {}))
        for fname, spec in feeds.items():
            url = spec.get("url")
            if not url:
                continue
            resp = self.http.get(url)
            if not resp.ok:
                self.log.warning("feed %s: HTTP problem (%s)", fname, resp.error or resp.status)
                continue
            tags = [t.strip() for t in str(spec.get("tags", "")).split(",") if t.strip()]
            yield from self._parse(fname, url, spec.get("kind", "text"),
                                   spec.get("column_hint", "auto"), resp.body, tags)

    def _parse(self, feed: str, url: str, kind: str, hint: str,
               body: str, tags: list[str]) -> Iterable[IntelItem]:
        from .base import iocs_from_text
        if kind == "csv":
            import csv
            rows = list(csv.reader(io.StringIO(body)))
            for row in rows:
                if not row or row[0].startswith("#"):
                    continue
                cells = [c.strip() for c in row]
                vals = self._pick(cells, hint)
                for cat, val in vals:
                    yield IntelItem(category=cat, value=val, source=f"{self.name}:{feed}",
                                    source_ref=url, tags=tags + [feed])
        else:
            for it in iocs_from_text(body, source=f"{self.name}:{feed}",
                                     source_ref=url, tags=tags + [feed]):
                yield it

    @staticmethod
    def _pick(cells: list[str], hint: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for c in cells:
            cl = c.lower()
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", c):
                out.append(("ioc_ipv4", c))
            elif cl.startswith(("http://", "https://")):
                out.append(("ioc_url", c))
            elif re.fullmatch(r"[a-f0-9]{64}", cl):
                out.append(("ioc_sha256", cl))
            elif re.fullmatch(r"[a-f0-9]{32}", cl):
                out.append(("ioc_md5", cl))
        return out


class StixFileCollector(Collector):

    name = "stix_files"

    def collect(self) -> Iterable[IntelItem]:
        paths = [Path(p) for p in self.cfg.get("paths", []) if Path(p).exists()]
        urls = self.cfg.get("urls", [
            "https://raw.githubusercontent.com/digitalside/threat-actor/master/latest.tar.gz",
        ])
        tmp = Path(self.cfg.get("cache_dir", "data/cache/stix"))
        tmp.mkdir(parents=True, exist_ok=True)
        for u in urls:
            if re.match(r"^https?://", u):
                resp = self.http.get(u)
                if not resp.ok:
                    self.log.warning("stix url %s failed", u)
                    continue
                dest = tmp / re.sub(r"\W+", "_", u)[-60:]
                dest.write_bytes(resp.body.encode(errors="replace"))
                paths.append(dest)
        for p in paths:
            yield from self._ingest_path(p)

    def _ingest_path(self, p: Path) -> Iterable[IntelItem]:
        names: list[tuple[str, bytes]] = []
        try:
            if p.suffix == ".gz" or p.name.endswith(".tar.gz"):
                with tarfile.open(p, "r:*") as tf:
                    for m in tf.getmembers():
                        if m.isfile() and m.name.endswith((".json", ".stix")):
                            fobj = tf.extractfile(m)
                            if fobj:
                                names.append((m.name, fobj.read()))
            elif p.suffix == ".zip":
                with zipfile.ZipFile(p) as zf:
                    for n in zf.namelist():
                        if n.endswith((".json", ".stix")):
                            names.append((n, zf.read(n)))
            else:
                names.append((p.name, p.read_bytes()))
        except Exception as exc:
            self.log.warning("cannot unpack %s: %s", p, exc)
            return

        for member, blob in names:
            try:
                data = json.loads(blob.decode(errors="replace"))
            except json.JSONDecodeError:
                continue
            objs = data if isinstance(data, list) else data.get("objects", [data])
            for o in objs:
                yield from self._stix_object(o, f"{p.name}::{member}")

    def _stix_object(self, o: dict[str, Any], origin: str) -> Iterable[IntelItem]:
        if o.get("type") != "indicator":
            return
        pattern = o.get("pattern", "")
        m = re.search(r"\[([A-Za-z0-9-]+):'value'\s*=\s*'([^']+)'\]", pattern)
        if not m:
            return
        stix_type, value = m.group(1), m.group(2)
        cat = IOC_CATEGORY_BY_STIX.get(stix_type)
        if not cat:
            return
        name = o.get("name", "")
        refs = o.get("external_references", []) or []
        source_refs = [r.get("url") for r in refs if r.get("url")]
        yield IntelItem(
            category=cat, value=value, source=self.name,
            source_ref=source_refs[0] if source_refs else origin,
            first_seen=o.get("created"),
            confidence=float(o.get("confidence", 70) or 70) / 100.0,
            tags=["stix"] + ([o.get("kill_chain_phases", [{}])[0].get("phase_name", "")]
                              if o.get("kill_chain_phases") else []),
            attributes={"indicator_name": name, "origin_file": origin},
        )
