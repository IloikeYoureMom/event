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
            "url": "https://threatfox.abuse.ch/export/csv/recent/",
            "kind": "ioc_csv", "tags": "c2",
        },
    }

    def collect(self) -> Iterable[IntelItem]:
        feeds = dict(self.DEFAULT_FEEDS)
        feeds.update(self.cfg.get("feeds", {}))
        specs = [(fname, spec) for fname, spec in feeds.items() if spec.get("url")]
        urls = [spec["url"] for _, spec in specs]
        cache_dir = self.cfg.get("cache_dir", "data/cache/feeds")
        responses = [self.http.cached_get(u, cache_dir) for u in urls]
        for (fname, spec), resp in zip(specs, responses):
            url = spec["url"]
            if not resp.ok:
                self.log.warning("feed %s: HTTP problem (%s)", fname, resp.error or resp.status)
                continue
            tags = [t.strip() for t in str(spec.get("tags", "")).split(",") if t.strip()]
            yield from self._parse(fname, url, spec.get("kind", "text"),
                                   spec.get("column_hint", "auto"), resp.body, tags)

    def _parse(self, feed: str, url: str, kind: str, hint: str,
               body: str, tags: list[str]) -> Iterable[IntelItem]:
        from .base import iocs_from_text
        if kind == "ioc_csv":
            import csv
            for row in csv.reader(io.StringIO(body)):
                if not row or row[0].startswith("#"):
                    continue
                cells = [c.strip().strip('"').strip() for c in row]
                ioc_type = ""
                ioc_value = ""
                first_seen = None
                for cell in cells:
                    cl = cell.lower()
                    if cl in ("ip:port", "ip", "domain", "url", "md5", "sha1",
                              "sha256", "email"):
                        ioc_type = cl
                    elif re.fullmatch(r"\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?", cell):
                        if first_seen is None:
                            first_seen = cell.replace(" ", "T") + "Z"
                    elif ioc_value == "" and len(cell) > 3 and not cell.isdigit():
                        ioc_value = cell
                cat = {"ip:port": "ioc_ipv4", "ip": "ioc_ipv4", "domain": "ioc_domain",
                       "url": "ioc_url", "md5": "ioc_md5", "sha1": "ioc_sha1",
                       "sha256": "ioc_sha256"}.get(ioc_type)
                if not cat or not ioc_value:
                    continue
                value = ioc_value
                if cat == "ioc_ipv4":
                    value = ioc_value.rsplit(":", 1)[0]
                yield IntelItem(category=cat, value=value, source=f"{self.name}:{feed}",
                                source_ref=url, first_seen=first_seen,
                                tags=tags + [feed])
        elif kind == "csv":
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
        urls = [u for u in self.cfg.get("urls", [
            "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        ]) if u]
        tmp = Path(self.cfg.get("cache_dir", "data/cache/stix"))
        tmp.mkdir(parents=True, exist_ok=True)
        for u in urls:
            if not re.match(r"^https?://", u):
                continue
            resp = self.http.cached_get(u, tmp)
            if not resp.ok:
                self.log.warning("stix url %s failed (%s)", u, resp.error or resp.status)
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
