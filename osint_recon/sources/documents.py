from __future__ import annotations

import re
from collections import deque
from typing import Iterable

from ..models import IntelItem
from .base import Collector, RE_URL, iocs_from_text


class DocLinkHarvester(Collector):
    name = "doc_links"

    def collect(self) -> Iterable[IntelItem]:
        seeds: list[str] = self.cfg.get("seed_urls", [])
        max_docs = int(self.cfg.get("max_docs", 25))
        allowed_hosts = set(h.lower() for h in self.cfg.get("allowed_hosts", []))
        queue = deque(seeds)
        seen: set[str] = set()
        n = 0
        while queue and n < max_docs:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            host = re.sub(r"^www\.", "", re.split(r"/", url.split("//")[-1])[0]).lower()
            if allowed_hosts and host not in allowed_hosts:
                continue
            resp = self.http.get(url)
            if not resp.ok:
                continue
            n += 1
            body = resp.body
            is_pdf = ("%PDF" in body[:8]) or "pdf" in resp.headers.get(
                "Content-Type", "").lower()
            text = self._pdf_text(body) if is_pdf else re.sub(r"<[^>]+>", " ", body)
            yield from self._emit(url, text, is_pdf)
            if self.cfg.get("follow_links", False):
                for m in RE_URL.finditer(text):
                    u = m.group(0)
                    if u.startswith("http") and u not in seen:
                        queue.append(u)

    def _emit(self, doc_url: str, text: str, is_pdf: bool) -> Iterable[IntelItem]:
        base = re.sub(r"https?://([^/]+)/.*", r"\1", doc_url)
        internal = re.compile(re.escape(base).replace(r"\.", r"\.") + r"/")
        for m in RE_URL.finditer(text):
            u = m.group(0).rstrip('.,");\'')
            if internal.search(u):
                continue                       # skip same-site nav links
            yield IntelItem(
                category="link_from_document", value=u, source=self.name,
                source_ref=doc_url, confidence=0.4, tlp="CLEAR",
                tags=["harvested-link", "pdf" if is_pdf else "html"],
                attributes={"document": doc_url})
        for it in iocs_from_text(text, source=f"{self.name}:ioc",
                                 source_ref=doc_url,
                                 tags=["from-document"]):
            it.attributes["document"] = doc_url
            yield it

    @staticmethod
    def _pdf_text(blob: str) -> str:
        import shutil
        import subprocess
        import tempfile
        if shutil.which("pdftotext"):
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
                f.write(blob.encode(errors="replace"))
                path = f.name
            try:
                out = subprocess.run(["pdftotext", "-q", path, "-"],
                                     capture_output=True, timeout=60)
                if out.returncode == 0:
                    return out.stdout.decode(errors="replace")
            except Exception:
                pass
            finally:
                import os
                try:
                    os.unlink(path)
                except OSError:
                    pass
        return " ".join(re.findall(r"\(([^)\\]{3,200})\)", blob))
